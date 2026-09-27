/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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
//! This module provides typed helper APIs over the raw byte-level IE structs
//! defined in [`crate::nas_5gs::types`]. The raw `.value` fields remain `pub` for
//! backward compatibility; these accessors add type-safe parsing and builders
//! where this crate exposes typed structure directly.
//!
//! # Architecture
//!
//! ```text
//! Layer 3 — This module: typed enums, accessor methods, builder helpers
//! Layer 2 — messages.rs:  NAS message structs with IEI dispatch
//! Layer 1 — types.rs:     raw TLV/TV/V/LV wire codec
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use unicode_normalization::UnicodeNormalization;

use crate::common::nas_opaque_ie;
use crate::nas_5gs::types::*;

// ============================================================================
// Core IEs — identity, registration, security, tracking area
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
    /// Decode a value from its wire octet.
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

/// SUPI format field within a SUCI mobile identity (TS 24.501 §9.11.3.4, octet 3 bits 5-7).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SupiFormat {
    /// IMSI (MCC+MNC+MSIN).
    Imsi = 0,
    /// Network-specific identifier (NAI).
    NetworkSpecific = 1,
    /// Global Cable Identifier (GCI) — Rel-16.
    Gci = 2,
    /// Global Line Identifier (GLI) — Rel-16.
    Gli = 3,
}

impl SupiFormat {
    /// Parse the SUPI format with the TS 24.501 §9.11.3.4 receive-side fallback.
    ///
    /// Values `4..=7` are not table-defined in this release, but are interpreted
    /// as IMSI when received.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::Imsi),
            1 => Some(Self::NetworkSpecific),
            2 => Some(Self::Gci),
            3 => Some(Self::Gli),
            _ => Some(Self::Imsi),
        }
    }

    /// Strict parser for the table-defined SUPI format values only.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::Imsi),
            1 => Some(Self::NetworkSpecific),
            2 => Some(Self::Gci),
            3 => Some(Self::Gli),
            _ => None,
        }
    }
}

/// Parsed 5G-GUTI (§9.11.3.4, Figure 9.11.3.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Guti {
    /// PLMN.
    pub plmn: PlmnId,
    /// AMF region identifier.
    pub amf_region_id: u8,
    /// AMF set identifier.
    pub amf_set_id: u16, // 10 bits
    /// AMF pointer.
    pub amf_pointer: u8, // 6 bits
    /// TMSI.
    pub tmsi: u32,
}

/// Parsed 5G-S-TMSI (§9.11.3.4, Figure 9.11.3.4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct STmsi {
    /// AMF set identifier.
    pub amf_set_id: u16, // 10 bits
    /// AMF pointer.
    pub amf_pointer: u8, // 6 bits
    /// TMSI.
    pub tmsi: u32,
}

/// SUCI protection scheme per TS 33.501 Annex C.
///
/// Values 0x00..=0x02 are the standardised schemes, 0x03..=0x0B are reserved,
/// and 0x0C..=0x0F are HPLMN-defined/operator-specific. Non-standard raw codes
/// are preserved losslessly.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtectionScheme {
    /// Null scheme (MSIN sent in cleartext).
    Null,
    /// ECIES Profile A (Curve25519).
    ProfileA,
    /// ECIES Profile B (secp256r1).
    ProfileB,
    /// Reserved protection scheme identifier, raw 4-bit identifier in 0x03..=0x0B.
    Reserved(u8),
    /// HPLMN-defined/operator-specific protection scheme, raw 4-bit identifier in 0x0C..=0x0F.
    HplmnDefined(u8),
}

impl ProtectionScheme {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::Null),
            0x01 => Some(Self::ProfileA),
            0x02 => Some(Self::ProfileB),
            raw @ 0x03..=0x0B => Some(Self::Reserved(raw)),
            raw @ 0x0C..=0x0F => Some(Self::HplmnDefined(raw)),
            _ => None,
        }
    }

    /// Encode a protection-scheme identifier after checking the variant domain.
    pub fn try_to_u8(self) -> Option<u8> {
        match self {
            Self::Null => Some(0x00),
            Self::ProfileA => Some(0x01),
            Self::ProfileB => Some(0x02),
            Self::Reserved(raw @ 0x03..=0x0B) => Some(raw),
            Self::HplmnDefined(raw @ 0x0C..=0x0F) => Some(raw),
            Self::Reserved(_) | Self::HplmnDefined(_) => None,
        }
    }

    /// Lossless encoding to the 4-bit protection scheme identifier.
    ///
    /// # Panics
    ///
    /// Panics if a payload-carrying enum variant contains a value outside its
    /// specified domain. Use [`Self::try_to_u8`] for untrusted values.
    pub fn to_u8(self) -> u8 {
        self.try_to_u8()
            .expect("protection-scheme variant must contain a value in its declared domain")
    }
}

/// Parsed IMSI-form SUCI (§9.11.3.4, Figure 9.11.3.4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ImsiSuci {
    /// PLMN identifier.
    pub plmn_id: PlmnId,
    /// Routing indicator.
    pub routing_indicator: Vec<u8>,
    /// Protection scheme.
    pub protection_scheme: ProtectionScheme,
    /// Home nw public key identifier.
    pub home_nw_public_key_id: u8,
    /// Scheme output.
    pub scheme_output: Vec<u8>,
}

/// Parsed SUCI (§9.11.3.4, Figures 9.11.3.4.3 and 9.11.3.4.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Suci {
    /// IMSI.
    Imsi(ImsiSuci),
    /// Utf 8.
    Utf8 {
        /// SUPI format.
        supi_format: SupiFormat,
        /// Nai.
        nai: String,
    },
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

impl ImsiSuci {
    /// Format as SUCI NAI string per 3GPP TS 23.003 §28.7.3.
    ///
    /// Output: `suci-0-<MCC>-<MNC>-<RI>-<scheme>-<key_id>-<scheme_output>`
    pub fn to_nai_string(&self) -> String {
        let ri = bcd_to_string(&self.routing_indicator);
        let scheme_output = if self.protection_scheme == ProtectionScheme::Null {
            bcd_to_string(&self.scheme_output)
        } else {
            hex::encode(&self.scheme_output)
        };
        format!(
            "suci-0-{}-{}-{}-{}-{}-{}",
            self.plmn_id.mcc_string(),
            self.plmn_id.mnc_string(),
            ri,
            self.protection_scheme.to_u8(),
            self.home_nw_public_key_id,
            scheme_output
        )
    }
}

impl Suci {
    /// Return SUPI format.
    pub fn supi_format(&self) -> SupiFormat {
        match self {
            Self::Imsi(_) => SupiFormat::Imsi,
            Self::Utf8 { supi_format, .. } => *supi_format,
        }
    }

    /// Return the value as IMSI.
    pub fn as_imsi(&self) -> Option<&ImsiSuci> {
        match self {
            Self::Imsi(suci) => Some(suci),
            Self::Utf8 { .. } => None,
        }
    }

    /// Return nai.
    pub fn nai(&self) -> Option<&str> {
        match self {
            Self::Imsi(_) => None,
            Self::Utf8 { nai, .. } => Some(nai),
        }
    }

    /// Return the nai string representation.
    pub fn to_nai_string(&self) -> String {
        match self {
            Self::Imsi(suci) => suci.to_nai_string(),
            Self::Utf8 { nai, .. } => nai.clone(),
        }
    }
}

pub use crate::common::PlmnId;

impl NasFGsMobileIdentity {
    /// Extract the identity type from bits 1-3 of the first byte.
    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        self.value
            .first()
            .and_then(|b| MobileIdentityType::from_u8(b & 0x07))
    }

    /// Parse as 5G-GUTI. Returns `None` if type is not GUTI or bytes are malformed.
    ///
    /// Wire format (11 bytes), TS 24.501 §9.11.3.4 Figure 9.11.3.4.1:
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
            plmn,
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

    /// Parse as a SUCI.
    ///
    /// Wire format per TS 24.501 §9.11.3.4 Figures 9.11.3.4.3 and 9.11.3.4.4:
    ///   byte 0: spare (1 bit) + SUPI format (3 bits) + spare (1 bit) + type=001 (3 bits)
    ///   IMSI form:
    ///     bytes 1-3: PLMN (TBCD)
    ///     bytes 4-5: Routing indicator (BCD, 2 bytes)
    ///     byte 6: Protection scheme ID
    ///     byte 7: Home network public key identifier
    ///     bytes 8+: Scheme output
    ///   Network-specific/GCI/GLI forms:
    ///     bytes 1+: UTF-8 NAI payload
    pub fn as_suci(&self) -> Option<Suci> {
        if self.value.len() < 2 || (self.value[0] & 0x07) != 0x01 {
            return None;
        }
        let supi_format = self.supi_format()?;
        if supi_format != SupiFormat::Imsi {
            let nai = std::str::from_utf8(&self.value[1..]).ok()?;
            if !valid_suci_nai(supi_format, nai) {
                return None;
            }
            return Some(Suci::Utf8 {
                supi_format,
                nai: nai.to_owned(),
            });
        }
        if self.value.len() < 8 {
            return None;
        }
        let plmn = PlmnId::from_tbcd(&self.value[1..4])?;
        let routing_indicator = self.value[4..6].to_vec();
        if !valid_routing_indicator(&routing_indicator) {
            return None;
        }
        let protection_scheme = ProtectionScheme::from_u8(self.value[6] & 0x0F)?;
        let home_nw_public_key_id = self.value[7];
        if matches!(protection_scheme, ProtectionScheme::Reserved(_))
            || home_nw_public_key_id == 0xff
            || (protection_scheme == ProtectionScheme::Null) != (home_nw_public_key_id == 0)
        {
            return None;
        }
        let scheme_output = self.value[8..].to_vec();
        if protection_scheme == ProtectionScheme::Null
            && !valid_null_suci_msin(&plmn, &scheme_output)
        {
            return None;
        }
        Some(Suci::Imsi(ImsiSuci {
            plmn_id: plmn,
            routing_indicator,
            protection_scheme,
            home_nw_public_key_id,
            scheme_output,
        }))
    }

    /// Return the raw UTF-8 payload of a non-IMSI SUCI.
    ///
    /// This diagnostic accessor deliberately preserves malformed NAI text. Use
    /// [`Self::as_suci`] when TS 23.003/RFC 7542 semantic validation is required.
    pub fn suci_nai(&self) -> Option<(SupiFormat, &str)> {
        if self.value.len() < 2 || (self.value[0] & 0x07) != 0x01 {
            return None;
        }
        let supi_format = self.supi_format()?;
        if supi_format == SupiFormat::Imsi {
            return None;
        }
        let nai = std::str::from_utf8(&self.value[1..]).ok()?;
        Some((supi_format, nai))
    }

    /// Parse as IMEI. Returns the 15-digit IMEI string.
    pub fn as_imei(&self) -> Option<String> {
        decode_receiver_identity_digits(&self.value, 0x03, 15).filter(|digits| digits.len() == 15)
    }

    /// Parse as IMEISV. Returns the 16-digit IMEISV string.
    pub fn as_imeisv(&self) -> Option<String> {
        decode_receiver_identity_digits(&self.value, 0x05, 16).filter(|digits| digits.len() == 16)
    }

    /// Parse as MAC address (type=6). Returns the 6-byte MAC.
    pub fn as_mac_address(&self) -> Option<[u8; 6]> {
        if self.value.len() < 7 || (self.value[0] & 0x07) != 0x06 {
            return None;
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.value[1..7]);
        Some(mac)
    }

    /// MAC address usability as an equipment identifier (MAURI bit).
    pub fn mauri(&self) -> Option<bool> {
        if self.value.is_empty() || (self.value[0] & 0x07) != 0x06 {
            return None;
        }
        Some((self.value[0] & 0x08) != 0)
    }

    /// Set the MAURI bit on a MAC-address mobile identity.
    pub fn set_mauri(&mut self, mauri: bool) {
        if self.value.is_empty() || (self.value[0] & 0x07) != 0x06 {
            return;
        }
        self.value[0] = 0x06 | if mauri { 0x08 } else { 0x00 };
    }

    /// Builder-style MAURI setter for MAC-address mobile identities.
    pub fn with_mauri(mut self, mauri: bool) -> Self {
        self.set_mauri(mauri);
        self
    }

    /// Construct a MAC address mobile identity (type=6). TS 24.501 §9.11.3.4.
    pub fn from_mac_address(mac: [u8; 6]) -> Self {
        Self::from_mac_address_with_mauri(mac, false)
    }

    /// Construct a MAC address mobile identity (type=6) with an explicit MAURI bit.
    pub fn from_mac_address_with_mauri(mac: [u8; 6], mauri: bool) -> Self {
        let mut value = Vec::with_capacity(7);
        // TS 24.501 §9.11.3.4: spare bits 8-5 = 0000, bit 4 = MAURI, type = 110.
        value.push(0x06 | if mauri { 0x08 } else { 0x00 });
        value.extend_from_slice(&mac);
        Self::new(value)
    }

    /// Parse as EUI-64 (type=7). Returns the 8-byte identifier.
    pub fn as_eui64(&self) -> Option<[u8; 8]> {
        if self.value.len() < 9 || (self.value[0] & 0x07) != 0x07 {
            return None;
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&self.value[1..9]);
        Some(id)
    }

    /// Construct an EUI-64 mobile identity (type=7). TS 24.501 §9.11.3.4.
    pub fn from_eui64(id: [u8; 8]) -> Self {
        let mut value = Vec::with_capacity(9);
        // TS 24.501 §9.11.3.4: spare bits 8-4 = 00000, type = 111 (EUI-64).
        value.push(0x07);
        value.extend_from_slice(&id);
        Self::new(value)
    }

    /// Return the SUPI format field of a SUCI identity, if the identity is a SUCI.
    pub fn supi_format(&self) -> Option<SupiFormat> {
        if self.value.is_empty() || (self.value[0] & 0x07) != 0x01 {
            return None;
        }
        SupiFormat::from_u8((self.value[0] >> 4) & 0x07)
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

    /// Extract the PLMN from an IMSI-form SUCI or a GUTI identity.
    pub fn plmn(&self) -> Option<PlmnId> {
        match self.identity_type()? {
            MobileIdentityType::Suci => match self.as_suci()? {
                Suci::Imsi(suci) => Some(suci.plmn_id),
                Suci::Utf8 { .. } => None,
            },
            MobileIdentityType::Guti if self.value.len() >= 4 => {
                PlmnId::from_tbcd(&self.value[1..4])
            }
            _ => None,
        }
    }

    /// Construct a GUTI mobile identity from checked structured fields.
    pub fn try_from_guti(guti: &Guti) -> Option<Self> {
        if guti.amf_set_id > 0x03ff || guti.amf_pointer > 0x3f {
            return None;
        }
        let tbcd = guti.plmn.try_to_tbcd()?;
        let set_ptr_hi = (guti.amf_set_id >> 2) as u8;
        let set_ptr_lo = ((guti.amf_set_id & 0x03) << 6) as u8 | guti.amf_pointer;
        let mut value = Vec::with_capacity(11);
        value.push(0xF2);
        value.extend_from_slice(&tbcd);
        value.push(guti.amf_region_id);
        value.push(set_ptr_hi);
        value.push(set_ptr_lo);
        value.extend_from_slice(&guti.tmsi.to_be_bytes());
        Some(Self::new(value))
    }

    /// Construct a GUTI mobile identity from structured fields.
    ///
    /// # Panics
    ///
    /// Panics for invalid PLMN digits, AMF set identifiers, or AMF pointers.
    pub fn from_guti(guti: &Guti) -> Self {
        Self::try_from_guti(guti).expect("GUTI fields must fit their specified wire domains")
    }

    /// Construct an S-TMSI mobile identity from checked structured fields.
    pub fn try_from_s_tmsi(tmsi: &STmsi) -> Option<Self> {
        if tmsi.amf_set_id > 0x03ff || tmsi.amf_pointer > 0x3f {
            return None;
        }
        let set_ptr_hi = (tmsi.amf_set_id >> 2) as u8;
        let set_ptr_lo = ((tmsi.amf_set_id & 0x03) << 6) as u8 | tmsi.amf_pointer;
        let mut value = Vec::with_capacity(7);
        value.push(0xF4);
        value.push(set_ptr_hi);
        value.push(set_ptr_lo);
        value.extend_from_slice(&tmsi.tmsi.to_be_bytes());
        Some(Self::new(value))
    }

    /// Construct an S-TMSI mobile identity from structured fields.
    ///
    /// # Panics
    ///
    /// Panics for an out-of-range AMF set identifier or AMF pointer.
    pub fn from_s_tmsi(tmsi: &STmsi) -> Self {
        Self::try_from_s_tmsi(tmsi).expect("S-TMSI fields must fit their specified wire domains")
    }

    /// Construct a SUCI mobile identity after validating all structured fields.
    pub fn try_from_suci(suci: &Suci) -> Option<Self> {
        match suci {
            Suci::Imsi(suci) => {
                let tbcd = suci.plmn_id.try_to_tbcd()?;
                if !valid_routing_indicator(&suci.routing_indicator)
                    || matches!(suci.protection_scheme, ProtectionScheme::Reserved(_))
                    || suci.home_nw_public_key_id == 0xff
                    || (suci.protection_scheme == ProtectionScheme::Null)
                        != (suci.home_nw_public_key_id == 0)
                    || (suci.protection_scheme == ProtectionScheme::Null
                        && !valid_null_suci_msin(&suci.plmn_id, &suci.scheme_output))
                {
                    return None;
                }
                let protection_scheme = suci.protection_scheme.try_to_u8()?;
                let mut value = Vec::with_capacity(8 + suci.scheme_output.len());
                value.push(0x01);
                value.extend_from_slice(&tbcd);
                value.extend_from_slice(&suci.routing_indicator);
                value.push(protection_scheme);
                value.push(suci.home_nw_public_key_id);
                value.extend_from_slice(&suci.scheme_output);
                Some(Self::new(value))
            }
            Suci::Utf8 { supi_format, nai } => Self::from_suci_nai(*supi_format, nai),
        }
    }

    /// Construct a SUCI mobile identity from structured fields.
    ///
    /// # Panics
    ///
    /// Panics if the structured value cannot be represented by the IE.
    pub fn from_suci(suci: &Suci) -> Self {
        Self::try_from_suci(suci).expect("SUCI fields must fit their specified wire domains")
    }

    /// Construct a non-IMSI SUCI carrying a UTF-8 NAI payload.
    pub fn from_suci_nai(supi_format: SupiFormat, nai: &str) -> Option<Self> {
        if supi_format == SupiFormat::Imsi || !valid_suci_nai(supi_format, nai) {
            return None;
        }
        let mut value = Vec::with_capacity(1 + nai.len());
        value.push(((supi_format as u8) << 4) | 0x01);
        value.extend_from_slice(nai.as_bytes());
        Some(Self::new(value))
    }

    /// Construct an IMEI mobile identity from a 15-digit IMEI string.
    ///
    /// Wire format: BCD-encoded with type=3 (IMEI), odd indicator set.
    /// Panics if the input is not exactly 15 decimal digits per TS 23.003 §6.2.1.
    pub fn from_imei(imei: &str) -> Self {
        Self::try_from_imei(imei)
            .expect("IMEI must be exactly 15 decimal digits (TS 23.003 §6.2.1)")
    }

    /// Fallible IMEI mobile identity builder.
    pub fn try_from_imei(imei: &str) -> Option<Self> {
        is_decimal_digit_string(imei, 15)
            .then(|| crate::common::encode_identity_digits(imei, 0x03, 15))?
            .map(Self::new)
    }

    /// Build a transmitted IMEI from its 14 TAC and serial-number digits.
    ///
    /// TS 23.003 §6.2.1 uses zero, rather than the Luhn check digit, as the
    /// fifteenth digit on the wire.
    pub fn from_imei_tac_snr(tac_snr: &str) -> Option<Self> {
        Self::try_from_imei(&crate::common::imei_with_spare(tac_snr)?)
    }

    /// Construct an IMEISV mobile identity from a 16-digit IMEISV string.
    ///
    /// Wire format: BCD-encoded with type=5 (IMEISV), even indicator.
    /// Panics if the input is not exactly 16 decimal digits per TS 23.003 §6.2.2.
    pub fn from_imeisv(imeisv: &str) -> Self {
        Self::try_from_imeisv(imeisv)
            .expect("IMEISV must be exactly 16 decimal digits (TS 23.003 §6.2.2)")
    }

    /// Fallible IMEISV mobile identity builder.
    pub fn try_from_imeisv(imeisv: &str) -> Option<Self> {
        is_decimal_digit_string(imeisv, 16)
            .then(|| crate::common::encode_identity_digits(imeisv, 0x05, 16))?
            .map(Self::new)
    }

    /// Construct a "no identity" mobile identity (type=0).
    ///
    /// TS 24.501 §9.11.3.4: single octet with type-of-identity = 0; upper nibble is spare
    /// (set to zero).
    pub fn from_no_identity() -> Self {
        Self::new(vec![0x00])
    }

    /// Whether the IE is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        match self.identity_type() {
            Some(MobileIdentityType::NoIdentity) => self.value.as_slice() == [0x00],
            Some(MobileIdentityType::Suci) => {
                self.value.first().is_some_and(|octet| octet & 0x88 == 0)
                    && self.as_suci().is_some()
                    && (self.supi_format() != Some(SupiFormat::Imsi)
                        || self.value.get(6).is_some_and(|octet| octet & 0xf0 == 0))
            }
            Some(MobileIdentityType::Guti) => {
                self.value.len() == 11 && self.value[0] == 0xf2 && self.as_guti().is_some()
            }
            Some(MobileIdentityType::Imei) => self.value.len() == 8 && self.as_imei().is_some(),
            Some(MobileIdentityType::STmsi) => {
                self.value.len() == 7 && self.value[0] == 0xf4 && self.as_s_tmsi().is_some()
            }
            Some(MobileIdentityType::Imeisv) => self.value.len() == 9 && self.as_imeisv().is_some(),
            Some(MobileIdentityType::MacAddr) => {
                self.value.len() == 7
                    && self.value[0] & 0xf7 == 0x06
                    && self.as_mac_address().is_some()
            }
            Some(MobileIdentityType::Eui64) => {
                self.value.len() == 9 && self.value[0] == 0x07 && self.as_eui64().is_some()
            }
            None => false,
        }
    }

    pub(crate) fn receiver_syntax_is_valid(&self) -> bool {
        match self.identity_type() {
            Some(MobileIdentityType::NoIdentity) => !self.value.is_empty(),
            Some(MobileIdentityType::Suci) => self.as_suci().is_some(),
            Some(MobileIdentityType::Guti) => self.as_guti().is_some(),
            Some(MobileIdentityType::Imei) => self.as_imei().is_some(),
            Some(MobileIdentityType::STmsi) => self.as_s_tmsi().is_some(),
            Some(MobileIdentityType::Imeisv) => self.as_imeisv().is_some(),
            Some(MobileIdentityType::MacAddr) => self.as_mac_address().is_some(),
            Some(MobileIdentityType::Eui64) => self.as_eui64().is_some(),
            None => false,
        }
    }
}

fn decode_receiver_identity_digits(value: &[u8], kind: u8, max_digits: usize) -> Option<String> {
    let max_octets = 1 + max_digits.saturating_sub(1).div_ceil(2);
    (2..=value.len().min(max_octets))
        .rev()
        .find_map(|end| crate::common::decode_identity_digits(&value[..end], kind, max_digits))
}

fn is_decimal_digit_string(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit())
}

fn valid_null_suci_msin(plmn: &PlmnId, value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut digits = 0usize;
    for (index, octet) in value.iter().copied().enumerate() {
        if octet & 0x0f > 9 {
            return false;
        }
        digits += 1;
        match octet >> 4 {
            0..=9 => digits += 1,
            0x0f if index + 1 == value.len() => {}
            _ => return false,
        }
    }
    let mnc_digits = if plmn.mnc[2] == 0x0f { 2 } else { 3 };
    3 + mnc_digits + digits <= 15
}

fn valid_nai_realm(value: &str) -> bool {
    if value.nfc().ne(value.chars()) {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    let abnf_matches = labels.len() >= 2
        && labels.iter().all(|label| {
            let is_rtext =
                |character: char| character.is_ascii_alphanumeric() || !character.is_ascii();
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| is_rtext(character) || character == '-')
                && label.chars().next().is_some_and(is_rtext)
                && label.chars().last().is_some_and(is_rtext)
        });
    let Ok(ascii) = idna::domain_to_ascii_strict(value) else {
        return false;
    };
    if !abnf_matches || value.is_ascii() {
        return abnf_matches;
    }
    let (canonical_unicode, status) = idna::domain_to_unicode(&ascii);
    status.is_ok() && canonical_unicode == value
}

fn valid_nai_username(value: &str, allow_empty: bool) -> bool {
    if value.is_empty() {
        return allow_empty;
    }
    if value.nfc().ne(value.chars()) {
        return false;
    }
    value.split('.').all(|atom| {
        !atom.is_empty()
            && atom.chars().all(|character| {
                if character.is_ascii() {
                    character.is_ascii_alphanumeric()
                        || matches!(
                            character,
                            '!' | '#'
                                | '$'
                                | '%'
                                | '&'
                                | '\''
                                | '*'
                                | '+'
                                | '-'
                                | '/'
                                | '='
                                | '?'
                                | '^'
                                | '_'
                                | '`'
                                | '{'
                                | '|'
                                | '}'
                                | '~'
                        )
                } else {
                    !character.is_control()
                }
            })
    })
}

fn parse_suci_nai_decimal(field: &str, prefix: &str) -> Option<u8> {
    let digits = field.strip_prefix(prefix)?;
    (!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse().ok())?
}

fn valid_suci_nai(supi_format: SupiFormat, value: &str) -> bool {
    let Some((username, realm)) = value.rsplit_once('@') else {
        return false;
    };
    if username.contains('@') || !valid_nai_realm(realm) {
        return false;
    }
    let fields: Vec<&str> = username.split('.').collect();
    if fields.len() < 4 {
        return false;
    }
    let expected_type = match supi_format {
        SupiFormat::Imsi => return false,
        SupiFormat::NetworkSpecific => 1,
        // TS 24.501 values 2/3 are GCI/GLI, while TS 23.003 textual values
        // 2/3 are GLI/GCI.
        SupiFormat::Gci => 3,
        SupiFormat::Gli => 2,
    };
    if parse_suci_nai_decimal(fields[0], "type") != Some(expected_type) {
        return false;
    }
    let Some(routing_indicator) = fields[1].strip_prefix("rid") else {
        return false;
    };
    if !(1..=4).contains(&routing_indicator.len())
        || !routing_indicator.bytes().all(|byte| byte.is_ascii_digit())
        || (matches!(supi_format, SupiFormat::Gci | SupiFormat::Gli) && routing_indicator != "0")
    {
        return false;
    }
    let Some(scheme_id) = parse_suci_nai_decimal(fields[2], "schid") else {
        return false;
    };
    match scheme_id {
        0 => {
            let prefix = format!("{}.{}.{}.userid", fields[0], fields[1], fields[2]);
            let Some(output) = username.strip_prefix(&prefix) else {
                return false;
            };
            match supi_format {
                SupiFormat::NetworkSpecific => valid_nai_username(output, true),
                SupiFormat::Gci => valid_nai_username(output, false),
                SupiFormat::Gli => {
                    !output.is_empty()
                        && output.len() <= 200
                        && BASE64_STANDARD.decode(output).is_ok_and(|decoded| {
                            decoded.len() <= 150 && BASE64_STANDARD.encode(decoded) == output
                        })
                }
                SupiFormat::Imsi => false,
            }
        }
        1 | 2 => {
            if supi_format != SupiFormat::NetworkSpecific || fields.len() != 7 {
                return false;
            }
            let Some(key_id) = parse_suci_nai_decimal(fields[3], "hnkey") else {
                return false;
            };
            let Some(ephemeral) = fields[4]
                .strip_prefix("ecckey")
                .and_then(|v| hex::decode(v).ok())
            else {
                return false;
            };
            let Some(ciphertext) = fields[5]
                .strip_prefix("cip")
                .and_then(|v| hex::decode(v).ok())
            else {
                return false;
            };
            let Some(mac) = fields[6]
                .strip_prefix("mac")
                .and_then(|v| hex::decode(v).ok())
            else {
                return false;
            };
            key_id != 0
                && ephemeral.len() == if scheme_id == 1 { 32 } else { 33 }
                && !ciphertext.is_empty()
                && mac.len() == 8
        }
        3..=11 => false,
        12..=15 => {
            if supi_format != SupiFormat::NetworkSpecific || fields.len() < 5 {
                return false;
            }
            let Some(key_id) = parse_suci_nai_decimal(fields[3], "hnkey") else {
                return false;
            };
            let prefix = format!(
                "{}.{}.{}.{}.out",
                fields[0], fields[1], fields[2], fields[3]
            );
            key_id != 0
                && username
                    .strip_prefix(&prefix)
                    .is_some_and(|output| output.bytes().all(|byte| byte.is_ascii_hexdigit()))
        }
        _ => false,
    }
}

fn valid_routing_indicator(value: &[u8]) -> bool {
    if value.len() != 2 || value[0] & 0x0f > 9 {
        return false;
    }
    let mut filler_seen = false;
    for digit in value.iter().flat_map(|octet| [octet & 0x0f, octet >> 4]) {
        match digit {
            0..=9 if !filler_seen => {}
            0x0f => filler_seen = true,
            _ => return false,
        }
    }
    true
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
    /// Reserved algorithm code 4.
    NEA4 = 0x04,
    /// Reserved algorithm code 5.
    NEA5 = 0x05,
    /// Reserved algorithm code 6.
    NEA6 = 0x06,
    /// Reserved algorithm code 7.
    NEA7 = 0x07,
}

impl CipheringAlgorithm {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NEA0),
            0x01 => Some(Self::NEA1),
            0x02 => Some(Self::NEA2),
            0x03 => Some(Self::NEA3),
            0x04 => Some(Self::NEA4),
            0x05 => Some(Self::NEA5),
            0x06 => Some(Self::NEA6),
            0x07 => Some(Self::NEA7),
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
    /// Reserved algorithm code 4.
    NIA4 = 0x04,
    /// Reserved algorithm code 5.
    NIA5 = 0x05,
    /// Reserved algorithm code 6.
    NIA6 = 0x06,
    /// Reserved algorithm code 7.
    NIA7 = 0x07,
}

impl IntegrityAlgorithm {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NIA0),
            0x01 => Some(Self::NIA1),
            0x02 => Some(Self::NIA2),
            0x03 => Some(Self::NIA3),
            0x04 => Some(Self::NIA4),
            0x05 => Some(Self::NIA5),
            0x06 => Some(Self::NIA6),
            0x07 => Some(Self::NIA7),
            _ => None,
        }
    }
}

crate::common::ts24301::nas_security_algorithms_ie!(
    NasSecurityAlgorithms,
    CipheringAlgorithm,
    IntegrityAlgorithm
);

impl NasN1ModeToS1ModeNasTransparentContainer {
    /// Sequence number (octet 2) per TS 24.501 §9.11.2.7 / Table 9.11.2.7.1.
    pub fn sequence_number(&self) -> u8 {
        self.value
    }

    /// Set the sequence number carried by this IE.
    pub fn with_sequence_number(mut self, sequence_number: u8) -> Self {
        self.set_sequence_number(sequence_number);
        self
    }

    /// Mutating setter for the sequence number carried by this IE.
    pub fn set_sequence_number(&mut self, sequence_number: u8) -> &mut Self {
        self.value = sequence_number;
        self
    }

    /// Build the IE from a sequence number.
    pub fn from_sequence_number(sequence_number: u8) -> Self {
        Self::new(sequence_number)
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
    /// SNPN onboarding registration (TS 24.501 Rel-17 §9.11.3.7).
    SnpnOnboarding = 0x05,
    /// Disaster roaming mobility registration updating (Rel-17).
    DisasterRoamingMobility = 0x06,
    /// Disaster roaming initial registration (Rel-17 §9.11.3.7).
    DisasterRoamingInitial = 0x07,
}

impl RegistrationType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::InitialRegistration),
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

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
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

impl Default for NasFGsRegistrationType {
    /// Default for the packed Registration Request octet: initial registration,
    /// no follow-on request, ngKSI = 7 (no key), native context.
    fn default() -> Self {
        Self::new(0x70 | (RegistrationType::InitialRegistration as u8))
    }
}

impl NasFGsRegistrationType {
    /// Build a standalone-clean registration type value with unrelated packed
    /// ngKSI/TSC bits cleared.
    pub fn from_registration_type(reg_type: RegistrationType) -> Self {
        Self::new(reg_type as u8 & 0x07)
    }

    /// Registration type (lower nibble bits 1-3, mask 0x07).
    pub fn registration_type(&self) -> Option<RegistrationType> {
        RegistrationType::from_u8(self.value & 0x07)
    }

    /// Set the registration type. Returns `self` for chaining.
    pub fn with_registration_type(mut self, reg_type: RegistrationType) -> Self {
        self.value = (self.value & 0xF8) | (reg_type as u8 & 0x07);
        self
    }

    /// Mutating setter for the registration type.
    pub fn set_registration_type(&mut self, reg_type: RegistrationType) {
        self.value = (self.value & 0xF8) | (reg_type as u8 & 0x07);
    }

    /// Follow-on request indicator (lower nibble bit 4, mask 0x08).
    pub fn follow_on_request(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// Set the follow-on request bit. Returns `self` for chaining.
    pub fn with_follow_on_request(mut self, for_flag: bool) -> Self {
        if for_flag {
            self.value |= 0x08;
        } else {
            self.value &= !0x08;
        }
        self
    }

    /// Mutating setter for the follow-on request bit.
    pub fn set_follow_on_request(&mut self, for_flag: bool) {
        if for_flag {
            self.value |= 0x08;
        } else {
            self.value &= !0x08;
        }
    }

    /// ngKSI value (upper nibble bits 1-3, mask 0x70).
    pub fn ngksi(&self) -> u8 {
        (self.value >> 4) & 0x07
    }

    /// Set ngKSI. Returns `self` for chaining.
    pub fn with_ngksi(mut self, ngksi: u8) -> Self {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
        self
    }

    /// Mutating setter for ngKSI.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
    }

    /// TSC flag (upper nibble bit 4, mask 0x80): false = native, true = mapped.
    pub fn tsc(&self) -> bool {
        (self.value >> 7) & 1 != 0
    }

    /// Set TSC. Returns `self` for chaining.
    pub fn with_tsc(mut self, tsc: bool) -> Self {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
        self
    }

    /// Mutating setter for TSC.
    pub fn set_tsc(&mut self, tsc: bool) {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
    }
}

// ---------------------------------------------------------------------------
// NAS Key Set Identifier (§9.11.3.32)
// ---------------------------------------------------------------------------

/// Special value indicating no NAS key is available.
pub use crate::common::ts24301::NAS_KSI_NO_KEY_AVAILABLE;

impl Default for NasKeySetIdentifier {
    /// Default: ngKSI = 7 (no key available), native context.
    fn default() -> Self {
        Self::new(NAS_KSI_NO_KEY_AVAILABLE)
    }
}

crate::common::ts24301::key_set_identifier_ie!(NasKeySetIdentifier, builders);
pub use crate::common::ts24301::KeySetIdentifier;

impl NasKeySetIdentifier {
    /// ngKSI (bits 3-1), the 5GS name of [`Self::ksi`].
    pub fn ngksi(&self) -> u8 {
        self.ksi()
    }

    /// Set ngKSI, preserving the other bits.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        self.set_ksi(ngksi);
    }

    /// Builder form of [`Self::set_ngksi`].
    pub fn with_ngksi(self, ngksi: u8) -> Self {
        self.with_ksi(ngksi)
    }
}

// ---------------------------------------------------------------------------
// 5GS Identity Type (§9.11.3.3)
// ---------------------------------------------------------------------------

impl NasFGsIdentityType {
    /// Identity type (bits 1-3), with the spec receive-side fallback applied.
    ///
    /// TS 24.501 §9.11.3.3 says unused values are interpreted as SUCI when
    /// received by the UE. `MobileIdentityType::NoIdentity` is valid for the
    /// 5GS mobile identity IE, but not for this request IE.
    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        match self.value & 0x07 {
            0x00 => Some(MobileIdentityType::Suci),
            value => MobileIdentityType::from_u8(value),
        }
    }

    /// Strict identity type without the §9.11.3.3 fallback for unused value 0.
    pub fn identity_type_strict(&self) -> Option<MobileIdentityType> {
        match self.value & 0x07 {
            0x00 => None,
            value => MobileIdentityType::from_u8(value),
        }
    }

    /// Set the identity type while preserving spare bits.
    pub fn with_identity_type(mut self, identity_type: MobileIdentityType) -> Self {
        self.set_identity_type(identity_type);
        self
    }

    /// Mutating setter for the identity type.
    pub fn set_identity_type(&mut self, identity_type: MobileIdentityType) -> &mut Self {
        let value = match identity_type {
            MobileIdentityType::NoIdentity => MobileIdentityType::Suci as u8,
            _ => identity_type as u8,
        };
        self.value = (self.value & !0x07) | (value & 0x07);
        self
    }

    /// Construct from identity type.
    pub fn from_identity_type(t: MobileIdentityType) -> Self {
        let value = match t {
            MobileIdentityType::NoIdentity => MobileIdentityType::Suci as u8,
            _ => t as u8,
        };
        Self::new(value)
    }
}

// ============================================================================
// Cause codes, timers, payload containers
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
    /// Illegal UE.
    IllegalUe = 3,
    /// PEI not accepted.
    PeiNotAccepted = 5,
    /// Illegal me.
    IllegalMe = 6,
    /// Five gs services not allowed.
    FiveGSServicesNotAllowed = 7,
    /// UE identity cannot be derived.
    UeIdentityCannotBeDerived = 9,
    /// Implicitly deregistered.
    ImplicitlyDeregistered = 10,
    /// PLMN not allowed.
    PlmnNotAllowed = 11,
    /// Tracking area not allowed.
    TrackingAreaNotAllowed = 12,
    /// Roaming not allowed in TA.
    RoamingNotAllowedInTa = 13,
    /// No cells in TA.
    NoCellsInTa = 15,
    /// Mac failure.
    MacFailure = 20,
    /// Synch failure.
    SynchFailure = 21,
    /// Congestion.
    Congestion = 22,
    /// UE security cap mismatch.
    UeSecurityCapMismatch = 23,
    /// Security mode rejected.
    SecurityModeRejected = 24,
    /// Non 5 g auth unacceptable.
    Non5GAuthUnacceptable = 26,
    /// N 1 mode not allowed.
    N1ModeNotAllowed = 27,
    /// Restricted service area.
    RestrictedServiceArea = 28,
    /// Redirection to epc required.
    RedirectionToEpcRequired = 31,
    /// IAB-node operation not authorized (TS 24.501 §9.11.3.2).
    IabNodeOperationNotAuthorized = 36,
    /// LADN not available.
    LadnNotAvailable = 43,
    /// No network slices available.
    NoNetworkSlicesAvailable = 62,
    /// Max PDU sessions reached.
    MaxPduSessionsReached = 65,
    /// Insufficient resources for slice DNN.
    InsufficientResourcesForSliceDnn = 67,
    /// Insufficient resources for slice.
    InsufficientResourcesForSlice = 69,
    /// Ng ksi already in use.
    NgKsiAlreadyInUse = 71,
    /// Non 3 gpp access to 5 gcn not allowed.
    Non3GppAccessTo5GcnNotAllowed = 72,
    /// Serving network not authorized.
    ServingNetworkNotAuthorized = 73,
    /// Temporarily not authorized for SNPN.
    TemporarilyNotAuthorizedForSnpn = 74,
    /// Permanently not authorized for SNPN.
    PermanentlyNotAuthorizedForSnpn = 75,
    /// Not authorized for CAG.
    NotAuthorizedForCag = 76,
    /// Wireline access area not allowed.
    WirelineAccessAreaNotAllowed = 77,
    /// PLMN not allowed to operate at the present UE location.
    PlmnNotAllowedAtUeLocation = 78,
    /// UAS services not allowed.
    UasServicesNotAllowed = 79,
    /// Disaster roaming for the determined PLMN with disaster condition not allowed.
    DisasterRoamingNotAllowed = 80,
    /// Selected N3IWF is not compatible with the allowed NSSAI.
    N3iwfNotCompatibleWithNssai = 81,
    /// Selected TNGF is not compatible with the allowed NSSAI.
    TngfNotCompatibleWithNssai = 82,
    /// Payload was not forwarded.
    PayloadWasNotForwarded = 90,
    /// DNN not supported in slice.
    DnnNotSupportedInSlice = 91,
    /// Insufficient user plane resources.
    InsufficientUserPlaneResources = 92,
    /// Onboarding services terminated.
    OnboardingServicesTerminated = 93,
    /// User plane positioning not authorized.
    UserPlanePositioningNotAuthorized = 94,
    /// Semantically incorrect message.
    SemanticallyIncorrectMessage = 95,
    /// Invalid mandatory information.
    InvalidMandatoryInformation = 96,
    /// Message type not existent.
    MessageTypeNotExistent = 97,
    /// Message type not compatible.
    MessageTypeNotCompatible = 98,
    /// Information element not existent.
    InformationElementNotExistent = 99,
    /// Conditional IE error.
    ConditionalIeError = 100,
    /// Message not compatible.
    MessageNotCompatible = 101,
    /// Protocol error unspecified.
    ProtocolErrorUnspecified = 111,
}

impl GmmCause {
    /// Decode a defined cause value; other values return `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::from_u8_strict(v)
    }

    /// Decode a received value: values not listed in TS 24.501 Table
    /// 9.11.3.2.1 are treated as #111 "protocol error, unspecified".
    pub fn from_u8_received(v: u8) -> Self {
        Self::from_u8_strict(v).unwrap_or(Self::ProtocolErrorUnspecified)
    }

    /// Decode only the values listed in TS 24.501 Table 9.11.3.2.1.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v {
            3 => Some(Self::IllegalUe),
            5 => Some(Self::PeiNotAccepted),
            6 => Some(Self::IllegalMe),
            7 => Some(Self::FiveGSServicesNotAllowed),
            9 => Some(Self::UeIdentityCannotBeDerived),
            10 => Some(Self::ImplicitlyDeregistered),
            11 => Some(Self::PlmnNotAllowed),
            12 => Some(Self::TrackingAreaNotAllowed),
            13 => Some(Self::RoamingNotAllowedInTa),
            15 => Some(Self::NoCellsInTa),
            20 => Some(Self::MacFailure),
            21 => Some(Self::SynchFailure),
            22 => Some(Self::Congestion),
            23 => Some(Self::UeSecurityCapMismatch),
            24 => Some(Self::SecurityModeRejected),
            26 => Some(Self::Non5GAuthUnacceptable),
            27 => Some(Self::N1ModeNotAllowed),
            28 => Some(Self::RestrictedServiceArea),
            31 => Some(Self::RedirectionToEpcRequired),
            36 => Some(Self::IabNodeOperationNotAuthorized),
            43 => Some(Self::LadnNotAvailable),
            62 => Some(Self::NoNetworkSlicesAvailable),
            65 => Some(Self::MaxPduSessionsReached),
            67 => Some(Self::InsufficientResourcesForSliceDnn),
            69 => Some(Self::InsufficientResourcesForSlice),
            71 => Some(Self::NgKsiAlreadyInUse),
            72 => Some(Self::Non3GppAccessTo5GcnNotAllowed),
            73 => Some(Self::ServingNetworkNotAuthorized),
            74 => Some(Self::TemporarilyNotAuthorizedForSnpn),
            75 => Some(Self::PermanentlyNotAuthorizedForSnpn),
            76 => Some(Self::NotAuthorizedForCag),
            77 => Some(Self::WirelineAccessAreaNotAllowed),
            78 => Some(Self::PlmnNotAllowedAtUeLocation),
            79 => Some(Self::UasServicesNotAllowed),
            80 => Some(Self::DisasterRoamingNotAllowed),
            81 => Some(Self::N3iwfNotCompatibleWithNssai),
            82 => Some(Self::TngfNotCompatibleWithNssai),
            90 => Some(Self::PayloadWasNotForwarded),
            91 => Some(Self::DnnNotSupportedInSlice),
            92 => Some(Self::InsufficientUserPlaneResources),
            93 => Some(Self::OnboardingServicesTerminated),
            94 => Some(Self::UserPlanePositioningNotAuthorized),
            95 => Some(Self::SemanticallyIncorrectMessage),
            96 => Some(Self::InvalidMandatoryInformation),
            97 => Some(Self::MessageTypeNotExistent),
            98 => Some(Self::MessageTypeNotCompatible),
            99 => Some(Self::InformationElementNotExistent),
            100 => Some(Self::ConditionalIeError),
            101 => Some(Self::MessageNotCompatible),
            111 => Some(Self::ProtocolErrorUnspecified),
            _ => None,
        }
    }

    /// Human-readable description per TS 24.501 Table 9.11.3.2.1.
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
            Self::RedirectionToEpcRequired => "Redirection to EPC required",
            Self::IabNodeOperationNotAuthorized => "IAB-node operation not authorized",
            Self::LadnNotAvailable => "LADN not available",
            Self::NoNetworkSlicesAvailable => "No network slices available",
            Self::MaxPduSessionsReached => "Maximum number of PDU sessions reached",
            Self::InsufficientResourcesForSliceDnn => {
                "Insufficient resources for specific slice and DNN"
            }
            Self::InsufficientResourcesForSlice => "Insufficient resources for specific slice",
            Self::NgKsiAlreadyInUse => "ngKSI already in use",
            Self::Non3GppAccessTo5GcnNotAllowed => "Non-3GPP access to 5GCN not allowed",
            Self::ServingNetworkNotAuthorized => "Serving network not authorized",
            Self::TemporarilyNotAuthorizedForSnpn => "Temporarily not authorized for this SNPN",
            Self::PermanentlyNotAuthorizedForSnpn => "Permanently not authorized for this SNPN",
            Self::NotAuthorizedForCag => {
                "Not authorized for this CAG or authorized for CAG cells only"
            }
            Self::WirelineAccessAreaNotAllowed => "Wireline access area not allowed",
            Self::PlmnNotAllowedAtUeLocation => {
                "PLMN not allowed to operate at the present UE location"
            }
            Self::UasServicesNotAllowed => "UAS services not allowed",
            Self::DisasterRoamingNotAllowed => {
                "Disaster roaming for the determined PLMN with disaster condition not allowed"
            }
            Self::N3iwfNotCompatibleWithNssai => {
                "Selected N3IWF is not compatible with the allowed NSSAI"
            }
            Self::TngfNotCompatibleWithNssai => {
                "Selected TNGF is not compatible with the allowed NSSAI"
            }
            Self::PayloadWasNotForwarded => "Payload was not forwarded",
            Self::DnnNotSupportedInSlice => "DNN not supported or not subscribed in the slice",
            Self::InsufficientUserPlaneResources => {
                "Insufficient user-plane resources for the PDU session"
            }
            Self::OnboardingServicesTerminated => "Onboarding services terminated",
            Self::UserPlanePositioningNotAuthorized => "User plane positioning not authorized",
            Self::SemanticallyIncorrectMessage => "Semantically incorrect message",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNotExistent => "Message type non-existent or not implemented",
            Self::MessageTypeNotCompatible => "Message type not compatible with the protocol state",
            Self::InformationElementNotExistent => {
                "Information element non-existent or not implemented"
            }
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatible => "Message not compatible with the protocol state",
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
        }
    }
}

impl NasFGmmCause {
    /// Parse as typed cause enum; `None` for a value not listed.
    pub fn cause(&self) -> Option<GmmCause> {
        GmmCause::from_u8(self.value)
    }

    /// Raw cause value.
    pub fn cause_raw(&self) -> u8 {
        self.value
    }

    /// Cause with the receiver rule of TS 24.501 Table 9.11.3.2.1 applied.
    pub fn cause_received(&self) -> GmmCause {
        GmmCause::from_u8_received(self.value)
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
    /// Operator determined barring.
    OperatorDeterminedBarring = 0x08,
    /// Insufficient resources.
    InsufficientResources = 0x1A,
    /// Missing or unknown DNN.
    MissingOrUnknownDnn = 0x1B,
    /// Unknown PDU session type.
    UnknownPduSessionType = 0x1C,
    /// User auth failed.
    UserAuthFailed = 0x1D,
    /// Request rejected unspecified.
    RequestRejectedUnspecified = 0x1F,
    /// Service option not supported.
    ServiceOptionNotSupported = 0x20,
    /// Service option not subscribed.
    ServiceOptionNotSubscribed = 0x21,
    /// PTI already in use.
    PtiAlreadyInUse = 0x23,
    /// Regular deactivation.
    RegularDeactivation = 0x24,
    /// 5GS QoS not accepted.
    FiveGsQosNotAccepted = 0x25,
    /// Network failure.
    NetworkFailure = 0x26,
    /// Reactivation requested.
    ReactivationRequested = 0x27,
    /// Semantic error in TFT.
    SemanticErrorInTft = 0x29,
    /// Syntactical error in TFT.
    SyntacticalErrorInTft = 0x2A,
    /// Invalid PDU session identity.
    InvalidPduSessionIdentity = 0x2B,
    /// Semantic error in packet filter.
    SemanticErrorInPacketFilter = 0x2C,
    /// Syntactical error in packet filter.
    SyntacticalErrorInPacketFilter = 0x2D,
    /// Out of LADN service area.
    OutOfLadnServiceArea = 0x2E,
    /// PTI mismatch.
    PtiMismatch = 0x2F,
    /// PDU session type ipv 4 only.
    PduSessionTypeIpv4Only = 0x32,
    /// PDU session type ipv 6 only.
    PduSessionTypeIpv6Only = 0x33,
    /// PDU session does not exist.
    PduSessionDoesNotExist = 0x36,
    /// PDU session type IPv4v6 only allowed.
    PduSessionTypeIpv4v6Only = 0x39,
    /// PDU session type Unstructured only allowed.
    PduSessionTypeUnstructuredOnly = 0x3A,
    /// Unsupported 5QI value.
    Unsupported5QiValue = 0x3B,
    /// PDU session type Ethernet only allowed.
    PduSessionTypeEthernetOnly = 0x3D,
    /// Insufficient resources for slice DNN.
    InsufficientResourcesForSliceDnn = 0x43,
    /// Not supported SSC mode.
    NotSupportedSscMode = 0x44,
    /// Insufficient resources for slice.
    InsufficientResourcesForSlice = 0x45,
    /// Missing or unknown DNN in slice.
    MissingOrUnknownDnnInSlice = 0x46,
    /// Invalid PTI value.
    InvalidPtiValue = 0x51,
    /// Maximum data rate per UE for user-plane integrity protection is too low.
    MaxDataRateForUpIpTooLow = 0x52,
    /// Semantic error in the QoS operation.
    SemanticErrorInQosOperation = 0x53,
    /// Syntactical error in the QoS operation.
    SyntacticalErrorInQosOperation = 0x54,
    /// Invalid mapped EPS bearer identity.
    InvalidMappedEpsBearerIdentity = 0x55,
    /// UAS services not allowed.
    UasServicesNotAllowed = 0x56,
    /// QoS differentiation for non-3GPP device identifier(s) not available.
    QosDiffNon3gppDeviceIdNotAvailable = 0x57,
    /// Semantically incorrect message.
    SemanticallyIncorrectMessage = 0x5F,
    /// Invalid mandatory information.
    InvalidMandatoryInformation = 0x60,
    /// Message type not existent.
    MessageTypeNotExistent = 0x61,
    /// Message type not compatible.
    MessageTypeNotCompatible = 0x62,
    /// Information element not existent.
    InformationElementNotExistent = 0x63,
    /// Conditional IE error.
    ConditionalIeError = 0x64,
    /// Message not compatible.
    MessageNotCompatible = 0x65,
    /// Protocol error unspecified.
    ProtocolErrorUnspecified = 0x6F,
}

impl GsmCause {
    /// Decode a defined cause value; other values return `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::from_u8_strict(v)
    }

    /// TS 24.501 §9.11.4.2 receive-side interpretation for values received by the UE.
    pub fn from_u8_for_ue(v: u8) -> Self {
        Self::from_u8_strict(v).unwrap_or(Self::RequestRejectedUnspecified)
    }

    /// TS 24.501 §9.11.4.2 receive-side interpretation for values received by the network.
    pub fn from_u8_for_network(v: u8) -> Self {
        Self::from_u8_strict(v).unwrap_or(Self::ProtocolErrorUnspecified)
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
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
            0x25 => Some(Self::FiveGsQosNotAccepted),
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
            0x39 => Some(Self::PduSessionTypeIpv4v6Only),
            0x3A => Some(Self::PduSessionTypeUnstructuredOnly),
            0x3B => Some(Self::Unsupported5QiValue),
            0x3D => Some(Self::PduSessionTypeEthernetOnly),
            0x43 => Some(Self::InsufficientResourcesForSliceDnn),
            0x44 => Some(Self::NotSupportedSscMode),
            0x45 => Some(Self::InsufficientResourcesForSlice),
            0x46 => Some(Self::MissingOrUnknownDnnInSlice),
            0x51 => Some(Self::InvalidPtiValue),
            0x52 => Some(Self::MaxDataRateForUpIpTooLow),
            0x53 => Some(Self::SemanticErrorInQosOperation),
            0x54 => Some(Self::SyntacticalErrorInQosOperation),
            0x55 => Some(Self::InvalidMappedEpsBearerIdentity),
            0x56 => Some(Self::UasServicesNotAllowed),
            0x57 => Some(Self::QosDiffNon3gppDeviceIdNotAvailable),
            0x5F => Some(Self::SemanticallyIncorrectMessage),
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

    /// Return a human-readable description.
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
            Self::FiveGsQosNotAccepted => "5GS QoS not accepted",
            Self::NetworkFailure => "Network failure",
            Self::ReactivationRequested => "Reactivation requested",
            Self::SemanticErrorInTft => "Semantic error in the TFT operation",
            Self::SyntacticalErrorInTft => "Syntactical error in the TFT operation",
            Self::InvalidPduSessionIdentity => "Invalid PDU session identity",
            Self::SemanticErrorInPacketFilter => "Semantic errors in packet filter(s)",
            Self::SyntacticalErrorInPacketFilter => "Syntactical error in packet filter(s)",
            Self::OutOfLadnServiceArea => "Out of LADN service area",
            Self::PtiMismatch => "PTI mismatch",
            Self::PduSessionTypeIpv4Only => "PDU session type IPv4 only allowed",
            Self::PduSessionTypeIpv6Only => "PDU session type IPv6 only allowed",
            Self::PduSessionDoesNotExist => "PDU session does not exist",
            Self::PduSessionTypeIpv4v6Only => "PDU session type IPv4v6 only allowed",
            Self::PduSessionTypeUnstructuredOnly => "PDU session type Unstructured only allowed",
            Self::Unsupported5QiValue => "Unsupported 5QI value",
            Self::PduSessionTypeEthernetOnly => "PDU session type Ethernet only allowed",
            Self::InsufficientResourcesForSliceDnn => {
                "Insufficient resources for specific slice and DNN"
            }
            Self::NotSupportedSscMode => "Not supported SSC mode",
            Self::InsufficientResourcesForSlice => "Insufficient resources for specific slice",
            Self::MissingOrUnknownDnnInSlice => "Missing or unknown DNN in a slice",
            Self::InvalidPtiValue => "Invalid PTI value",
            Self::MaxDataRateForUpIpTooLow => {
                "Maximum data rate per UE for user-plane integrity protection is too low"
            }
            Self::SemanticErrorInQosOperation => "Semantic error in the QoS operation",
            Self::SyntacticalErrorInQosOperation => "Syntactical error in the QoS operation",
            Self::InvalidMappedEpsBearerIdentity => "Invalid mapped EPS bearer identity",
            Self::UasServicesNotAllowed => "UAS services not allowed",
            Self::QosDiffNon3gppDeviceIdNotAvailable => {
                "QoS differentiation for non-3GPP device identifier(s) not available"
            }
            Self::SemanticallyIncorrectMessage => "Semantically incorrect message",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNotExistent => "Message type non-existent or not implemented",
            Self::MessageTypeNotCompatible => "Message type not compatible with the protocol state",
            Self::InformationElementNotExistent => {
                "Information element non-existent or not implemented"
            }
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatible => "Message not compatible with the protocol state",
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
        }
    }
}

impl NasFGsmCause {
    /// Parse as typed cause enum; `None` for a value not listed.
    pub fn cause(&self) -> Option<GsmCause> {
        GsmCause::from_u8(self.value)
    }

    /// Raw cause value.
    pub fn cause_raw(&self) -> u8 {
        self.value
    }

    /// Cause as received by the UE (TS 24.501 §9.11.4.2).
    pub fn cause_for_ue(&self) -> GsmCause {
        GsmCause::from_u8_for_ue(self.value)
    }

    /// Cause as received by the network (TS 24.501 §9.11.4.2).
    pub fn cause_for_network(&self) -> GsmCause {
        GsmCause::from_u8_for_network(self.value)
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
        Self::new(c as u8)
    }
}

// ---------------------------------------------------------------------------
// GPRS timer, GPRS timer 2 and GPRS timer 3 (§9.11.2.3 to §9.11.2.5)
// ---------------------------------------------------------------------------

pub use crate::common::ts24008::{GprsTimer3Unit, GprsTimerUnit, GprsTimerValue};
use crate::common::ts24008::{gprs_timer_2_ie, gprs_timer_3_ie, gprs_timer_ie};

gprs_timer_ie!(NasGprsTimer, false);
gprs_timer_2_ie!(NasGprsTimer2);
gprs_timer_3_ie!(NasGprsTimer3);

impl NasGprsTimer3 {
    /// T3512 value as the UE interprets it: unit 110 means 320 hours when
    /// the carrying message is integrity protected and 1 hour otherwise
    /// (TS 24.008 Table 10.5.163a NOTE 1), and a zero value deactivates the
    /// timer (TS 24.501 §5.3.7). `None` when the value octet is missing.
    pub fn t3512_value_for_ue(&self, integrity_protected: bool) -> Option<GprsTimerValue> {
        let (unit, value) = self.timer()?;
        Some(match unit {
            GprsTimer3Unit::Deactivated => GprsTimerValue::Deactivated,
            _ if value == 0 => GprsTimerValue::Deactivated,
            GprsTimer3Unit::ThreeHundredTwentyHours if !integrity_protected => {
                GprsTimerValue::Seconds(3_600 * u64::from(value))
            }
            unit => GprsTimerValue::Seconds(unit.seconds_multiplier() * u64::from(value)),
        })
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
    /// N 1 sm information.
    N1SmInformation = 0x01,
    /// Sms.
    Sms = 0x02,
    /// LTE Positioning Protocol (LPP) message container.
    LtePp = 0x03,
    /// Sor transparent container.
    SorTransparentContainer = 0x04,
    /// UE policy.
    UePolicy = 0x05,
    /// UE parameters update.
    UeParametersUpdate = 0x06,
    /// Location services.
    LocationServices = 0x07,
    /// C io t.
    CIoT = 0x08,
    /// Service-level-AA container (Rel-17), TS 24.501 §9.11.3.39.
    ServiceLevelAaContainer = 0x09,
    /// Event notification.
    EventNotification = 0x0A,
    /// UPP-CMI container (User Plane Positioning — Capability Management Information).
    UppCmiContainer = 0x0B,
    /// SLPP message container (Sidelink Positioning Protocol).
    SlppMessageContainer = 0x0C,
    /// Multiple payloads.
    MultiplePayloads = 0x0F,
}

impl PayloadContainerKind {
    /// Decode a value from its wire octet.
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
            0x09 => Some(Self::ServiceLevelAaContainer),
            0x0A => Some(Self::EventNotification),
            0x0B => Some(Self::UppCmiContainer),
            0x0C => Some(Self::SlppMessageContainer),
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

    /// Set the payload container kind while preserving spare bits.
    pub fn with_kind(mut self, kind: PayloadContainerKind) -> Self {
        self.set_kind(kind);
        self
    }

    /// Mutating setter for the payload container kind.
    pub fn set_kind(&mut self, kind: PayloadContainerKind) -> &mut Self {
        self.value = (self.value & !0x0F) | (kind as u8 & 0x0F);
        self
    }

    /// Build from a typed payload container kind.
    pub fn from_kind(kind: PayloadContainerKind) -> Self {
        Self::new(kind as u8)
    }

    /// Whether this value is valid for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.value & 0xF0 == 0 && self.kind().is_some()
    }
}

// ---------------------------------------------------------------------------
// PDU Session Type (§9.11.4.11)
// ---------------------------------------------------------------------------

/// PDU session type per TS 24.501 §9.11.4.11.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PduSessionTypeValue {
    /// I pv 4.
    IPv4 = 0x01,
    /// I pv 6.
    IPv6 = 0x02,
    /// I pv 4 v 6.
    IPv4v6 = 0x03,
    /// Unstructured.
    Unstructured = 0x04,
    /// Ethernet.
    Ethernet = 0x05,
}

impl PduSessionTypeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::IPv4v6),
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            0x03 => Some(Self::IPv4v6),
            0x04 => Some(Self::Unstructured),
            0x05 => Some(Self::Ethernet),
            0x06 => Some(Self::IPv4v6),
            _ => None,
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            0x03 => Some(Self::IPv4v6),
            0x04 => Some(Self::Unstructured),
            0x05 => Some(Self::Ethernet),
            _ => None,
        }
    }

    /// 3GPP SBI string representation (TS 29.502).
    pub fn sbi_str(&self) -> &'static str {
        match self {
            Self::IPv4 => "IPV4",
            Self::IPv6 => "IPV6",
            Self::IPv4v6 => "IPV4V6",
            Self::Unstructured => "UNSTRUCTURED",
            Self::Ethernet => "ETHERNET",
        }
    }
}

impl NasPduSessionType {
    /// Typed PDU session type.
    pub fn session_type(&self) -> Option<PduSessionTypeValue> {
        PduSessionTypeValue::from_u8(self.value)
    }

    /// Raw session type value (lower 3 bits).
    pub fn session_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the typed PDU session type and clear the spare TV-1 bit.
    pub fn with_session_type(mut self, session_type: PduSessionTypeValue) -> Self {
        self.set_session_type(session_type);
        self
    }

    /// Mutating setter for the typed PDU session type.
    pub fn set_session_type(&mut self, session_type: PduSessionTypeValue) -> &mut Self {
        self.value = session_type as u8 & 0x07;
        self
    }

    /// Build from a typed session type.
    pub fn from_session_type(st: PduSessionTypeValue) -> Self {
        Self::new(st as u8)
    }

    /// Whether this value uses a defined sender code with spare bits cleared.
    pub fn is_well_formed(&self) -> bool {
        self.value & !0x07 == 0 && PduSessionTypeValue::from_u8_strict(self.value).is_some()
    }
}

// ---------------------------------------------------------------------------
// Access Type (§9.11.2.1A)
// ---------------------------------------------------------------------------

/// Access type per TS 24.501 §9.11.2.1A.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AccessTypeValue {
    /// 3GPP access
    ThreeGpp = 0x01,
    /// Non-3GPP access
    Non3Gpp = 0x02,
}

impl AccessTypeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x01 => Some(Self::ThreeGpp),
            0x02 => Some(Self::Non3Gpp),
            _ => None,
        }
    }
}

impl NasAccessType {
    /// Typed access type value.
    pub fn access_type(&self) -> Option<AccessTypeValue> {
        AccessTypeValue::from_u8(self.value)
    }

    /// Raw access type value (lower 2 bits).
    pub fn access_type_raw(&self) -> u8 {
        self.value & 0x03
    }

    /// Set the typed access type and clear the spare TV-1 bits.
    pub fn with_access_type(mut self, access_type: AccessTypeValue) -> Self {
        self.set_access_type(access_type);
        self
    }

    /// Mutating setter for the typed access type.
    pub fn set_access_type(&mut self, access_type: AccessTypeValue) -> &mut Self {
        self.value = access_type as u8 & 0x03;
        self
    }

    /// Build from a typed access type.
    pub fn from_access_type(at: AccessTypeValue) -> Self {
        Self::new(at as u8)
    }

    /// Whether the value nibble is valid for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.value & !0x03 == 0 && self.access_type().is_some()
    }
}

// ---------------------------------------------------------------------------
// Request Type (§9.11.3.47)
// ---------------------------------------------------------------------------

/// Request type per TS 24.501 §9.11.3.47.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RequestTypeValue {
    /// Initial request.
    InitialRequest = 0x01,
    /// Existing PDU session.
    ExistingPduSession = 0x02,
    /// Initial emergency request.
    InitialEmergencyRequest = 0x03,
    /// Existing emergency PDU session.
    ExistingEmergencyPduSession = 0x04,
    /// Modification request.
    ModificationRequest = 0x05,
    /// Ma PDU request.
    MaPduRequest = 0x06,
}

impl RequestTypeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::InitialRequest),
            0x01 => Some(Self::InitialRequest),
            0x02 => Some(Self::ExistingPduSession),
            0x03 => Some(Self::InitialEmergencyRequest),
            0x04 => Some(Self::ExistingEmergencyPduSession),
            0x05 => Some(Self::ModificationRequest),
            0x06 => Some(Self::MaPduRequest),
            _ => None,
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x01 => Some(Self::InitialRequest),
            0x02 => Some(Self::ExistingPduSession),
            0x03 => Some(Self::InitialEmergencyRequest),
            0x04 => Some(Self::ExistingEmergencyPduSession),
            0x05 => Some(Self::ModificationRequest),
            0x06 => Some(Self::MaPduRequest),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SSC Mode (§9.11.4.16)
// ---------------------------------------------------------------------------

/// SSC mode per TS 24.501 §9.11.4.16.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SscModeValue {
    /// SSC 1.
    Ssc1 = 0x01,
    /// SSC 2.
    Ssc2 = 0x02,
    /// SSC 3.
    Ssc3 = 0x03,
}

impl SscModeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x01 => Some(Self::Ssc1),
            0x02 => Some(Self::Ssc2),
            0x03 => Some(Self::Ssc3),
            0x04 => Some(Self::Ssc1),
            0x05 => Some(Self::Ssc2),
            0x06 => Some(Self::Ssc3),
            _ => None,
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x01 => Some(Self::Ssc1),
            0x02 => Some(Self::Ssc2),
            0x03 => Some(Self::Ssc3),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// NSSAI Inclusion Mode (§9.11.3.37A)
// ---------------------------------------------------------------------------

/// NSSAI inclusion mode per TS 24.501 §9.11.3.37A.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NssaiInclusionModeValue {
    /// Mode A (0b00) — see TS 24.501 §9.11.3.37A table 9.11.3.37A.1.
    A = 0x00,
    /// Mode B (0b01) — see TS 24.501 §9.11.3.37A table 9.11.3.37A.1.
    B = 0x01,
    /// Mode C (0b10) — see TS 24.501 §9.11.3.37A table 9.11.3.37A.1.
    C = 0x02,
    /// Mode D (0b11) — see TS 24.501 §9.11.3.37A table 9.11.3.37A.1.
    D = 0x03,
}

impl NssaiInclusionModeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x03 {
            0x00 => Self::A,
            0x01 => Self::B,
            0x02 => Self::C,
            _ => Self::D,
        }
    }
}

// ---------------------------------------------------------------------------
// 5GS Registration Result (§9.11.3.6)
// ---------------------------------------------------------------------------

/// Registration result value per TS 24.501 §9.11.3.6.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RegistrationResult {
    /// 3GPP access
    ThreeGppAccess = 0x01,
    /// Non-3GPP access
    Non3GppAccess = 0x02,
    /// 3GPP and non-3GPP access
    ThreeGppAndNon3Gpp = 0x03,
}

impl RegistrationResult {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::ThreeGppAccess),
            0x01 => Some(Self::ThreeGppAccess),
            0x02 => Some(Self::Non3GppAccess),
            0x03 => Some(Self::ThreeGppAndNon3Gpp),
            0x04..=0x06 => Some(Self::ThreeGppAccess),
            _ => None,
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x01 => Some(Self::ThreeGppAccess),
            0x02 => Some(Self::Non3GppAccess),
            0x03 => Some(Self::ThreeGppAndNon3Gpp),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Daylight Saving Time (§9.11.3.19)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Integrity Protection Maximum Data Rate (§9.11.4.7)
// ---------------------------------------------------------------------------

/// Integrity protection maximum data rate per TS 24.501 §9.11.4.7.
///
/// Three named values are defined; all others are reserved.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MaxDataRate {
    /// 64 kbps
    Kbps64 = 0x00,
    /// NULL — integrity protection not used (TS 24.501 Table 9.11.4.7.1).
    Null = 0x01,
    /// Full data rate
    FullRate = 0xFF,
}

impl MaxDataRate {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(Self::from_u8_strict(v).unwrap_or(Self::Kbps64))
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Kbps64),
            0x01 => Some(Self::Null),
            0xFF => Some(Self::FullRate),
            _ => None,
        }
    }
}

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

    /// EPS encryption algorithms byte (EEA0-EEA7). Byte 2 of value (only present
    /// when the IE is 4 bytes long, per TS 24.501 §9.11.3.54).
    pub fn eea_byte(&self) -> u8 {
        self.value.get(2).copied().unwrap_or(0)
    }

    /// EPS integrity algorithms byte (EIA0-EIA7). Byte 3 of value.
    pub fn eia_byte(&self) -> u8 {
        self.value.get(3).copied().unwrap_or(0)
    }

    /// Whether a specific EPS encryption algorithm is supported (0=EEA0..7=EEA7).
    pub fn supports_eea(&self, algo: u8) -> bool {
        if algo > 7 {
            return false;
        }
        (self.eea_byte() >> (7 - algo)) & 1 != 0
    }

    /// Whether a specific EPS integrity algorithm is supported.
    pub fn supports_eia(&self, algo: u8) -> bool {
        if algo > 7 {
            return false;
        }
        (self.eia_byte() >> (7 - algo)) & 1 != 0
    }

    /// Whether the IE includes EPS algorithm bytes (4-byte form).
    pub fn has_eps_algorithms(&self) -> bool {
        self.value.len() >= 4
    }

    /// Construct from EA and IA bytes (2-byte 5G-only form).
    pub fn from_capabilities(ea: u8, ia: u8) -> Self {
        Self::new(vec![ea, ia])
    }

    /// Construct from EA, IA, EEA, EIA bytes (4-byte form including EPS algorithms).
    pub fn from_capabilities_extended(ea: u8, ia: u8, eea: u8, eia: u8) -> Self {
        Self::new(vec![ea, ia, eea, eia])
    }
}

// ---------------------------------------------------------------------------
// PDU Session Status (§9.11.3.44)
// ---------------------------------------------------------------------------

impl NasPduSessionStatus {
    /// Whether a given PDU session identity (`1..=15`) is active.
    pub fn is_active(&self, session_id: u8) -> bool {
        if !(1..=15).contains(&session_id) {
            return false;
        }
        let byte_idx = (session_id / 8) as usize;
        let bit_idx = session_id % 8;
        self.value
            .get(byte_idx)
            .map(|b| (b >> bit_idx) & 1 != 0)
            .unwrap_or(false)
    }

    /// List all active PDU session identities (`1..=15`).
    pub fn active_sessions(&self) -> Vec<u8> {
        (1..=15).filter(|&id| self.is_active(id)).collect()
    }

    /// Construct from a list of active PDU session identities (`1..=15`).
    pub fn from_sessions(sessions: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        for &id in sessions {
            if (1..=15).contains(&id) {
                let byte_idx = (id / 8) as usize;
                let bit_idx = id % 8;
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
        bytes[0] &= !0x01;
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

impl SNssaiContents {
    /// Build a [`NasSNssai`] from this parsed structure.
    ///
    /// Wire format lengths per TS 24.501 §9.11.2.8:
    /// - 1 byte: SST only
    /// - 2 bytes: SST + mapped SST (no SD)
    /// - 4 bytes: SST + SD
    /// - 5 bytes: SST + SD + mapped SST
    /// - 8 bytes: SST + SD + mapped SST + mapped SD
    ///
    /// Returns `None` if the field combination does not match one of the spec
    /// lengths — in particular, `mapped_sd` without `mapped_sst`, or `mapped_sd`
    /// without `sd` (§9.11.2.8 Table 9.11.2.8.1 does not allow these).
    pub fn to_snssai(&self) -> Option<NasSNssai> {
        // Reject illegal combinations.
        if self.mapped_sd.is_some() && self.mapped_sst.is_none() {
            return None;
        }
        if self.mapped_sd.is_some() && self.sd.is_none() {
            return None;
        }
        let mut value = vec![self.sst];
        if let Some(sd) = self.sd {
            value.extend_from_slice(&sd);
        }
        if let Some(mapped_sst) = self.mapped_sst {
            value.push(mapped_sst);
        }
        if let Some(mapped_sd) = self.mapped_sd {
            value.extend_from_slice(&mapped_sd);
        }
        // Final length check (defensive; the branches above enforce this).
        match value.len() {
            1 | 2 | 4 | 5 | 8 => Some(NasSNssai::new(value)),
            _ => None,
        }
    }
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
            _ => return None,
        }

        Some(SNssaiContents {
            sst,
            sd,
            mapped_sst,
            mapped_sd,
        })
    }

    /// Construct from S-NSSAI value bytes after validating the permitted lengths.
    pub fn from_value(value: Vec<u8>) -> Option<Self> {
        let snssai = Self::new(value);
        snssai.parse()?;
        Some(snssai)
    }

    /// Construct from parsed S-NSSAI contents.
    pub fn from_contents(contents: SNssaiContents) -> Option<Self> {
        contents.to_snssai()
    }

    /// Whether this S-NSSAI uses one of the sender-permitted layouts.
    pub fn is_well_formed(&self) -> bool {
        self.parse().is_some()
    }

    /// Construct from SST and optional SD.
    pub fn from_sst_sd(sst: u8, sd: Option<[u8; 3]>) -> Self {
        Self::from_contents(SNssaiContents {
            sst,
            sd,
            mapped_sst: None,
            mapped_sd: None,
        })
        .expect("SST with optional SD is always a valid S-NSSAI layout")
    }
}

// ---------------------------------------------------------------------------
// DNN (§9.11.2.1B)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// De-registration Type (§9.11.3.20)
// ---------------------------------------------------------------------------

impl NasDeRegistrationType {
    /// Switch off flag (bit 4) — only meaningful for **UE-originated** deregistration
    /// (DeregistrationRequestFromUe, TS 24.501 §9.11.3.20 Table 9.11.3.20.1).
    ///
    /// When set, the UE is powering off and does not expect a DeregistrationAccept.
    pub fn switch_off(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// Re-registration required flag (bit 3) — only meaningful for **network-originated**
    /// deregistration (DeregistrationRequestToUe, TS 24.501 §9.11.3.20 Table 9.11.3.20.2).
    pub fn re_registration_required(&self) -> bool {
        (self.value >> 2) & 1 != 0
    }

    /// Typed access type (bits 1-2) using the common two-value access type.
    ///
    /// For this IE, value `0b11` means both 3GPP and non-3GPP access; use
    /// [`Self::deregistration_access_type`] when that value must be represented.
    pub fn access_type(&self) -> Option<AccessTypeValue> {
        AccessTypeValue::from_u8(self.value & 0x03)
    }

    /// De-registration-specific access type (bits 1-2).
    pub fn deregistration_access_type(&self) -> Option<DeregistrationAccessType> {
        DeregistrationAccessType::from_u8(self.value & 0x03)
    }

    /// Raw access type (bits 1-2).
    pub fn access_type_raw(&self) -> u8 {
        self.value & 0x03
    }

    /// ngKSI (bits 5-7 of the upper nibble, when packed with KSI).
    pub fn ngksi(&self) -> u8 {
        (self.value >> 4) & 0x07
    }

    /// TSC flag (bit 8): false = native, true = mapped.
    pub fn tsc(&self) -> bool {
        (self.value >> 7) & 1 != 0
    }

    /// Set the access type (bits 1-2). Returns `self` for chaining.
    pub fn with_access_type(mut self, t: AccessTypeValue) -> Self {
        self.value = (self.value & 0xFC) | (t as u8 & 0x03);
        self
    }

    /// Mutating setter for the access type.
    pub fn set_access_type(&mut self, t: AccessTypeValue) {
        self.value = (self.value & 0xFC) | (t as u8 & 0x03);
    }

    /// Set the de-registration access type (bits 1-2), including the both-accesses value.
    pub fn with_deregistration_access_type(mut self, t: DeregistrationAccessType) -> Self {
        self.value = (self.value & 0xFC) | (t as u8 & 0x03);
        self
    }

    /// Mutating setter for the de-registration-specific access type.
    pub fn set_deregistration_access_type(&mut self, t: DeregistrationAccessType) {
        self.value = (self.value & 0xFC) | (t as u8 & 0x03);
    }

    /// Set the switch-off bit (UE-originated deregistration). Returns `self`.
    pub fn with_switch_off(mut self, on: bool) -> Self {
        if on {
            self.value |= 0x08;
        } else {
            self.value &= !0x08;
        }
        self
    }

    /// Mutating setter for the switch-off bit.
    pub fn set_switch_off(&mut self, on: bool) {
        if on {
            self.value |= 0x08;
        } else {
            self.value &= !0x08;
        }
    }

    /// Set the re-registration-required bit (network-originated deregistration).
    pub fn with_re_registration_required(mut self, on: bool) -> Self {
        if on {
            self.value |= 0x04;
        } else {
            self.value &= !0x04;
        }
        self
    }

    /// Mutating setter for the re-registration-required bit.
    pub fn set_re_registration_required(&mut self, on: bool) {
        if on {
            self.value |= 0x04;
        } else {
            self.value &= !0x04;
        }
    }

    /// Set ngKSI (upper nibble bits 1-3, mask 0x70). Returns `self`.
    pub fn with_ngksi(mut self, ngksi: u8) -> Self {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
        self
    }

    /// Mutating setter for ngKSI.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
    }

    /// Set TSC (upper nibble bit 4, mask 0x80). Returns `self`.
    pub fn with_tsc(mut self, tsc: bool) -> Self {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
        self
    }

    /// Mutating setter for TSC.
    pub fn set_tsc(&mut self, tsc: bool) {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
    }
}

impl Default for NasDeRegistrationType {
    /// Default: 3GPP access, no switch-off, ngKSI = 7 (no key), native context.
    fn default() -> Self {
        Self::new(0x70 | (AccessTypeValue::ThreeGpp as u8))
    }
}

/// De-registration type access type values (TS 24.501 §9.11.3.20, bits 1-2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DeregistrationAccessType {
    /// Three gpp.
    ThreeGpp = 0x01,
    /// Non 3 gpp.
    Non3Gpp = 0x02,
    /// Three gpp and non 3 gpp.
    ThreeGppAndNon3Gpp = 0x03,
}

impl DeregistrationAccessType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x01 => Some(Self::ThreeGpp),
            0x02 => Some(Self::Non3Gpp),
            0x03 => Some(Self::ThreeGppAndNon3Gpp),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 5GS Registration Result (§9.11.3.6)
// ---------------------------------------------------------------------------

impl NasFGsRegistrationResult {
    /// Registration result value (bits 1-3 of first byte).
    pub fn result_value(&self) -> Option<RegistrationResult> {
        RegistrationResult::from_u8(self.value.first().copied().unwrap_or(0))
    }

    /// Raw registration result value (bits 1-3 of first byte).
    pub fn result_value_raw(&self) -> u8 {
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

    /// Emergency registered (bit 6) per TS 24.501 §9.11.3.6.
    pub fn emergency_registered(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 5) & 1 != 0)
            .unwrap_or(false)
    }

    /// Disaster roaming registration result (bit 7) per TS 24.501 §9.11.3.6.
    pub fn disaster_roaming(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 6) & 1 != 0)
            .unwrap_or(false)
    }

    fn first_byte(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }
    fn set_first_byte(&mut self, b: u8) {
        let b = b & 0x7F;
        if self.value.is_empty() {
            self.value.push(b);
        } else {
            self.value[0] = b;
        }
        self.length = self.value.len() as _;
    }

    /// Set the registration result value (bits 1-3, mask 0x07). Returns `self`.
    pub fn with_result_value(mut self, r: RegistrationResult) -> Self {
        let b = (self.first_byte() & 0xF8) | (r as u8 & 0x07);
        self.set_first_byte(b);
        self
    }
    /// Set result value.
    pub fn set_result_value(&mut self, r: RegistrationResult) {
        let b = (self.first_byte() & 0xF8) | (r as u8 & 0x07);
        self.set_first_byte(b);
    }

    /// Set SMS-allowed (bit 4, mask 0x08). Returns `self`.
    pub fn with_sms_allowed(mut self, on: bool) -> Self {
        let mut b = self.first_byte();
        if on {
            b |= 0x08;
        } else {
            b &= !0x08;
        }
        self.set_first_byte(b);
        self
    }
    /// Set sms allowed.
    pub fn set_sms_allowed(&mut self, on: bool) {
        let mut b = self.first_byte();
        if on {
            b |= 0x08;
        } else {
            b &= !0x08;
        }
        self.set_first_byte(b);
    }

    /// Set NSSAA-performed (bit 5, mask 0x10). Returns `self`.
    pub fn with_nssaa_performed(mut self, on: bool) -> Self {
        let mut b = self.first_byte();
        if on {
            b |= 0x10;
        } else {
            b &= !0x10;
        }
        self.set_first_byte(b);
        self
    }
    /// Set nssaa performed.
    pub fn set_nssaa_performed(&mut self, on: bool) {
        let mut b = self.first_byte();
        if on {
            b |= 0x10;
        } else {
            b &= !0x10;
        }
        self.set_first_byte(b);
    }

    /// Set emergency-registered (bit 6, mask 0x20). Returns `self`.
    pub fn with_emergency_registered(mut self, on: bool) -> Self {
        let mut b = self.first_byte();
        if on {
            b |= 0x20;
        } else {
            b &= !0x20;
        }
        self.set_first_byte(b);
        self
    }
    /// Set emergency registered.
    pub fn set_emergency_registered(&mut self, on: bool) {
        let mut b = self.first_byte();
        if on {
            b |= 0x20;
        } else {
            b &= !0x20;
        }
        self.set_first_byte(b);
    }

    /// Set disaster-roaming (bit 7, mask 0x40). Returns `self`.
    pub fn with_disaster_roaming(mut self, on: bool) -> Self {
        let mut b = self.first_byte();
        if on {
            b |= 0x40;
        } else {
            b &= !0x40;
        }
        self.set_first_byte(b);
        self
    }
    /// Set disaster roaming.
    pub fn set_disaster_roaming(&mut self, on: bool) {
        let mut b = self.first_byte();
        if on {
            b |= 0x40;
        } else {
            b &= !0x40;
        }
        self.set_first_byte(b);
    }
}

impl NasFGsRegistrationResult {
    /// Whether this mandatory LV has its exact sender length and defined value.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 1 && self.value[0] & 0x80 == 0 && self.result_value().is_some()
    }
}

impl Default for NasFGsRegistrationResult {
    /// Default: 3GPP access registration result, no flags set.
    fn default() -> Self {
        Self::new(vec![RegistrationResult::ThreeGppAccess as u8])
    }
}

// ---------------------------------------------------------------------------
// Service type (§9.11.3.50)
// ---------------------------------------------------------------------------

/// Service type values per TS 24.501 §9.11.3.50.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ServiceType {
    /// Signalling.
    Signalling = 0x00,
    /// Data.
    Data = 0x01,
    /// Mobile terminated services.
    MobileTerminatedServices = 0x02,
    /// Emergency services.
    EmergencyServices = 0x03,
    /// Emergency services fallback.
    EmergencyServicesFallback = 0x04,
    /// High priority access.
    HighPriorityAccess = 0x05,
    /// Elevated signalling.
    ElevatedSignalling = 0x06,
}

impl ServiceType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::Signalling),
            0x01 => Some(Self::Data),
            0x02 => Some(Self::MobileTerminatedServices),
            0x03 => Some(Self::EmergencyServices),
            0x04 => Some(Self::EmergencyServicesFallback),
            0x05 => Some(Self::HighPriorityAccess),
            0x06 => Some(Self::ElevatedSignalling),
            0x07 | 0x08 => Some(Self::Signalling),
            0x09..=0x0B => Some(Self::Data),
            _ => None,
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x0F {
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
// NAS Message Container (§9.11.3.33) — recursive decode
// ---------------------------------------------------------------------------

impl NasMessageContainer {
    /// Decode a plain inner NAS message from this container's raw bytes.
    pub fn decode_plain_inner(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::messages::Nas5gsMessage> {
        crate::nas_5gs::messages::decode_nas_5gs_message(&self.value)
    }

    /// Build from a plain NAS message (encodes it and wraps it in the container).
    pub fn from_plain_message(
        msg: &crate::nas_5gs::messages::Nas5gsMessage,
    ) -> crate::nas_5gs::types::Result<Self> {
        let bytes = crate::nas_5gs::messages::encode_nas_5gs_message(msg)?;
        Ok(Self::new(bytes))
    }
}

// ---------------------------------------------------------------------------
// Payload Container (§9.11.3.39)
// ---------------------------------------------------------------------------

impl NasPayloadContainer {
    /// Decode the payload as a plain NAS message.
    ///
    /// The payload container IE itself does not carry the payload container type, so callers
    /// should only use this helper when the enclosing payload container type is known to carry
    /// a plain NAS message.
    pub fn decode_plain_nas_message(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::messages::Nas5gsMessage> {
        crate::nas_5gs::messages::decode_nas_5gs_message(&self.value)
    }

    /// Build from a plain NAS message.
    pub fn from_plain_nas_message(
        msg: &crate::nas_5gs::messages::Nas5gsMessage,
    ) -> crate::nas_5gs::types::Result<Self> {
        let bytes = crate::nas_5gs::messages::encode_nas_5gs_message(msg)?;
        Ok(Self::new(bytes))
    }

    /// Decode the payload as an N1 SM message.
    pub fn decode_as_n1_sm_message(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::messages::Nas5gsMessage> {
        self.decode_plain_nas_message()
    }

    /// Build from an N1 SM message.
    pub fn from_n1_sm_message(
        msg: &crate::nas_5gs::messages::Nas5gsMessage,
    ) -> crate::nas_5gs::types::Result<Self> {
        Self::from_plain_nas_message(msg)
    }

    /// Decode the payload as a UE policy container message (TS 24.501 Annex D).
    pub fn decode_as_ue_policy_message(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::upds::NasUpdsEnvelope> {
        crate::nas_5gs::upds::NasUpdsEnvelope::decode_from_slice(&self.value)
    }

    /// Build from a UE policy container message (TS 24.501 Annex D).
    pub fn from_ue_policy_message(
        message: &crate::nas_5gs::upds::NasUpdsEnvelope,
    ) -> crate::nas_5gs::types::Result<Self> {
        Ok(Self::new(message.encode_to_vec()?))
    }

    /// Decode the payload as a SOR transparent container (§9.11.3.39 / §9.11.3.51).
    pub fn decode_as_sor_transparent_container(
        &self,
    ) -> crate::nas_5gs::types::Result<NasSorTransparentContainer> {
        let container = NasSorTransparentContainer::new(self.value.clone());
        if !container.receiver_syntax_is_valid() {
            return Err(NasError::DecodingError(
                "Malformed SOR transparent container".into(),
            ));
        }
        Ok(container)
    }

    /// Build from a SOR transparent container payload.
    pub fn from_sor_transparent_container(container: &NasSorTransparentContainer) -> Self {
        Self::new(container.value.clone())
    }

    /// Decode the payload as a UE parameters update transparent container (§9.11.3.39 / §9.11.3.53A).
    pub fn decode_as_ue_parameters_update_container(
        &self,
    ) -> crate::nas_5gs::types::Result<NasUeParametersUpdateTransparentContainer> {
        let container = NasUeParametersUpdateTransparentContainer::new(self.value.clone());
        if container.parse().is_none() {
            return Err(NasError::DecodingError(
                "Malformed UE parameters update transparent container".into(),
            ));
        }
        Ok(container)
    }

    /// Build from a UE parameters update transparent container payload.
    pub fn from_ue_parameters_update_container(
        container: &NasUeParametersUpdateTransparentContainer,
    ) -> Self {
        Self::new(container.value.clone())
    }

    /// Decode the payload as a CIoT user data container (§9.11.3.39 / TS 24.301 §9.9.4.24).
    pub fn decode_as_ciot_user_data_container(
        &self,
    ) -> crate::nas_5gs::types::Result<NasCiotSmallDataContainer> {
        let container = NasCiotSmallDataContainer::new(self.value.clone());
        container.validate_strict()?;
        Ok(container)
    }

    /// Build from a CIoT user data container payload.
    pub fn from_ciot_user_data_container(container: &NasCiotSmallDataContainer) -> Self {
        Self::new(container.value.clone())
    }

    /// Decode the payload as a service-level-AA container (§9.11.3.39 / §9.11.2.10).
    pub fn decode_as_service_level_aa_container(
        &self,
    ) -> crate::nas_5gs::types::Result<NasServiceLevelAaContainer> {
        let container = NasServiceLevelAaContainer::new(self.value.clone());
        container.validate_strict()?;
        Ok(container)
    }

    /// Build from a service-level-AA container payload.
    pub fn from_service_level_aa_container(container: &NasServiceLevelAaContainer) -> Self {
        Self::new(container.value.clone())
    }

    /// Decode the payload as an event notification container (§9.11.3.39).
    pub fn decode_as_event_notification_container(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::upds::UpdsEventNotificationContainer> {
        crate::nas_5gs::upds::UpdsEventNotificationContainer::decode_from_slice(&self.value)
    }

    /// Build from an event notification container payload.
    pub fn from_event_notification_container(
        container: &crate::nas_5gs::upds::UpdsEventNotificationContainer,
    ) -> crate::nas_5gs::types::Result<Self> {
        Ok(Self::new(container.encode_to_vec()?))
    }

    /// Decode the payload as a multiple-payload container (§9.11.3.39).
    pub fn decode_as_multiple_payload_container(
        &self,
    ) -> crate::nas_5gs::types::Result<crate::nas_5gs::upds::UpdsMultiplePayloadContainer> {
        crate::nas_5gs::upds::UpdsMultiplePayloadContainer::decode_from_slice(&self.value)
    }

    /// Build from a multiple-payload container payload.
    pub fn from_multiple_payload_container(
        container: &crate::nas_5gs::upds::UpdsMultiplePayloadContainer,
    ) -> crate::nas_5gs::types::Result<Self> {
        Ok(Self::new(container.encode_to_vec()?))
    }
}

// ---------------------------------------------------------------------------
// NSSAI list (§9.11.3.37) — multi-S-NSSAI parsing and building
// ---------------------------------------------------------------------------

impl NasNssai {
    /// Parse all S-NSSAI entries, returning `None` for malformed framing or values.
    pub fn try_parse_all(&self) -> Option<Vec<SNssaiContents>> {
        if self.value.is_empty() {
            return None;
        }
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() {
            let entry_len = *self.value.get(pos)? as usize;
            pos += 1;
            if !matches!(entry_len, 1 | 2 | 4 | 5 | 8) {
                return None;
            }
            let end = pos.checked_add(entry_len)?;
            let parsed = NasSNssai::new(self.value.get(pos..end)?.to_vec()).parse()?;
            entries.push(parsed);
            pos = end;
        }
        (!entries.is_empty()).then_some(entries)
    }

    /// Parse all valid S-NSSAI entries from the NSSAI value.
    ///
    /// This compatibility accessor returns an empty list for malformed data;
    /// use [`Self::try_parse_all`] when the distinction matters.
    pub fn parse_all(&self) -> Vec<SNssaiContents> {
        self.try_parse_all().unwrap_or_default()
    }

    /// Build an NSSAI IE from checked S-NSSAI entries.
    pub fn try_from_snssais(snssais: &[NasSNssai]) -> Option<Self> {
        if snssais.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for snssai in snssais {
            snssai.parse()?;
            let len = u8::try_from(snssai.value.len()).ok()?;
            value.push(len);
            value.extend_from_slice(&snssai.value);
        }
        Some(Self::new(value))
    }

    /// Build an NSSAI IE from S-NSSAI entries.
    ///
    /// # Panics
    ///
    /// Panics for an empty list or a malformed S-NSSAI.
    pub fn from_snssais(snssais: &[NasSNssai]) -> Self {
        Self::try_from_snssais(snssais)
            .expect("NSSAI requires one or more structurally valid S-NSSAIs")
    }

    /// Whether the complete NSSAI value has valid entry framing and contents.
    pub fn is_well_formed(&self) -> bool {
        self.try_parse_all().is_some()
    }
}

// ---------------------------------------------------------------------------
// 5GS Tracking Area Identity (§9.11.3.8) — single TAI
// ---------------------------------------------------------------------------

/// Parsed Tracking Area Identity: PLMN + TAC.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TrackingAreaIdentity {
    /// PLMN.
    pub plmn: PlmnId,
    /// Tracking Area Code (3 bytes).
    pub tac: [u8; 3],
}

/// Receiver interpretation of a 5GS tracking area identity.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ReceivedTrackingAreaIdentity {
    /// An assigned TAI with decimal PLMN digits and a non-deletion TAC.
    Assigned(TrackingAreaIdentity),
    /// A deleted TAI. The raw PLMN is retained because an abnormal hexadecimal
    /// MCC is itself the TS 24.501 receiver indication for deletion.
    Deleted {
        /// Raw TBCD or abnormal hexadecimal PLMN octets.
        raw_plmn: [u8; 3],
        /// Received TAC octets.
        tac: [u8; 3],
    },
}

impl NasFGsTrackingAreaIdentity {
    /// Parse the TAI value: PLMN (3 bytes TBCD) + TAC (3 bytes).
    pub fn parse(&self) -> Option<TrackingAreaIdentity> {
        match self.receiver_value()? {
            ReceivedTrackingAreaIdentity::Assigned(tai) => Some(tai),
            ReceivedTrackingAreaIdentity::Deleted { .. } => None,
        }
    }

    /// Interpret a received TAI, including the specified deleted-TAI fallbacks.
    ///
    /// TS 24.501 §9.11.3.8 requires an MCC containing non-decimal hexadecimal
    /// digits to be treated as deleted. TAC `FF FF FE`, and TAC `00 00 00` when
    /// read from a USIM, are also deletion encodings; treating both as deleted
    /// is the conservative receiver behavior for a standalone IE.
    pub fn receiver_value(&self) -> Option<ReceivedTrackingAreaIdentity> {
        let raw: [u8; 6] = self.value.as_slice().try_into().ok()?;
        let raw_plmn = [raw[0], raw[1], raw[2]];
        let tac = [raw[3], raw[4], raw[5]];
        let plmn = PlmnId::from_tbcd(&raw_plmn);
        if plmn.is_none() || matches!(tac, [0xff, 0xff, 0xfe] | [0x00, 0x00, 0x00]) {
            return Some(ReceivedTrackingAreaIdentity::Deleted { raw_plmn, tac });
        }
        Some(ReceivedTrackingAreaIdentity::Assigned(
            TrackingAreaIdentity {
                plmn: plmn.expect("checked above"),
                tac,
            },
        ))
    }

    /// Whether the received value denotes a deleted TAI.
    pub fn is_deleted(&self) -> bool {
        matches!(
            self.receiver_value(),
            Some(ReceivedTrackingAreaIdentity::Deleted { .. })
        )
    }

    /// Build an assigned TAI after checking the PLMN and deletion TAC values.
    pub fn try_from_plmn_tac(plmn: &PlmnId, tac: [u8; 3]) -> Option<Self> {
        if matches!(tac, [0xff, 0xff, 0xfe] | [0x00, 0x00, 0x00]) {
            return None;
        }
        let mut value = plmn.try_to_tbcd()?.to_vec();
        value.extend_from_slice(&tac);
        Some(Self::new(value))
    }

    /// Build an assigned TAI from a PLMN and TAC.
    ///
    /// # Panics
    ///
    /// Panics for invalid PLMN digits or a TAC reserved for a deleted TAI.
    pub fn from_plmn_tac(plmn: &PlmnId, tac: [u8; 3]) -> Self {
        Self::try_from_plmn_tac(plmn, tac)
            .expect("TAI requires valid PLMN digits and a non-deletion TAC")
    }

    /// Build the canonical deleted-TAI encoding while retaining the PLMN.
    pub fn from_deleted(plmn: &PlmnId) -> Option<Self> {
        let mut value = plmn.try_to_tbcd()?.to_vec();
        value.extend_from_slice(&[0xff, 0xff, 0xfe]);
        Some(Self::new(value))
    }
}

// ---------------------------------------------------------------------------
// 5GS Tracking Area Identity List (§9.11.3.9) — TAI list parsing
// ---------------------------------------------------------------------------

/// Type of a partial tracking area list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TaiListType {
    /// One PLMN non consecutive.
    OnePlmnNonConsecutive = 0x00,
    /// One PLMN consecutive.
    OnePlmnConsecutive = 0x01,
    /// Different plmns.
    DifferentPlmns = 0x02,
}

impl TaiListType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::OnePlmnNonConsecutive),
            0x01 => Some(Self::OnePlmnConsecutive),
            0x02 => Some(Self::DifferentPlmns),
            _ => None,
        }
    }
}

/// A single partial tracking area list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TaiListEntry {
    /// One PLMN non consecutive.
    OnePlmnNonConsecutive {
        /// PLMN.
        plmn: PlmnId,
        /// Tacs.
        tacs: Vec<[u8; 3]>,
    },
    /// One PLMN consecutive.
    OnePlmnConsecutive {
        /// PLMN.
        plmn: PlmnId,
        /// First TAC.
        first_tac: [u8; 3],
        /// Count.
        count: usize,
    },
    /// Different plmns.
    DifferentPlmns(Vec<TrackingAreaIdentity>),
}

impl TaiListEntry {
    /// Return list type.
    pub fn list_type(&self) -> TaiListType {
        match self {
            Self::OnePlmnNonConsecutive { .. } => TaiListType::OnePlmnNonConsecutive,
            Self::OnePlmnConsecutive { .. } => TaiListType::OnePlmnConsecutive,
            Self::DifferentPlmns(_) => TaiListType::DifferentPlmns,
        }
    }

    /// Return PLMN.
    pub fn plmn(&self) -> Option<&PlmnId> {
        match self {
            Self::OnePlmnNonConsecutive { plmn, .. } | Self::OnePlmnConsecutive { plmn, .. } => {
                Some(plmn)
            }
            Self::DifferentPlmns(_) => None,
        }
    }

    /// Return tracking area identities.
    pub fn tracking_area_identities(&self) -> Vec<TrackingAreaIdentity> {
        match self {
            Self::OnePlmnNonConsecutive { plmn, tacs } => tacs
                .iter()
                .copied()
                .map(|tac| TrackingAreaIdentity { plmn: *plmn, tac })
                .collect(),
            Self::OnePlmnConsecutive {
                plmn,
                first_tac,
                count,
            } => expand_consecutive_tacs(*first_tac, *count)
                .into_iter()
                .map(|tac| TrackingAreaIdentity { plmn: *plmn, tac })
                .collect(),
            Self::DifferentPlmns(tais) => tais.clone(),
        }
    }

    /// Return tacs.
    pub fn tacs(&self) -> Vec<[u8; 3]> {
        match self {
            Self::OnePlmnNonConsecutive { tacs, .. } => tacs.clone(),
            Self::OnePlmnConsecutive {
                first_tac, count, ..
            } => expand_consecutive_tacs(*first_tac, *count),
            Self::DifferentPlmns(tais) => tais.iter().map(|tai| tai.tac).collect(),
        }
    }
}

impl NasFGsTrackingAreaIdentityList {
    /// Parse the TAI list into partial-list entries.
    ///
    /// Handles the three list types defined in TS 24.501 §9.11.3.9 Table 9.11.3.9.2.
    pub fn parse(&self) -> Vec<TaiListEntry> {
        let data = &self.value;
        let mut entries = Vec::new();
        let mut pos = 0;
        let mut total_tais = 0usize;

        while pos < data.len() && total_tais < MAX_TAI_LIST_ELEMENTS {
            let header = data[pos];
            if header & 0x80 != 0 {
                break;
            }
            let list_type = match TaiListType::from_u8((header >> 5) & 0x03) {
                Some(list_type) => list_type,
                None => break,
            };
            let count_field = header & 0x1F;
            let num_elements = if count_field <= 0x0F {
                count_field as usize + 1
            } else {
                MAX_TAI_LIST_ELEMENTS
            };
            let remaining = MAX_TAI_LIST_ELEMENTS - total_tais;
            let take_elements = num_elements.min(remaining);
            pos += 1;

            match list_type {
                TaiListType::OnePlmnNonConsecutive => {
                    // Type 00: one PLMN + N non-consecutive TACs.
                    if pos + 3 > data.len() {
                        break;
                    }
                    let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                        Some(p) => p,
                        None => break,
                    };
                    pos += 3;
                    let mut tacs = Vec::with_capacity(take_elements);
                    for _ in 0..take_elements {
                        if pos + 3 > data.len() {
                            break;
                        }
                        tacs.push([data[pos], data[pos + 1], data[pos + 2]]);
                        pos += 3;
                    }
                    total_tais += tacs.len();
                    entries.push(TaiListEntry::OnePlmnNonConsecutive { plmn, tacs });
                }
                TaiListType::OnePlmnConsecutive => {
                    // Type 01: one PLMN + first TAC; remaining N-1 are consecutive
                    // (first+1, first+2, ...). TS 24.501 §9.11.3.9 Figure 9.11.3.9.4.
                    if pos + 6 > data.len() {
                        break;
                    }
                    let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                        Some(p) => p,
                        None => break,
                    };
                    pos += 3;
                    let first_tac = [data[pos], data[pos + 1], data[pos + 2]];
                    pos += 3;
                    entries.push(TaiListEntry::OnePlmnConsecutive {
                        plmn,
                        first_tac,
                        count: take_elements,
                    });
                    total_tais += take_elements;
                }
                TaiListType::DifferentPlmns => {
                    // Type 10: N individual (PLMN + TAC) pairs from different PLMNs.
                    let mut tais = Vec::with_capacity(take_elements);
                    for _ in 0..take_elements {
                        if pos + 6 > data.len() {
                            break;
                        }
                        let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                            Some(p) => p,
                            None => break,
                        };
                        let tac = [data[pos + 3], data[pos + 4], data[pos + 5]];
                        pos += 6;
                        tais.push(TrackingAreaIdentity { plmn, tac });
                    }
                    total_tais += tais.len();
                    entries.push(TaiListEntry::DifferentPlmns(tais));
                }
            }
        }
        entries
    }

    fn receiver_prefix_length(&self) -> Option<usize> {
        let data = self.value.as_slice();
        let mut pos = 0usize;
        let mut total_tais = 0usize;
        while pos < data.len() && total_tais < MAX_TAI_LIST_ELEMENTS {
            let header = *data.get(pos)?;
            if header & 0x80 != 0 {
                return None;
            }
            let list_type = TaiListType::from_u8((header >> 5) & 0x03)?;
            let count = if header & 0x1F <= 0x0F {
                usize::from(header & 0x1F) + 1
            } else {
                MAX_TAI_LIST_ELEMENTS
            };
            let take = count.min(MAX_TAI_LIST_ELEMENTS - total_tais);
            pos += 1;
            match list_type {
                TaiListType::OnePlmnNonConsecutive => {
                    PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                    pos += 3;
                    pos = pos.checked_add(3usize.checked_mul(take)?)?;
                    data.get(..pos)?;
                }
                TaiListType::OnePlmnConsecutive => {
                    PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                    pos += 6;
                    data.get(..pos)?;
                }
                TaiListType::DifferentPlmns => {
                    for _ in 0..take {
                        PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                        pos += 6;
                        data.get(..pos)?;
                    }
                }
            }
            total_tais += take;
        }
        (total_tais > 0).then_some(pos)
    }

    /// Whether the receiver can parse the declared TAI entries. Once sixteen
    /// TAIs are complete, remaining value octets are ignored by §9.11.3.9.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.receiver_prefix_length().is_some()
    }

    /// Whether this is a canonical sender list of one through sixteen TAIs.
    pub fn is_well_formed(&self) -> bool {
        self.receiver_prefix_length() == Some(self.value.len())
            && Self::try_from_entries(&self.parse()).is_some_and(|value| value.value == self.value)
    }

    /// Try to build a type `00` TAI list (one PLMN, multiple TACs).
    pub fn try_from_plmn_tacs(plmn: &PlmnId, tacs: &[[u8; 3]]) -> Option<Self> {
        let entry = TaiListEntry::OnePlmnNonConsecutive {
            plmn: *plmn,
            tacs: tacs.to_vec(),
        };
        Self::try_from_entries(std::slice::from_ref(&entry))
    }

    /// Build a type `00` TAI list.
    ///
    /// # Panics
    ///
    /// Panics unless the PLMN is valid and the list contains 1 through 16 TACs.
    pub fn from_plmn_tacs(plmn: &PlmnId, tacs: &[[u8; 3]]) -> Self {
        Self::try_from_plmn_tacs(plmn, tacs)
            .expect("TAI list must contain 1..=16 TACs and a valid PLMN")
    }

    /// Try to build a type `10` TAI list (individual PLMN and TAC pairs).
    pub fn try_from_tai_list(entries: &[TrackingAreaIdentity]) -> Option<Self> {
        Self::try_from_entries(std::slice::from_ref(&TaiListEntry::DifferentPlmns(
            entries.to_vec(),
        )))
    }

    /// Build a type `10` TAI list.
    ///
    /// # Panics
    ///
    /// Panics unless the list contains 1 through 16 entries with valid PLMNs.
    pub fn from_tai_list(entries: &[TrackingAreaIdentity]) -> Self {
        Self::try_from_tai_list(entries)
            .expect("TAI list must contain 1..=16 entries with valid PLMNs")
    }

    /// Try to build a type `01` list of consecutive TACs.
    pub fn try_from_consecutive_tacs(
        plmn: &PlmnId,
        first_tac: [u8; 3],
        count: usize,
    ) -> Option<Self> {
        let entry = TaiListEntry::OnePlmnConsecutive {
            plmn: *plmn,
            first_tac,
            count,
        };
        Self::try_from_entries(std::slice::from_ref(&entry))
    }

    /// Build a type `01` list of consecutive TACs.
    ///
    /// # Panics
    ///
    /// Panics unless the PLMN is valid, `count` is 1 through 16, and the
    /// 24-bit TAC sequence does not wrap.
    pub fn from_consecutive_tacs(plmn: &PlmnId, first_tac: [u8; 3], count: usize) -> Self {
        Self::try_from_consecutive_tacs(plmn, first_tac, count)
            .expect("consecutive TAI list must be valid, contain 1..=16 TACs, and not wrap")
    }

    /// Try to build one through sixteen TAIs from partial-list entries.
    pub fn try_from_entries(entries: &[TaiListEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        let mut total = 0usize;
        let mut value = Vec::new();
        for entry in entries {
            match entry {
                TaiListEntry::OnePlmnNonConsecutive { plmn, tacs } => {
                    if !(1..=MAX_TAI_LIST_ELEMENTS).contains(&tacs.len())
                        || plmn.try_to_tbcd().is_none()
                    {
                        return None;
                    }
                    total = total.checked_add(tacs.len())?;
                    push_tai_list_one_plmn_non_consecutive(&mut value, plmn, tacs);
                }
                TaiListEntry::OnePlmnConsecutive {
                    plmn,
                    first_tac,
                    count,
                } => {
                    let first = u32::from_be_bytes([0, first_tac[0], first_tac[1], first_tac[2]]);
                    if !(1..=MAX_TAI_LIST_ELEMENTS).contains(count)
                        || plmn.try_to_tbcd().is_none()
                        || first.checked_add(u32::try_from(count - 1).ok()?)? > 0x00ff_ffff
                    {
                        return None;
                    }
                    total = total.checked_add(*count)?;
                    push_tai_list_one_plmn_consecutive(&mut value, plmn, *first_tac, *count);
                }
                TaiListEntry::DifferentPlmns(tais) => {
                    if !(1..=MAX_TAI_LIST_ELEMENTS).contains(&tais.len())
                        || tais.iter().any(|tai| tai.plmn.try_to_tbcd().is_none())
                    {
                        return None;
                    }
                    total = total.checked_add(tais.len())?;
                    push_tai_list_different_plmns(&mut value, tais);
                }
            }
            if total > MAX_TAI_LIST_ELEMENTS {
                return None;
            }
        }
        Some(Self::new(value))
    }

    /// Build from partial-list entries.
    ///
    /// # Panics
    ///
    /// Panics if the entries do not encode 1 through 16 valid TAIs.
    pub fn from_entries(entries: &[TaiListEntry]) -> Self {
        Self::try_from_entries(entries).expect("TAI list entries must encode 1..=16 valid TAIs")
    }
}

const MAX_TAI_LIST_ELEMENTS: usize = 16;

fn encode_tai_list_count(count: usize) -> u8 {
    assert!(
        (1..=MAX_TAI_LIST_ELEMENTS).contains(&count),
        "TAI list partial entry count must be in 1..={MAX_TAI_LIST_ELEMENTS}"
    );
    ((count - 1) as u8) & 0x1F
}

fn push_tai_list_one_plmn_non_consecutive(value: &mut Vec<u8>, plmn: &PlmnId, tacs: &[[u8; 3]]) {
    value.push(encode_tai_list_count(tacs.len()));
    value.extend_from_slice(&plmn.to_tbcd());
    for tac in tacs {
        value.extend_from_slice(tac);
    }
}

fn push_tai_list_one_plmn_consecutive(
    value: &mut Vec<u8>,
    plmn: &PlmnId,
    first_tac: [u8; 3],
    count: usize,
) {
    value.push(0x20 | encode_tai_list_count(count));
    value.extend_from_slice(&plmn.to_tbcd());
    value.extend_from_slice(&first_tac);
}

fn push_tai_list_different_plmns(value: &mut Vec<u8>, entries: &[TrackingAreaIdentity]) {
    value.push(0x40 | encode_tai_list_count(entries.len()));
    for tai in entries {
        value.extend_from_slice(&tai.plmn.to_tbcd());
        value.extend_from_slice(&tai.tac);
    }
}

fn expand_consecutive_tacs(first_tac: [u8; 3], count: usize) -> Vec<[u8; 3]> {
    let first = u32::from_be_bytes([0, first_tac[0], first_tac[1], first_tac[2]]);
    let mut tacs = Vec::with_capacity(count);
    for i in 0..count {
        let tac = first.wrapping_add(i as u32) & 0x00FF_FFFF;
        tacs.push([(tac >> 16) as u8, (tac >> 8) as u8, tac as u8]);
    }
    tacs
}

// ---------------------------------------------------------------------------
// Allowed PDU Session Status (§9.11.3.13) — same bitmask as PDU Session Status
// ---------------------------------------------------------------------------

impl NasAllowedPduSessionStatus {
    /// Whether a given PDU session identity (`1..=15`) is allowed.
    pub fn is_allowed(&self, session_id: u8) -> bool {
        if !(1..=15).contains(&session_id) {
            return false;
        }
        let byte_idx = (session_id / 8) as usize;
        let bit_idx = session_id % 8;
        self.value
            .get(byte_idx)
            .map(|b| (b >> bit_idx) & 1 != 0)
            .unwrap_or(false)
    }

    /// List all allowed PDU session identities (`1..=15`).
    pub fn allowed_sessions(&self) -> Vec<u8> {
        (1..=15).filter(|&id| self.is_allowed(id)).collect()
    }

    /// Construct from a list of allowed PDU session identities (`1..=15`).
    pub fn from_sessions(sessions: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        for &id in sessions {
            if (1..=15).contains(&id) {
                let byte_idx = (id / 8) as usize;
                let bit_idx = id % 8;
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
        bytes[0] &= !0x01;
        Self::new(bytes.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Session-AMBR (§9.11.4.14) — DL/UL aggregate maximum bit rate
// ---------------------------------------------------------------------------

/// Parsed Session-AMBR with resolved bit rates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SessionAmbrValue {
    /// Downlink rate in kbps.
    pub dl_kbps: u64,
    /// Uplink rate in kbps.
    pub ul_kbps: u64,
}

/// Session-AMBR unit values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SessionAmbrUnit {
    /// Not used.
    NotUsed = 0x00,
    /// Kbps 1.
    Kbps1 = 0x01,
    /// Kbps 4.
    Kbps4 = 0x02,
    /// Kbps 16.
    Kbps16 = 0x03,
    /// Kbps 64.
    Kbps64 = 0x04,
    /// Kbps 256.
    Kbps256 = 0x05,
    /// Mbps 1.
    Mbps1 = 0x06,
    /// Mbps 4.
    Mbps4 = 0x07,
    /// Mbps 16.
    Mbps16 = 0x08,
    /// Mbps 64.
    Mbps64 = 0x09,
    /// Mbps 256.
    Mbps256 = 0x0A,
    /// Gbps 1.
    Gbps1 = 0x0B,
    /// Gbps 4.
    Gbps4 = 0x0C,
    /// Gbps 16.
    Gbps16 = 0x0D,
    /// Gbps 64.
    Gbps64 = 0x0E,
    /// Gbps 256.
    Gbps256 = 0x0F,
    /// Tbps 1.
    Tbps1 = 0x10,
    /// Tbps 4.
    Tbps4 = 0x11,
    /// Tbps 16.
    Tbps16 = 0x12,
    /// Tbps 64.
    Tbps64 = 0x13,
    /// Tbps 256.
    Tbps256 = 0x14,
    /// Pbps 1.
    Pbps1 = 0x15,
    /// Pbps 4.
    Pbps4 = 0x16,
    /// Pbps 16.
    Pbps16 = 0x17,
    /// Pbps 64.
    Pbps64 = 0x18,
    /// Pbps 256.
    Pbps256 = 0x19,
}

impl SessionAmbrUnit {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NotUsed),
            0x01 => Some(Self::Kbps1),
            0x02 => Some(Self::Kbps4),
            0x03 => Some(Self::Kbps16),
            0x04 => Some(Self::Kbps64),
            0x05 => Some(Self::Kbps256),
            0x06 => Some(Self::Mbps1),
            0x07 => Some(Self::Mbps4),
            0x08 => Some(Self::Mbps16),
            0x09 => Some(Self::Mbps64),
            0x0A => Some(Self::Mbps256),
            0x0B => Some(Self::Gbps1),
            0x0C => Some(Self::Gbps4),
            0x0D => Some(Self::Gbps16),
            0x0E => Some(Self::Gbps64),
            0x0F => Some(Self::Gbps256),
            0x10 => Some(Self::Tbps1),
            0x11 => Some(Self::Tbps4),
            0x12 => Some(Self::Tbps16),
            0x13 => Some(Self::Tbps64),
            0x14 => Some(Self::Tbps256),
            0x15 => Some(Self::Pbps1),
            0x16 => Some(Self::Pbps4),
            0x17 => Some(Self::Pbps16),
            0x18 => Some(Self::Pbps64),
            0x19 => Some(Self::Pbps256),
            _ => None,
        }
    }

    /// Return kbps multiplier.
    pub fn kbps_multiplier(self) -> Option<u64> {
        ambr_unit_to_kbps(self as u8)
    }
}

impl NasSessionAmbr {
    fn ensure_len(&mut self) {
        if self.value.len() < 6 {
            self.value.resize(6, 0);
        }
        self.length = self.value.len() as _;
    }

    /// Downlink unit octet as it appears on the wire.
    pub fn downlink_unit_raw(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// Downlink unit decoded as a known AMBR unit, if recognized.
    pub fn downlink_unit(&self) -> Option<SessionAmbrUnit> {
        SessionAmbrUnit::from_u8(self.downlink_unit_raw())
    }

    /// Downlink raw 16-bit value field.
    pub fn downlink_value(&self) -> u16 {
        if self.value.len() < 3 {
            return 0;
        }
        u16::from_be_bytes([self.value[1], self.value[2]])
    }

    /// Downlink rate resolved to kbps using the on-wire unit semantics.
    pub fn downlink_kbps(&self) -> Option<u64> {
        if self.value.len() < 6 {
            return None;
        }
        (self.downlink_value() as u64).checked_mul(ambr_unit_to_kbps(self.downlink_unit_raw())?)
    }

    /// Uplink unit octet as it appears on the wire.
    pub fn uplink_unit_raw(&self) -> u8 {
        self.value.get(3).copied().unwrap_or(0)
    }

    /// Uplink unit decoded as a known AMBR unit, if recognized.
    pub fn uplink_unit(&self) -> Option<SessionAmbrUnit> {
        SessionAmbrUnit::from_u8(self.uplink_unit_raw())
    }

    /// Uplink raw 16-bit value field.
    pub fn uplink_value(&self) -> u16 {
        if self.value.len() < 6 {
            return 0;
        }
        u16::from_be_bytes([self.value[4], self.value[5]])
    }

    /// Uplink rate resolved to kbps using the on-wire unit semantics.
    pub fn uplink_kbps(&self) -> Option<u64> {
        if self.value.len() < 6 {
            return None;
        }
        (self.uplink_value() as u64).checked_mul(ambr_unit_to_kbps(self.uplink_unit_raw())?)
    }

    /// Replace the downlink unit and value fields.
    pub fn set_downlink(&mut self, unit: u8, value: u16) {
        self.ensure_len();
        self.value[0] = unit;
        self.value[1..3].copy_from_slice(&value.to_be_bytes());
    }

    /// Builder-style downlink field setter.
    pub fn with_downlink(mut self, unit: u8, value: u16) -> Self {
        self.set_downlink(unit, value);
        self
    }

    /// Replace the uplink unit and value fields.
    pub fn set_uplink(&mut self, unit: u8, value: u16) {
        self.ensure_len();
        self.value[3] = unit;
        self.value[4..6].copy_from_slice(&value.to_be_bytes());
    }

    /// Builder-style uplink field setter.
    pub fn with_uplink(mut self, unit: u8, value: u16) -> Self {
        self.set_uplink(unit, value);
        self
    }

    /// Build from raw DL and UL fields.
    pub fn from_raw_fields(dl_unit: u8, dl_value: u16, ul_unit: u8, ul_value: u16) -> Self {
        Self::new(vec![
            dl_unit,
            (dl_value >> 8) as u8,
            dl_value as u8,
            ul_unit,
            (ul_value >> 8) as u8,
            ul_value as u8,
        ])
    }

    /// Parse the Session-AMBR value bytes.
    ///
    /// Wire format: DL unit (1) + DL value (2) + UL unit (1) + UL value (2).
    /// Unit values per TS 24.501 §9.11.4.14 Table 9.11.4.14.1.
    pub fn parse(&self) -> Option<SessionAmbrValue> {
        if self.value.len() < 6 {
            return None;
        }
        Some(SessionAmbrValue {
            dl_kbps: self.downlink_kbps()?,
            ul_kbps: self.uplink_kbps()?,
        })
    }

    /// Try to build an exactly representable DL and UL rate in kbps.
    pub fn try_from_kbps(dl_kbps: u64, ul_kbps: u64) -> Option<Self> {
        let (dl_unit, dl_val) = kbps_to_ambr_unit(dl_kbps)?;
        let (ul_unit, ul_val) = kbps_to_ambr_unit(ul_kbps)?;
        Some(Self::from_raw_fields(dl_unit, dl_val, ul_unit, ul_val))
    }

    /// Build exactly representable DL and UL rates in kbps.
    ///
    /// # Panics
    ///
    /// Panics if either value exceeds the representable range. Use
    /// [`Self::try_from_kbps`] for untrusted values.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> Self {
        Self::try_from_kbps(dl_kbps, ul_kbps)
            .expect("Session-AMBR rates must be exactly representable")
    }

    /// Whether this is a canonical sender value with assigned unit codes.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 6
            && matches!(self.downlink_unit_raw(), 0x01..=0x19)
            && matches!(self.uplink_unit_raw(), 0x01..=0x19)
    }
}

/// Convert AMBR unit code to kbps multiplier per TS 24.501 §9.11.4.14 Table 9.11.4.14.1.
fn ambr_unit_to_kbps(unit: u8) -> Option<u64> {
    match unit {
        0x00 => Some(1),
        0x01..=0x05 => Some(4u64.pow((unit - 0x01) as u32)),
        0x06..=0x0A => Some(1_000 * 4u64.pow((unit - 0x06) as u32)),
        0x0B..=0x0F => Some(1_000_000 * 4u64.pow((unit - 0x0B) as u32)),
        0x10..=0x14 => Some(1_000_000_000 * 4u64.pow((unit - 0x10) as u32)),
        0x15..=0x19 => Some(1_000_000_000_000 * 4u64.pow((unit - 0x15) as u32)),
        _ => Some(256_000_000_000_000),
    }
}

/// Pick the largest AMBR unit whose multiplier fits the given kbps value,
/// returning `(unit_code, value)` where `value * multiplier == kbps`.
fn kbps_to_ambr_unit(kbps: u64) -> Option<(u8, u16)> {
    // Walk the table from largest to smallest unit.
    const UNITS: [(u8, u64); 25] = [
        (0x19, 256_000_000_000_000),
        (0x18, 64_000_000_000_000),
        (0x17, 16_000_000_000_000),
        (0x16, 4_000_000_000_000),
        (0x15, 1_000_000_000_000),
        (0x14, 256_000_000_000),
        (0x13, 64_000_000_000),
        (0x12, 16_000_000_000),
        (0x11, 4_000_000_000),
        (0x10, 1_000_000_000),
        (0x0F, 256_000_000),
        (0x0E, 64_000_000),
        (0x0D, 16_000_000),
        (0x0C, 4_000_000),
        (0x0B, 1_000_000),
        (0x0A, 256_000),
        (0x09, 64_000),
        (0x08, 16_000),
        (0x07, 4_000),
        (0x06, 1_000),
        (0x05, 256),
        (0x04, 64),
        (0x03, 16),
        (0x02, 4),
        (0x01, 1),
    ];
    for &(unit, multiplier) in &UNITS {
        if kbps.is_multiple_of(multiplier) {
            let value = kbps / multiplier;
            if value <= u64::from(u16::MAX) {
                return Some((unit, value as u16));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// EPS NAS Security Algorithms (§9.11.3.25)
// ---------------------------------------------------------------------------

// The EPS algorithm identifiers (EEA and EIA) are those of TS 24.301.
crate::common::ts24301::nas_security_algorithms_ie!(
    NasEpsNasSecurityAlgorithms,
    crate::common::ts24301::CipheringAlgorithm,
    crate::common::ts24301::IntegrityAlgorithm
);

// ---------------------------------------------------------------------------
// 5GS Network Feature Support (§9.11.3.5)
// ---------------------------------------------------------------------------

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// Emergency service support values.
pub enum EmergencyServiceSupport {
    /// Not supported.
    NotSupported = 0x00,
    /// Nr only.
    NrOnly = 0x01,
    /// Eutra only.
    EutraOnly = 0x02,
    /// Nr and eutra.
    NrAndEutra = 0x03,
}

impl EmergencyServiceSupport {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NotSupported),
            0x01 => Some(Self::NrOnly),
            0x02 => Some(Self::EutraOnly),
            0x03 => Some(Self::NrAndEutra),
            _ => None,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// Emergency fallback support values.
pub enum EmergencyFallbackSupport {
    /// Not supported.
    NotSupported = 0x00,
    /// Nr only.
    NrOnly = 0x01,
    /// Eutra only.
    EutraOnly = 0x02,
    /// Nr and eutra.
    NrAndEutra = 0x03,
}

impl EmergencyFallbackSupport {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NotSupported),
            0x01 => Some(Self::NrOnly),
            0x02 => Some(Self::EutraOnly),
            0x03 => Some(Self::NrAndEutra),
            _ => None,
        }
    }
}

/// Restriction on enhanced coverage support value carried in octet 4 of the IE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RestrictionOnEnhancedCoverage {
    /// Enhanced coverage is not restricted.
    NotRestricted = 0x00,
    /// Enhanced coverage is restricted.
    Restricted = 0x01,
    /// CE mode B is restricted.
    CeModeBRestricted = 0x02,
    /// Reserved value.
    Reserved = 0x03,
}

impl RestrictionOnEnhancedCoverage {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NotRestricted),
            0x01 => Some(Self::Restricted),
            0x02 => Some(Self::CeModeBRestricted),
            0x03 => Some(Self::Reserved),
            _ => None,
        }
    }
}

impl NasFGsNetworkFeatureSupport {
    /// IMS VoPS support (bit 1 of octet 1).
    pub fn ims_vops_3gpp(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// IMS VoPS support over non-3GPP (bit 2 of octet 1).
    pub fn ims_vops_n3gpp(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set IMS vops 3 gpp.
    pub fn set_ims_vops_3gpp(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 0, value);
        self.length = self.value.len() as _;
    }

    /// Set IMS vops 3 gpp and return the updated value.
    pub fn with_ims_vops_3gpp(mut self, value: bool) -> Self {
        self.set_ims_vops_3gpp(value);
        self
    }

    /// Set IMS vops n 3 gpp.
    pub fn set_ims_vops_n3gpp(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 1, value);
        self.length = self.value.len() as _;
    }

    /// Set IMS vops n 3 gpp and return the updated value.
    pub fn with_ims_vops_n3gpp(mut self, value: bool) -> Self {
        self.set_ims_vops_n3gpp(value);
        self
    }

    /// Emergency services support (bits 3-4 of octet 1).
    pub fn emc(&self) -> u8 {
        self.value.first().map(|b| (b >> 2) & 0x03).unwrap_or(0)
    }

    /// Emergency services support as a typed value.
    pub fn emc_value(&self) -> Option<EmergencyServiceSupport> {
        EmergencyServiceSupport::from_u8(self.emc())
    }

    /// Set emc.
    pub fn set_emc(&mut self, value: u8) {
        if self.value.is_empty() {
            self.value.resize(1, 0);
        }
        self.value[0] = (self.value[0] & !0x0C) | ((value & 0x03) << 2);
        self.length = self.value.len() as _;
    }

    /// Set emc and return the updated value.
    pub fn with_emc(mut self, value: u8) -> Self {
        self.set_emc(value);
        self
    }

    /// Set emc value.
    pub fn set_emc_value(&mut self, value: EmergencyServiceSupport) {
        self.set_emc(value as u8);
    }

    /// Set emc value and return the updated value.
    pub fn with_emc_value(mut self, value: EmergencyServiceSupport) -> Self {
        self.set_emc_value(value);
        self
    }

    /// Emergency services fallback (bits 5-6 of octet 1).
    pub fn emf(&self) -> u8 {
        self.value.first().map(|b| (b >> 4) & 0x03).unwrap_or(0)
    }

    /// Emergency services fallback support as a typed value.
    pub fn emf_value(&self) -> Option<EmergencyFallbackSupport> {
        EmergencyFallbackSupport::from_u8(self.emf())
    }

    /// Set emf.
    pub fn set_emf(&mut self, value: u8) {
        if self.value.is_empty() {
            self.value.resize(1, 0);
        }
        self.value[0] = (self.value[0] & !0x30) | ((value & 0x03) << 4);
        self.length = self.value.len() as _;
    }

    /// Set emf and return the updated value.
    pub fn with_emf(mut self, value: u8) -> Self {
        self.set_emf(value);
        self
    }

    /// Set emf value.
    pub fn set_emf_value(&mut self, value: EmergencyFallbackSupport) {
        self.set_emf(value as u8);
    }

    /// Set emf value and return the updated value.
    pub fn with_emf_value(mut self, value: EmergencyFallbackSupport) -> Self {
        self.set_emf_value(value);
        self
    }

    /// Interworking without N26 (bit 7 of octet 1).
    pub fn iwk_n26(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 6) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set iwk n 26.
    pub fn set_iwk_n26(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 6, value);
        self.length = self.value.len() as _;
    }

    /// Set iwk n 26 and return the updated value.
    pub fn with_iwk_n26(mut self, value: bool) -> Self {
        self.set_iwk_n26(value);
        self
    }

    /// Access identity 1 valid in the RPLMN or an equivalent PLMN (bit 8 of octet 1).
    pub fn mpsi(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 7) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set mpsi.
    pub fn set_mpsi(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 7, value);
        self.length = self.value.len() as _;
    }

    /// Set mpsi and return the updated value.
    pub fn with_mpsi(mut self, value: bool) -> Self {
        self.set_mpsi(value);
        self
    }

    /// MCS indicator (octet 4 bit 2 on wire; bit 2 of contents octet 2).
    pub fn mcsi(&self) -> bool {
        self.value
            .get(1)
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Return access identity 1 valid.
    pub fn access_identity_1_valid(&self) -> bool {
        self.mpsi()
    }

    /// Return access identity 2 valid.
    pub fn access_identity_2_valid(&self) -> bool {
        self.mcsi()
    }

    /// Emergency service support for non-3GPP access (octet 4 bit 1 on wire).
    pub fn emcn3(&self) -> bool {
        self.value.get(1).map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Set emcn 3.
    pub fn set_emcn3(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 0, value);
        self.length = self.value.len() as _;
    }

    /// Set emcn 3 and return the updated value.
    pub fn with_emcn3(mut self, value: bool) -> Self {
        self.set_emcn3(value);
        self
    }

    /// Set mcsi.
    pub fn set_mcsi(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 1, value);
        self.length = self.value.len() as _;
    }

    /// Set mcsi and return the updated value.
    pub fn with_mcsi(mut self, value: bool) -> Self {
        self.set_mcsi(value);
        self
    }

    /// Restriction on enhanced coverage support (bits 3-4 of octet 2).
    pub fn restrict_ec(&self) -> u8 {
        self.value.get(1).map(|b| (b >> 2) & 0x03).unwrap_or(0)
    }

    /// Return restrict ec value.
    pub fn restrict_ec_value(&self) -> Option<RestrictionOnEnhancedCoverage> {
        RestrictionOnEnhancedCoverage::from_u8(self.restrict_ec())
    }

    /// Set restrict ec.
    pub fn set_restrict_ec(&mut self, value: u8) {
        if self.value.len() < 2 {
            self.value.resize(2, 0);
        }
        self.value[1] = (self.value[1] & !0x0C) | ((value & 0x03) << 2);
        self.length = self.value.len() as _;
    }

    /// Set restrict ec and return the updated value.
    pub fn with_restrict_ec(mut self, value: u8) -> Self {
        self.set_restrict_ec(value);
        self
    }

    /// Set restrict ec value.
    pub fn set_restrict_ec_value(&mut self, value: RestrictionOnEnhancedCoverage) {
        self.set_restrict_ec(value as u8);
    }

    /// Set restrict ec value and return the updated value.
    pub fn with_restrict_ec_value(mut self, value: RestrictionOnEnhancedCoverage) -> Self {
        self.set_restrict_ec_value(value);
        self
    }

    /// 5G CP CIoT support (bit 5 of octet 2).
    pub fn cp_ciot(&self) -> bool {
        bit_at(&self.value, 1, 4)
    }

    /// Set cp CIoT.
    pub fn set_cp_ciot(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 4, value);
        self.length = self.value.len() as _;
    }

    /// Set cp CIoT and return the updated value.
    pub fn with_cp_ciot(mut self, value: bool) -> Self {
        self.set_cp_ciot(value);
        self
    }

    /// N3 data transfer support (octet 4 bit 6 on wire).
    ///
    /// The encoded bit is inverted by the spec: 0 means supported, 1 means not supported.
    pub fn n3_data(&self) -> bool {
        !self.n3_data_not_supported()
    }

    /// Raw N3-data encoded state: true means N3 data transfer is not supported.
    pub fn n3_data_not_supported(&self) -> bool {
        bit_at(&self.value, 1, 5)
    }

    /// Set n 3 data.
    pub fn set_n3_data(&mut self, supported: bool) {
        set_bit(&mut self.value, 1, 5, !supported);
        self.length = self.value.len() as _;
    }

    /// Set n 3 data not supported.
    pub fn set_n3_data_not_supported(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 5, value);
        self.length = self.value.len() as _;
    }

    /// Set n 3 data and return the updated value.
    pub fn with_n3_data(mut self, supported: bool) -> Self {
        self.set_n3_data(supported);
        self
    }

    /// Set n 3 data not supported and return the updated value.
    pub fn with_n3_data_not_supported(mut self, value: bool) -> Self {
        self.set_n3_data_not_supported(value);
        self
    }

    /// 5G IPHC CP CIoT support (bit 7 of octet 2).
    pub fn iphc_cp_ciot(&self) -> bool {
        bit_at(&self.value, 1, 6)
    }

    /// Set iphc cp CIoT.
    pub fn set_iphc_cp_ciot(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 6, value);
        self.length = self.value.len() as _;
    }

    /// Set iphc cp CIoT and return the updated value.
    pub fn with_iphc_cp_ciot(mut self, value: bool) -> Self {
        self.set_iphc_cp_ciot(value);
        self
    }

    /// 5G UP CIoT support (bit 8 of octet 2).
    pub fn up_ciot(&self) -> bool {
        bit_at(&self.value, 1, 7)
    }

    /// Set up CIoT.
    pub fn set_up_ciot(&mut self, value: bool) {
        set_bit(&mut self.value, 1, 7, value);
        self.length = self.value.len() as _;
    }

    /// Set up CIoT and return the updated value.
    pub fn with_up_ciot(mut self, value: bool) -> Self {
        self.set_up_ciot(value);
        self
    }

    /// 5G LCS support (bit 1 of octet 3).
    pub fn lcs_5g(&self) -> bool {
        bit_at(&self.value, 2, 0)
    }

    /// Set lcs 5 g.
    pub fn set_lcs_5g(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 0, value);
        self.length = self.value.len() as _;
    }

    /// Set lcs 5 g and return the updated value.
    pub fn with_lcs_5g(mut self, value: bool) -> Self {
        self.set_lcs_5g(value);
        self
    }

    /// ATS indication (bit 2 of octet 3).
    pub fn ats_ind(&self) -> bool {
        bit_at(&self.value, 2, 1)
    }

    /// Set ats ind.
    pub fn set_ats_ind(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 1, value);
        self.length = self.value.len() as _;
    }

    /// Set ats ind and return the updated value.
    pub fn with_ats_ind(mut self, value: bool) -> Self {
        self.set_ats_ind(value);
        self
    }

    /// 5G EHC CP CIoT support (bit 3 of octet 3).
    pub fn ehc_cp_ciot(&self) -> bool {
        bit_at(&self.value, 2, 2)
    }

    /// Set ehc cp CIoT.
    pub fn set_ehc_cp_ciot(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 2, value);
        self.length = self.value.len() as _;
    }

    /// Set ehc cp CIoT and return the updated value.
    pub fn with_ehc_cp_ciot(mut self, value: bool) -> Self {
        self.set_ehc_cp_ciot(value);
        self
    }

    /// NCR support (bit 4 of octet 3).
    pub fn ncr(&self) -> bool {
        bit_at(&self.value, 2, 3)
    }

    /// Set ncr.
    pub fn set_ncr(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 3, value);
        self.length = self.value.len() as _;
    }

    /// Set ncr and return the updated value.
    pub fn with_ncr(mut self, value: bool) -> Self {
        self.set_ncr(value);
        self
    }

    /// PIV support (bit 5 of octet 3).
    pub fn piv(&self) -> bool {
        bit_at(&self.value, 2, 4)
    }

    /// Set piv.
    pub fn set_piv(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 4, value);
        self.length = self.value.len() as _;
    }

    /// Set piv and return the updated value.
    pub fn with_piv(mut self, value: bool) -> Self {
        self.set_piv(value);
        self
    }

    /// RPR support (bit 6 of octet 3).
    pub fn rpr(&self) -> bool {
        bit_at(&self.value, 2, 5)
    }

    /// Set rpr.
    pub fn set_rpr(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 5, value);
        self.length = self.value.len() as _;
    }

    /// Set rpr and return the updated value.
    pub fn with_rpr(mut self, value: bool) -> Self {
        self.set_rpr(value);
        self
    }

    /// PR support (bit 7 of octet 3).
    pub fn pr(&self) -> bool {
        bit_at(&self.value, 2, 6)
    }

    /// Set pr.
    pub fn set_pr(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 6, value);
        self.length = self.value.len() as _;
    }

    /// Set pr and return the updated value.
    pub fn with_pr(mut self, value: bool) -> Self {
        self.set_pr(value);
        self
    }

    /// UN-PER support (bit 8 of octet 3).
    pub fn un_per(&self) -> bool {
        bit_at(&self.value, 2, 7)
    }

    /// Set un per.
    pub fn set_un_per(&mut self, value: bool) {
        set_bit(&mut self.value, 2, 7, value);
        self.length = self.value.len() as _;
    }

    /// Set un per and return the updated value.
    pub fn with_un_per(mut self, value: bool) -> Self {
        self.set_un_per(value);
        self
    }

    /// NAPS support (bit 1 of octet 4).
    pub fn naps(&self) -> bool {
        bit_at(&self.value, 3, 0)
    }

    /// Set naps.
    pub fn set_naps(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 0, value);
        self.length = self.value.len() as _;
    }

    /// Set naps and return the updated value.
    pub fn with_naps(mut self, value: bool) -> Self {
        self.set_naps(value);
        self
    }

    /// LCS UPP support (bit 2 of octet 4).
    pub fn lcs_upp(&self) -> bool {
        bit_at(&self.value, 3, 1)
    }

    /// Set lcs upp.
    pub fn set_lcs_upp(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 1, value);
        self.length = self.value.len() as _;
    }

    /// Set lcs upp and return the updated value.
    pub fn with_lcs_upp(mut self, value: bool) -> Self {
        self.set_lcs_upp(value);
        self
    }

    /// SUPL support (bit 3 of octet 4).
    pub fn supl(&self) -> bool {
        bit_at(&self.value, 3, 2)
    }

    /// Set supl.
    pub fn set_supl(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 2, value);
        self.length = self.value.len() as _;
    }

    /// Set supl and return the updated value.
    pub fn with_supl(mut self, value: bool) -> Self {
        self.set_supl(value);
        self
    }

    /// RSLP support (bit 4 of octet 4).
    pub fn rslp(&self) -> bool {
        bit_at(&self.value, 3, 3)
    }

    /// Set rslp.
    pub fn set_rslp(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 3, value);
        self.length = self.value.len() as _;
    }

    /// Set rslp and return the updated value.
    pub fn with_rslp(mut self, value: bool) -> Self {
        self.set_rslp(value);
        self
    }

    /// MLCSUP support (bit 5 of octet 4).
    pub fn mlcsup(&self) -> bool {
        bit_at(&self.value, 3, 4)
    }

    /// Set mlcsup.
    pub fn set_mlcsup(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 4, value);
        self.length = self.value.len() as _;
    }

    /// Set mlcsup and return the updated value.
    pub fn with_mlcsup(mut self, value: bool) -> Self {
        self.set_mlcsup(value);
        self
    }

    /// EF5L support (bit 6 of octet 4).
    pub fn ef5l(&self) -> bool {
        bit_at(&self.value, 3, 5)
    }

    /// Set ef 5 l.
    pub fn set_ef5l(&mut self, value: bool) {
        set_bit(&mut self.value, 3, 5, value);
        self.length = self.value.len() as _;
    }

    /// Set ef 5 l and return the updated value.
    pub fn with_ef5l(mut self, value: bool) -> Self {
        self.set_ef5l(value);
        self
    }

    /// Raw octet at the given 1-based index (per spec numbering: `octet(1)` is octet 3 on wire).
    /// Octet 4 onwards carry additional feature bits — callers can
    /// index into this raw view for feature bits not exposed as typed accessors.
    pub fn octet(&self, index: usize) -> u8 {
        if index == 0 {
            return 0;
        }
        self.value.get(index - 1).copied().unwrap_or(0)
    }

    /// All raw octets of the 5GS network feature support IE.
    pub fn octets(&self) -> &[u8] {
        &self.value
    }

    /// Build from individual feature flags (octet 1 + optional octet 2).
    #[allow(clippy::too_many_arguments)]
    pub fn from_features(
        ims_vops_3gpp: bool,
        ims_vops_n3gpp: bool,
        emc: u8,
        emf: u8,
        iwk_n26: bool,
        mpsi: bool,
        mcsi: bool,
        emcn3: bool,
    ) -> Self {
        let mut b0: u8 = 0;
        if ims_vops_3gpp {
            b0 |= 0x01;
        }
        if ims_vops_n3gpp {
            b0 |= 0x02;
        }
        b0 |= (emc & 0x03) << 2;
        b0 |= (emf & 0x03) << 4;
        if iwk_n26 {
            b0 |= 0x40;
        }
        if mpsi {
            b0 |= 0x80;
        }
        let mut b1: u8 = 0;
        if emcn3 {
            b1 |= 0x01;
        }
        if mcsi {
            b1 |= 0x02;
        }
        if b1 != 0 {
            Self::new(vec![b0, b1])
        } else {
            Self::new(vec![b0])
        }
    }
}

impl NasFGsNetworkFeatureSupport {
    /// Whether this IE has the sender-permitted one-to-four value octets.
    pub fn is_well_formed(&self) -> bool {
        (1..=4).contains(&self.value.len())
    }
}

impl Default for NasFGsNetworkFeatureSupport {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

// ---------------------------------------------------------------------------
// TV-1 half-byte types
// ---------------------------------------------------------------------------

impl NasAdditionalConfigurationIndication {
    /// SCMR (bit 1): release of N1 NAS signalling connection not required.
    pub fn scmr(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build from SCMR flag.
    pub fn from_scmr(scmr: bool) -> Self {
        Self::new(if scmr { 0x01 } else { 0x00 })
    }
}

impl NasAllowedSscMode {
    /// SSC mode 1 allowed (bit 1).
    pub fn ssc1(&self) -> bool {
        self.value & 0x01 != 0
    }
    /// SSC mode 2 allowed (bit 2).
    pub fn ssc2(&self) -> bool {
        (self.value >> 1) & 0x01 != 0
    }
    /// SSC mode 3 allowed (bit 3).
    pub fn ssc3(&self) -> bool {
        (self.value >> 2) & 0x01 != 0
    }

    /// Build from SSC mode flags.
    pub fn from_modes(ssc1: bool, ssc2: bool, ssc3: bool) -> Self {
        let mut v: u8 = 0;
        if ssc1 {
            v |= 0x01;
        }
        if ssc2 {
            v |= 0x02;
        }
        if ssc3 {
            v |= 0x04;
        }
        Self::new(v)
    }
}

impl NasAlwaysOnPduSessionIndication {
    /// APSI: Always-on PDU session indication value (bit 1).
    pub fn apsi(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from apsi.
    pub fn from_apsi(apsi: bool) -> Self {
        Self::new(if apsi { 0x01 } else { 0x00 })
    }
}

impl NasAlwaysOnPduSessionRequested {
    /// APSR: Always-on PDU session requested (bit 1).
    pub fn apsr(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from apsr.
    pub fn from_apsr(apsr: bool) -> Self {
        Self::new(if apsr { 0x01 } else { 0x00 })
    }
}

impl NasConfigurationUpdateIndication {
    /// ACK: Acknowledgement requested (bit 1).
    pub fn ack(&self) -> bool {
        self.value & 0x01 != 0
    }
    /// RED: Registration requested (bit 2).
    pub fn red(&self) -> bool {
        (self.value >> 1) & 0x01 != 0
    }

    /// Construct a value from flags.
    pub fn from_flags(ack: bool, red: bool) -> Self {
        let mut v: u8 = 0;
        if ack {
            v |= 0x01;
        }
        if red {
            v |= 0x02;
        }
        Self::new(v)
    }
}

/// Control plane service type per TS 24.501 §9.11.3.18D.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ControlPlaneServiceTypeValue {
    /// Mobile originating request.
    MobileOriginatingRequest = 0x00,
    /// Mobile terminating request.
    MobileTerminatingRequest = 0x01,
    /// Emergency services.
    EmergencyServices = 0x02,
    /// Emergency services fallback.
    EmergencyServicesFallback = 0x03,
}

impl ControlPlaneServiceTypeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::MobileOriginatingRequest),
            0x01 => Some(Self::MobileTerminatingRequest),
            0x02 => Some(Self::EmergencyServices),
            0x03 => Some(Self::EmergencyServicesFallback),
            _ => Some(Self::MobileOriginatingRequest),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::MobileOriginatingRequest),
            0x01 => Some(Self::MobileTerminatingRequest),
            0x02 => Some(Self::EmergencyServices),
            0x03 => Some(Self::EmergencyServicesFallback),
            _ => None,
        }
    }
}

impl Default for NasControlPlaneServiceType {
    /// Default for the packed Control Plane Service Request octet:
    /// mobile-originating request, ngKSI = 7 (no key), native context.
    fn default() -> Self {
        Self::new(0x70 | (ControlPlaneServiceTypeValue::MobileOriginatingRequest as u8))
    }
}

impl NasControlPlaneServiceType {
    /// Build a standalone-clean control plane service type value with unrelated
    /// packed ngKSI/TSC bits cleared.
    pub fn from_service_type(service_type: ControlPlaneServiceTypeValue) -> Self {
        Self::new(service_type as u8 & 0x07)
    }

    /// Control plane service type (lower nibble bits 1-3, mask 0x07).
    pub fn service_type(&self) -> Option<ControlPlaneServiceTypeValue> {
        ControlPlaneServiceTypeValue::from_u8(self.value & 0x07)
    }

    /// Raw control plane service type value (lower nibble bits 1-3).
    pub fn service_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the control plane service type. Returns `self` for chaining.
    pub fn with_service_type(mut self, service_type: ControlPlaneServiceTypeValue) -> Self {
        self.value = (self.value & 0xF8) | (service_type as u8 & 0x07);
        self
    }

    /// Mutating setter for the control plane service type.
    pub fn set_service_type(&mut self, service_type: ControlPlaneServiceTypeValue) {
        self.value = (self.value & 0xF8) | (service_type as u8 & 0x07);
    }

    /// ngKSI value (upper nibble bits 1-3, mask 0x70).
    pub fn ngksi(&self) -> u8 {
        (self.value >> 4) & 0x07
    }

    /// Set ngKSI. Returns `self` for chaining.
    pub fn with_ngksi(mut self, ngksi: u8) -> Self {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
        self
    }

    /// Mutating setter for ngKSI.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        self.value = (self.value & 0x8F) | ((ngksi & 0x07) << 4);
    }

    /// TSC flag (upper nibble bit 4, mask 0x80): false = native, true = mapped.
    pub fn tsc(&self) -> bool {
        (self.value >> 7) & 1 != 0
    }

    /// Set TSC. Returns `self` for chaining.
    pub fn with_tsc(mut self, tsc: bool) -> Self {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
        self
    }

    /// Mutating setter for TSC.
    pub fn set_tsc(&mut self, tsc: bool) {
        if tsc {
            self.value |= 0x80;
        } else {
            self.value &= !0x80;
        }
    }
}

impl NasControlPlaneOnlyIndication {
    /// CPOI: Control plane only indication (bit 1).
    pub fn cpoi(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// EPS-compatible semantic alias for [`Self::cpoi`].
    pub fn is_control_plane_only(&self) -> bool {
        self.cpoi()
    }

    /// Build the only defined sending value.
    pub fn control_plane_only() -> Self {
        Self::new(0x01)
    }

    /// Fallible form of [`Self::from_cpoi`]; `false` means the IE must be
    /// omitted and therefore returns `None`.
    pub fn try_from_cpoi(cpoi: bool) -> Option<Self> {
        cpoi.then(Self::control_plane_only)
    }

    /// Build from the indication value retained by the 0.2 API.
    ///
    /// # Panics
    ///
    /// Panics when `cpoi` is false because zero is reserved on the wire; use
    /// [`Self::try_from_cpoi`] for a fallible builder.
    pub fn from_cpoi(cpoi: bool) -> Self {
        Self::try_from_cpoi(cpoi)
            .expect("CPOI value 0 is reserved; omit the IE instead of building it")
    }

    /// Sender check: CPOI is present only with the defined value one.
    pub fn is_well_formed(&self) -> bool {
        self.value == 0x01
    }
}

pub use crate::common::ts24008::ImeisvRequestValue;
crate::common::ts24008::access_point_name_ie!(NasDnn);
crate::common::ts24008::plmn_list_ie!(NasPlmnList);
pub use crate::common::ts24008::{
    DaylightSavingAdjustment, EmergencyNumber, NetworkNameCodingScheme,
};
crate::common::ts24008::network_name_ie!(NasNetworkName);
crate::common::ts24008::time_zone_ie!(NasTimeZone);
crate::common::ts24008::time_zone_and_time_ie!(NasTimeZoneAndTime);
crate::common::ts24008::daylight_saving_time_ie!(NasDaylightSavingTime);
crate::common::ts24008::emergency_number_list_ie!(NasEmergencyNumberList);
pub use crate::common::ts24301::ExtendedEmergencyNumber;
crate::common::ts24301::extended_emergency_number_list_ie!(NasExtendedEmergencyNumberList);
pub use crate::common::ts24008::EutraMode;
crate::common::ts24008::extended_drx_parameters_ie!(NasExtendedDrxParameters);
crate::common::ts24008::supported_codec_list_ie!(NasSupportedCodecList);
nas_opaque_ie!(NasSupportedCodecList, "24.501", "9.11.3.51A");
pub use crate::common::ts24301::{UePagingProbability, UeRequestType};
crate::common::ts24301::wus_assistance_information_ie!(NasWusAssistanceInformation);
nas_opaque_ie!(NasWusAssistanceInformation, "24.501", "9.11.3.71");
crate::common::ts24301::ue_request_type_ie!(NasUeRequestType);
nas_opaque_ie!(NasUeRequestType, "24.501", "9.11.3.76");
crate::common::ts24301::unavailability_information_ie!(NasUnavailabilityInformation);
nas_opaque_ie!(NasUnavailabilityInformation, "24.501", "9.11.2.20");
crate::common::ts24301::unavailability_configuration_ie!(NasUnavailabilityConfiguration);
nas_opaque_ie!(NasUnavailabilityConfiguration, "24.501", "9.11.2.21");
crate::common::ts24301::access_technology_utilization_control_ie!(
    NasAccessTechnologyUtilizationControl
);
nas_opaque_ie!(
    NasAccessTechnologyUtilizationControl,
    "24.501",
    "9.11.3.110"
);
pub use crate::common::ts24501::RadioCapabilityIdDeletionRequest;
crate::common::ts24501::ue_radio_capability_id_ie!(NasUeRadioCapabilityId);
nas_opaque_ie!(NasUeRadioCapabilityId, "24.501", "9.11.3.68");
crate::common::ts24501::ue_radio_capability_id_deletion_indication_ie!(
    NasUeRadioCapabilityIdDeletionIndication
);
crate::common::ts24501::plmn_identity_ie!(NasPlmnIdentity);
crate::common::ts24501::registration_wait_range_ie!(NasRegistrationWaitRange);

impl NasRegistrationWaitRange {
    /// Minimum registration wait time as a GPRS timer.
    pub fn min_timer(&self) -> Option<NasGprsTimer> {
        self.value.first().copied().map(NasGprsTimer::new)
    }

    /// Maximum registration wait time as a GPRS timer.
    pub fn max_timer(&self) -> Option<NasGprsTimer> {
        self.value.get(1).copied().map(NasGprsTimer::new)
    }

    /// Build from minimum and maximum GPRS timers.
    pub fn from_timers(min_timer: NasGprsTimer, max_timer: NasGprsTimer) -> Self {
        Self::new(vec![min_timer.value, max_timer.value])
    }
}
crate::common::ts24501::disaster_plmn_list_ie!(NasListOfPlmnsToBeUsedInDisasterCondition);
nas_opaque_ie!(
    NasListOfPlmnsToBeUsedInDisasterCondition,
    "24.501",
    "9.11.3.83"
);
pub use crate::common::ts24008::{Pco, PcoDirection, PcoEntry};
crate::common::ts24008::extended_protocol_configuration_options_ie!(
    NasExtendedProtocolConfigurationOptions
);
crate::common::ts24301::eps_bearer_context_status_ie!(NasEpsBearerContextStatus);
crate::common::ts24301::serving_plmn_rate_control_ie!(NasServingPlmnRateControl);
pub use crate::common::ts24301::DownlinkDataExpected;
crate::common::ts24301::release_assistance_indication_ie!(NasReleaseAssistanceIndication);
pub use crate::common::ts24301::{IpHdrCompAdditionalSetupType, IpHdrCompProfiles};
crate::common::ts24301::header_compression_configuration_ie!(NasIpHeaderCompressionConfiguration);

crate::common::ts24008::imeisv_request_ie!(NasImeisvRequest);

/// MA PDU session information value per TS 24.501 §9.11.3.31A.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MaPduSessionInfoValue {
    /// No additional information.
    NoAdditionalInformation = 0x00,
    /// MA PDU session network upgrade is allowed.
    NetworkUpgradeAllowed = 0x01,
}

impl MaPduSessionInfoValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::NoAdditionalInformation),
            0x01 => Some(Self::NetworkUpgradeAllowed),
            _ => None,
        }
    }
}

impl NasMaPduSessionInformation {
    /// Typed MA PDU session information value (bits 1-4).
    pub fn info(&self) -> Option<MaPduSessionInfoValue> {
        MaPduSessionInfoValue::from_u8(self.value & 0x0F)
    }

    /// Raw MA PDU session information value (bits 1-4).
    pub fn info_raw(&self) -> u8 {
        self.value & 0x0F
    }

    /// Set the typed MA PDU session information while preserving spare bits.
    pub fn with_info(mut self, info: MaPduSessionInfoValue) -> Self {
        self.set_info(info);
        self
    }

    /// Mutating setter for the typed MA PDU session information.
    pub fn set_info(&mut self, info: MaPduSessionInfoValue) -> &mut Self {
        self.value = (self.value & !0x0F) | (info as u8 & 0x0F);
        self
    }

    /// Construct a value from info.
    pub fn from_info(info: MaPduSessionInfoValue) -> Self {
        Self::new(info as u8)
    }
}

impl NasMicoIndication {
    /// RAAI: Registration Area Allocation Indication (bit 1).
    pub fn raai(&self) -> bool {
        self.value & 0x01 != 0
    }
    /// SPRTI: MICO mode (bit 2).
    pub fn sprti(&self) -> bool {
        (self.value >> 1) & 0x01 != 0
    }

    /// Construct a value from flags.
    pub fn from_flags(raai: bool, sprti: bool) -> Self {
        let mut v: u8 = 0;
        if raai {
            v |= 0x01;
        }
        if sprti {
            v |= 0x02;
        }
        Self::new(v)
    }
}

impl NasN5gcIndication {
    /// N5GC indication (bit 1).
    pub fn n5gc(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from n 5 gc.
    pub fn from_n5gc(n5gc: bool) -> Self {
        Self::new(if n5gc { 0x01 } else { 0x00 })
    }
}

impl NasNetworkSlicingIndication {
    /// NSSCI: Network slicing subscription change indication (bit 1).
    pub fn nssci(&self) -> bool {
        self.value & 0x01 != 0
    }
    /// DCNI: Default configured NSSAI indication (bit 2).
    pub fn dcni(&self) -> bool {
        (self.value >> 1) & 0x01 != 0
    }

    /// Construct a value from flags.
    pub fn from_flags(nssci: bool, dcni: bool) -> Self {
        let mut v: u8 = 0;
        if nssci {
            v |= 0x01;
        }
        if dcni {
            v |= 0x02;
        }
        Self::new(v)
    }
}

crate::common::ts24008::non_3gpp_nw_provided_policies_ie!(NasNon3GppNwProvidedPolicies);

impl NasNssaiInclusionMode {
    /// NSSAI inclusion mode (bits 1-2).
    pub fn mode(&self) -> NssaiInclusionModeValue {
        NssaiInclusionModeValue::from_u8(self.value & 0x03)
    }

    /// Set the typed NSSAI inclusion mode while preserving spare bits.
    pub fn with_mode(mut self, mode: NssaiInclusionModeValue) -> Self {
        self.set_mode(mode);
        self
    }

    /// Mutating setter for the typed NSSAI inclusion mode.
    pub fn set_mode(&mut self, mode: NssaiInclusionModeValue) -> &mut Self {
        self.value = (self.value & !0x03) | (mode as u8 & 0x03);
        self
    }

    /// Construct a value from mode.
    pub fn from_mode(mode: NssaiInclusionModeValue) -> Self {
        Self::new(mode as u8)
    }
}

impl NasPriorityIndicator {
    /// MPSI, access identity 1 valid (bit 1).
    pub fn mpsi(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// MCSI, access identity 2 valid (bit 2).
    pub fn mcsi(&self) -> bool {
        (self.value >> 1) & 0x01 != 0
    }

    /// Return access identity 1 valid.
    pub fn access_identity_1_valid(&self) -> bool {
        self.mpsi()
    }

    /// Return access identity 2 valid.
    pub fn access_identity_2_valid(&self) -> bool {
        self.mcsi()
    }

    /// Construct from typed flags. Both bits live in the same nibble.
    pub fn from_flags(mpsi: bool, mcsi: bool) -> Self {
        Self::new((mpsi as u8) | ((mcsi as u8) << 1))
    }
}

impl NasRequestType {
    /// Request type value (bits 1-3).
    pub fn request_type(&self) -> Option<RequestTypeValue> {
        RequestTypeValue::from_u8(self.value & 0x07)
    }

    /// Raw request type value (bits 1-3).
    pub fn request_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Whether this is an initial request (value = 1).
    pub fn is_initial(&self) -> bool {
        self.request_type() == Some(RequestTypeValue::InitialRequest)
    }

    /// Whether this is an existing PDU session (value = 2).
    pub fn is_existing(&self) -> bool {
        self.request_type() == Some(RequestTypeValue::ExistingPduSession)
    }

    /// Whether this is an emergency request (value = 3 or 4).
    pub fn is_emergency(&self) -> bool {
        matches!(
            self.request_type(),
            Some(
                RequestTypeValue::InitialEmergencyRequest
                    | RequestTypeValue::ExistingEmergencyPduSession
            )
        )
    }

    /// Set the typed request type and clear the spare TV-1 bit.
    pub fn with_request_type(mut self, request_type: RequestTypeValue) -> Self {
        self.set_request_type(request_type);
        self
    }

    /// Mutating setter for the typed request type.
    pub fn set_request_type(&mut self, request_type: RequestTypeValue) -> &mut Self {
        self.value = request_type as u8 & 0x07;
        self
    }

    /// Construct a value from request type.
    pub fn from_request_type(rt: RequestTypeValue) -> Self {
        Self::new(rt as u8)
    }

    /// Whether this is a defined sender code with the spare bit cleared.
    pub fn is_well_formed(&self) -> bool {
        self.value & !0x07 == 0 && RequestTypeValue::from_u8_strict(self.value).is_some()
    }
}

impl NasSmsIndication {
    /// SAI: SMS availability indication (bit 1).
    pub fn sai(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from sai.
    pub fn from_sai(sai: bool) -> Self {
        Self::new(if sai { 0x01 } else { 0x00 })
    }
}

impl NasSscMode {
    /// SSC mode value (bits 1-3).
    pub fn mode(&self) -> Option<SscModeValue> {
        SscModeValue::from_u8(self.value & 0x07)
    }

    /// Raw SSC mode value (bits 1-3).
    pub fn mode_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the typed SSC mode and clear the spare TV-1 bit.
    pub fn with_mode(mut self, mode: SscModeValue) -> Self {
        self.set_mode(mode);
        self
    }

    /// Mutating setter for the typed SSC mode.
    pub fn set_mode(&mut self, mode: SscModeValue) -> &mut Self {
        self.value = mode as u8 & 0x07;
        self
    }

    /// Construct a value from mode.
    pub fn from_mode(mode: SscModeValue) -> Self {
        Self::new(mode as u8)
    }

    /// Whether this value uses a defined sender code with the spare bit cleared.
    pub fn is_well_formed(&self) -> bool {
        self.value & !0x07 == 0 && SscModeValue::from_u8_strict(self.value).is_some()
    }
}

// ---------------------------------------------------------------------------
// TV types (1-byte value)
// ---------------------------------------------------------------------------

impl NasPduSessionIdentity2 {
    /// PDU session ID value.
    pub fn pdu_session_id(&self) -> u8 {
        self.value
    }

    /// Construct a value from PDU session identifier.
    pub fn from_pdu_session_id(id: u8) -> Self {
        Self::new(id)
    }
}

// ---------------------------------------------------------------------------
// TV-fixed types (multi-byte value)
// ---------------------------------------------------------------------------

crate::common::ts24008::authentication_parameter_rand_ie!(NasAuthenticationParameterRand);

impl Default for NasTimeZoneAndTime {
    /// Default: all-zero 7-byte payload (year=0, month=0, ... tz=0).
    fn default() -> Self {
        Self::new(vec![0u8; 7])
    }
}

// ---------------------------------------------------------------------------
// V types
// ---------------------------------------------------------------------------

impl NasIntegrityProtectionMaximumDataRate {
    /// Maximum data rate for UL.
    pub fn ul(&self) -> Option<MaxDataRate> {
        MaxDataRate::from_u8((self.value >> 8) as u8)
    }
    /// Maximum data rate for DL.
    pub fn dl(&self) -> Option<MaxDataRate> {
        MaxDataRate::from_u8((self.value & 0xFF) as u8)
    }
    /// Raw UL byte.
    pub fn ul_raw(&self) -> u8 {
        (self.value >> 8) as u8
    }
    /// Raw DL byte.
    pub fn dl_raw(&self) -> u8 {
        (self.value & 0xFF) as u8
    }

    /// Build from typed rates per TS 24.501 §9.11.4.7. Octet 3 is UL, octet 4 is DL.
    pub fn from_rates(ul: MaxDataRate, dl: MaxDataRate) -> Self {
        Self::new(((ul as u16) << 8) | (dl as u16))
    }

    /// Whether both direction octets use sender-defined rate codes.
    pub fn is_well_formed(&self) -> bool {
        MaxDataRate::from_u8_strict(self.ul_raw()).is_some()
            && MaxDataRate::from_u8_strict(self.dl_raw()).is_some()
    }
}

impl NasMaximumNumberOfSupportedPacketFilters {
    /// Maximum number of supported packet filters (11 bits from bytes 0-1).
    pub fn max_filters(&self) -> u16 {
        if self.value.len() < 2 {
            return 0;
        }
        (((self.value[0] as u16) << 3) | ((self.value[1] as u16) >> 5)) & 0x7FF
    }

    /// Construct a value from the specified maximum.
    ///
    /// TS 24.501 §9.11.4.9 permits values from 17 through 1024.
    pub fn try_from_max_filters(n: u16) -> Option<Self> {
        (17..=1024).contains(&n).then(|| {
            let b0 = (n >> 3) as u8;
            let b1 = ((n & 0x07) << 5) as u8;
            Self::new(vec![b0, b1])
        })
    }

    /// Construct a value from the specified maximum.
    ///
    /// # Panics
    ///
    /// Panics unless `n` is in the TS 24.501 range 17 through 1024. Use
    /// [`Self::try_from_max_filters`] for a fallible builder.
    pub fn from_max_filters(n: u16) -> Self {
        Self::try_from_max_filters(n)
            .expect("maximum number of supported packet filters must be in 17..=1024")
    }

    /// Whether spare bits 1-5 of octet 4 are zero.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value.get(1).copied().unwrap_or(0) & 0x1F == 0
    }

    /// Strict fixed-length/spare-bit validation for TS 24.501 §9.11.4.9.
    pub fn validate_strict(&self) -> Result<()> {
        if self.value.len() != 2 {
            return Err(NasError::DecodingError(
                "Maximum number of supported packet filters must be exactly 2 octets".into(),
            ));
        }
        if !self.spare_bits_are_zero() {
            return Err(NasError::DecodingError(
                "Maximum number of supported packet filters spare bits shall be zero".into(),
            ));
        }
        if !(17..=1024).contains(&self.max_filters()) {
            return Err(NasError::DecodingError(
                "Maximum number of supported packet filters must be in 17..=1024".into(),
            ));
        }
        Ok(())
    }

    /// Whether the sender encoding meets TS 24.501 §9.11.4.9.
    pub fn is_well_formed(&self) -> bool {
        self.validate_strict().is_ok()
    }
}

// ---------------------------------------------------------------------------
// LV types
// ---------------------------------------------------------------------------

impl NasAbba {
    /// The raw ABBA value bytes.
    pub fn abba(&self) -> &[u8] {
        &self.value
    }

    /// Build from ABBA bytes (typically [0x00, 0x00] for 5G standalone).
    pub fn from_bytes(abba: &[u8]) -> Self {
        Self::new(abba.to_vec())
    }
}

// ---------------------------------------------------------------------------
// TLV types — commonly used
// ---------------------------------------------------------------------------

impl NasAdditional5gSecurityInformation {
    /// RINMR: Retransmission of initial NAS message request (bit 2).
    pub fn rinmr(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }
    /// HDP: Horizontal derivation parameter (bit 1).
    pub fn hdp(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from flags.
    pub fn from_flags(rinmr: bool, hdp: bool) -> Self {
        let mut v: u8 = 0;
        if rinmr {
            v |= 0x02;
        }
        if hdp {
            v |= 0x01;
        }
        Self::new(vec![v])
    }
}

impl NasIntraN1ModeNasTransparentContainer {
    fn ensure_value_len(&mut self) -> &mut [u8] {
        self.value.resize(7, 0);
        self.length = 7;
        &mut self.value
    }

    /// Message authentication code (octets 3-6) per TS 24.501 §9.11.2.6 / Table 9.11.2.6.1.
    pub fn message_authentication_code(&self) -> Option<u32> {
        Some(u32::from_be_bytes(copy_array::<4>(self.value.get(0..4)?)?))
    }

    /// Security algorithms (octet 7).
    pub fn security_algorithms(&self) -> Option<NasSecurityAlgorithms> {
        self.value.get(4).copied().map(NasSecurityAlgorithms::new)
    }

    /// K_AMF change flag (octet 8, bit 5).
    pub fn k_amf_change_flag(&self) -> Option<bool> {
        self.value.get(5).map(|octet| octet & 0x10 != 0)
    }

    /// NAS key set identifier and TSC flag (octet 8, bits 1-4).
    pub fn key_set_identifier(&self) -> Option<NasKeySetIdentifier> {
        self.value
            .get(5)
            .map(|octet| NasKeySetIdentifier::new(octet & 0x0F))
    }

    /// Sequence number (octet 9).
    pub fn sequence_number(&self) -> Option<u8> {
        self.value.get(6).copied()
    }

    /// Set the message authentication code.
    pub fn with_message_authentication_code(mut self, mac: u32) -> Self {
        self.set_message_authentication_code(mac);
        self
    }

    /// Mutating setter for the message authentication code.
    pub fn set_message_authentication_code(&mut self, mac: u32) -> &mut Self {
        self.ensure_value_len()[0..4].copy_from_slice(&mac.to_be_bytes());
        self
    }

    /// Set the security algorithms octet.
    pub fn with_security_algorithms(mut self, algorithms: NasSecurityAlgorithms) -> Self {
        self.set_security_algorithms(algorithms);
        self
    }

    /// Mutating setter for the security algorithms octet.
    pub fn set_security_algorithms(&mut self, algorithms: NasSecurityAlgorithms) -> &mut Self {
        self.ensure_value_len()[4] = algorithms.value;
        self
    }

    /// Set the K_AMF change flag while preserving the key set identifier bits.
    pub fn with_k_amf_change_flag(mut self, k_amf_change_flag: bool) -> Self {
        self.set_k_amf_change_flag(k_amf_change_flag);
        self
    }

    /// Mutating setter for the K_AMF change flag.
    pub fn set_k_amf_change_flag(&mut self, k_amf_change_flag: bool) -> &mut Self {
        let octet = &mut self.ensure_value_len()[5];
        *octet = (*octet & 0x0F) | if k_amf_change_flag { 0x10 } else { 0x00 };
        self
    }

    /// Set the key set identifier while preserving the K_AMF change flag.
    pub fn with_key_set_identifier(mut self, key_set_identifier: NasKeySetIdentifier) -> Self {
        self.set_key_set_identifier(key_set_identifier);
        self
    }

    /// Mutating setter for the key set identifier while preserving the K_AMF change flag.
    pub fn set_key_set_identifier(&mut self, key_set_identifier: NasKeySetIdentifier) -> &mut Self {
        let octet = &mut self.ensure_value_len()[5];
        *octet = (*octet & 0x10) | (key_set_identifier.value & 0x0F);
        self
    }

    /// Set the sequence number.
    pub fn with_sequence_number(mut self, sequence_number: u8) -> Self {
        self.set_sequence_number(sequence_number);
        self
    }

    /// Mutating setter for the sequence number.
    pub fn set_sequence_number(&mut self, sequence_number: u8) -> &mut Self {
        self.ensure_value_len()[6] = sequence_number;
        self
    }

    /// Build the IE from typed fields.
    pub fn from_fields(
        message_authentication_code: u32,
        security_algorithms: NasSecurityAlgorithms,
        k_amf_change_flag: bool,
        key_set_identifier: NasKeySetIdentifier,
        sequence_number: u8,
    ) -> Self {
        let mut ie = Self::new(vec![0; 7]);
        ie.set_message_authentication_code(message_authentication_code)
            .set_security_algorithms(security_algorithms)
            .set_k_amf_change_flag(k_amf_change_flag)
            .set_key_set_identifier(key_set_identifier)
            .set_sequence_number(sequence_number);
        ie
    }
}

impl NasS1ModeToN1ModeNasTransparentContainer {
    fn ensure_value_len(&mut self) -> &mut [u8] {
        self.value.resize(8, 0);
        self.length = 8;
        &mut self.value
    }

    /// Message authentication code (octets 3-6) per TS 24.501 §9.11.2.9 / Table 9.11.2.9.1.
    pub fn message_authentication_code(&self) -> Option<u32> {
        Some(u32::from_be_bytes(copy_array::<4>(self.value.get(0..4)?)?))
    }

    /// Security algorithms (octet 7).
    pub fn security_algorithms(&self) -> Option<NasSecurityAlgorithms> {
        self.value.get(4).copied().map(NasSecurityAlgorithms::new)
    }

    /// Next hop chaining counter (octet 8, bits 5-7).
    pub fn ncc(&self) -> Option<u8> {
        self.value.get(5).map(|octet| (octet >> 4) & 0x07)
    }

    /// NAS key set identifier and TSC flag (octet 8, bits 1-4).
    pub fn key_set_identifier(&self) -> Option<NasKeySetIdentifier> {
        self.value
            .get(5)
            .map(|octet| NasKeySetIdentifier::new(octet & 0x0F))
    }

    /// Whether octets 9 and 10 are zero as required by TS 24.501 §9.11.2.9.
    pub fn spare_octets_are_zero(&self) -> bool {
        self.value.get(6).copied().unwrap_or(0) == 0 && self.value.get(7).copied().unwrap_or(0) == 0
    }

    /// Set the message authentication code.
    pub fn with_message_authentication_code(mut self, mac: u32) -> Self {
        self.set_message_authentication_code(mac);
        self
    }

    /// Mutating setter for the message authentication code.
    pub fn set_message_authentication_code(&mut self, mac: u32) -> &mut Self {
        self.ensure_value_len()[0..4].copy_from_slice(&mac.to_be_bytes());
        self
    }

    /// Set the security algorithms octet.
    pub fn with_security_algorithms(mut self, algorithms: NasSecurityAlgorithms) -> Self {
        self.set_security_algorithms(algorithms);
        self
    }

    /// Mutating setter for the security algorithms octet.
    pub fn set_security_algorithms(&mut self, algorithms: NasSecurityAlgorithms) -> &mut Self {
        self.ensure_value_len()[4] = algorithms.value;
        self
    }

    /// Set the NCC while preserving the key set identifier bits.
    pub fn with_ncc(mut self, ncc: u8) -> Self {
        self.set_ncc(ncc);
        self
    }

    /// Mutating setter for the NCC while preserving the key set identifier bits.
    pub fn set_ncc(&mut self, ncc: u8) -> &mut Self {
        assert!(ncc <= 7, "next-hop chaining counter must be in 0..=7");
        let octet = &mut self.ensure_value_len()[5];
        *octet = (*octet & 0x0F) | (ncc << 4);
        self
    }

    /// Set the key set identifier while preserving the NCC bits.
    pub fn with_key_set_identifier(mut self, key_set_identifier: NasKeySetIdentifier) -> Self {
        self.set_key_set_identifier(key_set_identifier);
        self
    }

    /// Mutating setter for the key set identifier while preserving the NCC bits.
    pub fn set_key_set_identifier(&mut self, key_set_identifier: NasKeySetIdentifier) -> &mut Self {
        let octet = &mut self.ensure_value_len()[5];
        *octet = (*octet & 0x70) | (key_set_identifier.value & 0x0F);
        self
    }

    /// Force octets 9 and 10 to zero.
    pub fn with_zeroed_spare_octets(mut self) -> Self {
        self.set_zeroed_spare_octets();
        self
    }

    /// Mutating helper to force octets 9 and 10 to zero.
    pub fn set_zeroed_spare_octets(&mut self) -> &mut Self {
        let value = self.ensure_value_len();
        value[6] = 0;
        value[7] = 0;
        self
    }

    /// Build the IE from typed fields, zeroing the spare octets.
    pub fn from_fields(
        message_authentication_code: u32,
        security_algorithms: NasSecurityAlgorithms,
        ncc: u8,
        key_set_identifier: NasKeySetIdentifier,
    ) -> Self {
        let mut ie = Self::new(vec![0; 8]);
        ie.set_message_authentication_code(message_authentication_code)
            .set_security_algorithms(security_algorithms)
            .set_ncc(ncc)
            .set_key_set_identifier(key_set_identifier)
            .set_zeroed_spare_octets();
        ie
    }
}

impl NasTimeDuration {
    /// Time duration in seconds per TS 24.501 §9.11.2.19 / TS 24.301 §9.9.3.68.
    pub fn seconds(&self) -> Option<u32> {
        crate::common::ts24301::read_time_duration(&self.value)
    }

    /// Set the time duration in seconds.
    pub fn with_seconds(mut self, seconds: u32) -> Option<Self> {
        self.set_seconds(seconds)?;
        Some(self)
    }

    /// Mutating setter for the time duration in seconds.
    pub fn set_seconds(&mut self, seconds: u32) -> Option<&mut Self> {
        if seconds > 0x00FF_FFFF {
            return None;
        }
        self.value = seconds.to_be_bytes()[1..].to_vec();
        self.length = 3;
        Some(self)
    }

    /// Build the IE from a time duration in seconds.
    pub fn from_seconds(seconds: u32) -> Option<Self> {
        if seconds > 0x00FF_FFFF {
            return None;
        }
        Some(Self::new(seconds.to_be_bytes()[1..].to_vec()))
    }
}

impl Default for NasExtendedDrxParameters {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

/// Helper: read bit `bit` (0..=7, 0=LSB/mask 0x01) from byte at index `idx` of `bytes`.
#[inline]
fn bit_at(bytes: &[u8], idx: usize, bit: u8) -> bool {
    bytes
        .get(idx)
        .map(|b| (b >> bit) & 0x01 != 0)
        .unwrap_or(false)
}

/// Helper: ensure `bytes` is at least `len + 1` bytes (pads with zeros), then set bit.
#[inline]
fn set_bit(bytes: &mut Vec<u8>, idx: usize, bit: u8, value: bool) {
    if bytes.len() <= idx {
        bytes.resize(idx + 1, 0);
    }
    if value {
        bytes[idx] |= 1 << bit;
    } else {
        bytes[idx] &= !(1 << bit);
    }
}

const FGMM_CAPABILITY_MAX_CONTENT_OCTETS: usize = 13;
const FGMM_CAPABILITY_SPARE_ONLY_START_INDEX: usize = 10;

impl NasFGmmCapability {
    // ──────────────────────────────────────────────────────────────────
    // Octet 3 on the wire (index 0 in `value`) — TS 24.501 §9.11.3.1
    // Bit 8 = MSB (mask 0x80), Bit 1 = LSB (mask 0x01).
    // ──────────────────────────────────────────────────────────────────

    /// SGC — Service gap control (octet 3 bit 8, mask 0x80).
    pub fn sgc(&self) -> bool {
        bit_at(&self.value, 0, 7)
    }
    /// Set SGC.
    pub fn set_sgc(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 7, v);
        self.length = self.value.len() as _;
    }

    /// 5G-IPHC-CP CIoT — IP header compression for CP CIoT (octet 3 bit 7, mask 0x40).
    pub fn iphc_cp_ciot(&self) -> bool {
        bit_at(&self.value, 0, 6)
    }
    /// Set iphc cp CIoT.
    pub fn set_iphc_cp_ciot(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 6, v);
        self.length = self.value.len() as _;
    }

    /// N3 data — N3 data transfer (octet 3 bit 6, mask 0x20).
    pub fn n3_data(&self) -> bool {
        bit_at(&self.value, 0, 5)
    }
    /// Set n 3 data.
    pub fn set_n3_data(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 5, v);
        self.length = self.value.len() as _;
    }

    /// 5G-CP CIoT — Control plane CIoT 5GS optimisation (octet 3 bit 5, mask 0x10).
    pub fn cp_ciot(&self) -> bool {
        bit_at(&self.value, 0, 4)
    }
    /// Set cp CIoT.
    pub fn set_cp_ciot(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 4, v);
        self.length = self.value.len() as _;
    }

    /// RestrictEC — Restriction on use of enhanced coverage (octet 3 bit 4, mask 0x08).
    pub fn restrict_ec(&self) -> bool {
        bit_at(&self.value, 0, 3)
    }
    /// Set restrict ec.
    pub fn set_restrict_ec(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 3, v);
        self.length = self.value.len() as _;
    }

    /// LPP — LTE Positioning Protocol capability (octet 3 bit 3, mask 0x04).
    pub fn lpp(&self) -> bool {
        bit_at(&self.value, 0, 2)
    }
    /// Set lpp.
    pub fn set_lpp(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 2, v);
        self.length = self.value.len() as _;
    }

    /// HO attach (octet 3 bit 2, mask 0x02).
    pub fn ho_attach(&self) -> bool {
        bit_at(&self.value, 0, 1)
    }
    /// Set ho attach.
    pub fn set_ho_attach(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 1, v);
        self.length = self.value.len() as _;
    }

    /// S1 mode — EPC NAS supported (octet 3 bit 1, mask 0x01).
    pub fn s1_mode(&self) -> bool {
        bit_at(&self.value, 0, 0)
    }
    /// Set s 1 mode.
    pub fn set_s1_mode(&mut self, v: bool) {
        set_bit(&mut self.value, 0, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 4 on the wire (index 1) — Rel-16
    // ──────────────────────────────────────────────────────────────────

    /// RACS — Radio Capability Signalling optimisation (octet 4 bit 8, mask 0x80).
    pub fn racs(&self) -> bool {
        bit_at(&self.value, 1, 7)
    }
    /// Set racs.
    pub fn set_racs(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 7, v);
        self.length = self.value.len() as _;
    }

    /// NSSAA — Network Slice-Specific Authentication and Authorization (octet 4 bit 7, mask 0x40).
    pub fn nssaa(&self) -> bool {
        bit_at(&self.value, 1, 6)
    }
    /// Set nssaa.
    pub fn set_nssaa(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 6, v);
        self.length = self.value.len() as _;
    }

    /// 5G-LCS — 5G location services (octet 4 bit 6, mask 0x20).
    pub fn lcs_5g(&self) -> bool {
        bit_at(&self.value, 1, 5)
    }
    /// Set lcs 5 g.
    pub fn set_lcs_5g(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 5, v);
        self.length = self.value.len() as _;
    }

    /// V2XCNPC5 — V2X communication over NR PC5 (octet 4 bit 5, mask 0x10).
    pub fn v2x_cnpc5(&self) -> bool {
        bit_at(&self.value, 1, 4)
    }
    /// Set v 2 x cnpc 5.
    pub fn set_v2x_cnpc5(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 4, v);
        self.length = self.value.len() as _;
    }

    /// V2XCEPC5 — V2X communication over E-UTRA PC5 (octet 4 bit 4, mask 0x08).
    pub fn v2x_cepc5(&self) -> bool {
        bit_at(&self.value, 1, 3)
    }
    /// Set v 2 x cepc 5.
    pub fn set_v2x_cepc5(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 3, v);
        self.length = self.value.len() as _;
    }

    /// V2X — V2X capability (octet 4 bit 3, mask 0x04).
    pub fn v2x(&self) -> bool {
        bit_at(&self.value, 1, 2)
    }
    /// Set v 2 x.
    pub fn set_v2x(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 2, v);
        self.length = self.value.len() as _;
    }

    /// 5G-UP CIoT — user-plane CIoT 5GS optimisation (octet 4 bit 2, mask 0x02).
    pub fn up_ciot(&self) -> bool {
        bit_at(&self.value, 1, 1)
    }
    /// Set up CIoT.
    pub fn set_up_ciot(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 1, v);
        self.length = self.value.len() as _;
    }

    /// 5GSRVCC — 5G SRVCC from NG-RAN to UTRAN (octet 4 bit 1, mask 0x01).
    pub fn srvcc_5g(&self) -> bool {
        bit_at(&self.value, 1, 0)
    }
    /// Set srvcc 5 g.
    pub fn set_srvcc_5g(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 5 on the wire (index 2) — Rel-16/17
    // ──────────────────────────────────────────────────────────────────

    /// 5G ProSe L2 Relay (octet 5 bit 8, mask 0x80).
    pub fn prose_l2_relay(&self) -> bool {
        bit_at(&self.value, 2, 7)
    }
    /// Set prose l 2 relay.
    pub fn set_prose_l2_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 7, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe direct communication (octet 5 bit 7, mask 0x40).
    pub fn prose_dc(&self) -> bool {
        bit_at(&self.value, 2, 6)
    }
    /// Set prose dc.
    pub fn set_prose_dc(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 6, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe direct discovery (octet 5 bit 6, mask 0x20).
    pub fn prose_dd(&self) -> bool {
        bit_at(&self.value, 2, 5)
    }
    /// Set prose dd.
    pub fn set_prose_dd(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 5, v);
        self.length = self.value.len() as _;
    }

    /// ER-NSSAI — Extended rejected NSSAI (octet 5 bit 5, mask 0x10).
    pub fn er_nssai(&self) -> bool {
        bit_at(&self.value, 2, 4)
    }
    /// Set er NSSAI.
    pub fn set_er_nssai(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 4, v);
        self.length = self.value.len() as _;
    }

    /// 5G-EHC CP CIoT — Ethernet header compression for CP CIoT (octet 5 bit 4, mask 0x08).
    pub fn ehc_cp_ciot(&self) -> bool {
        bit_at(&self.value, 2, 3)
    }
    /// Set ehc cp CIoT.
    pub fn set_ehc_cp_ciot(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 3, v);
        self.length = self.value.len() as _;
    }

    /// Multiple UP — Multiple user-plane resources (octet 5 bit 3, mask 0x04).
    pub fn multiple_up(&self) -> bool {
        bit_at(&self.value, 2, 2)
    }
    /// Set multiple up.
    pub fn set_multiple_up(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 2, v);
        self.length = self.value.len() as _;
    }

    /// WUSA — WUS assistance information supported (octet 5 bit 2, mask 0x02).
    pub fn wusa(&self) -> bool {
        bit_at(&self.value, 2, 1)
    }
    /// Set wusa.
    pub fn set_wusa(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 1, v);
        self.length = self.value.len() as _;
    }

    /// CAG — Closed Access Group (octet 5 bit 1, mask 0x01).
    pub fn cag(&self) -> bool {
        bit_at(&self.value, 2, 0)
    }
    /// Set CAG.
    pub fn set_cag(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 6 on the wire (index 3) — Rel-17
    // ──────────────────────────────────────────────────────────────────

    /// PR — Paging restriction (octet 6 bit 8, mask 0x80).
    pub fn pr(&self) -> bool {
        bit_at(&self.value, 3, 7)
    }
    /// Set pr.
    pub fn set_pr(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 7, v);
        self.length = self.value.len() as _;
    }

    /// RPR — Reject paging request (octet 6 bit 7, mask 0x40).
    pub fn rpr(&self) -> bool {
        bit_at(&self.value, 3, 6)
    }
    /// Set rpr.
    pub fn set_rpr(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 6, v);
        self.length = self.value.len() as _;
    }

    /// PIV — Periodic registration update timer enhanced value (octet 6 bit 6, mask 0x20).
    pub fn piv(&self) -> bool {
        bit_at(&self.value, 3, 5)
    }
    /// Set piv.
    pub fn set_piv(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 5, v);
        self.length = self.value.len() as _;
    }

    /// NCR — Non-cellular Capability Restriction (octet 6 bit 5, mask 0x10).
    pub fn ncr(&self) -> bool {
        bit_at(&self.value, 3, 4)
    }
    /// Set ncr.
    pub fn set_ncr(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 4, v);
        self.length = self.value.len() as _;
    }

    /// NR-PSSI — NR positioning SIB types (octet 6 bit 4, mask 0x08).
    pub fn nr_pssi(&self) -> bool {
        bit_at(&self.value, 3, 3)
    }
    /// Set nr pssi.
    pub fn set_nr_pssi(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 3, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe L3 Remote (octet 6 bit 3, mask 0x04).
    pub fn prose_l3_remote(&self) -> bool {
        bit_at(&self.value, 3, 2)
    }
    /// Set prose l 3 remote.
    pub fn set_prose_l3_remote(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 2, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe L2 Remote (octet 6 bit 2, mask 0x02).
    pub fn prose_l2_remote(&self) -> bool {
        bit_at(&self.value, 3, 1)
    }
    /// Set prose l 2 remote.
    pub fn set_prose_l2_remote(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 1, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe L3 Relay (octet 6 bit 1, mask 0x01).
    pub fn prose_l3_relay(&self) -> bool {
        bit_at(&self.value, 3, 0)
    }
    /// Set prose l 3 relay.
    pub fn set_prose_l3_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 3, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 7 on the wire (index 4) — Rel-17
    // ──────────────────────────────────────────────────────────────────

    /// MPSIU — Multimedia priority service in inter-PLMN scenarios (octet 7 bit 8, mask 0x80).
    pub fn mpsiu(&self) -> bool {
        bit_at(&self.value, 4, 7)
    }
    /// Set mpsiu.
    pub fn set_mpsiu(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 7, v);
        self.length = self.value.len() as _;
    }

    /// UAS — Uncrewed Aerial Systems services (octet 7 bit 7, mask 0x40).
    pub fn uas(&self) -> bool {
        bit_at(&self.value, 4, 6)
    }
    /// Set uas.
    pub fn set_uas(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 6, v);
        self.length = self.value.len() as _;
    }

    /// NSAG — Network Slice AS Group (octet 7 bit 6, mask 0x20).
    pub fn nsag(&self) -> bool {
        bit_at(&self.value, 4, 5)
    }
    /// Set nsag.
    pub fn set_nsag(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 5, v);
        self.length = self.value.len() as _;
    }

    /// Ex-CAG — Extended CAG information (octet 7 bit 5, mask 0x10).
    pub fn ex_cag(&self) -> bool {
        bit_at(&self.value, 4, 4)
    }
    /// Set ex CAG.
    pub fn set_ex_cag(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 4, v);
        self.length = self.value.len() as _;
    }

    /// SSNPNSI — Subscribed SNPN signalling (octet 7 bit 4, mask 0x08).
    pub fn ssnpnsi(&self) -> bool {
        bit_at(&self.value, 4, 3)
    }
    /// Set ssnpnsi.
    pub fn set_ssnpnsi(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 3, v);
        self.length = self.value.len() as _;
    }

    /// Event notification (octet 7 bit 3, mask 0x04).
    pub fn event_notification(&self) -> bool {
        bit_at(&self.value, 4, 2)
    }
    /// Set event notification.
    pub fn set_event_notification(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 2, v);
        self.length = self.value.len() as _;
    }

    /// MINT — Minimization of service interruption (octet 7 bit 2, mask 0x02).
    pub fn mint(&self) -> bool {
        bit_at(&self.value, 4, 1)
    }
    /// Set mint.
    pub fn set_mint(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 1, v);
        self.length = self.value.len() as _;
    }

    /// NSSRG — Network Slice Simultaneous Registration Group (octet 7 bit 1, mask 0x01).
    pub fn nssrg(&self) -> bool {
        bit_at(&self.value, 4, 0)
    }
    /// Set nssrg.
    pub fn set_nssrg(&mut self, v: bool) {
        set_bit(&mut self.value, 4, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 8 on the wire (index 5) — Rel-17/18
    // ──────────────────────────────────────────────────────────────────

    /// SBTS — Satellite NR access (octet 8 bit 8, mask 0x80).
    pub fn sbts(&self) -> bool {
        bit_at(&self.value, 5, 7)
    }
    /// Set sbts.
    pub fn set_sbts(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 7, v);
        self.length = self.value.len() as _;
    }

    /// NSR — Non-satellite roaming (octet 8 bit 7, mask 0x40).
    pub fn nsr(&self) -> bool {
        bit_at(&self.value, 5, 6)
    }
    /// Set nsr.
    pub fn set_nsr(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 6, v);
        self.length = self.value.len() as _;
    }

    /// LADN-DS — LADN data structure (octet 8 bit 6, mask 0x20).
    pub fn ladn_ds(&self) -> bool {
        bit_at(&self.value, 5, 5)
    }
    /// Set LADN ds.
    pub fn set_ladn_ds(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 5, v);
        self.length = self.value.len() as _;
    }

    /// RAN timing synchronisation (octet 8 bit 5, mask 0x10).
    pub fn ran_timing(&self) -> bool {
        bit_at(&self.value, 5, 4)
    }
    /// Set ran timing.
    pub fn set_ran_timing(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 4, v);
        self.length = self.value.len() as _;
    }

    /// ECI — Enhanced coverage indicator (octet 8 bit 4, mask 0x08).
    pub fn eci(&self) -> bool {
        bit_at(&self.value, 5, 3)
    }
    /// Set eci.
    pub fn set_eci(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 3, v);
        self.length = self.value.len() as _;
    }

    /// ESI — Emergency services indicator (octet 8 bit 3, mask 0x04).
    pub fn esi(&self) -> bool {
        bit_at(&self.value, 5, 2)
    }
    /// Set esi.
    pub fn set_esi(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 2, v);
        self.length = self.value.len() as _;
    }

    /// RcMan — Reachability via congested mobile-terminated access (octet 8 bit 2, mask 0x02).
    pub fn rcman(&self) -> bool {
        bit_at(&self.value, 5, 1)
    }
    /// Set rcman.
    pub fn set_rcman(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 1, v);
        self.length = self.value.len() as _;
    }

    /// RcMap — Reachability via congested mobile-terminated access policy (octet 8 bit 1, mask 0x01).
    pub fn rcmap(&self) -> bool {
        bit_at(&self.value, 5, 0)
    }
    /// Set rcmap.
    pub fn set_rcmap(&mut self, v: bool) {
        set_bit(&mut self.value, 5, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 9 on the wire (index 6) — Rel-18
    // ──────────────────────────────────────────────────────────────────

    /// 5G ProSe Layer-2 endpoint (octet 9 bit 8, mask 0x80).
    pub fn prose_l2_endpoint(&self) -> bool {
        bit_at(&self.value, 6, 7)
    }
    /// Set prose l 2 endpoint.
    pub fn set_prose_l2_endpoint(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 7, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe Layer-3 UE-to-UE relay (octet 9 bit 7, mask 0x40).
    pub fn prose_l3_u2u_relay(&self) -> bool {
        bit_at(&self.value, 6, 6)
    }
    /// Set prose l 3 u 2 u relay.
    pub fn set_prose_l3_u2u_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 6, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe Layer-2 UE-to-UE relay (octet 9 bit 6, mask 0x20).
    pub fn prose_l2_u2u_relay(&self) -> bool {
        bit_at(&self.value, 6, 5)
    }
    /// Set prose l 2 u 2 u relay.
    pub fn set_prose_l2_u2u_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 5, v);
        self.length = self.value.len() as _;
    }

    /// RSLPS — Ranging and SideLink Positioning Service (octet 9 bit 5, mask 0x10).
    pub fn rslps(&self) -> bool {
        bit_at(&self.value, 6, 4)
    }
    /// Set rslps.
    pub fn set_rslps(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 4, v);
        self.length = self.value.len() as _;
    }

    /// SBNS — Satellite-based NB-IoT NAS support (octet 9 bit 4, mask 0x08).
    pub fn sbns(&self) -> bool {
        bit_at(&self.value, 6, 3)
    }
    /// Set sbns.
    pub fn set_sbns(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 3, v);
        self.length = self.value.len() as _;
    }

    /// UN-PER — UAS NF periodic reporting (octet 9 bit 3, mask 0x04).
    pub fn un_per(&self) -> bool {
        bit_at(&self.value, 6, 2)
    }
    /// Set un per.
    pub fn set_un_per(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 2, v);
        self.length = self.value.len() as _;
    }

    /// A2X NPC5 — A2X over NR PC5 (octet 9 bit 2, mask 0x02).
    pub fn a2x_npc5(&self) -> bool {
        bit_at(&self.value, 6, 1)
    }
    /// Set a 2 x npc 5.
    pub fn set_a2x_npc5(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 1, v);
        self.length = self.value.len() as _;
    }

    /// A2X EPC5 — A2X over E-UTRA PC5 (octet 9 bit 1, mask 0x01).
    pub fn a2x_epc5(&self) -> bool {
        bit_at(&self.value, 6, 0)
    }
    /// Set a 2 x epc 5.
    pub fn set_a2x_epc5(&mut self, v: bool) {
        set_bit(&mut self.value, 6, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 10 on the wire (index 7) — Rel-18
    // ──────────────────────────────────────────────────────────────────

    /// A2X over Uu (octet 10 bit 8, mask 0x80).
    pub fn a2x_uu(&self) -> bool {
        bit_at(&self.value, 7, 7)
    }
    /// Set a 2 x uu.
    pub fn set_a2x_uu(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 7, v);
        self.length = self.value.len() as _;
    }

    /// SLVI — Sidelink V2X (octet 10 bit 7, mask 0x40).
    pub fn slvi(&self) -> bool {
        bit_at(&self.value, 7, 6)
    }
    /// Set slvi.
    pub fn set_slvi(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 6, v);
        self.length = self.value.len() as _;
    }

    /// TempNS — Temporary network slice (octet 10 bit 6, mask 0x20).
    pub fn temp_ns(&self) -> bool {
        bit_at(&self.value, 7, 5)
    }
    /// Set temp ns.
    pub fn set_temp_ns(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 5, v);
        self.length = self.value.len() as _;
    }

    /// SUPL — Secure User-Plane Location (octet 10 bit 5, mask 0x10).
    pub fn supl(&self) -> bool {
        bit_at(&self.value, 7, 4)
    }
    /// Set supl.
    pub fn set_supl(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 4, v);
        self.length = self.value.len() as _;
    }

    /// LCS-UPP — Location Services User-Plane Positioning (octet 10 bit 4, mask 0x08).
    pub fn lcs_upp(&self) -> bool {
        bit_at(&self.value, 7, 3)
    }
    /// Set lcs upp.
    pub fn set_lcs_upp(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 3, v);
        self.length = self.value.len() as _;
    }

    /// PNS — Positioning NAS support (octet 10 bit 3, mask 0x04).
    pub fn pns(&self) -> bool {
        bit_at(&self.value, 7, 2)
    }
    /// Set pns.
    pub fn set_pns(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 2, v);
        self.length = self.value.len() as _;
    }

    /// RSLP — Ranging and SideLink Positioning (octet 10 bit 2, mask 0x02).
    pub fn rslp(&self) -> bool {
        bit_at(&self.value, 7, 1)
    }
    /// Set rslp.
    pub fn set_rslp(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 1, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe Layer-3 endpoint (octet 10 bit 1, mask 0x01).
    pub fn prose_l3_endpoint(&self) -> bool {
        bit_at(&self.value, 7, 0)
    }
    /// Set prose l 3 endpoint.
    pub fn set_prose_l3_endpoint(&mut self, v: bool) {
        set_bit(&mut self.value, 7, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 11 on the wire (index 8) — Rel-18
    // ──────────────────────────────────────────────────────────────────

    /// LP-WUS-PSAI — Low-power Wake-Up Signal paging subgroup assistance info (octet 11 bit 8).
    pub fn lp_wus_psai(&self) -> bool {
        bit_at(&self.value, 8, 7)
    }
    /// Set lp wus psai.
    pub fn set_lp_wus_psai(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 7, v);
        self.length = self.value.len() as _;
    }

    /// ATUC — Anchor TS UDM connection (octet 11 bit 7, mask 0x40).
    pub fn atuc(&self) -> bool {
        bit_at(&self.value, 8, 6)
    }
    /// Set atuc.
    pub fn set_atuc(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 6, v);
        self.length = self.value.len() as _;
    }

    /// RSLPPU — Ranging and SideLink Positioning protocol over user plane (octet 11 bit 6).
    pub fn rslppu(&self) -> bool {
        bit_at(&self.value, 8, 5)
    }
    /// Set rslppu.
    pub fn set_rslppu(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 5, v);
        self.length = self.value.len() as _;
    }

    /// RSLPVU — RSLP via UE (octet 11 bit 5, mask 0x10).
    pub fn rslpvu(&self) -> bool {
        bit_at(&self.value, 8, 4)
    }
    /// Set rslpvu.
    pub fn set_rslpvu(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 4, v);
        self.length = self.value.len() as _;
    }

    /// NSUC — Network Slice Usage Control (octet 11 bit 4, mask 0x08).
    pub fn nsuc(&self) -> bool {
        bit_at(&self.value, 8, 3)
    }
    /// Set nsuc.
    pub fn set_nsuc(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 3, v);
        self.length = self.value.len() as _;
    }

    /// RSLPL — RSLP via location services (octet 11 bit 3, mask 0x04).
    pub fn rslpl(&self) -> bool {
        bit_at(&self.value, 8, 2)
    }
    /// Set rslpl.
    pub fn set_rslpl(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 2, v);
        self.length = self.value.len() as _;
    }

    /// NVL-SatNR — NVL satellite NR (octet 11 bit 2, mask 0x02).
    pub fn nvl_satnr(&self) -> bool {
        bit_at(&self.value, 8, 1)
    }
    /// Set nvl satnr.
    pub fn set_nvl_satnr(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 1, v);
        self.length = self.value.len() as _;
    }

    /// MCSIU — Mission Critical Service interruption (octet 11 bit 1, mask 0x01).
    pub fn mcsiu(&self) -> bool {
        bit_at(&self.value, 8, 0)
    }
    /// Set mcsiu.
    pub fn set_mcsiu(&mut self, v: bool) {
        set_bit(&mut self.value, 8, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Octet 12 on the wire (index 9) — Rel-18
    // ──────────────────────────────────────────────────────────────────

    /// LWD — Localised wireless data (octet 12 bit 8, mask 0x80).
    pub fn lwd(&self) -> bool {
        bit_at(&self.value, 9, 7)
    }
    /// Set lwd.
    pub fn set_lwd(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 7, v);
        self.length = self.value.len() as _;
    }

    /// EF5L — Extended five-letter feature (octet 12 bit 7, mask 0x40).
    pub fn ef5l(&self) -> bool {
        bit_at(&self.value, 9, 6)
    }
    /// Set ef 5 l.
    pub fn set_ef5l(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 6, v);
        self.length = self.value.len() as _;
    }

    /// MINT-EPS — Minimization of service interruption in EPS (octet 12 bit 6, mask 0x20).
    pub fn mint_eps(&self) -> bool {
        bit_at(&self.value, 9, 5)
    }
    /// Set mint EPS.
    pub fn set_mint_eps(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 5, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe Layer-2 IP-mode relay (octet 12 bit 5, mask 0x10).
    pub fn prose_l2_im_relay(&self) -> bool {
        bit_at(&self.value, 9, 4)
    }
    /// Set prose l 2 im relay.
    pub fn set_prose_l2_im_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 4, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe Layer-3 IP-mode relay (octet 12 bit 4, mask 0x08).
    pub fn prose_l3_im_relay(&self) -> bool {
        bit_at(&self.value, 9, 3)
    }
    /// Set prose l 3 im relay.
    pub fn set_prose_l3_im_relay(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 3, v);
        self.length = self.value.len() as _;
    }

    /// MLCSUP — Multi-link sidelink user plane (octet 12 bit 3, mask 0x04).
    pub fn mlcsup(&self) -> bool {
        bit_at(&self.value, 9, 2)
    }
    /// Set mlcsup.
    pub fn set_mlcsup(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 2, v);
        self.length = self.value.len() as _;
    }

    /// 5G ProSe MCI — ProSe MC indication (octet 12 bit 2, mask 0x02).
    pub fn prose_mci(&self) -> bool {
        bit_at(&self.value, 9, 1)
    }
    /// Set prose mci.
    pub fn set_prose_mci(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 1, v);
        self.length = self.value.len() as _;
    }

    /// OPHPAE — Operator policies for home PLMN access (octet 12 bit 1, mask 0x01).
    pub fn ophpae(&self) -> bool {
        bit_at(&self.value, 9, 0)
    }
    /// Set ophpae.
    pub fn set_ophpae(&mut self, v: bool) {
        set_bit(&mut self.value, 9, 0, v);
        self.length = self.value.len() as _;
    }

    // ──────────────────────────────────────────────────────────────────
    // Construction / raw access
    // ──────────────────────────────────────────────────────────────────

    /// Build a single-octet 5GMM capability with the most common Rel-15 flags.
    /// For Rel-16+ bits use the per-bit `set_*()` setters or [`Self::from_octets`].
    #[allow(clippy::too_many_arguments)]
    pub fn from_flags(
        sgc: bool,
        iphc_cp_ciot: bool,
        n3_data: bool,
        cp_ciot: bool,
        restrict_ec: bool,
        lpp: bool,
        ho_attach: bool,
        s1_mode: bool,
    ) -> Self {
        let mut b: u8 = 0;
        if sgc {
            b |= 0x80;
        }
        if iphc_cp_ciot {
            b |= 0x40;
        }
        if n3_data {
            b |= 0x20;
        }
        if cp_ciot {
            b |= 0x10;
        }
        if restrict_ec {
            b |= 0x08;
        }
        if lpp {
            b |= 0x04;
        }
        if ho_attach {
            b |= 0x02;
        }
        if s1_mode {
            b |= 0x01;
        }
        Self::new(vec![b])
    }

    /// Build from checked capability contents. Octet 1 (= wire octet 3) is the
    /// mandatory core capability; octets 2..13 (= wire octets 4..15) carry
    /// extensions per TS 24.501 §9.11.3.1. Wire octets 13..15 are spare-only
    /// in v19.6.2 and must be zero.
    pub fn try_from_octets(octets: Vec<u8>) -> Option<Self> {
        if octets.is_empty() || octets.len() > FGMM_CAPABILITY_MAX_CONTENT_OCTETS {
            return None;
        }
        if octets
            .iter()
            .skip(FGMM_CAPABILITY_SPARE_ONLY_START_INDEX)
            .any(|octet| *octet != 0)
        {
            return None;
        }
        Some(Self::new(octets))
    }

    /// Build from capability contents.
    ///
    /// Panics if the contents are empty, longer than 13 octets, or set the
    /// spare-only v19.6.2 extension octets.
    pub fn from_octets(octets: Vec<u8>) -> Self {
        assert!(
            !octets.is_empty() && octets.len() <= FGMM_CAPABILITY_MAX_CONTENT_OCTETS,
            "5GMM capability contents must contain 1..=13 octets"
        );
        assert!(
            octets
                .iter()
                .skip(FGMM_CAPABILITY_SPARE_ONLY_START_INDEX)
                .all(|octet| *octet == 0),
            "5GMM capability wire octets 13..15 are spare-only and must be zero"
        );
        Self::new(octets)
    }

    /// Whether spare-only wire octets 13..15 are zero.
    pub fn spare_octets_are_zero(&self) -> bool {
        self.value
            .iter()
            .skip(FGMM_CAPABILITY_SPARE_ONLY_START_INDEX)
            .all(|octet| *octet == 0)
    }

    /// Strict structural validation for TS 24.501 §9.11.3.1 v19.6.2.
    pub fn validate_strict(&self) -> Result<()> {
        if self.value.is_empty() {
            return Err(NasError::DecodingError(
                "5GMM capability contents must not be empty".into(),
            ));
        }
        if self.value.len() > FGMM_CAPABILITY_MAX_CONTENT_OCTETS {
            return Err(NasError::DecodingError(
                "5GMM capability contents exceed 13 octets".into(),
            ));
        }
        if !self.spare_octets_are_zero() {
            return Err(NasError::DecodingError(
                "5GMM capability wire octets 13..15 are spare-only and must be zero".into(),
            ));
        }
        Ok(())
    }

    /// Raw capability octet at 1-based wire index. `octet(1)` returns octet 3 on the wire
    /// (the mandatory core capability), `octet(2)` returns octet 4, and so on. Returns 0 if
    /// the requested octet is beyond the IE length.
    pub fn octet(&self, index: usize) -> u8 {
        if index == 0 {
            return 0;
        }
        self.value.get(index - 1).copied().unwrap_or(0)
    }

    /// All raw capability octets.
    pub fn octets(&self) -> &[u8] {
        &self.value
    }
}

/// 5GS DRX cycle length per TS 24.501 §9.11.3.2A.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DrxValue {
    /// DRX value not specified.
    NotSpecified = 0x00,
    /// DRX cycle T = 32.
    Cycle32 = 0x01,
    /// DRX cycle T = 64.
    Cycle64 = 0x02,
    /// DRX cycle T = 128.
    Cycle128 = 0x03,
    /// DRX cycle T = 256.
    Cycle256 = 0x04,
}

impl DrxValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::NotSpecified),
            0x01 => Some(Self::Cycle32),
            0x02 => Some(Self::Cycle64),
            0x03 => Some(Self::Cycle128),
            0x04 => Some(Self::Cycle256),
            _ => Some(Self::NotSpecified),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::NotSpecified),
            0x01 => Some(Self::Cycle32),
            0x02 => Some(Self::Cycle64),
            0x03 => Some(Self::Cycle128),
            0x04 => Some(Self::Cycle256),
            _ => None,
        }
    }
}

impl NasFGsDrxParameters {
    /// Typed DRX value (bits 1-4 of octet 1).
    pub fn drx_value(&self) -> Option<DrxValue> {
        DrxValue::from_u8(self.value.first().copied().unwrap_or(0))
    }

    /// Raw DRX value (bits 1-4 of octet 1).
    pub fn drx_value_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x0F).unwrap_or(0)
    }

    /// Construct a value from drx value.
    pub fn from_drx_value(drx: DrxValue) -> Self {
        Self::new(vec![drx as u8])
    }
}

impl NasFGsUpdateType {
    fn fb(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }
    fn write_first(&mut self, b: u8) {
        if self.value.is_empty() {
            self.value.push(b);
        } else {
            self.value[0] = b;
        }
        self.length = self.value.len() as _;
    }

    /// SMS requested (bit 1, mask 0x01). TS 24.501 §9.11.3.9A.
    pub fn sms_requested(&self) -> bool {
        self.fb() & 0x01 != 0
    }
    /// Set the SMS-requested bit. Returns `self`.
    pub fn with_sms_requested(mut self, on: bool) -> Self {
        let b = (self.fb() & !0x01) | if on { 0x01 } else { 0 };
        self.write_first(b);
        self
    }
    /// Set sms requested.
    pub fn set_sms_requested(&mut self, on: bool) {
        let b = (self.fb() & !0x01) | if on { 0x01 } else { 0 };
        self.write_first(b);
    }

    /// NG-RAN Radio Capability Update (bit 2, mask 0x02).
    pub fn ng_ran_rcu(&self) -> bool {
        (self.fb() >> 1) & 0x01 != 0
    }
    /// Set ng ran rcu and return the updated value.
    pub fn with_ng_ran_rcu(mut self, on: bool) -> Self {
        let b = (self.fb() & !0x02) | if on { 0x02 } else { 0 };
        self.write_first(b);
        self
    }
    /// Set ng ran rcu.
    pub fn set_ng_ran_rcu(&mut self, on: bool) {
        let b = (self.fb() & !0x02) | if on { 0x02 } else { 0 };
        self.write_first(b);
    }

    /// PNB-CIoT — preferred CIoT network behaviour for 5GS (bits 3-4, mask 0x0C).
    /// 0 = no indication, 1 = control plane, 2 = user plane, 3 = reserved.
    pub fn pnb_ciot(&self) -> u8 {
        (self.fb() >> 2) & 0x03
    }
    /// Set pnb CIoT and return the updated value.
    pub fn with_pnb_ciot(mut self, v: u8) -> Self {
        let b = (self.fb() & !0x0C) | ((v & 0x03) << 2);
        self.write_first(b);
        self
    }
    /// Set pnb CIoT.
    pub fn set_pnb_ciot(&mut self, v: u8) {
        let b = (self.fb() & !0x0C) | ((v & 0x03) << 2);
        self.write_first(b);
    }

    /// EPS-PNB-CIoT — preferred CIoT network behaviour for EPS (bits 5-6, mask 0x30).
    pub fn eps_pnb_ciot(&self) -> u8 {
        (self.fb() >> 4) & 0x03
    }
    /// Set EPS pnb CIoT and return the updated value.
    pub fn with_eps_pnb_ciot(mut self, v: u8) -> Self {
        let b = (self.fb() & !0x30) | ((v & 0x03) << 4);
        self.write_first(b);
        self
    }
    /// Set EPS pnb CIoT.
    pub fn set_eps_pnb_ciot(&mut self, v: u8) {
        let b = (self.fb() & !0x30) | ((v & 0x03) << 4);
        self.write_first(b);
    }
}

impl Default for NasFGsUpdateType {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl NasFGsmCapability {
    fn clear_spare_bits(&mut self) {
        if self.value.len() >= 3 {
            self.value[2] &= 0x03;
        }
        for byte in self.value.iter_mut().skip(3) {
            *byte = 0;
        }
    }

    /// TPMIC (octet 3 bit 8 = mask 0x80): Transfer of port management information containers.
    /// TS 24.501 §9.11.4.1 Table 9.11.4.1.1 octet 3.
    pub fn tpmic(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 7) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set tpmic.
    pub fn set_tpmic(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 7, value);
        self.length = self.value.len() as _;
    }

    /// Set tpmic and return the updated value.
    pub fn with_tpmic(mut self, value: bool) -> Self {
        self.set_tpmic(value);
        self
    }

    /// ATSSS-ST (octet 3 bits 4-7 = mask 0x78): selected steering functionality patterns.
    pub fn atsss_st(&self) -> u8 {
        self.value.first().map(|b| (b >> 3) & 0x0F).unwrap_or(0)
    }

    /// Return atsss st value.
    pub fn atsss_st_value(&self) -> Option<AtsssSteeringFunctionality> {
        AtsssSteeringFunctionality::from_u8(self.atsss_st())
    }

    /// Set atsss st.
    pub fn set_atsss_st(&mut self, value: u8) {
        assert!(
            AtsssSteeringFunctionality::from_u8(value).is_some(),
            "ATSSS-ST must be one of 0x0, 0x3, 0xC, or 0xF"
        );
        if self.value.is_empty() {
            self.value.resize(1, 0);
        }
        self.value[0] = (self.value[0] & !0x78) | (value << 3);
        self.length = self.value.len() as _;
    }

    /// Set atsss st and return the updated value.
    pub fn with_atsss_st(mut self, value: u8) -> Self {
        self.set_atsss_st(value);
        self
    }

    /// Set atsss st value.
    pub fn set_atsss_st_value(&mut self, value: AtsssSteeringFunctionality) {
        self.set_atsss_st(value as u8);
    }

    /// Set atsss st value and return the updated value.
    pub fn with_atsss_st_value(mut self, value: AtsssSteeringFunctionality) -> Self {
        self.set_atsss_st_value(value);
        self
    }

    /// EPT-S1 (octet 3 bit 3 = mask 0x04): Ethernet PDU type over S1 mode.
    pub fn ept_s1(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 2) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set ept s 1.
    pub fn set_ept_s1(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 2, value);
        self.length = self.value.len() as _;
    }

    /// Set ept s 1 and return the updated value.
    pub fn with_ept_s1(mut self, value: bool) -> Self {
        self.set_ept_s1(value);
        self
    }

    /// MH6-PDU (octet 3 bit 2 = mask 0x02): Multi-homed IPv6 PDU session.
    pub fn mh6_pdu(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Set mh 6 PDU.
    pub fn set_mh6_pdu(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 1, value);
        self.length = self.value.len() as _;
    }

    /// Set mh 6 PDU and return the updated value.
    pub fn with_mh6_pdu(mut self, value: bool) -> Self {
        self.set_mh6_pdu(value);
        self
    }

    /// RqoS (octet 3 bit 1 = mask 0x01): Reflective QoS.
    pub fn rqos(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Set rqos.
    pub fn set_rqos(&mut self, value: bool) {
        set_bit(&mut self.value, 0, 0, value);
        self.length = self.value.len() as _;
    }

    /// Set rqos and return the updated value.
    pub fn with_rqos(mut self, value: bool) -> Self {
        self.set_rqos(value);
        self
    }

    // ── Octet 4 (Rust value[1]) — Rel-17 ────────────────────────────────

    /// MPQUIC-IP — MPQUIC over IP (octet 4 bit 8, mask 0x80).
    pub fn mpquic_ip(&self) -> bool {
        bit_at(&self.value, 1, 7)
    }
    /// Set mpquic ip.
    pub fn set_mpquic_ip(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 7, v);
        self.length = self.value.len() as _;
    }
    /// Set mpquic ip and return the updated value.
    pub fn with_mpquic_ip(mut self, v: bool) -> Self {
        self.set_mpquic_ip(v);
        self
    }

    /// MPQUIC-UDP — MPQUIC over UDP (octet 4 bit 7, mask 0x40).
    pub fn mpquic_udp(&self) -> bool {
        bit_at(&self.value, 1, 6)
    }
    /// Set mpquic udp.
    pub fn set_mpquic_udp(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 6, v);
        self.length = self.value.len() as _;
    }
    /// Set mpquic udp and return the updated value.
    pub fn with_mpquic_udp(mut self, v: bool) -> Self {
        self.set_mpquic_udp(v);
        self
    }

    /// MPTCP — Multipath TCP support (octet 4 bit 6, mask 0x20).
    pub fn mptcp(&self) -> bool {
        bit_at(&self.value, 1, 5)
    }
    /// Set mptcp.
    pub fn set_mptcp(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 5, v);
        self.length = self.value.len() as _;
    }
    /// Set mptcp and return the updated value.
    pub fn with_mptcp(mut self, v: bool) -> Self {
        self.set_mptcp(v);
        self
    }

    /// ATSSS-LL — ATSSS Low-Layer (octet 4 bits 4-5, mask 0x18). 2-bit value.
    pub fn atsss_ll(&self) -> u8 {
        self.value.get(1).map(|b| (b >> 3) & 0x03).unwrap_or(0)
    }
    /// Return atsss ll value.
    pub fn atsss_ll_value(&self) -> Option<AtsssLowLayerFunctionality> {
        AtsssLowLayerFunctionality::from_u8(self.atsss_ll())
    }
    /// Set atsss ll.
    pub fn set_atsss_ll(&mut self, v: u8) {
        assert!(
            AtsssLowLayerFunctionality::from_u8(v & 0x03).is_some(),
            "ATSSS-LL must be one of 0x0, 0x1, or 0x2"
        );
        if self.value.len() < 2 {
            self.value.resize(2, 0);
        }
        self.value[1] = (self.value[1] & !0x18) | ((v & 0x03) << 3);
        self.length = self.value.len() as _;
    }
    /// Set atsss ll and return the updated value.
    pub fn with_atsss_ll(mut self, v: u8) -> Self {
        self.set_atsss_ll(v);
        self
    }
    /// Set atsss ll value.
    pub fn set_atsss_ll_value(&mut self, v: AtsssLowLayerFunctionality) {
        self.set_atsss_ll(v as u8);
    }
    /// Set atsss ll value and return the updated value.
    pub fn with_atsss_ll_value(mut self, v: AtsssLowLayerFunctionality) -> Self {
        self.set_atsss_ll_value(v);
        self
    }

    /// RTPMMII — Reflective QoS over multiple media identification information
    /// (octet 4 bit 3, mask 0x04).
    pub fn rtpmmii(&self) -> bool {
        bit_at(&self.value, 1, 2)
    }
    /// Set rtpmmii.
    pub fn set_rtpmmii(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 2, v);
        self.length = self.value.len() as _;
    }
    /// Set rtpmmii and return the updated value.
    pub fn with_rtpmmii(mut self, v: bool) -> Self {
        self.set_rtpmmii(v);
        self
    }

    /// SDNAEPC — Satellite NAS support over EPC (octet 4 bit 2, mask 0x02).
    pub fn sdnaepc(&self) -> bool {
        bit_at(&self.value, 1, 1)
    }
    /// Set sdnaepc.
    pub fn set_sdnaepc(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 1, v);
        self.length = self.value.len() as _;
    }
    /// Set sdnaepc and return the updated value.
    pub fn with_sdnaepc(mut self, v: bool) -> Self {
        self.set_sdnaepc(v);
        self
    }

    /// APMQF — Access Path Management QoS Flow (octet 4 bit 1, mask 0x01).
    pub fn apmqf(&self) -> bool {
        bit_at(&self.value, 1, 0)
    }
    /// Set apmqf.
    pub fn set_apmqf(&mut self, v: bool) {
        set_bit(&mut self.value, 1, 0, v);
        self.length = self.value.len() as _;
    }
    /// Set apmqf and return the updated value.
    pub fn with_apmqf(mut self, v: bool) -> Self {
        self.set_apmqf(v);
        self
    }

    // ── Octet 5 (Rust value[2]) — Rel-18 ────────────────────────────────

    /// E8PCPDEI — Ethernet over 8PCPDE indication (octet 5 bit 2, mask 0x02).
    pub fn e8pcpdei(&self) -> bool {
        bit_at(&self.value, 2, 1)
    }
    /// Set e 8 pcpdei.
    pub fn set_e8pcpdei(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 1, v);
        self.length = self.value.len() as _;
        self.clear_spare_bits();
    }
    /// Set e 8 pcpdei and return the updated value.
    pub fn with_e8pcpdei(mut self, v: bool) -> Self {
        self.set_e8pcpdei(v);
        self
    }

    /// MPQUIC-E — MPQUIC enhanced (octet 5 bit 1, mask 0x01).
    pub fn mpquic_e(&self) -> bool {
        bit_at(&self.value, 2, 0)
    }
    /// Set mpquic e.
    pub fn set_mpquic_e(&mut self, v: bool) {
        set_bit(&mut self.value, 2, 0, v);
        self.length = self.value.len() as _;
        self.clear_spare_bits();
    }
    /// Set mpquic e and return the updated value.
    pub fn with_mpquic_e(mut self, v: bool) -> Self {
        self.set_mpquic_e(v);
        self
    }

    /// Build a single-octet 5GSM capability with the most common Rel-15 flags.
    /// ATSSS-ST is restricted to the selected patterns from TS 24.501 §9.11.4.1.
    pub fn from_flags(tpmic: bool, atsss_st: u8, ept_s1: bool, mh6_pdu: bool, rqos: bool) -> Self {
        assert!(
            AtsssSteeringFunctionality::from_u8(atsss_st).is_some(),
            "ATSSS-ST must be one of 0x0, 0x3, 0xC, or 0xF"
        );
        let mut b: u8 = 0;
        if tpmic {
            b |= 0x80;
        }
        b |= atsss_st << 3;
        if ept_s1 {
            b |= 0x04;
        }
        if mh6_pdu {
            b |= 0x02;
        }
        if rqos {
            b |= 0x01;
        }
        Self::new(vec![b])
    }

    /// Build from checked capability contents (wire octets 3..15).
    pub fn from_octets(octets: Vec<u8>) -> Option<Self> {
        if octets.is_empty() || octets.len() > 13 {
            return None;
        }
        AtsssSteeringFunctionality::from_u8((octets[0] >> 3) & 0x0F)?;
        if octets
            .get(1)
            .is_some_and(|octet| AtsssLowLayerFunctionality::from_u8((octet >> 3) & 0x03).is_none())
        {
            return None;
        }
        if octets.get(2).is_some_and(|octet| (octet & !0x03) != 0) {
            return None;
        }
        if octets.iter().skip(3).any(|octet| *octet != 0) {
            return None;
        }
        Some(Self::new(octets))
    }

    /// Whether spare bits and spare octets are zero as required by TS 24.501 §9.11.4.1.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value.get(2).copied().unwrap_or(0) & !0x03 == 0
            && self.value.iter().skip(3).all(|octet| *octet == 0)
    }

    /// Raw capability octet at 1-based wire index. `octet(1)` returns octet 3 on
    /// the wire (the mandatory core capability), `octet(2)` returns octet 4, and so on.
    pub fn octet(&self, index: usize) -> u8 {
        if index == 0 {
            return 0;
        }
        self.value.get(index - 1).copied().unwrap_or(0)
    }

    /// All raw capability octets.
    pub fn octets(&self) -> &[u8] {
        &self.value
    }
}

impl Default for NasFGsmCapability {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

/// ATSSS steering functionality support advertised in the 5GSM capability IE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AtsssSteeringFunctionality {
    /// Not supported.
    NotSupported = 0x00,
    /// Low layer any steering.
    LowLayerAnySteering = 0x03,
    /// Mptcp any and low layer active standby.
    MptcpAnyAndLowLayerActiveStandby = 0x0C,
    /// Mptcp any and low layer any.
    MptcpAnyAndLowLayerAny = 0x0F,
}

impl AtsssSteeringFunctionality {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NotSupported),
            0x03 => Some(Self::LowLayerAnySteering),
            0x0C => Some(Self::MptcpAnyAndLowLayerActiveStandby),
            0x0F => Some(Self::MptcpAnyAndLowLayerAny),
            _ => None,
        }
    }
}

/// ATSSS low-layer functionality support advertised in the 5GSM capability IE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AtsssLowLayerFunctionality {
    /// Not supported.
    NotSupported = 0x00,
    /// Active standby only.
    ActiveStandbyOnly = 0x01,
    /// Any steering.
    AnySteering = 0x02,
}

impl AtsssLowLayerFunctionality {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NotSupported),
            0x01 => Some(Self::ActiveStandbyOnly),
            0x02 => Some(Self::AnySteering),
            _ => None,
        }
    }
}

impl NasFGsmCongestionReAttemptIndicator {
    /// ABO (bit 1, mask 0x01) — back-off timer applied in all PLMNs/SNPNs vs registered only.
    /// TS 24.501 §9.11.4.21.
    pub fn abo(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// CATBO (bit 2, mask 0x02) — back-off timer applied in current access type vs both 3GPP
    /// and non-3GPP access types. TS 24.501 §9.11.4.21.
    pub fn catbo(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Build from both flags.
    pub fn from_flags(abo: bool, catbo: bool) -> Self {
        let mut b = 0u8;
        if abo {
            b |= 0x01;
        }
        if catbo {
            b |= 0x02;
        }
        Self::new(vec![b])
    }

    /// Backwards-compatible constructor for the ABO-only case.
    pub fn from_abo(abo: bool) -> Self {
        Self::from_flags(abo, false)
    }
}

impl NasFGsmNetworkFeatureSupport {
    /// EPT-S1 (bit 1, mask 0x01) — Ethernet PDU type over S1 mode supported.
    /// TS 24.501 §9.11.4.18.
    pub fn ept_s1(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// NAPS (bit 2, mask 0x02) — Non-3GPP access path switch supported.
    /// TS 24.501 §9.11.4.18.
    pub fn naps(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 1) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Build from both flags.
    pub fn from_flags(ept_s1: bool, naps: bool) -> Self {
        let mut b = 0u8;
        if ept_s1 {
            b |= 0x01;
        }
        if naps {
            b |= 0x02;
        }
        Self::new(vec![b])
    }

    /// Backwards-compatible constructor for the EPT-S1-only case.
    pub fn from_ept_s1(ept_s1: bool) -> Self {
        Self::from_flags(ept_s1, false)
    }
}

impl NasMappedNssai {
    /// Parse every complete mapped S-NSSAI entry.
    ///
    /// This IE only carries the SST-only and SST+SD entry forms. A framed but
    /// malformed value returns `None` instead of a valid prefix.
    pub fn try_parse_all(&self) -> Option<Vec<SNssaiContents>> {
        let mut entries = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() {
            let entry_len = usize::from(*self.value.get(pos)?);
            pos += 1;
            if entry_len != 1 && entry_len != 4 {
                return None;
            }
            let end = pos.checked_add(entry_len)?;
            let snssai = NasSNssai::new(self.value.get(pos..end)?.to_vec());
            entries.push(snssai.parse()?);
            pos = end;
        }
        (!entries.is_empty()).then_some(entries)
    }

    /// Parse the mapped S-NSSAIs, returning an empty list for malformed input.
    pub fn parse_all(&self) -> Vec<SNssaiContents> {
        self.try_parse_all().unwrap_or_default()
    }

    /// Build from one through eight mapped S-NSSAI entries.
    ///
    /// Returns `None` if any entry is not encoded as SST only or SST+SD.
    pub fn from_snssais(snssais: &[NasSNssai]) -> Option<Self> {
        if !(1..=8).contains(&snssais.len()) {
            return None;
        }
        let mut value = Vec::new();
        for s in snssais {
            if s.value.len() != 1 && s.value.len() != 4 || s.parse().is_none() {
                return None;
            }
            value.push(u8::try_from(s.value.len()).ok()?);
            value.extend_from_slice(&s.value);
        }
        Some(Self::new(value))
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.try_parse_all().is_some_and(|entries| {
            entries.len() <= 8
                && Self::from_snssais(
                    &entries
                        .iter()
                        .map(|entry| match entry.sd {
                            Some(sd) => NasSNssai::from_sst_sd(entry.sst, Some(sd)),
                            None => NasSNssai::from_sst_sd(entry.sst, None),
                        })
                        .collect::<Vec<_>>(),
                )
                .is_some_and(|canonical| canonical.value == self.value)
        })
    }
}

impl Default for NasNetworkName {
    /// Default: extension bit set, GSM 7-bit coding, no Add CI, no spare bits, empty name.
    fn default() -> Self {
        Self::new(vec![0x80])
    }
}

impl NasPduAddress {
    /// Typed PDU session type (bits 1-3 of first byte).
    pub fn session_type(&self) -> Option<PduSessionTypeValue> {
        match self.session_type_raw() {
            0x01 => Some(PduSessionTypeValue::IPv4),
            0x02 => Some(PduSessionTypeValue::IPv6),
            0x03 => Some(PduSessionTypeValue::IPv4v6),
            _ => None,
        }
    }

    /// PDU address-specific session type. Only IPv4, IPv6, and IPv4v6 are valid
    /// in TS 24.501 §9.11.4.10.
    pub fn address_type(&self) -> Option<PduAddressTypeValue> {
        PduAddressTypeValue::from_u8(self.session_type_raw())
    }

    /// Raw session type (bits 1-3 of first byte).
    pub fn session_type_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x07).unwrap_or(0)
    }

    /// IPv4 address (if type is IPv4 or IPv4v6).
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        match self.session_type() {
            Some(PduSessionTypeValue::IPv4) if self.value.len() >= 5 => {
                Some([self.value[1], self.value[2], self.value[3], self.value[4]])
            }
            Some(PduSessionTypeValue::IPv4v6) if self.value.len() >= 13 => Some([
                self.value[9],
                self.value[10],
                self.value[11],
                self.value[12],
            ]),
            _ => None,
        }
    }

    /// IPv6 interface identifier (8 bytes, if type is IPv6 or IPv4v6).
    pub fn ipv6_interface_id(&self) -> Option<&[u8]> {
        match self.session_type() {
            Some(PduSessionTypeValue::IPv6) if self.value.len() >= 9 => Some(&self.value[1..9]),
            Some(PduSessionTypeValue::IPv4v6) if self.value.len() >= 9 => Some(&self.value[1..9]),
            _ => None,
        }
    }

    fn smf_ipv6_link_local_address_offset(&self) -> Option<usize> {
        if !self.smf_ipv6_ll_indicator() {
            return None;
        }
        match self.session_type() {
            Some(PduSessionTypeValue::IPv4) if self.value.len() >= 21 => Some(5),
            Some(PduSessionTypeValue::IPv6) if self.value.len() >= 25 => Some(9),
            Some(PduSessionTypeValue::IPv4v6) if self.value.len() >= 29 => Some(13),
            _ => None,
        }
    }

    /// Optional SMF IPv6 link-local address (16 bytes).
    pub fn smf_ipv6_link_local_address(&self) -> Option<[u8; 16]> {
        let offset = self.smf_ipv6_link_local_address_offset()?;
        self.value
            .get(offset..offset + 16)
            .and_then(|bytes| bytes.try_into().ok())
    }

    /// Build an IPv4 PDU address.
    pub fn from_ipv4(addr: [u8; 4]) -> Self {
        let mut v = vec![PduSessionTypeValue::IPv4 as u8];
        v.extend_from_slice(&addr);
        Self::new(v)
    }

    /// Build an IPv6 PDU address from the interface identifier (8 bytes).
    pub fn from_ipv6_iid(iid: [u8; 8]) -> Self {
        let mut v = vec![PduSessionTypeValue::IPv6 as u8];
        v.extend_from_slice(&iid);
        Self::new(v)
    }

    /// Build an IPv4v6 PDU address from IPv6 interface identifier and IPv4 address.
    pub fn from_ipv4v6(iid: [u8; 8], ipv4: [u8; 4]) -> Self {
        let mut v = vec![PduSessionTypeValue::IPv4v6 as u8];
        v.extend_from_slice(&iid);
        v.extend_from_slice(&ipv4);
        Self::new(v)
    }

    /// SMF's IPv6 link-local address indicator (bit 4 of first byte) per TS 24.501 §9.11.4.10.
    pub fn smf_ipv6_ll_indicator(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 3) & 0x01 != 0)
            .unwrap_or(false)
    }

    /// Whether spare bits 5-8 of octet 3 are zero.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value.first().copied().unwrap_or(0) & 0xF0 == 0
    }

    /// Build an IPv4 PDU address with an additional SMF IPv6 link-local address.
    pub fn from_ipv4_with_smf_ipv6_link_local_address(
        addr: [u8; 4],
        smf_ipv6_link_local_address: [u8; 16],
    ) -> Self {
        let mut v = vec![(PduSessionTypeValue::IPv4 as u8) | 0x08];
        v.extend_from_slice(&addr);
        v.extend_from_slice(&smf_ipv6_link_local_address);
        Self::new(v)
    }

    /// Build an IPv6 PDU address with an additional SMF IPv6 link-local address.
    pub fn from_ipv6_iid_with_smf_ipv6_link_local_address(
        iid: [u8; 8],
        smf_ipv6_link_local_address: [u8; 16],
    ) -> Self {
        let mut v = vec![(PduSessionTypeValue::IPv6 as u8) | 0x08];
        v.extend_from_slice(&iid);
        v.extend_from_slice(&smf_ipv6_link_local_address);
        Self::new(v)
    }

    /// Build an IPv4v6 PDU address with an additional SMF IPv6 link-local address.
    pub fn from_ipv4v6_with_smf_ipv6_link_local_address(
        iid: [u8; 8],
        ipv4: [u8; 4],
        smf_ipv6_link_local_address: [u8; 16],
    ) -> Self {
        let mut v = vec![(PduSessionTypeValue::IPv4v6 as u8) | 0x08];
        v.extend_from_slice(&iid);
        v.extend_from_slice(&ipv4);
        v.extend_from_slice(&smf_ipv6_link_local_address);
        Self::new(v)
    }

    fn required_value_length(&self) -> Option<usize> {
        let first = *self.value.first()?;
        if first & 0xF0 != 0 {
            return None;
        }
        let base = match self.address_type()? {
            PduAddressTypeValue::IPv4 => 5,
            PduAddressTypeValue::IPv6 => 9,
            PduAddressTypeValue::IPv4v6 => 13,
        };
        Some(base + if first & 0x08 != 0 { 16 } else { 0 })
    }

    /// Whether the receiver can decode the defined prefix. Extra value octets
    /// are ignored under TS 24.007 §11.4.2.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.required_value_length()
            .is_some_and(|required| self.value.len() >= required)
    }

    /// Whether this is an exact sender encoding for the selected address type.
    pub fn is_well_formed(&self) -> bool {
        self.required_value_length() == Some(self.value.len())
    }
}

/// PDU address type value per TS 24.501 §9.11.4.10.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PduAddressTypeValue {
    /// I pv 4.
    IPv4 = 0x01,
    /// I pv 6.
    IPv6 = 0x02,
    /// I pv 4 v 6.
    IPv4v6 = 0x03,
}

impl PduAddressTypeValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0x01 => Some(Self::IPv4),
            0x02 => Some(Self::IPv6),
            0x03 => Some(Self::IPv4v6),
            _ => None,
        }
    }
}

impl NasPduSessionReactivationResult {
    /// Whether reactivation was unsuccessful or not performed for a PDU session in 1..=15.
    pub fn reactivation_failed(&self, session_id: u8) -> bool {
        if !(1..=15).contains(&session_id) {
            return false;
        }
        let byte_idx = (session_id / 8) as usize;
        let bit_idx = session_id % 8;
        self.value
            .get(byte_idx)
            .map(|byte| byte >> bit_idx & 1 != 0)
            .unwrap_or(false)
    }

    /// Sessions whose reactivation was unsuccessful or not performed.
    pub fn failed_sessions(&self) -> Vec<u8> {
        (1..=15)
            .filter(|session_id| self.reactivation_failed(*session_id))
            .collect()
    }

    /// Construct the failure bitmap from PDU session identities.
    pub fn from_failed_sessions(sessions: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        for &id in sessions {
            if (1..=15).contains(&id) {
                bytes[(id / 8) as usize] |= 1 << (id % 8);
            }
        }
        bytes[0] &= !0x01;
        Self::new(bytes.to_vec())
    }

    /// Deprecated semantic alias for reactivation_failed.
    #[deprecated(note = "PSI(x)=1 means reactivation failed; use reactivation_failed")]
    pub fn is_active(&self, session_id: u8) -> bool {
        self.reactivation_failed(session_id)
    }

    /// Deprecated semantic alias for failed_sessions.
    #[deprecated(note = "PSI(x)=1 means reactivation failed; use failed_sessions")]
    pub fn active_sessions(&self) -> Vec<u8> {
        self.failed_sessions()
    }

    /// Deprecated semantic alias for from_failed_sessions.
    #[deprecated(note = "PSI(x)=1 means reactivation failed; use from_failed_sessions")]
    pub fn from_sessions(sessions: &[u8]) -> Self {
        Self::from_failed_sessions(sessions)
    }
}

/// Rejected S-NSSAI cause per TS 24.501 §9.11.3.46.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RejectedNssaiCause {
    /// The S-NSSAI is unavailable in the current PLMN or SNPN.
    NotAvailableInPlmnOrSnpn = 0,
    /// The S-NSSAI is unavailable in the current registration area.
    NotAvailableInRegistrationArea = 1,
    /// Network-slice authentication and authorization failed or was revoked.
    AuthenticationOrAuthorizationFailedOrRevoked = 2,
}

impl RejectedNssaiCause {
    /// Decode the four-bit cause field; reserved values remain available via
    /// [`NasRejectedNssai::entries_raw`].
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NotAvailableInPlmnOrSnpn),
            1 => Some(Self::NotAvailableInRegistrationArea),
            2 => Some(Self::AuthenticationOrAuthorizationFailedOrRevoked),
            _ => None,
        }
    }
}

impl NasRejectedNssai {
    fn try_entries_raw(&self) -> Option<Vec<(u8, NasSNssai)>> {
        let mut result = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() {
            let header = *self.value.get(pos)?;
            let len = usize::from(header >> 4);
            let cause = header & 0x0f;
            pos += 1;
            if len != 1 && len != 4 {
                return None;
            }
            let end = pos.checked_add(len)?;
            let snssai = NasSNssai::new(self.value.get(pos..end)?.to_vec());
            snssai.parse()?;
            result.push((cause, snssai));
            pos = end;
        }
        (!result.is_empty()).then_some(result)
    }

    /// Parse up to the first eight defined rejected S-NSSAI entries.
    ///
    /// Reserved causes are omitted from this typed view and remain visible in
    /// [`Self::entries_raw`], as required for lossless receiver handling.
    pub fn entries(&self) -> Vec<(RejectedNssaiCause, SNssaiContents)> {
        self.try_entries_raw()
            .unwrap_or_default()
            .into_iter()
            .take(8)
            .filter_map(|(cause, snssai)| {
                Some((RejectedNssaiCause::from_u8(cause)?, snssai.parse()?))
            })
            .collect()
    }

    /// Parse up to the first eight entries while preserving reserved cause values.
    pub fn entries_raw(&self) -> Vec<(u8, SNssaiContents)> {
        self.try_entries_raw()
            .unwrap_or_default()
            .into_iter()
            .take(8)
            .filter_map(|(cause, snssai)| Some((cause, snssai.parse()?)))
            .collect()
    }

    /// Build from one through eight typed `(cause, S-NSSAI)` pairs.
    pub fn from_entries(entries: &[(RejectedNssaiCause, &NasSNssai)]) -> Option<Self> {
        let raw = entries
            .iter()
            .map(|(cause, snssai)| (*cause as u8, *snssai))
            .collect::<Vec<_>>();
        Self::from_entries_raw(&raw)
    }

    /// Build from one through eight raw `(cause, S-NSSAI)` pairs.
    ///
    /// Reserved cause values are rejected for senders.
    pub fn from_entries_raw(entries: &[(u8, &NasSNssai)]) -> Option<Self> {
        if !(1..=8).contains(&entries.len()) {
            return None;
        }
        let mut value = Vec::new();
        for &(cause, snssai) in entries {
            let len = snssai.value.len();
            if RejectedNssaiCause::from_u8(cause).is_none()
                || (len != 1 && len != 4)
                || snssai.parse().is_none()
            {
                return None;
            }
            value.push((u8::try_from(len).ok()? << 4) | cause);
            value.extend_from_slice(&snssai.value);
        }
        Some(Self::new(value))
    }

    /// Whether this is a canonical sender encoding with at most eight entries.
    pub fn is_well_formed(&self) -> bool {
        self.try_entries_raw().is_some_and(|entries| {
            entries.len() <= 8
                && entries
                    .iter()
                    .all(|(cause, _)| RejectedNssaiCause::from_u8(*cause).is_some())
        })
    }

    /// Whether a receiver can parse the complete list framing.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.try_entries_raw().is_some()
    }
}

crate::common::ts24501::ue_status_ie!(NasUeStatus);

impl NasUeUsageSetting {
    /// UE usage setting (bit 1): 0=voice centric, 1=data centric.
    pub fn data_centric(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from data centric.
    pub fn from_data_centric(data_centric: bool) -> Self {
        Self::new(vec![if data_centric { 0x01 } else { 0x00 }])
    }
}

impl NasUplinkDataStatus {
    /// Whether a given assigned PSI bit (`1..=15`) has pending uplink data.
    pub fn has_data(&self, session_id: u8) -> bool {
        if !(1..=15).contains(&session_id) {
            return false;
        }
        let byte_idx = (session_id / 8) as usize;
        let bit_idx = session_id % 8;
        self.value
            .get(byte_idx)
            .map(|b| (b >> bit_idx) & 1 != 0)
            .unwrap_or(false)
    }

    /// Return sessions with data.
    pub fn sessions_with_data(&self) -> Vec<u8> {
        (1..=15).filter(|&id| self.has_data(id)).collect()
    }

    /// Construct a value from sessions.
    pub fn from_sessions(sessions: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        for &id in sessions {
            if (1..=15).contains(&id) {
                bytes[(id / 8) as usize] |= 1 << (id % 8);
            }
        }
        bytes[0] &= !0x01;
        Self::new(bytes.to_vec())
    }

    /// Whether this value is canonical for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 2 && self.value[0] & 0x01 == 0
    }
}

crate::common::nas_ie_flags!(NasReAttemptIndicator {
    /// Whether retry in the current cell/tracking area is forbidden
    /// (TS 24.008 §10.5.5.30, bit 1).
    ratc_not_allowed: 0, 1;
    /// Whether retry in an equivalent PLMN is forbidden (bit 2).
    eplmnc_not_allowed: 0, 2;
});

impl NasReAttemptIndicator {
    /// Build from spec-polarity flags: `eplmnc_not_allowed`, `ratc_not_allowed`.
    pub fn from_flags(eplmnc_not_allowed: bool, ratc_not_allowed: bool) -> Self {
        let mut v: u8 = 0;
        if eplmnc_not_allowed {
            v |= 0x02;
        }
        if ratc_not_allowed {
            v |= 0x01;
        }
        Self::new(vec![v])
    }

    /// Sender check: one octet with all six spare bits clear.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0xfc == 0)
    }
}

/// Redundant sequence number per TS 24.501 §9.11.4.33.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RsnValue {
    /// RSN version 1.
    V1 = 0x00,
    /// RSN version 2.
    V2 = 0x01,
}

impl RsnValue {
    /// Parse the raw RSN octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::V1),
            0x01 => Some(Self::V2),
            _ => None,
        }
    }
}

impl NasRsn {
    /// Typed RSN value.
    pub fn rsn(&self) -> Option<RsnValue> {
        self.value.first().and_then(|b| RsnValue::from_u8(*b))
    }

    /// Raw RSN value.
    pub fn rsn_raw(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// Construct a value from rsn.
    pub fn from_rsn(rsn: RsnValue) -> Self {
        Self::new(vec![rsn as u8])
    }

    /// Construct a value from rsn raw.
    pub fn from_rsn_raw(rsn: u8) -> Self {
        Self::new(vec![rsn])
    }
}

/// Paging restriction decision per TS 24.501 §9.11.3.81.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PagingRestrictionDecision {
    /// No additional information.
    NoAdditionalInfo = 0x00,
    /// Paging restriction is accepted.
    PagingRestrictionAccepted = 0x01,
    /// Paging restriction is rejected.
    PagingRestrictionRejected = 0x02,
}

impl PagingRestrictionDecision {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NoAdditionalInfo),
            0x01 => Some(Self::PagingRestrictionAccepted),
            0x02 => Some(Self::PagingRestrictionRejected),
            _ => None,
        }
    }
}

impl NasFGsAdditionalRequestResult {
    /// Typed PRD: Paging restriction decision (bits 1-2).
    pub fn prd(&self) -> Option<PagingRestrictionDecision> {
        self.value
            .first()
            .and_then(|b| PagingRestrictionDecision::from_u8(b & 0x03))
    }

    /// Raw PRD value (bits 1-2).
    pub fn prd_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x03).unwrap_or(0)
    }

    /// Construct a value from prd.
    pub fn from_prd(prd: PagingRestrictionDecision) -> Self {
        Self::new(vec![prd as u8])
    }
}

crate::common::ts24301::ue_network_capability_ie!(NasS1UeNetworkCapability);
crate::common::ts24301::ue_security_capability_ie!(
    NasS1UeSecurityCapability,
    NasS1UeNetworkCapability
);

// ============================================================================
// Remaining TLV / TLV-E / LV-E IE accessors
// ============================================================================

// ── Authentication IEs ───────────────────────────────────────────────────────

crate::common::ts24008::authentication_parameter_autn_ie!(NasAuthenticationParameterAutn);
crate::common::ts24301::authentication_response_parameter_ie!(NasAuthenticationResponseParameter);
crate::common::ts24008::authentication_failure_parameter_ie!(NasAuthenticationFailureParameter);

// ── EAP / NAS container IEs ─────────────────────────────────────────────────

/// EAP code per RFC 3748 §4.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EapCode {
    /// Request.
    Request = 1,
    /// Response.
    Response = 2,
    /// Success.
    Success = 3,
    /// Failure.
    Failure = 4,
    /// Initiate (RFC 5296 §3.2 — ERP Initiate).
    Initiate = 5,
    /// Finish (RFC 5296 §3.2 — ERP Finish).
    Finish = 6,
}

impl EapCode {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            5 => Some(Self::Initiate),
            6 => Some(Self::Finish),
            _ => None,
        }
    }
}

impl NasEapMessage {
    /// Check the EAP packet size and its internal length (TS 24.501 §9.11.2.2).
    pub fn validate_strict(&self) -> Result<()> {
        if !(4..=1500).contains(&self.value.len())
            || self.eap_length() != Some(self.value.len() as u16)
        {
            return Err(NasError::DecodingError(
                "EAP message must contain 4–1500 octets with a matching EAP length".into(),
            ));
        }
        Ok(())
    }

    /// The raw EAP message bytes (RFC 3748).
    pub fn eap_data(&self) -> &[u8] {
        &self.value
    }

    /// EAP code (first byte).
    pub fn eap_code(&self) -> Option<EapCode> {
        self.value.first().and_then(|&b| EapCode::from_u8(b))
    }

    /// EAP identifier.
    pub fn eap_identifier(&self) -> Option<u8> {
        self.value.get(1).copied()
    }

    /// EAP length field (bytes 2-3, big-endian, per RFC 3748 §4).
    pub fn eap_length(&self) -> Option<u16> {
        if self.value.len() >= 4 {
            Some(u16::from_be_bytes([self.value[2], self.value[3]]))
        } else {
            None
        }
    }

    /// Build from raw EAP bytes.
    pub fn from_eap_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasEpsNasMessageContainer {
    /// The encapsulated EPS NAS message bytes.
    pub fn eps_nas_data(&self) -> &[u8] {
        &self.value
    }

    /// Build from EPS NAS message bytes.
    pub fn from_eps_nas_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Decode the carried EPS NAS message (TS 24.501 §8.2.6.16, §9.11.3.24).
    ///
    /// The container carries a complete ATTACH REQUEST or TRACKING AREA
    /// UPDATE REQUEST, integrity protected with the EPS security context.
    /// Other EPS messages are rejected. Verify the MAC with
    /// `nas_eps::NasSecurityContext` (feature `security`) when the EPS keys are
    /// known. TS 24.501 §7.5.2 limits the AMF's own diagnosis of this IE to
    /// presence and length, so a decoding error does not by itself make the
    /// REGISTRATION REQUEST invalid.
    pub fn decode_as_eps_message(&self) -> crate::common::Result<crate::nas_eps::NasEpsMessage> {
        let message = crate::nas_eps::decode_nas_eps_message_with_direction(
            &self.value,
            crate::common::Direction::Uplink,
        )?;
        if eps_container_message_is_supported(&message) {
            Ok(message)
        } else {
            Err(crate::common::NasError::DecodingError(
                "EPS NAS message container requires an ATTACH or TRACKING AREA UPDATE REQUEST"
                    .into(),
            ))
        }
    }

    /// Build a container from an integrity protected ATTACH REQUEST or
    /// TRACKING AREA UPDATE REQUEST.
    pub fn from_eps_message(
        message: &crate::nas_eps::NasEpsMessage,
    ) -> crate::common::Result<Self> {
        if !eps_container_message_is_supported(message) {
            return Err(crate::common::NasError::EncodingError(
                "EPS NAS message container requires an ATTACH or TRACKING AREA UPDATE REQUEST"
                    .into(),
            ));
        }
        Ok(Self::new(crate::nas_eps::encode_nas_eps_message(message)?))
    }
}

/// Whether an EPS PDU is a request that TS 24.501 §8.2.6.16 allows in the
/// EPS NAS message container. The plain form is accepted for receive
/// tolerance; senders use the integrity protected form.
fn eps_container_message_is_supported(message: &crate::nas_eps::NasEpsMessage) -> bool {
    use crate::nas_eps::{NasEmmMessage, NasEpsMessage, NasEpsSecurityHeaderType};
    let inner = match message {
        NasEpsMessage::SecurityProtected(header, inner)
            if header.security_header_type == NasEpsSecurityHeaderType::IntegrityProtected =>
        {
            inner.as_ref()
        }
        plain => plain,
    };
    matches!(
        inner,
        NasEpsMessage::Emm(
            _,
            NasEmmMessage::AttachRequest(_) | NasEmmMessage::TrackingAreaUpdateRequest(_)
        )
    )
}

/// QoS rule operation code per TS 24.501 §9.11.4.13.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum QosRuleOpCode {
    /// 000 — Reserved.
    Reserved = 0,
    /// 001 — Create new QoS rule.
    Create = 1,
    /// 010 — Delete existing QoS rule.
    Delete = 2,
    /// 011 — Modify existing QoS rule and add packet filters.
    ModifyAdd = 3,
    /// 100 — Modify existing QoS rule and replace all packet filters.
    ModifyReplace = 4,
    /// 101 — Modify existing QoS rule and delete packet filters.
    ModifyDelete = 5,
    /// 110 — Modify existing QoS rule without modifying packet filters.
    ModifyNoFilters = 6,
    /// 111 — Reserved.
    ReservedHigh = 7,
}

impl QosRuleOpCode {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x07 {
            0 => Self::Reserved,
            1 => Self::Create,
            2 => Self::Delete,
            3 => Self::ModifyAdd,
            4 => Self::ModifyReplace,
            5 => Self::ModifyDelete,
            6 => Self::ModifyNoFilters,
            _ => Self::ReservedHigh,
        }
    }
}

/// Packet filter direction in a QoS rule per TS 24.501 §9.11.4.13.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum QosPacketFilterDirection {
    /// Reserved.
    Reserved = 0,
    /// Downlink only.
    Downlink = 1,
    /// Uplink only.
    Uplink = 2,
    /// Bidirectional.
    Bidirectional = 3,
}

impl QosPacketFilterDirection {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x03 {
            0 => Self::Reserved,
            1 => Self::Downlink,
            2 => Self::Uplink,
            _ => Self::Bidirectional,
        }
    }
}

/// One decoded `(S)RTP multiplexed media identification information` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QosSrtpMultiplexedMediaIdentificationInformationEntry {
    /// SSRC field when present.
    pub ssrc: Option<u32>,
    /// Payload type field when present.
    pub payload_type: Option<u8>,
    /// MID identification tag when present.
    pub mid_identification_tag: Option<Vec<u8>>,
    /// RTP SDES header extension identifier bytes when present.
    pub rtp_sdes_header_extension_id: Option<Vec<u8>>,
    /// RTCP packet type when present.
    pub rtcp_packet_type: Option<u8>,
}

/// One packet-filter component inside a QoS rule per TS 24.501 §9.11.4.13.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QosPacketFilterComponent {
    /// Match all.
    MatchAll,
    /// Ipv 4 remote address.
    Ipv4RemoteAddress {
        /// Address.
        address: [u8; 4],
        /// Mask.
        mask: [u8; 4],
    },
    /// Ipv 4 local address.
    Ipv4LocalAddress {
        /// Address.
        address: [u8; 4],
        /// Mask.
        mask: [u8; 4],
    },
    /// Ipv 6 remote address prefix.
    Ipv6RemoteAddressPrefix {
        /// Address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// Ipv 6 local address prefix.
    Ipv6LocalAddressPrefix {
        /// Address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// Protocol identifier or next header.
    ProtocolIdentifierOrNextHeader(u8),
    /// Single local port.
    SingleLocalPort(u16),
    /// Local port range.
    LocalPortRange {
        /// Low.
        low: u16,
        /// High.
        high: u16,
    },
    /// Single remote port.
    SingleRemotePort(u16),
    /// Remote port range.
    RemotePortRange {
        /// Low.
        low: u16,
        /// High.
        high: u16,
    },
    /// Security parameter index.
    SecurityParameterIndex(u32),
    /// Type of service or traffic class.
    TypeOfServiceOrTrafficClass {
        /// Raw information-element contents.
        value: u8,
        /// Mask.
        mask: u8,
    },
    /// Flow label.
    FlowLabel([u8; 3]),
    /// Destination mac address.
    DestinationMacAddress([u8; 6]),
    /// Source mac address.
    SourceMacAddress([u8; 6]),
    /// C tag vid.
    CTagVid(u16),
    /// S tag vid.
    STagVid(u16),
    /// C tag pcp dei.
    CTagPcpDei {
        /// Pcp present.
        pcp_present: bool,
        /// Dei present.
        dei_present: bool,
        /// Pcp.
        pcp: u8,
        /// Dei.
        dei: bool,
    },
    /// S tag pcp dei.
    STagPcpDei {
        /// Pcp present.
        pcp_present: bool,
        /// Dei present.
        dei_present: bool,
        /// Pcp.
        pcp: u8,
        /// Dei.
        dei: bool,
    },
    /// Extended c tag pcp dei.
    ExtendedCTagPcpDei {
        /// Pcp present.
        pcp_present: bool,
        /// Dei present.
        dei_present: bool,
        /// Pcp.
        pcp: u8,
        /// Dei.
        dei: bool,
    },
    /// Extended s tag pcp dei.
    ExtendedSTagPcpDei {
        /// Pcp present.
        pcp_present: bool,
        /// Dei present.
        dei_present: bool,
        /// Pcp.
        pcp: u8,
        /// Dei.
        dei: bool,
    },
    /// Ethertype.
    Ethertype(u16),
    /// Destination mac address range.
    DestinationMacAddressRange {
        /// Low.
        low: [u8; 6],
        /// High.
        high: [u8; 6],
    },
    /// Source mac address range.
    SourceMacAddressRange {
        /// Low.
        low: [u8; 6],
        /// High.
        high: [u8; 6],
    },
    /// Srtp multiplexed media identification information.
    SrtpMultiplexedMediaIdentificationInformation {
        /// Entries.
        entries: Vec<QosSrtpMultiplexedMediaIdentificationInformationEntry>,
    },
    /// Unknown.
    Unknown {
        /// Component type.
        component_type: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

/// One packet filter inside a QoS rule per TS 24.501 §9.11.4.13.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QosPacketFilter {
    /// Packet filter identifier only, used by "modify existing QoS rule and delete packet filters".
    Delete {
        /// Packet-filter identifier.
        identifier: u8,
    },
    /// Packet filter with direction, identifier, and decoded component list.
    Match {
        /// Direction.
        direction: QosPacketFilterDirection,
        /// Identifier.
        identifier: u8,
        /// Components.
        components: Vec<QosPacketFilterComponent>,
    },
}

impl QosPacketFilter {
    /// Return identifier.
    pub fn identifier(&self) -> u8 {
        match self {
            Self::Delete { identifier } | Self::Match { identifier, .. } => *identifier,
        }
    }
}

fn qos_packet_filter_components_are_semantically_valid(
    components: &[QosPacketFilterComponent],
) -> bool {
    if components.is_empty() {
        return false;
    }
    if components
        .iter()
        .any(|component| matches!(component, QosPacketFilterComponent::MatchAll))
    {
        return components.len() == 1;
    }

    let mut address_family = None;
    let mut ipv4_remote = false;
    let mut ipv4_local = false;
    let mut ipv6_remote = false;
    let mut ipv6_local = false;
    let mut protocol = false;
    let mut local_port = false;
    let mut remote_port = false;
    let mut spi = false;
    let mut tos = false;
    let mut flow_label = false;
    let mut dst_mac = false;
    let mut src_mac = false;
    let mut ctag_vid = false;
    let mut stag_vid = false;
    let mut ctag_pcp_dei = false;
    let mut stag_pcp_dei = false;
    let mut ethertype = false;
    let mut srtp_info = false;

    for component in components {
        match component {
            QosPacketFilterComponent::MatchAll => return false,
            QosPacketFilterComponent::Ipv4RemoteAddress { .. } => {
                if ipv4_remote || address_family == Some(6) {
                    return false;
                }
                ipv4_remote = true;
                address_family = Some(4);
            }
            QosPacketFilterComponent::Ipv4LocalAddress { .. } => {
                if ipv4_local || address_family == Some(6) {
                    return false;
                }
                ipv4_local = true;
                address_family = Some(4);
            }
            QosPacketFilterComponent::Ipv6RemoteAddressPrefix { prefix_length, .. } => {
                if ipv6_remote || address_family == Some(4) || *prefix_length > 128 {
                    return false;
                }
                ipv6_remote = true;
                address_family = Some(6);
            }
            QosPacketFilterComponent::Ipv6LocalAddressPrefix { prefix_length, .. } => {
                if ipv6_local || address_family == Some(4) || *prefix_length > 128 {
                    return false;
                }
                ipv6_local = true;
                address_family = Some(6);
            }
            QosPacketFilterComponent::ProtocolIdentifierOrNextHeader(_) => {
                if protocol {
                    return false;
                }
                protocol = true;
            }
            QosPacketFilterComponent::SingleLocalPort(_)
            | QosPacketFilterComponent::LocalPortRange { .. } => {
                if local_port {
                    return false;
                }
                if let QosPacketFilterComponent::LocalPortRange { low, high } = component
                    && low > high
                {
                    return false;
                }
                local_port = true;
            }
            QosPacketFilterComponent::SingleRemotePort(_)
            | QosPacketFilterComponent::RemotePortRange { .. } => {
                if remote_port {
                    return false;
                }
                if let QosPacketFilterComponent::RemotePortRange { low, high } = component
                    && low > high
                {
                    return false;
                }
                remote_port = true;
            }
            QosPacketFilterComponent::SecurityParameterIndex(_) => {
                if spi {
                    return false;
                }
                spi = true;
            }
            QosPacketFilterComponent::TypeOfServiceOrTrafficClass { .. } => {
                if tos {
                    return false;
                }
                tos = true;
            }
            QosPacketFilterComponent::FlowLabel(value) => {
                if flow_label || value[0] & 0xF0 != 0 {
                    return false;
                }
                flow_label = true;
            }
            QosPacketFilterComponent::DestinationMacAddress(_)
            | QosPacketFilterComponent::DestinationMacAddressRange { .. } => {
                if dst_mac {
                    return false;
                }
                dst_mac = true;
            }
            QosPacketFilterComponent::SourceMacAddress(_)
            | QosPacketFilterComponent::SourceMacAddressRange { .. } => {
                if src_mac {
                    return false;
                }
                src_mac = true;
            }
            QosPacketFilterComponent::CTagVid(_) => {
                if ctag_vid {
                    return false;
                }
                ctag_vid = true;
            }
            QosPacketFilterComponent::STagVid(_) => {
                if stag_vid {
                    return false;
                }
                stag_vid = true;
            }
            QosPacketFilterComponent::CTagPcpDei { .. }
            | QosPacketFilterComponent::ExtendedCTagPcpDei { .. } => {
                if ctag_pcp_dei {
                    return false;
                }
                ctag_pcp_dei = true;
            }
            QosPacketFilterComponent::STagPcpDei { .. }
            | QosPacketFilterComponent::ExtendedSTagPcpDei { .. } => {
                if stag_pcp_dei {
                    return false;
                }
                stag_pcp_dei = true;
            }
            QosPacketFilterComponent::Ethertype(_) => {
                if ethertype {
                    return false;
                }
                ethertype = true;
            }
            QosPacketFilterComponent::SrtpMultiplexedMediaIdentificationInformation { entries } => {
                if srtp_info || entries.is_empty() {
                    return false;
                }
                if entries.iter().any(|entry| {
                    entry.ssrc.is_none()
                        && entry.payload_type.is_none()
                        && entry.mid_identification_tag.is_none()
                        && entry.rtp_sdes_header_extension_id.is_none()
                        && entry.rtcp_packet_type.is_none()
                }) {
                    return false;
                }
                if entries
                    .iter()
                    .filter_map(|entry| entry.payload_type)
                    .any(|payload_type| payload_type > 127)
                {
                    return false;
                }
                srtp_info = true;
            }
            QosPacketFilterComponent::Unknown { .. } => return false,
        }
    }

    true
}

fn qos_rule_is_semantically_valid(rule: &QosRule) -> bool {
    if rule.qfi.is_some_and(|qfi| qfi == 0 || qfi > 63) {
        return false;
    }

    let mut identifiers = [false; 16];
    for packet_filter in &rule.packet_filters {
        let identifier = packet_filter.identifier();
        if identifier == 0 || identifier > 15 || identifiers[identifier as usize] {
            return false;
        }
        identifiers[identifier as usize] = true;

        if let QosPacketFilter::Match {
            direction,
            components,
            ..
        } = packet_filter
            && (matches!(direction, QosPacketFilterDirection::Reserved)
                || !qos_packet_filter_components_are_semantically_valid(components))
        {
            return false;
        }
    }

    true
}

/// One QoS rule per TS 24.501 §9.11.4.13.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QosRule {
    /// QoS rule identifier (octet 4 of the rule).
    pub rule_id: u8,
    /// Rule operation code (3 bits).
    pub op_code: QosRuleOpCode,
    /// DQR — default QoS rule indicator (bit 5 of the header octet, mask 0x10).
    pub dqr: bool,
    /// Packet filter list. Empty for "delete existing" and "modify without filters".
    pub packet_filters: Vec<QosPacketFilter>,
    /// QoS rule precedence (octet z+1).
    pub precedence: Option<u8>,
    /// QoS Flow Identifier (lower 6 bits of octet z+2).
    pub qfi: Option<u8>,
    /// Raw segregation bit from octet z+2. This bit is only interpreted on uplink.
    pub segregation: Option<bool>,
}

fn copy_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() < N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[..N]);
    Some(out)
}

fn hex_digit_char(value: u8) -> char {
    match value & 0x0F {
        0..=9 => (b'0' + (value & 0x0F)) as char,
        value => (b'a' + (value - 10)) as char,
    }
}

fn hex_digit_value(ch: char) -> Option<u8> {
    match ch {
        '0'..='9' => Some(ch as u8 - b'0'),
        'a'..='f' => Some(ch as u8 - b'a' + 10),
        'A'..='F' => Some(ch as u8 - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_digit_string(bytes: &[u8]) -> String {
    let mut digits = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        digits.push(hex_digit_char(byte & 0x0F));
        digits.push(hex_digit_char((byte >> 4) & 0x0F));
    }
    digits
}

fn parse_qos_srtp_entries(
    data: &[u8],
) -> Option<Vec<QosSrtpMultiplexedMediaIdentificationInformationEntry>> {
    let entry_count = *data.first()? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    let mut pos = 1;
    for _ in 0..entry_count {
        if pos >= data.len() {
            return None;
        }
        let entry_len = data[pos] as usize;
        pos += 1;
        if pos + entry_len > data.len() || entry_len == 0 {
            return None;
        }
        let entry_end = pos + entry_len;
        let flags = data[pos];
        pos += 1;

        let ssrc = if flags & 0x01 != 0 {
            let value = u32::from_be_bytes(copy_array::<4>(&data[pos..entry_end])?);
            pos += 4;
            Some(value)
        } else {
            None
        };

        let payload_type = if flags & 0x02 != 0 {
            let value = *data.get(pos)?;
            pos += 1;
            Some(value)
        } else {
            None
        };

        let mid_identification_tag = if flags & 0x04 != 0 {
            let len = *data.get(pos)? as usize;
            pos += 1;
            if pos + len > entry_end {
                return None;
            }
            let tag = data[pos..pos + len].to_vec();
            pos += len;
            Some(tag)
        } else {
            None
        };

        let rtp_sdes_header_extension_id = if flags & 0x08 != 0 {
            let trailing_rtcp_len = usize::from(flags & 0x10 != 0);
            if pos + trailing_rtcp_len > entry_end {
                return None;
            }
            let len = entry_end.saturating_sub(pos + trailing_rtcp_len);
            let value = data[pos..pos + len].to_vec();
            pos += len;
            Some(value)
        } else {
            None
        };

        let rtcp_packet_type = if flags & 0x10 != 0 {
            let value = *data.get(pos)?;
            pos += 1;
            Some(value)
        } else {
            None
        };

        if pos != entry_end {
            return None;
        }

        entries.push(QosSrtpMultiplexedMediaIdentificationInformationEntry {
            ssrc,
            payload_type,
            mid_identification_tag,
            rtp_sdes_header_extension_id,
            rtcp_packet_type,
        });
    }

    if pos == data.len() {
        Some(entries)
    } else {
        None
    }
}

fn encode_qos_srtp_entries(
    entries: &[QosSrtpMultiplexedMediaIdentificationInformationEntry],
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.push(entries.len().try_into().ok()?);
    for entry in entries {
        let mut flags = 0u8;
        let mut body = Vec::new();
        if let Some(ssrc) = entry.ssrc {
            flags |= 0x01;
            body.extend_from_slice(&ssrc.to_be_bytes());
        }
        if let Some(payload_type) = entry.payload_type {
            flags |= 0x02;
            body.push(payload_type);
        }
        if let Some(mid) = &entry.mid_identification_tag {
            flags |= 0x04;
            body.push(mid.len().try_into().ok()?);
            body.extend_from_slice(mid);
        }
        if let Some(id) = &entry.rtp_sdes_header_extension_id {
            flags |= 0x08;
            body.extend_from_slice(id);
        }
        if let Some(rtcp_packet_type) = entry.rtcp_packet_type {
            flags |= 0x10;
            body.push(rtcp_packet_type);
        }
        out.push((1 + body.len()).try_into().ok()?);
        out.push(flags);
        out.extend_from_slice(&body);
    }
    Some(out)
}

fn parse_qos_packet_filter_components(data: &[u8]) -> Option<Vec<QosPacketFilterComponent>> {
    let mut components = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let component_type = data[pos];
        pos += 1;
        let component = match component_type {
            0x01 => QosPacketFilterComponent::MatchAll,
            0x10 => {
                let address = copy_array::<4>(&data[pos..])?;
                pos += 4;
                let mask = copy_array::<4>(&data[pos..])?;
                pos += 4;
                QosPacketFilterComponent::Ipv4RemoteAddress { address, mask }
            }
            0x11 => {
                let address = copy_array::<4>(&data[pos..])?;
                pos += 4;
                let mask = copy_array::<4>(&data[pos..])?;
                pos += 4;
                QosPacketFilterComponent::Ipv4LocalAddress { address, mask }
            }
            0x21 => {
                let address = copy_array::<16>(&data[pos..])?;
                pos += 16;
                let prefix_length = *data.get(pos)?;
                pos += 1;
                QosPacketFilterComponent::Ipv6RemoteAddressPrefix {
                    address,
                    prefix_length,
                }
            }
            0x23 => {
                let address = copy_array::<16>(&data[pos..])?;
                pos += 16;
                let prefix_length = *data.get(pos)?;
                pos += 1;
                QosPacketFilterComponent::Ipv6LocalAddressPrefix {
                    address,
                    prefix_length,
                }
            }
            0x30 => {
                let value = *data.get(pos)?;
                pos += 1;
                QosPacketFilterComponent::ProtocolIdentifierOrNextHeader(value)
            }
            0x40 => {
                let value = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::SingleLocalPort(value)
            }
            0x41 => {
                let low = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                let high = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::LocalPortRange { low, high }
            }
            0x50 => {
                let value = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::SingleRemotePort(value)
            }
            0x51 => {
                let low = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                let high = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::RemotePortRange { low, high }
            }
            0x60 => {
                let value = u32::from_be_bytes(copy_array::<4>(&data[pos..])?);
                pos += 4;
                QosPacketFilterComponent::SecurityParameterIndex(value)
            }
            0x70 => {
                let value = *data.get(pos)?;
                let mask = *data.get(pos + 1)?;
                pos += 2;
                QosPacketFilterComponent::TypeOfServiceOrTrafficClass { value, mask }
            }
            0x80 => {
                let value = copy_array::<3>(&data[pos..])?;
                pos += 3;
                QosPacketFilterComponent::FlowLabel(value)
            }
            0x81 => {
                let value = copy_array::<6>(&data[pos..])?;
                pos += 6;
                QosPacketFilterComponent::DestinationMacAddress(value)
            }
            0x82 => {
                let value = copy_array::<6>(&data[pos..])?;
                pos += 6;
                QosPacketFilterComponent::SourceMacAddress(value)
            }
            0x83 => {
                let value = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::CTagVid(value)
            }
            0x84 => {
                let value = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::STagVid(value)
            }
            0x85 | 0x86 => {
                let value = *data.get(pos)?;
                pos += 1;
                let pcp = (value & 0x0E) >> 1;
                let dei = value & 0x01 != 0;
                if component_type == 0x85 {
                    QosPacketFilterComponent::CTagPcpDei {
                        pcp_present: true,
                        dei_present: true,
                        pcp,
                        dei,
                    }
                } else {
                    QosPacketFilterComponent::STagPcpDei {
                        pcp_present: true,
                        dei_present: true,
                        pcp,
                        dei,
                    }
                }
            }
            0x8A | 0x8B => {
                let value = *data.get(pos)?;
                pos += 1;
                let pcp_present = value & 0x20 != 0;
                let dei_present = value & 0x10 != 0;
                let pcp = if pcp_present { (value & 0x0E) >> 1 } else { 0 };
                let dei = dei_present && value & 0x01 != 0;
                if component_type == 0x8A {
                    QosPacketFilterComponent::ExtendedCTagPcpDei {
                        pcp_present,
                        dei_present,
                        pcp,
                        dei,
                    }
                } else {
                    QosPacketFilterComponent::ExtendedSTagPcpDei {
                        pcp_present,
                        dei_present,
                        pcp,
                        dei,
                    }
                }
            }
            0x87 => {
                let value = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                QosPacketFilterComponent::Ethertype(value)
            }
            0x88 => {
                let low = copy_array::<6>(&data[pos..])?;
                pos += 6;
                let high = copy_array::<6>(&data[pos..])?;
                pos += 6;
                QosPacketFilterComponent::DestinationMacAddressRange { low, high }
            }
            0x89 => {
                let low = copy_array::<6>(&data[pos..])?;
                pos += 6;
                let high = copy_array::<6>(&data[pos..])?;
                pos += 6;
                QosPacketFilterComponent::SourceMacAddressRange { low, high }
            }
            0x91 => {
                let entries = parse_qos_srtp_entries(&data[pos..])?;
                pos = data.len();
                QosPacketFilterComponent::SrtpMultiplexedMediaIdentificationInformation { entries }
            }
            _ => {
                let contents = data[pos..].to_vec();
                pos = data.len();
                QosPacketFilterComponent::Unknown {
                    component_type,
                    contents,
                }
            }
        };
        components.push(component);
    }
    Some(components)
}

fn qos_packet_filter_component_len(component: &QosPacketFilterComponent) -> Option<usize> {
    Some(match component {
        QosPacketFilterComponent::MatchAll => 1,
        QosPacketFilterComponent::Ipv4RemoteAddress { .. }
        | QosPacketFilterComponent::Ipv4LocalAddress { .. } => 1 + 8,
        QosPacketFilterComponent::Ipv6RemoteAddressPrefix { .. }
        | QosPacketFilterComponent::Ipv6LocalAddressPrefix { .. } => 1 + 17,
        QosPacketFilterComponent::ProtocolIdentifierOrNextHeader(_) => 1 + 1,
        QosPacketFilterComponent::SingleLocalPort(_)
        | QosPacketFilterComponent::SingleRemotePort(_) => 1 + 2,
        QosPacketFilterComponent::LocalPortRange { .. }
        | QosPacketFilterComponent::RemotePortRange { .. } => 1 + 4,
        QosPacketFilterComponent::SecurityParameterIndex(_) => 1 + 4,
        QosPacketFilterComponent::TypeOfServiceOrTrafficClass { .. } => 1 + 2,
        QosPacketFilterComponent::FlowLabel(_) => 1 + 3,
        QosPacketFilterComponent::DestinationMacAddress(_)
        | QosPacketFilterComponent::SourceMacAddress(_) => 1 + 6,
        QosPacketFilterComponent::CTagVid(_) | QosPacketFilterComponent::STagVid(_) => 1 + 2,
        QosPacketFilterComponent::CTagPcpDei { .. }
        | QosPacketFilterComponent::STagPcpDei { .. }
        | QosPacketFilterComponent::ExtendedCTagPcpDei { .. }
        | QosPacketFilterComponent::ExtendedSTagPcpDei { .. } => 1 + 1,
        QosPacketFilterComponent::Ethertype(_) => 1 + 2,
        QosPacketFilterComponent::DestinationMacAddressRange { .. }
        | QosPacketFilterComponent::SourceMacAddressRange { .. } => 1 + 12,
        QosPacketFilterComponent::SrtpMultiplexedMediaIdentificationInformation { entries } => {
            1 + encode_qos_srtp_entries(entries)?.len()
        }
        QosPacketFilterComponent::Unknown { contents, .. } => 1 + contents.len(),
    })
}

fn encode_qos_packet_filter_component(
    out: &mut Vec<u8>,
    component: &QosPacketFilterComponent,
) -> Option<()> {
    match component {
        QosPacketFilterComponent::MatchAll => out.push(0x01),
        QosPacketFilterComponent::Ipv4RemoteAddress { address, mask } => {
            out.push(0x10);
            out.extend_from_slice(address);
            out.extend_from_slice(mask);
        }
        QosPacketFilterComponent::Ipv4LocalAddress { address, mask } => {
            out.push(0x11);
            out.extend_from_slice(address);
            out.extend_from_slice(mask);
        }
        QosPacketFilterComponent::Ipv6RemoteAddressPrefix {
            address,
            prefix_length,
        } => {
            out.push(0x21);
            out.extend_from_slice(address);
            out.push(*prefix_length);
        }
        QosPacketFilterComponent::Ipv6LocalAddressPrefix {
            address,
            prefix_length,
        } => {
            out.push(0x23);
            out.extend_from_slice(address);
            out.push(*prefix_length);
        }
        QosPacketFilterComponent::ProtocolIdentifierOrNextHeader(value) => {
            out.push(0x30);
            out.push(*value);
        }
        QosPacketFilterComponent::SingleLocalPort(value) => {
            out.push(0x40);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::LocalPortRange { low, high } => {
            out.push(0x41);
            out.extend_from_slice(&low.to_be_bytes());
            out.extend_from_slice(&high.to_be_bytes());
        }
        QosPacketFilterComponent::SingleRemotePort(value) => {
            out.push(0x50);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::RemotePortRange { low, high } => {
            out.push(0x51);
            out.extend_from_slice(&low.to_be_bytes());
            out.extend_from_slice(&high.to_be_bytes());
        }
        QosPacketFilterComponent::SecurityParameterIndex(value) => {
            out.push(0x60);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::TypeOfServiceOrTrafficClass { value, mask } => {
            out.push(0x70);
            out.push(*value);
            out.push(*mask);
        }
        QosPacketFilterComponent::FlowLabel(value) => {
            out.push(0x80);
            out.extend_from_slice(value);
        }
        QosPacketFilterComponent::DestinationMacAddress(value) => {
            out.push(0x81);
            out.extend_from_slice(value);
        }
        QosPacketFilterComponent::SourceMacAddress(value) => {
            out.push(0x82);
            out.extend_from_slice(value);
        }
        QosPacketFilterComponent::CTagVid(value) => {
            out.push(0x83);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::STagVid(value) => {
            out.push(0x84);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::CTagPcpDei {
            pcp_present: _,
            dei_present: _,
            pcp,
            dei,
        } => {
            out.push(0x85);
            out.push(((*pcp & 0x07) << 1) | u8::from(*dei));
        }
        QosPacketFilterComponent::STagPcpDei {
            pcp_present: _,
            dei_present: _,
            pcp,
            dei,
        } => {
            out.push(0x86);
            out.push(((*pcp & 0x07) << 1) | u8::from(*dei));
        }
        QosPacketFilterComponent::ExtendedCTagPcpDei {
            pcp_present,
            dei_present,
            pcp,
            dei,
        } => {
            out.push(0x8A);
            out.push(
                (if *pcp_present { 0x20 } else { 0 })
                    | (if *dei_present { 0x10 } else { 0 })
                    | (if *pcp_present { (*pcp & 0x07) << 1 } else { 0 })
                    | (if *dei_present { u8::from(*dei) } else { 0 }),
            );
        }
        QosPacketFilterComponent::ExtendedSTagPcpDei {
            pcp_present,
            dei_present,
            pcp,
            dei,
        } => {
            out.push(0x8B);
            out.push(
                (if *pcp_present { 0x20 } else { 0 })
                    | (if *dei_present { 0x10 } else { 0 })
                    | (if *pcp_present { (*pcp & 0x07) << 1 } else { 0 })
                    | (if *dei_present { u8::from(*dei) } else { 0 }),
            );
        }
        QosPacketFilterComponent::Ethertype(value) => {
            out.push(0x87);
            out.extend_from_slice(&value.to_be_bytes());
        }
        QosPacketFilterComponent::DestinationMacAddressRange { low, high } => {
            out.push(0x88);
            out.extend_from_slice(low);
            out.extend_from_slice(high);
        }
        QosPacketFilterComponent::SourceMacAddressRange { low, high } => {
            out.push(0x89);
            out.extend_from_slice(low);
            out.extend_from_slice(high);
        }
        QosPacketFilterComponent::SrtpMultiplexedMediaIdentificationInformation { entries } => {
            out.push(0x91);
            out.extend_from_slice(&encode_qos_srtp_entries(entries)?);
        }
        QosPacketFilterComponent::Unknown {
            component_type,
            contents,
        } => {
            out.push(*component_type);
            out.extend_from_slice(contents);
        }
    }
    Some(())
}

impl NasQosRules {
    /// The raw QoS rules bytes (TS 24.501 §9.11.4.13).
    pub fn rules_data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the IE into structured QoS rules.
    pub fn rules(&self) -> Vec<QosRule> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let rule_id = data[pos];
            pos += 1;
            let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if length == 0 || pos + length > data.len() {
                break;
            }

            let rule_end = pos + length;
            let header = data[pos];
            let op_code = QosRuleOpCode::from_u8((header >> 5) & 0x07);
            let dqr = header & 0x10 != 0;
            let num_filters = (header & 0x0F) as usize;
            pos += 1;

            if matches!(
                op_code,
                QosRuleOpCode::Reserved | QosRuleOpCode::ReservedHigh
            ) || matches!(
                op_code,
                QosRuleOpCode::Delete | QosRuleOpCode::ModifyNoFilters
            ) && num_filters != 0
                || matches!(op_code, QosRuleOpCode::Delete) && length > 1
            {
                pos = rule_end;
                continue;
            }

            let mut packet_filters = Vec::with_capacity(num_filters);
            let mut valid = true;
            for _ in 0..num_filters {
                if pos >= rule_end {
                    valid = false;
                    break;
                }
                let id_byte = data[pos];
                pos += 1;
                if matches!(op_code, QosRuleOpCode::ModifyDelete) {
                    packet_filters.push(QosPacketFilter::Delete {
                        identifier: id_byte & 0x0F,
                    });
                    continue;
                }

                let direction = QosPacketFilterDirection::from_u8((id_byte >> 4) & 0x03);
                let identifier = id_byte & 0x0F;
                let pf_len = match data.get(pos) {
                    Some(len) => *len as usize,
                    None => {
                        valid = false;
                        break;
                    }
                };
                pos += 1;
                if pos + pf_len > rule_end {
                    valid = false;
                    break;
                }
                let components = match parse_qos_packet_filter_components(&data[pos..pos + pf_len])
                {
                    Some(components) => components,
                    None => {
                        valid = false;
                        break;
                    }
                };
                pos += pf_len;
                packet_filters.push(QosPacketFilter::Match {
                    direction,
                    identifier,
                    components,
                });
            }

            if !valid {
                pos = rule_end;
                continue;
            }

            let mut precedence = None;
            let mut qfi = None;
            let mut segregation = None;
            if !matches!(op_code, QosRuleOpCode::Delete) && pos < rule_end {
                precedence = Some(data[pos]);
                pos += 1;
                if pos < rule_end {
                    let value = data[pos];
                    qfi = Some(value & 0x3F);
                    segregation = Some(value & 0x40 != 0);
                }
            }

            pos = rule_end;
            out.push(QosRule {
                rule_id,
                op_code,
                dqr,
                packet_filters,
                precedence,
                qfi,
                segregation,
            });
        }
        out
    }

    /// Build from a validated list of structured QoS rules.
    pub fn try_from_rules(rules: &[QosRule]) -> Option<Self> {
        let mut value = Vec::new();
        for rule in rules {
            if !qos_rule_is_semantically_valid(rule) {
                return None;
            }
            if matches!(
                rule.op_code,
                QosRuleOpCode::Reserved | QosRuleOpCode::ReservedHigh
            ) {
                return None;
            }
            if rule.packet_filters.len() > 0x0F {
                return None;
            }
            if rule.qfi.is_some() && rule.precedence.is_none() {
                return None;
            }
            if rule.segregation.is_some() && rule.qfi.is_none() {
                return None;
            }
            if matches!(rule.op_code, QosRuleOpCode::Create)
                && (rule.precedence.is_none() || rule.qfi.is_none())
            {
                return None;
            }

            let header_filter_count = match rule.op_code {
                QosRuleOpCode::Delete | QosRuleOpCode::ModifyNoFilters => {
                    if !rule.packet_filters.is_empty()
                        || rule.segregation.is_some()
                        || rule.qfi.is_some()
                        || matches!(rule.op_code, QosRuleOpCode::Delete)
                            && rule.precedence.is_some()
                    {
                        return None;
                    }
                    0
                }
                QosRuleOpCode::ModifyDelete => {
                    if rule.packet_filters.iter().any(|packet_filter| {
                        !matches!(packet_filter, QosPacketFilter::Delete { .. })
                    }) {
                        return None;
                    }
                    rule.packet_filters.len() as u8
                }
                QosRuleOpCode::Create | QosRuleOpCode::ModifyAdd | QosRuleOpCode::ModifyReplace => {
                    if rule.packet_filters.iter().any(|packet_filter| {
                        !matches!(packet_filter, QosPacketFilter::Match { .. })
                    }) {
                        return None;
                    }
                    rule.packet_filters.len() as u8
                }
                QosRuleOpCode::Reserved | QosRuleOpCode::ReservedHigh => return None,
            };

            let mut body = Vec::new();
            body.push(
                ((rule.op_code as u8) << 5)
                    | (if rule.dqr { 0x10 } else { 0 })
                    | header_filter_count,
            );

            for packet_filter in &rule.packet_filters {
                match packet_filter {
                    QosPacketFilter::Delete { identifier } => body.push(identifier & 0x0F),
                    QosPacketFilter::Match {
                        direction,
                        identifier,
                        components,
                    } => {
                        let pf_len = components.iter().try_fold(0usize, |len, component| {
                            len.checked_add(qos_packet_filter_component_len(component)?)
                        })?;
                        body.push(((*direction as u8) << 4) | (identifier & 0x0F));
                        body.push(pf_len.try_into().ok()?);
                        for component in components {
                            encode_qos_packet_filter_component(&mut body, component)?;
                        }
                    }
                }
            }

            if let Some(precedence) = rule.precedence {
                body.push(precedence);
                if let Some(qfi) = rule.qfi {
                    body.push(
                        (qfi & 0x3F)
                            | if rule.segregation.unwrap_or(false) {
                                0x40
                            } else {
                                0
                            },
                    );
                }
            }

            value.push(rule.rule_id);
            value.extend_from_slice(&(body.len() as u16).to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
    }

    /// Strict structural and semantic validation for TS 24.501 §9.11.4.13.
    pub fn validate_strict(&self) -> Result<()> {
        let rules = self.rules();
        if !self.value.is_empty() && rules.is_empty() {
            return Err(NasError::DecodingError(
                "QoS rules could not be parsed strictly".into(),
            ));
        }
        let rebuilt = Self::try_from_rules(&rules)
            .ok_or_else(|| NasError::DecodingError("QoS rules fail semantic validation".into()))?;
        if rebuilt.value != self.value {
            return Err(NasError::DecodingError(
                "QoS rules are not in canonical strict form".into(),
            ));
        }
        Ok(())
    }

    /// Build from a list of structured QoS rules.
    pub fn from_rules(rules: &[QosRule]) -> Self {
        Self::try_from_rules(rules).expect("QoS rules must follow the TS 24.501 wire layout")
    }

    /// Build from raw QoS rules bytes.
    pub fn from_rules_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.validate_strict().is_ok()
    }
}

/// QoS flow description operation code per TS 24.501 §9.11.4.12.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum QosFlowOpCode {
    /// 000 — Reserved.
    Reserved = 0,
    /// 001 — Create new QoS flow description.
    Create = 1,
    /// 010 — Delete existing QoS flow description.
    Delete = 2,
    /// 011 — Modify existing QoS flow description.
    Modify = 3,
}

impl QosFlowOpCode {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Create,
            2 => Self::Delete,
            3 => Self::Modify,
            _ => Self::Reserved,
        }
    }
}

/// QoS flow parameter identifier per TS 24.501 §9.11.4.12.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum QosFlowParamId {
    /// 5QI — 5G QoS Identifier (1 byte).
    FiveQi = 0x01,
    /// GFBR uplink (3 bytes: unit + 2 byte value).
    GfbrUl = 0x02,
    /// GFBR downlink.
    GfbrDl = 0x03,
    /// MFBR uplink.
    MfbrUl = 0x04,
    /// MFBR downlink.
    MfbrDl = 0x05,
    /// Averaging window (2 bytes).
    AveragingWindow = 0x06,
    /// EPS bearer identity (1 byte).
    EpsBearerId = 0x07,
}

impl QosFlowParamId {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::FiveQi),
            0x02 => Some(Self::GfbrUl),
            0x03 => Some(Self::GfbrDl),
            0x04 => Some(Self::MfbrUl),
            0x05 => Some(Self::MfbrDl),
            0x06 => Some(Self::AveragingWindow),
            0x07 => Some(Self::EpsBearerId),
            _ => None,
        }
    }
}

/// One AMBR-style bit-rate parameter inside a QoS flow description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QosFlowBitRate {
    /// Unit octet as carried on the wire.
    pub unit: u8,
    /// 16-bit value field.
    pub value: u16,
}

impl QosFlowBitRate {
    /// Return unit value.
    pub fn unit_value(&self) -> Option<SessionAmbrUnit> {
        SessionAmbrUnit::from_u8(self.unit)
    }

    /// Return kbps.
    pub fn kbps(&self) -> Option<u64> {
        (self.value as u64).checked_mul(ambr_unit_to_kbps(self.unit)?)
    }

    /// Try to construct an exactly representable value from kbps.
    pub fn try_from_kbps(kbps: u64) -> Option<Self> {
        let (unit, value) = kbps_to_ambr_unit(kbps)?;
        Some(Self { unit, value })
    }

    /// Construct an exactly representable value from kbps.
    ///
    /// # Panics
    ///
    /// Panics if the value exceeds the representable range. Use
    /// [`Self::try_from_kbps`] for untrusted values.
    pub fn from_kbps(kbps: u64) -> Self {
        Self::try_from_kbps(kbps).expect("QoS flow bit rate must be exactly representable")
    }
}

/// One parameter inside a QoS flow description.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum QosFlowParameter {
    /// Five qi.
    FiveQi(u8),
    /// Gfbr ul.
    GfbrUl(QosFlowBitRate),
    /// Gfbr dl.
    GfbrDl(QosFlowBitRate),
    /// Mfbr ul.
    MfbrUl(QosFlowBitRate),
    /// Mfbr dl.
    MfbrDl(QosFlowBitRate),
    /// Averaging window.
    AveragingWindow(u16),
    /// EPS bearer identifier.
    EpsBearerId(u8),
    /// Unknown.
    Unknown {
        /// Param identifier.
        param_id: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

impl QosFlowParameter {
    /// Return param identifier.
    pub fn param_id(&self) -> u8 {
        match self {
            Self::FiveQi(_) => QosFlowParamId::FiveQi as u8,
            Self::GfbrUl(_) => QosFlowParamId::GfbrUl as u8,
            Self::GfbrDl(_) => QosFlowParamId::GfbrDl as u8,
            Self::MfbrUl(_) => QosFlowParamId::MfbrUl as u8,
            Self::MfbrDl(_) => QosFlowParamId::MfbrDl as u8,
            Self::AveragingWindow(_) => QosFlowParamId::AveragingWindow as u8,
            Self::EpsBearerId(_) => QosFlowParamId::EpsBearerId as u8,
            Self::Unknown { param_id, .. } => *param_id,
        }
    }

    fn encoded_contents(&self) -> Vec<u8> {
        match self {
            Self::FiveQi(value) => vec![*value],
            Self::EpsBearerId(value) => vec![(*value & 0x0F) << 4],
            Self::GfbrUl(rate) | Self::GfbrDl(rate) | Self::MfbrUl(rate) | Self::MfbrDl(rate) => {
                let mut out = Vec::with_capacity(3);
                out.push(rate.unit);
                out.extend_from_slice(&rate.value.to_be_bytes());
                out
            }
            Self::AveragingWindow(value) => value.to_be_bytes().to_vec(),
            Self::Unknown { contents, .. } => contents.clone(),
        }
    }
}

/// One QoS flow description per TS 24.501 §9.11.4.12.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QosFlowDescription {
    /// QoS Flow Identifier (lower 6 bits of octet 4, mask 0x3F).
    pub qfi: u8,
    /// Operation code (octet 5 bits 8-6).
    pub op_code: QosFlowOpCode,
    /// E flag — when true and op_code = Modify, indicates the parameter list replaces
    /// all previously provided parameters; otherwise the list extends them.
    pub e_flag: bool,
    /// QoS flow parameter list.
    pub params: Vec<QosFlowParameter>,
}

impl NasQosFlowDescriptions {
    /// The raw QoS flow descriptions bytes (TS 24.501 §9.11.4.12).
    pub fn descriptions_data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the complete IE into structured QoS flow descriptions.
    ///
    /// Unknown parameter identifiers are preserved. A known parameter with a
    /// wrong length, truncated framing, or an invalid operation/count
    /// combination makes the whole optional IE syntactically incorrect.
    pub fn try_descriptions(&self) -> Option<Vec<QosFlowDescription>> {
        let data = &self.value;
        if data.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 3 > data.len() || data[pos] & 0xc0 != 0 {
                return None;
            }
            let qfi = data[pos] & 0x3f;
            if qfi == 0 {
                return None;
            }
            let op_byte = data[pos + 1];
            let count_byte = data[pos + 2];
            if op_byte & 0x1f != 0 || count_byte & 0x80 != 0 {
                return None;
            }
            let op_code = QosFlowOpCode::from_u8((op_byte >> 5) & 0x07);
            let e_flag = count_byte & 0x40 != 0;
            let num_params = (count_byte & 0x3f) as usize;
            pos += 3;
            if matches!(op_code, QosFlowOpCode::Reserved)
                || matches!(op_code, QosFlowOpCode::Create) && (!e_flag || num_params == 0)
                || matches!(op_code, QosFlowOpCode::Delete) && (e_flag || num_params != 0)
                || matches!(op_code, QosFlowOpCode::Modify) && num_params == 0
            {
                return None;
            }

            let mut params = Vec::with_capacity(num_params);
            for _ in 0..num_params {
                if pos + 2 > data.len() {
                    return None;
                }
                let param_id = data[pos];
                let plen = data[pos + 1] as usize;
                pos += 2;
                let end = pos.checked_add(plen)?;
                let contents = data.get(pos..end)?;
                let parameter = match QosFlowParamId::from_u8(param_id) {
                    Some(QosFlowParamId::FiveQi) if plen == 1 => {
                        QosFlowParameter::FiveQi(contents[0])
                    }
                    Some(QosFlowParamId::GfbrUl) if plen == 3 => {
                        QosFlowParameter::GfbrUl(QosFlowBitRate {
                            unit: contents[0],
                            value: u16::from_be_bytes([contents[1], contents[2]]),
                        })
                    }
                    Some(QosFlowParamId::GfbrDl) if plen == 3 => {
                        QosFlowParameter::GfbrDl(QosFlowBitRate {
                            unit: contents[0],
                            value: u16::from_be_bytes([contents[1], contents[2]]),
                        })
                    }
                    Some(QosFlowParamId::MfbrUl) if plen == 3 => {
                        QosFlowParameter::MfbrUl(QosFlowBitRate {
                            unit: contents[0],
                            value: u16::from_be_bytes([contents[1], contents[2]]),
                        })
                    }
                    Some(QosFlowParamId::MfbrDl) if plen == 3 => {
                        QosFlowParameter::MfbrDl(QosFlowBitRate {
                            unit: contents[0],
                            value: u16::from_be_bytes([contents[1], contents[2]]),
                        })
                    }
                    Some(QosFlowParamId::AveragingWindow) if plen == 2 => {
                        QosFlowParameter::AveragingWindow(u16::from_be_bytes([
                            contents[0],
                            contents[1],
                        ]))
                    }
                    Some(QosFlowParamId::EpsBearerId) if plen == 1 && contents[0] & 0x0f == 0 => {
                        QosFlowParameter::EpsBearerId(contents[0] >> 4)
                    }
                    Some(_) => return None,
                    None => QosFlowParameter::Unknown {
                        param_id,
                        contents: contents.to_vec(),
                    },
                };
                params.push(parameter);
                pos = end;
            }
            out.push(QosFlowDescription {
                qfi,
                op_code,
                e_flag,
                params,
            });
        }
        (!out.is_empty()).then_some(out)
    }

    /// Parse valid QoS flow descriptions.
    ///
    /// This compatibility accessor returns an empty list for malformed data;
    /// use try_descriptions when the distinction matters.
    pub fn descriptions(&self) -> Vec<QosFlowDescription> {
        self.try_descriptions().unwrap_or_default()
    }

    /// Build from validated QoS flow descriptions.
    pub fn try_from_descriptions(descs: &[QosFlowDescription]) -> Option<Self> {
        let mut value = Vec::new();
        for d in descs {
            if matches!(d.op_code, QosFlowOpCode::Reserved)
                || d.qfi == 0
                || d.qfi > 0x3F
                || d.params.len() > 0x3F
                || matches!(d.op_code, QosFlowOpCode::Create) && (!d.e_flag || d.params.is_empty())
                || matches!(d.op_code, QosFlowOpCode::Delete) && (d.e_flag || !d.params.is_empty())
                || matches!(d.op_code, QosFlowOpCode::Modify) && d.params.is_empty()
            {
                return None;
            }
            let mut seen = Vec::new();
            for parameter in &d.params {
                let id = parameter.param_id();
                if seen.contains(&id) {
                    return None;
                }
                seen.push(id);
                let valid = match parameter {
                    QosFlowParameter::FiveQi(value) => (1..=254).contains(value),
                    QosFlowParameter::GfbrUl(rate)
                    | QosFlowParameter::GfbrDl(rate)
                    | QosFlowParameter::MfbrUl(rate)
                    | QosFlowParameter::MfbrDl(rate) => rate.unit_value().is_some(),
                    QosFlowParameter::AveragingWindow(_) => true,
                    QosFlowParameter::EpsBearerId(value) => (5..=15).contains(value),
                    QosFlowParameter::Unknown { .. } => false,
                };
                if !valid {
                    return None;
                }
            }
            for (mfbr_id, gfbr_id) in [
                (QosFlowParamId::MfbrUl as u8, QosFlowParamId::GfbrUl as u8),
                (QosFlowParamId::MfbrDl as u8, QosFlowParamId::GfbrDl as u8),
            ] {
                let mfbr_is_zero = d.params.iter().any(|parameter| {
                    parameter.param_id() == mfbr_id
                        && matches!(
                            parameter,
                            QosFlowParameter::MfbrUl(rate)
                                | QosFlowParameter::MfbrDl(rate) if rate.value == 0
                        )
                });
                if mfbr_is_zero
                    && !d.params.iter().any(|parameter| {
                        parameter.param_id() == gfbr_id
                            && matches!(
                                parameter,
                                QosFlowParameter::GfbrUl(rate)
                                    | QosFlowParameter::GfbrDl(rate) if rate.value == 0
                            )
                    })
                {
                    return None;
                }
            }

            value.push(d.qfi);
            value.push((d.op_code as u8) << 5);
            let mut count = (d.params.len() as u8) & 0x3F;
            if d.e_flag {
                count |= 0x40;
            }
            value.push(count);
            for p in &d.params {
                let contents = p.encoded_contents();
                if matches!(p, QosFlowParameter::Unknown { .. }) {
                    return None;
                }
                value.push(p.param_id());
                value.push(contents.len().try_into().ok()?);
                value.extend_from_slice(&contents);
            }
        }
        Some(Self::new(value))
    }

    /// Whether any description carries the EPS bearer identity parameter.
    pub fn contains_eps_bearer_identity(&self) -> bool {
        self.try_descriptions().is_some_and(|descriptions| {
            descriptions.iter().any(|description| {
                description
                    .params
                    .iter()
                    .any(|parameter| matches!(parameter, QosFlowParameter::EpsBearerId(_)))
            })
        })
    }

    /// Strict sender grammar and value validation.
    pub fn is_well_formed(&self) -> bool {
        let Some(descriptions) = self.try_descriptions() else {
            return false;
        };
        Self::try_from_descriptions(&descriptions)
            .is_some_and(|rebuilt| rebuilt.value == self.value)
    }

    /// Build from typed QoS flow descriptions.
    pub fn from_descriptions(descs: &[QosFlowDescription]) -> Self {
        Self::try_from_descriptions(descs)
            .expect("QoS flow descriptions must follow the TS 24.501 wire layout")
    }

    /// Build from raw QoS flow descriptions bytes.
    pub fn from_descriptions_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── Protocol Configuration / Container IEs ──────────────────────────────────

impl NasAtsssContainer {
    /// The raw ATSSS container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw ATSSS container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Replace the raw ATSSS container bytes.
    pub fn set_container_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.value = data;
        self.length = self.value.len() as _;
        self
    }

    /// Replace the raw ATSSS container bytes while returning `self`.
    pub fn with_container_data(mut self, data: Vec<u8>) -> Self {
        self.value = data;
        self.length = self.value.len() as _;
        self
    }
}

impl NasPortManagementInformationContainer {
    /// The raw container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Replace the raw container bytes.
    pub fn set_container_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.value = data;
        self.length = self.value.len() as _;
        self
    }

    /// Replace the raw container bytes while returning `self`.
    pub fn with_container_data(mut self, data: Vec<u8>) -> Self {
        self.value = data;
        self.length = self.value.len() as _;
        self
    }
}

/// Service-level-AA server address type per TS 24.501 §9.11.2.12.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ServiceLevelAaServerAddressType {
    /// Ipv 4.
    Ipv4 = 0x01,
    /// Ipv 6.
    Ipv6 = 0x02,
    /// Ipv 4 v 6.
    Ipv4v6 = 0x03,
    /// Fqdn.
    Fqdn = 0x04,
}

impl ServiceLevelAaServerAddressType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Ipv4),
            0x02 => Some(Self::Ipv6),
            0x03 => Some(Self::Ipv4v6),
            0x04 => Some(Self::Fqdn),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Service level aa server address values.
pub enum ServiceLevelAaServerAddress {
    /// Ipv 4.
    Ipv4([u8; 4]),
    /// Ipv 6.
    Ipv6([u8; 16]),
    /// Ipv 4 v 6.
    Ipv4v6 {
        /// Ipv 4.
        ipv4: [u8; 4],
        /// Ipv 6.
        ipv6: [u8; 16],
    },
    /// Dot-separated FQDN; encoded as DNS labels on the wire.
    Fqdn(String),
    /// Unknown.
    Unknown {
        /// Address type.
        address_type: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// Service level aa response c 2 authorization result values.
pub enum ServiceLevelAaResponseC2AuthorizationResult {
    /// No information.
    NoInformation = 0,
    /// Successful.
    Successful = 1,
    /// Not successful or revoked.
    NotSuccessfulOrRevoked = 2,
    /// Reserved.
    Reserved = 3,
}

impl ServiceLevelAaResponseC2AuthorizationResult {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::NoInformation,
            1 => Self::Successful,
            2 => Self::NotSuccessfulOrRevoked,
            _ => Self::Reserved,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// Service level aa response result values.
pub enum ServiceLevelAaResponseResult {
    /// No information.
    NoInformation = 0,
    /// Successful.
    Successful = 1,
    /// Not successful or revoked.
    NotSuccessfulOrRevoked = 2,
    /// Reserved.
    Reserved = 3,
}

impl ServiceLevelAaResponseResult {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0 => Self::NoInformation,
            1 => Self::Successful,
            2 => Self::NotSuccessfulOrRevoked,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of service level aa response.
pub struct ServiceLevelAaResponse {
    /// C 2 ar.
    pub c2ar: ServiceLevelAaResponseC2AuthorizationResult,
    /// Slar.
    pub slar: ServiceLevelAaResponseResult,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// Service level aa payload type values.
pub enum ServiceLevelAaPayloadType {
    /// Uuaa.
    Uuaa = 0x01,
    /// C 2 authorization.
    C2Authorization = 0x02,
}

impl ServiceLevelAaPayloadType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Uuaa),
            0x02 => Some(Self::C2Authorization),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Service level aa parameter values.
pub enum ServiceLevelAaParameter {
    /// Device identifier.
    DeviceId(String),
    /// Server address.
    ServerAddress(ServiceLevelAaServerAddress),
    /// Response.
    Response(ServiceLevelAaResponse),
    /// Payload type.
    PayloadType(ServiceLevelAaPayloadType),
    /// Payload.
    Payload(Vec<u8>),
    /// Pending indication.
    PendingIndication(bool),
    /// Service status indication.
    ServiceStatusIndication(bool),
    /// Unknown.
    Unknown {
        /// Parameter type.
        parameter_type: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

impl NasServiceLevelAaContainer {
    /// The raw service-level AA container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Decode the container into structured parameters.
    pub fn parameters(&self) -> Result<Vec<ServiceLevelAaParameter>> {
        self.try_parameters()
    }

    /// Decode the container into structured parameters with strict error reporting.
    pub fn try_parameters(&self) -> Result<Vec<ServiceLevelAaParameter>> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let type_octet = *data.get(pos).ok_or(NasError::BufferTooShort)?;
            let parameter_type = if type_octet & 0xF0 == 0xA0 {
                0xA0
            } else {
                type_octet
            };
            pos += 1;

            if parameter_type == 0xA0 {
                out.push(ServiceLevelAaParameter::PendingIndication(
                    type_octet & 0x01 != 0,
                ));
                continue;
            }

            let length = if parameter_type == 0x70 {
                if pos + 2 > data.len() {
                    return Err(NasError::BufferTooShort);
                }
                let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                length
            } else {
                let length = *data.get(pos).ok_or(NasError::BufferTooShort)? as usize;
                pos += 1;
                length
            };

            if pos + length > data.len() {
                return Err(NasError::BufferTooShort);
            }
            let contents = &data[pos..pos + length];
            pos += length;

            let parameter = match parameter_type {
                0x10 => ServiceLevelAaParameter::DeviceId(
                    std::str::from_utf8(contents)
                        .map_err(|_| {
                            NasError::DecodingError(
                                "Service-level device ID is not valid UTF-8".into(),
                            )
                        })?
                        .to_owned(),
                ),
                0x20 => {
                    let (&address_type, rest) = contents.split_first().ok_or_else(|| {
                        NasError::DecodingError(
                            "Service-level-AA server address is missing its address type octet"
                                .into(),
                        )
                    })?;
                    let address = match contents.split_first() {
                        Some((&0x01, rest)) if rest.len() == 4 => {
                            ServiceLevelAaServerAddress::Ipv4(copy_array::<4>(rest).unwrap())
                        }
                        Some((&0x02, rest)) if rest.len() == 16 => {
                            ServiceLevelAaServerAddress::Ipv6(copy_array::<16>(rest).unwrap())
                        }
                        Some((&0x03, rest)) if rest.len() == 20 => {
                            ServiceLevelAaServerAddress::Ipv4v6 {
                                ipv4: copy_array::<4>(rest).unwrap(),
                                ipv6: copy_array::<16>(&rest[4..]).unwrap(),
                            }
                        }
                        Some((&0x04, rest)) => ServiceLevelAaServerAddress::Fqdn(
                            crate::common::decode_labels_with_maximum(rest, 254).ok_or_else(
                                || {
                                    NasError::DecodingError(
                                        "Service-level-AA server FQDN is malformed".into(),
                                    )
                                },
                            )?,
                        ),
                        Some((&address_type, rest)) => ServiceLevelAaServerAddress::Unknown {
                            address_type,
                            contents: rest.to_vec(),
                        },
                        None => unreachable!(),
                    };
                    if matches!(address_type, 0x01..=0x03)
                        && matches!(address, ServiceLevelAaServerAddress::Unknown { .. })
                    {
                        return Err(NasError::DecodingError(format!(
                            "Service-level-AA server address type 0x{address_type:02X} has invalid length {}",
                            rest.len()
                        )));
                    }
                    ServiceLevelAaParameter::ServerAddress(address)
                }
                0x30 if contents.len() == 1 => {
                    ServiceLevelAaParameter::Response(ServiceLevelAaResponse {
                        c2ar: ServiceLevelAaResponseC2AuthorizationResult::from_u8(
                            (contents[0] >> 2) & 0x03,
                        ),
                        slar: ServiceLevelAaResponseResult::from_u8(contents[0] & 0x03),
                    })
                }
                0x30 => {
                    return Err(NasError::DecodingError(format!(
                        "Service-level-AA response shall be 1 octet, got {}",
                        contents.len()
                    )));
                }
                0x40 if contents.len() == 1 => {
                    match ServiceLevelAaPayloadType::from_u8(contents[0]) {
                        Some(payload_type) => ServiceLevelAaParameter::PayloadType(payload_type),
                        None => ServiceLevelAaParameter::Unknown {
                            parameter_type,
                            contents: contents.to_vec(),
                        },
                    }
                }
                0x40 => {
                    return Err(NasError::DecodingError(format!(
                        "Service-level-AA payload type shall be 1 octet, got {}",
                        contents.len()
                    )));
                }
                0x50 if contents.len() == 1 => {
                    ServiceLevelAaParameter::ServiceStatusIndication(contents[0] & 0x01 != 0)
                }
                0x50 => {
                    return Err(NasError::DecodingError(format!(
                        "Service-level-AA service status indication shall be 1 octet, got {}",
                        contents.len()
                    )));
                }
                0x70 => ServiceLevelAaParameter::Payload(contents.to_vec()),
                _ => continue,
            };
            out.push(parameter);
        }
        Ok(out)
    }

    /// Strict structural validation for the service-level-AA container.
    ///
    /// The permissive parser keeps forward-compatible receive behaviour. This
    /// validator adds checks for rules that are easy to miss when callers need a
    /// spec-clean container: type-1 spare bits, payload-type/payload pairing, and
    /// known parameter lengths.
    pub fn validate_strict(&self) -> Result<()> {
        self.try_parameters()?;

        let data = &self.value;
        let mut pos = 0usize;
        let mut payload_type_needs_payload = false;
        while pos < data.len() {
            let type_octet = *data.get(pos).ok_or(NasError::BufferTooShort)?;
            let parameter_type = if type_octet & 0xF0 == 0xA0 {
                0xA0
            } else {
                type_octet
            };
            pos += 1;

            if payload_type_needs_payload && parameter_type != 0x70 {
                return Err(NasError::DecodingError(
                    "Service-level-AA payload type shall be immediately followed by payload".into(),
                ));
            }

            if parameter_type == 0xA0 {
                if type_octet & 0x0E != 0 {
                    return Err(NasError::DecodingError(
                        "Service-level-AA pending indication spare bits shall be zero".into(),
                    ));
                }
                if type_octet & 0x01 == 0 {
                    return Err(NasError::DecodingError(
                        "Service-level-AA pending indication shall be set when present".into(),
                    ));
                }
                payload_type_needs_payload = false;
                continue;
            }

            let length = if parameter_type == 0x70 {
                if pos + 2 > data.len() {
                    return Err(NasError::BufferTooShort);
                }
                let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                length
            } else {
                let length = *data.get(pos).ok_or(NasError::BufferTooShort)? as usize;
                pos += 1;
                length
            };

            if pos + length > data.len() {
                return Err(NasError::BufferTooShort);
            }
            let contents = &data[pos..pos + length];
            pos += length;

            match parameter_type {
                0x10 => {
                    if contents.is_empty() || std::str::from_utf8(contents).is_err() {
                        return Err(NasError::DecodingError(
                            "Service-level device ID shall be a non-empty UTF-8 string".into(),
                        ));
                    }
                    payload_type_needs_payload = false;
                }
                0x20 => {
                    let Some((&address_type, address)) = contents.split_first() else {
                        return Err(NasError::DecodingError(
                            "Service-level-AA server address is empty".into(),
                        ));
                    };
                    let valid = match address_type {
                        0x01 => address.len() == 4,
                        0x02 => address.len() == 16,
                        0x03 => address.len() == 20,
                        0x04 => crate::common::decode_labels_with_maximum(address, 254).is_some(),
                        _ => false,
                    };
                    if !valid {
                        return Err(NasError::DecodingError(
                            "Service-level-AA server address has a reserved type or invalid length"
                                .into(),
                        ));
                    }
                    payload_type_needs_payload = false;
                }
                0x30 => {
                    if contents.len() != 1
                        || contents[0] & 0xF0 != 0
                        || contents[0] & 0x03 == 0x03
                        || (contents[0] >> 2) & 0x03 == 0x03
                    {
                        return Err(NasError::DecodingError(
                            "Service-level-AA response contains an invalid length, spare bit, or reserved result"
                                .into(),
                        ));
                    }
                    payload_type_needs_payload = false;
                }
                0x40 => {
                    if contents.len() != 1 || !matches!(contents[0], 0x01 | 0x02) {
                        return Err(NasError::DecodingError(format!(
                            "Service-level-AA payload type shall be one octet containing 1 or 2, got {contents:?}"
                        )));
                    }
                    payload_type_needs_payload = true;
                }
                0x50 => {
                    if contents.len() != 1 {
                        return Err(NasError::DecodingError(format!(
                            "Service-level-AA service status indication shall be 1 octet, got {}",
                            contents.len()
                        )));
                    }
                    if contents[0] & !0x01 != 0 {
                        return Err(NasError::DecodingError(
                            "Service-level-AA service status indication spare bits shall be zero"
                                .into(),
                        ));
                    }
                    payload_type_needs_payload = false;
                }
                0x70 => {
                    payload_type_needs_payload = false;
                }
                _ => {
                    payload_type_needs_payload = false;
                }
            }
        }

        if payload_type_needs_payload {
            return Err(NasError::DecodingError(
                "Service-level-AA payload type shall be followed by payload".into(),
            ));
        }

        Ok(())
    }

    /// Construct a value from parameters.
    pub fn from_parameters(parameters: &[ServiceLevelAaParameter]) -> Option<Self> {
        let mut value = Vec::new();
        for parameter in parameters {
            match parameter {
                ServiceLevelAaParameter::DeviceId(device_id) => {
                    if device_id.is_empty() {
                        return None;
                    }
                    value.push(0x10);
                    value.push(device_id.len().try_into().ok()?);
                    value.extend_from_slice(device_id.as_bytes());
                }
                ServiceLevelAaParameter::ServerAddress(address) => {
                    value.push(0x20);
                    let mut contents = Vec::new();
                    match address {
                        ServiceLevelAaServerAddress::Ipv4(ipv4) => {
                            contents.push(ServiceLevelAaServerAddressType::Ipv4 as u8);
                            contents.extend_from_slice(ipv4);
                        }
                        ServiceLevelAaServerAddress::Ipv6(ipv6) => {
                            contents.push(ServiceLevelAaServerAddressType::Ipv6 as u8);
                            contents.extend_from_slice(ipv6);
                        }
                        ServiceLevelAaServerAddress::Ipv4v6 { ipv4, ipv6 } => {
                            contents.push(ServiceLevelAaServerAddressType::Ipv4v6 as u8);
                            contents.extend_from_slice(ipv4);
                            contents.extend_from_slice(ipv6);
                        }
                        ServiceLevelAaServerAddress::Fqdn(fqdn) => {
                            contents.push(ServiceLevelAaServerAddressType::Fqdn as u8);
                            contents.extend_from_slice(&crate::common::encode_labels(fqdn, 254)?);
                        }
                        ServiceLevelAaServerAddress::Unknown {
                            address_type,
                            contents: raw,
                        } => {
                            contents.push(*address_type);
                            contents.extend_from_slice(raw);
                        }
                    }
                    value.push(contents.len().try_into().ok()?);
                    value.extend_from_slice(&contents);
                }
                ServiceLevelAaParameter::Response(response) => {
                    if matches!(
                        response.c2ar,
                        ServiceLevelAaResponseC2AuthorizationResult::Reserved
                    ) || matches!(response.slar, ServiceLevelAaResponseResult::Reserved)
                    {
                        return None;
                    }
                    value.push(0x30);
                    value.push(1);
                    value.push(((response.c2ar as u8) << 2) | (response.slar as u8));
                }
                ServiceLevelAaParameter::PayloadType(payload_type) => {
                    value.push(0x40);
                    value.push(1);
                    value.push(*payload_type as u8);
                }
                ServiceLevelAaParameter::Payload(payload) => {
                    value.push(0x70);
                    value.extend_from_slice(&(u16::try_from(payload.len()).ok()?).to_be_bytes());
                    value.extend_from_slice(payload);
                }
                ServiceLevelAaParameter::PendingIndication(pending) => {
                    if !pending {
                        return None;
                    }
                    value.push(0xA0 | u8::from(*pending));
                }
                ServiceLevelAaParameter::ServiceStatusIndication(enabled) => {
                    value.push(0x50);
                    value.push(1);
                    value.push(u8::from(*enabled));
                }
                ServiceLevelAaParameter::Unknown {
                    parameter_type,
                    contents,
                } => {
                    value.push(*parameter_type);
                    if *parameter_type == 0x70 {
                        value.extend_from_slice(&(contents.len() as u16).to_be_bytes());
                    } else {
                        value.push(contents.len().try_into().ok()?);
                    }
                    value.extend_from_slice(contents);
                }
            }
        }
        if value.len() > u16::MAX as usize {
            return None;
        }
        let result = Self::new(value);
        result.validate_strict().ok()?;
        Some(result)
    }

    /// Build from raw container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasSmPduDnRequestContainer {
    /// The raw SM PDU DN request container bytes (UTF-8 encoded DN-specific identity
    /// string per TS 24.501 §9.11.4.15).
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Decode the container as a UTF-8 string. Returns `None` if the bytes are not
    /// valid UTF-8.
    pub fn as_utf8_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }

    /// Build from a UTF-8 string per TS 24.501 §9.11.4.15.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }

    /// Build from raw container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// Direction in which a SOR transparent container is sent.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SorTransparentContainerDirection {
    /// SOR information sent by the network to the UE.
    NetworkToUe,
    /// SOR acknowledgement sent by the UE to the network.
    UeToNetwork,
}

/// SOR transparent-container data type.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SorDataType {
    /// Network-provided steering-of-roaming information.
    Information,
    /// UE acknowledgement.
    Acknowledgement,
}

/// SOR information-list representation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SorListType {
    /// TS 31.115 secured packet.
    SecuredPacket,
    /// PLMN identity and access-technology list.
    PlmnAccessTechnologyList,
}

/// Parsed SOR transparent-container contents.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SorTransparentContainerContents {
    /// Network-to-UE SOR information.
    Information {
        /// Whether the PLMN/access-technology list is present.
        list_indication: bool,
        /// List representation selected by the header.
        list_type: SorListType,
        /// Whether the UE shall acknowledge the information.
        acknowledgement_requested: bool,
        /// Whether the Rel-17 additional-parameter section is present.
        additional_parameters: bool,
        /// SOR-MAC-I-AUSF.
        sor_mac_iausf: [u8; 16],
        /// CounterSOR.
        counter_sor: u16,
        /// Bytes following CounterSOR, framed according to the header flags.
        body: Vec<u8>,
    },
    /// UE-to-network SOR acknowledgement.
    Acknowledgement {
        /// ME support of SOR-CMCI.
        mssi: bool,
        /// ME support of SOR-SNPN-SI.
        mssnpnsi: bool,
        /// ME support of SOR-SNPN-SI-LS.
        msssnpnsils: bool,
        /// SOR-MAC-IUE.
        sor_mac_iue: [u8; 16],
    },
}

fn sor_take_u16_range(data: &[u8], position: &mut usize) -> Option<std::ops::Range<usize>> {
    let length = u16::from_be_bytes([*data.get(*position)?, *data.get(*position + 1)?]) as usize;
    *position += 2;
    let end = position.checked_add(length)?;
    (end <= data.len()).then(|| {
        let range = *position..end;
        *position = end;
        range
    })
}

fn sor_cmci_is_valid(contents: &[u8], canonical: bool) -> bool {
    let mut position = 0usize;
    while position < contents.len() {
        let Some(rule_length) = contents.get(position).copied().map(usize::from) else {
            return false;
        };
        position += 1;
        let Some(end) = position.checked_add(rule_length) else {
            return false;
        };
        let Some(rule) = contents.get(position..end) else {
            return false;
        };
        position = end;
        let Some(&criterion_type) = rule.get(1) else {
            return false;
        };
        let defined_length = match criterion_type {
            0x01 => {
                let Some(dnn_length) = rule.get(2).copied().map(usize::from) else {
                    return false;
                };
                let Some(length) = 3usize.checked_add(dnn_length) else {
                    return false;
                };
                if rule.len() < length || !NasDnn::new(rule[3..length].to_vec()).is_well_formed() {
                    return false;
                }
                length
            }
            0x02 => 3,
            0x03 => 6,
            0x04..=0x08 | 0xff => 2,
            _ if canonical => return false,
            _ => continue,
        };
        if rule.len() < defined_length || canonical && rule.len() != defined_length {
            return false;
        }
    }
    true
}

fn sor_snpn_information_is_valid(contents: &[u8], canonical: bool) -> bool {
    let Some(&flags) = contents.first() else {
        return false;
    };
    if canonical && flags & 0xfc != 0 {
        return false;
    }
    let mut position = 1usize;
    for mask in [0x01, 0x02] {
        if flags & mask != 0 {
            let Some(range) = sor_take_u16_range(contents, &mut position) else {
                return false;
            };
            if range.len() % 9 != 0 {
                return false;
            }
        }
    }
    position == contents.len()
}

fn sor_location_assistance_list_is_valid(contents: &[u8]) -> bool {
    let mut position = 0usize;
    while position < contents.len() {
        let Some(record_length) = contents.get(position).copied().map(usize::from) else {
            return false;
        };
        position += 1;
        let Some(end) = position.checked_add(record_length) else {
            return false;
        };
        let Some(record) = contents.get(position..end) else {
            return false;
        };
        // Indicator octet followed by the nine-octet SNPN or GIN identity.
        if record.len() < 10 {
            return false;
        }
        position = end;
    }
    true
}

fn sor_snpn_location_information_is_valid(contents: &[u8], canonical: bool) -> bool {
    let Some(&flags) = contents.first() else {
        return false;
    };
    if canonical && flags & 0xfc != 0 {
        return false;
    }
    let mut position = 1usize;
    for mask in [0x01, 0x02] {
        if flags & mask != 0 {
            let Some(range) = sor_take_u16_range(contents, &mut position) else {
                return false;
            };
            if !sor_location_assistance_list_is_valid(&contents[range]) {
                return false;
            }
        }
    }
    position == contents.len()
}

fn sor_information_body_is_valid(data: &[u8], header: u8, canonical: bool) -> bool {
    let list_indication = header & 0x02 != 0;
    let plmn_list = header & 0x04 != 0;
    let additional_parameters = header & 0x10 != 0;
    if !plmn_list {
        return !additional_parameters && (!canonical || !list_indication);
    }

    let mut position = 19usize;
    if !additional_parameters {
        return if list_indication {
            let list_length = data.len().saturating_sub(position);
            list_length <= 80 && list_length.is_multiple_of(5)
        } else {
            data.len() == position
        };
    }

    if list_indication {
        let Some(range) = sor_take_u16_range(data, &mut position) else {
            return false;
        };
        if range.len() > 80 || range.len() % 5 != 0 {
            return false;
        }
    }
    let Some(&flags) = data.get(position) else {
        return false;
    };
    position += 1;
    if canonical && flags & 0xf0 != 0 {
        return false;
    }

    if flags & 0x01 != 0 {
        let Some(range) = sor_take_u16_range(data, &mut position) else {
            return false;
        };
        if !sor_cmci_is_valid(&data[range], canonical) {
            return false;
        }
    }
    // SSCMI (bit 2) is an instruction to store SOR-CMCI; it carries no field.
    if flags & 0x04 != 0 {
        let Some(range) = sor_take_u16_range(data, &mut position) else {
            return false;
        };
        if !sor_snpn_information_is_valid(&data[range], canonical) {
            return false;
        }
    }
    if flags & 0x08 != 0 {
        let Some(range) = sor_take_u16_range(data, &mut position) else {
            return false;
        };
        if !sor_snpn_location_information_is_valid(&data[range], canonical) {
            return false;
        }
    }
    position == data.len()
}

impl NasSorTransparentContainer {
    /// The raw SOR transparent container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Raw SOR header octet.
    pub fn sor_header(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Typed SOR data type.
    pub fn data_type(&self) -> Option<SorDataType> {
        self.sor_header().map(|header| {
            if header & 0x01 == 0 {
                SorDataType::Information
            } else {
                SorDataType::Acknowledgement
            }
        })
    }

    /// Whether the SOR data type is the UE acknowledgement form.
    pub fn sor_data_type_ack(&self) -> bool {
        self.data_type() == Some(SorDataType::Acknowledgement)
    }

    /// List indication (bit 2), meaningful for SOR information with a PLMN list.
    pub fn sor_list_ind(&self) -> bool {
        self.sor_header().is_some_and(|header| header & 0x02 != 0)
    }

    /// Typed list representation for SOR information.
    pub fn list_type(&self) -> Option<SorListType> {
        (self.data_type()? == SorDataType::Information).then(|| {
            if self.sor_header().unwrap() & 0x04 == 0 {
                SorListType::SecuredPacket
            } else {
                SorListType::PlmnAccessTechnologyList
            }
        })
    }

    /// Whether the list representation is a PLMN/access-technology list.
    pub fn sor_list_type_plmn_list(&self) -> bool {
        self.list_type() == Some(SorListType::PlmnAccessTechnologyList)
    }

    /// Acknowledgement requested (bit 4).
    pub fn ack_requested(&self) -> bool {
        self.sor_header().is_some_and(|header| header & 0x08 != 0)
    }

    /// Whether the additional-parameter section is present (bit 5).
    pub fn additional_parameters(&self) -> bool {
        self.sor_header().is_some_and(|header| header & 0x10 != 0)
    }

    /// ME support of SOR-CMCI (ACK bit 2).
    pub fn mssi(&self) -> bool {
        self.sor_data_type_ack() && self.sor_header().is_some_and(|header| header & 0x02 != 0)
    }

    /// ME support of SOR-SNPN-SI (ACK bit 3).
    pub fn mssnpnsi(&self) -> bool {
        self.sor_data_type_ack() && self.sor_header().is_some_and(|header| header & 0x04 != 0)
    }

    /// ME support of SOR-SNPN-SI-LS (ACK bit 4).
    pub fn msssnpnsils(&self) -> bool {
        self.sor_data_type_ack() && self.sor_header().is_some_and(|header| header & 0x08 != 0)
    }

    /// SOR-MAC-IUE, present only in the acknowledgement form.
    pub fn sor_mac_iue(&self) -> Option<[u8; 16]> {
        (self.sor_data_type_ack() && self.value.len() >= 17)
            .then(|| self.value[1..17].try_into().expect("fixed slice"))
    }

    /// SOR-MAC-I-AUSF, present only in the information form.
    pub fn sor_mac_iausf(&self) -> Option<[u8; 16]> {
        (self.data_type()? == SorDataType::Information && self.value.len() >= 17)
            .then(|| self.value[1..17].try_into().expect("fixed slice"))
    }

    /// CounterSOR, present only in the information form.
    pub fn counter_sor(&self) -> Option<u16> {
        (self.data_type()? == SorDataType::Information && self.value.len() >= 19)
            .then(|| u16::from_be_bytes([self.value[17], self.value[18]]))
    }

    /// TS 31.115 secured packet carried by an LT=0 information container.
    pub fn secured_packet(&self) -> Option<&[u8]> {
        (self.receiver_syntax_is_valid() && self.list_type() == Some(SorListType::SecuredPacket))
            .then_some(&self.value[19..])
    }

    /// Direct PLMN/access-technology list, excluding Rel-17 framing fields.
    pub fn plmn_list_payload(&self) -> Option<&[u8]> {
        if !self.receiver_syntax_is_valid()
            || self.list_type() != Some(SorListType::PlmnAccessTechnologyList)
            || !self.sor_list_ind()
        {
            return None;
        }
        if !self.additional_parameters() {
            return Some(&self.value[19..]);
        }
        let length = u16::from_be_bytes([self.value[19], self.value[20]]) as usize;
        Some(&self.value[21..21 + length])
    }

    /// Parse receiver-tolerated typed contents.
    pub fn parse(&self) -> Option<SorTransparentContainerContents> {
        if !self.receiver_syntax_is_valid() {
            return None;
        }
        match self.data_type()? {
            SorDataType::Acknowledgement => {
                Some(SorTransparentContainerContents::Acknowledgement {
                    mssi: self.mssi(),
                    mssnpnsi: self.mssnpnsi(),
                    msssnpnsils: self.msssnpnsils(),
                    sor_mac_iue: self.sor_mac_iue()?,
                })
            }
            SorDataType::Information => Some(SorTransparentContainerContents::Information {
                list_indication: self.sor_list_ind(),
                list_type: self.list_type()?,
                acknowledgement_requested: self.ack_requested(),
                additional_parameters: self.additional_parameters(),
                sor_mac_iausf: self.sor_mac_iausf()?,
                counter_sor: self.counter_sor()?,
                body: self.value[19..].to_vec(),
            }),
        }
    }

    fn syntax_is_valid(&self, canonical: bool) -> bool {
        let Some(header) = self.sor_header() else {
            return false;
        };
        match self.data_type().unwrap() {
            SorDataType::Acknowledgement => {
                self.value.len() == 17 && (!canonical || header & 0xf0 == 0)
            }
            SorDataType::Information => {
                self.value.len() >= 19
                    && (!canonical || header & 0xe0 == 0)
                    && sor_information_body_is_valid(&self.value, header, canonical)
            }
        }
    }

    /// Receiver-side syntax check. Spare bits and ignored CMCI rules remain tolerant.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.syntax_is_valid(false)
    }

    /// Canonical sender check, including spare bits and defined CMCI criteria.
    pub fn is_well_formed(&self) -> bool {
        self.syntax_is_valid(true)
    }

    /// Receiver syntax and direction check for the enclosing NAS message.
    pub fn receiver_syntax_is_valid_for(
        &self,
        direction: SorTransparentContainerDirection,
    ) -> bool {
        self.receiver_syntax_is_valid()
            && matches!(
                (direction, self.data_type()),
                (
                    SorTransparentContainerDirection::NetworkToUe,
                    Some(SorDataType::Information)
                ) | (
                    SorTransparentContainerDirection::UeToNetwork,
                    Some(SorDataType::Acknowledgement)
                )
            )
    }

    /// Canonical sender and direction check for the enclosing NAS message.
    pub fn is_well_formed_for(&self, direction: SorTransparentContainerDirection) -> bool {
        self.is_well_formed() && self.receiver_syntax_is_valid_for(direction)
    }

    /// Build a canonical SOR ACK container (UE to network).
    pub fn from_ack(mssi: bool, mssnpnsi: bool, msssnpnsils: bool, sor_mac_iue: [u8; 16]) -> Self {
        let mut header = 0x01;
        header |= u8::from(mssi) << 1;
        header |= u8::from(mssnpnsi) << 2;
        header |= u8::from(msssnpnsils) << 3;
        let mut value = Vec::with_capacity(17);
        value.push(header);
        value.extend_from_slice(&sor_mac_iue);
        Self::new(value)
    }

    /// Build canonical network-to-UE SOR information.
    ///
    /// `body` starts after CounterSOR and must use the framing selected by
    /// `list_type`, `list_indication`, and `additional_parameters`.
    pub fn from_information(
        list_indication: bool,
        list_type: SorListType,
        acknowledgement_requested: bool,
        additional_parameters: bool,
        sor_mac_iausf: [u8; 16],
        counter_sor: u16,
        body: &[u8],
    ) -> Option<Self> {
        let mut header = u8::from(list_indication) << 1;
        header |= u8::from(list_type == SorListType::PlmnAccessTechnologyList) << 2;
        header |= u8::from(acknowledgement_requested) << 3;
        header |= u8::from(additional_parameters) << 4;
        let mut value = Vec::with_capacity(19 + body.len());
        value.push(header);
        value.extend_from_slice(&sor_mac_iausf);
        value.extend_from_slice(&counter_sor.to_be_bytes());
        value.extend_from_slice(body);
        let container = Self::new(value);
        container
            .is_well_formed_for(SorTransparentContainerDirection::NetworkToUe)
            .then_some(container)
    }

    /// Build raw SOR container bytes for receiver diagnostics or relay.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// Mapped EPS bearer context operation code per TS 24.501 §9.11.4.8.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MappedEpsBearerOpCode {
    /// Reserved.
    Reserved = 0x00,
    /// Create new EPS bearer.
    Create = 0x01,
    /// Delete existing EPS bearer.
    Delete = 0x02,
    /// Modify existing EPS bearer.
    Modify = 0x03,
}

impl MappedEpsBearerOpCode {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::Reserved),
            0x01 => Some(Self::Create),
            0x02 => Some(Self::Delete),
            0x03 => Some(Self::Modify),
            _ => None,
        }
    }
}

/// EPS parameter identifier in a mapped EPS bearer context per TS 24.501 §9.11.4.8.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MappedEpsBearerParamId {
    /// Mapped EPS QoS parameters.
    EpsQos = 0x01,
    /// Mapped extended EPS QoS parameters.
    ExtendedEpsQos = 0x02,
    /// Traffic flow template (TFT).
    TrafficFlowTemplate = 0x03,
    /// APN-AMBR.
    ApnAmbr = 0x04,
    /// Extended APN-AMBR.
    ExtendedApnAmbr = 0x05,
}

impl MappedEpsBearerParamId {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::EpsQos),
            0x02 => Some(Self::ExtendedEpsQos),
            0x03 => Some(Self::TrafficFlowTemplate),
            0x04 => Some(Self::ApnAmbr),
            0x05 => Some(Self::ExtendedApnAmbr),
            _ => None,
        }
    }
}

/// One EPS parameter inside a mapped EPS bearer context.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MappedEpsBearerParam {
    /// Raw parameter identifier (use [`MappedEpsBearerParamId::from_u8`] for typed value).
    pub param_id: u8,
    /// Opaque parameter contents (the format depends on `param_id`).
    pub contents: Vec<u8>,
}

impl MappedEpsBearerParam {
    fn contents_for(&self, id: MappedEpsBearerParamId) -> Option<&[u8]> {
        (self.param_id == id as u8).then_some(self.contents.as_slice())
    }

    /// Mapped EPS QoS parameters (TS 24.301 §9.9.4.3).
    pub fn eps_qos(&self) -> Option<crate::nas_eps::EpsQos> {
        crate::nas_eps::EpsQos::from_bytes(self.contents_for(MappedEpsBearerParamId::EpsQos)?)
    }

    /// Mapped extended EPS QoS parameters (TS 24.301 §9.9.4.30).
    pub fn extended_eps_qos(&self) -> Option<crate::nas_eps::ExtendedEpsQos> {
        crate::nas_eps::ExtendedEpsQos::from_bytes(
            self.contents_for(MappedEpsBearerParamId::ExtendedEpsQos)?,
        )
    }

    /// Traffic flow template (TS 24.008 §10.5.6.12) under the receiver rules.
    pub fn tft(&self) -> Option<crate::nas_eps::Tft> {
        crate::nas_eps::Tft::from_bytes(
            self.contents_for(MappedEpsBearerParamId::TrafficFlowTemplate)?,
        )
    }

    /// APN-AMBR (TS 24.301 §9.9.4.2).
    pub fn apn_ambr(&self) -> Option<crate::nas_eps::ApnAmbr> {
        crate::nas_eps::ApnAmbr::from_bytes(self.contents_for(MappedEpsBearerParamId::ApnAmbr)?)
    }

    /// Extended APN-AMBR (TS 24.301 §9.9.4.29).
    pub fn extended_apn_ambr(&self) -> Option<crate::nas_eps::ExtendedApnAmbr> {
        crate::nas_eps::ExtendedApnAmbr::from_bytes(
            self.contents_for(MappedEpsBearerParamId::ExtendedApnAmbr)?,
        )
    }

    /// Typed parameter identifier, or `None` for a future/unsupported identifier.
    pub fn parameter_id(&self) -> Option<MappedEpsBearerParamId> {
        MappedEpsBearerParamId::from_u8(self.param_id)
    }

    /// Build mapped EPS QoS parameters.
    pub fn from_eps_qos(value: crate::nas_eps::EpsQos) -> Option<Self> {
        Some(Self {
            param_id: MappedEpsBearerParamId::EpsQos as u8,
            contents: value.to_bytes()?,
        })
    }

    /// Build mapped extended EPS QoS parameters.
    pub fn from_extended_eps_qos(value: crate::nas_eps::ExtendedEpsQos) -> Self {
        Self {
            param_id: MappedEpsBearerParamId::ExtendedEpsQos as u8,
            contents: value.to_bytes().to_vec(),
        }
    }

    /// Build a mapped traffic-flow template.
    pub fn from_tft(value: &crate::nas_eps::Tft) -> Option<Self> {
        Some(Self {
            param_id: MappedEpsBearerParamId::TrafficFlowTemplate as u8,
            contents: value.to_bytes()?,
        })
    }

    /// Build mapped APN-AMBR parameters.
    pub fn from_apn_ambr(value: crate::nas_eps::ApnAmbr) -> Option<Self> {
        Some(Self {
            param_id: MappedEpsBearerParamId::ApnAmbr as u8,
            contents: value.to_bytes()?,
        })
    }

    /// Build mapped extended APN-AMBR parameters.
    pub fn from_extended_apn_ambr(value: crate::nas_eps::ExtendedApnAmbr) -> Self {
        Self {
            param_id: MappedEpsBearerParamId::ExtendedApnAmbr as u8,
            contents: value.to_bytes().to_vec(),
        }
    }

    /// Whether this is a parameter encoding a sender may produce.
    pub fn is_well_formed(&self) -> bool {
        match self.parameter_id() {
            Some(MappedEpsBearerParamId::EpsQos) => {
                crate::nas_eps::EpsQos::from_bytes_strict(&self.contents)
                    .and_then(crate::nas_eps::EpsQos::to_bytes)
                    .as_deref()
                    == Some(self.contents.as_slice())
            }
            Some(MappedEpsBearerParamId::ExtendedEpsQos) => self.contents.len() == 10,
            Some(MappedEpsBearerParamId::TrafficFlowTemplate) => {
                crate::nas_eps::Tft::from_bytes_strict(&self.contents).is_some()
            }
            Some(MappedEpsBearerParamId::ApnAmbr) => {
                crate::nas_eps::ApnAmbr::from_bytes_strict(&self.contents)
                    .and_then(crate::nas_eps::ApnAmbr::to_bytes)
                    .as_deref()
                    == Some(self.contents.as_slice())
            }
            Some(MappedEpsBearerParamId::ExtendedApnAmbr) => self.contents.len() == 6,
            None => false,
        }
    }
}

/// One mapped EPS bearer context per TS 24.501 §9.11.4.8.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MappedEpsBearerContext {
    /// EPS bearer identity (octet 1 high nibble).
    pub eps_bearer_id: u8,
    /// Operation code (octet 4 bits 7-8, mask 0xC0).
    pub op_code: u8,
    /// E flag — whether the EPS parameters list is included (octet 4 bit 5, mask 0x10).
    pub e_flag: bool,
    /// EPS parameters list.
    pub params: Vec<MappedEpsBearerParam>,
}

impl MappedEpsBearerContext {
    /// Typed operation code.
    pub fn operation(&self) -> Option<MappedEpsBearerOpCode> {
        MappedEpsBearerOpCode::from_u8(self.op_code)
            .filter(|operation| *operation != MappedEpsBearerOpCode::Reserved)
    }

    /// Construct a context from a typed operation and parameter list.
    pub fn new(
        eps_bearer_id: u8,
        operation: MappedEpsBearerOpCode,
        e_flag: bool,
        params: Vec<MappedEpsBearerParam>,
    ) -> Option<Self> {
        let context = Self {
            eps_bearer_id,
            op_code: operation as u8,
            e_flag,
            params,
        };
        context.is_well_formed().then_some(context)
    }

    /// Whether this context meets the sender rules in TS 24.501 §9.11.4.8.
    pub fn is_well_formed(&self) -> bool {
        if !(5..=15).contains(&self.eps_bearer_id)
            || self.params.len() > 15
            || self
                .params
                .iter()
                .any(|parameter| !parameter.is_well_formed())
        {
            return false;
        }
        let mut identifiers = [false; 256];
        if self.params.iter().any(|parameter| {
            std::mem::replace(&mut identifiers[usize::from(parameter.param_id)], true)
        }) {
            return false;
        }
        match self.operation() {
            Some(MappedEpsBearerOpCode::Create) => self.e_flag && !self.params.is_empty(),
            Some(MappedEpsBearerOpCode::Delete) => !self.e_flag && self.params.is_empty(),
            Some(MappedEpsBearerOpCode::Modify) => !self.params.is_empty(),
            Some(MappedEpsBearerOpCode::Reserved) | None => false,
        }
    }
}

impl NasMappedEpsBearerContexts {
    /// The raw mapped EPS bearer contexts bytes.
    pub fn contexts_data(&self) -> &[u8] {
        &self.value
    }

    /// Parse every mapped EPS bearer context while preserving unknown parameters.
    ///
    /// This receiver view checks complete length/count framing and defined spare
    /// bits. Unsupported parameter identifiers are retained so applications can
    /// apply the specified discard rule without losing the original bytes.
    pub fn try_contexts(&self) -> Option<Vec<MappedEpsBearerContext>> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let first = *data.get(pos)?;
            if first & 0x0f != 0 {
                return None;
            }
            let eps_bearer_id = first >> 4;
            pos += 1;
            let length = usize::from(u16::from_be_bytes([*data.get(pos)?, *data.get(pos + 1)?]));
            pos += 2;
            if length == 0 {
                return None;
            }
            let end = pos.checked_add(length)?;
            let header = *data.get(pos)?;
            if end > data.len() || header & 0x20 != 0 {
                return None;
            }
            let op_code = header >> 6;
            let e_flag = header & 0x10 != 0;
            let num_params = usize::from(header & 0x0f);
            let mut parameter_pos = pos + 1;
            let mut params = Vec::with_capacity(num_params);
            for _ in 0..num_params {
                let param_id = *data.get(parameter_pos)?;
                let parameter_length = usize::from(*data.get(parameter_pos + 1)?);
                parameter_pos += 2;
                let parameter_end = parameter_pos.checked_add(parameter_length)?;
                if parameter_end > end {
                    return None;
                }
                params.push(MappedEpsBearerParam {
                    param_id,
                    contents: data[parameter_pos..parameter_end].to_vec(),
                });
                parameter_pos = parameter_end;
            }
            if parameter_pos != end {
                return None;
            }
            out.push(MappedEpsBearerContext {
                eps_bearer_id,
                op_code,
                e_flag,
                params,
            });
            pos = end;
        }
        (!out.is_empty()).then_some(out)
    }

    /// Parse the contexts, returning an empty list for malformed framing.
    pub fn contexts(&self) -> Vec<MappedEpsBearerContext> {
        self.try_contexts().unwrap_or_default()
    }

    /// Build a canonical, non-empty mapped EPS bearer context list.
    pub fn from_contexts(contexts: &[MappedEpsBearerContext]) -> Option<Self> {
        if contexts.is_empty() {
            return None;
        }
        let mut identities = [false; 16];
        let mut value = Vec::new();
        for context in contexts {
            if !context.is_well_formed()
                || std::mem::replace(&mut identities[usize::from(context.eps_bearer_id)], true)
            {
                return None;
            }
            let mut body = Vec::new();
            body.push(
                (context.op_code << 6)
                    | if context.e_flag { 0x10 } else { 0 }
                    | u8::try_from(context.params.len()).ok()?,
            );
            for parameter in &context.params {
                body.push(parameter.param_id);
                body.push(u8::try_from(parameter.contents.len()).ok()?);
                body.extend_from_slice(&parameter.contents);
            }
            value.push(context.eps_bearer_id << 4);
            value.extend_from_slice(&u16::try_from(body.len()).ok()?.to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
    }

    /// Build from raw EPS bearer contexts bytes without applying sender validation.
    pub fn from_contexts_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.try_contexts().is_some_and(|contexts| {
            Self::from_contexts(&contexts).is_some_and(|canonical| canonical.value == self.value)
        })
    }

    /// Whether a receiver can parse all context and parameter boundaries.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.try_contexts().is_some()
    }
}

/// TMGI carried inside an MBS container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MbsTmgi {
    /// MBMS service identifier.
    pub service_id: [u8; 3],
    /// Optional serving PLMN.
    pub plmn: Option<PlmnId>,
}

/// Requested MBS operation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RequestedMbsOperation {
    /// Join the multicast session.
    Join = 1,
    /// Leave the multicast session.
    Leave = 2,
}

/// Requested multicast-session identifier.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RequestedMbsSessionId {
    /// Temporary Mobile Group Identity.
    Tmgi(MbsTmgi),
    /// Source-specific IPv4 multicast pair.
    Ipv4 {
        /// Unicast source address.
        source: [u8; 4],
        /// Multicast destination address.
        destination: [u8; 4],
    },
    /// Source-specific IPv6 multicast pair.
    Ipv6 {
        /// Unicast source address.
        source: [u8; 16],
        /// Multicast destination address.
        destination: [u8; 16],
    },
}

/// One requested MBS session record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RequestedMbsSession {
    /// Requested operation.
    pub operation: RequestedMbsOperation,
    /// Multicast-session identifier.
    pub session_id: RequestedMbsSessionId,
}

/// Network MBS decision. Reserved received values fall back to NoIndication.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MbsDecision {
    /// Receiver fallback/no defined decision.
    NoIndication = 0,
    /// MBS service-area update.
    ServiceAreaUpdate = 1,
    /// Join accepted.
    JoinAccepted = 2,
    /// Join rejected.
    JoinRejected = 3,
    /// Remove the UE from the multicast session.
    RemoveUe = 4,
    /// Security-information update.
    SecurityInformationUpdate = 5,
}

impl MbsDecision {
    fn from_received(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::ServiceAreaUpdate,
            2 => Self::JoinAccepted,
            3 => Self::JoinRejected,
            4 => Self::RemoveUe,
            5 => Self::SecurityInformationUpdate,
            _ => Self::NoIndication,
        }
    }
}

/// MBS rejection/removal cause. Reserved received values fall back to NoAdditionalInformation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MbsRejectionCause {
    /// No additional information.
    NoAdditionalInformation = 0,
    /// Insufficient resources.
    InsufficientResources = 1,
    /// UE is not authorized.
    NotAuthorized = 2,
    /// Session has not started or will not start soon.
    SessionNotStarted = 3,
    /// UE is outside the local service area.
    OutsideServiceArea = 4,
    /// Session context not found.
    ContextNotFound = 5,
    /// Session was released.
    SessionReleased = 6,
}

impl MbsRejectionCause {
    fn from_received(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::InsufficientResources,
            2 => Self::NotAuthorized,
            3 => Self::SessionNotStarted,
            4 => Self::OutsideServiceArea,
            5 => Self::ContextNotFound,
            6 => Self::SessionReleased,
            _ => Self::NoAdditionalInformation,
        }
    }
}

/// NR Cell Global Identity in an MBS service area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MbsNrCgi {
    /// 36-bit NR cell identifier.
    pub nr_cell_id: u64,
    /// Cell PLMN.
    pub plmn: PlmnId,
}

/// MBS service-area representation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MbsServiceArea {
    /// 5GS TAI-list entries.
    TaiList(Vec<TaiListEntry>),
    /// NR CGI entries.
    NrCgiList(Vec<MbsNrCgi>),
    /// Both TAI-list and NR CGI entries.
    TaiAndNrCgi {
        /// 5GS TAI-list entries.
        tais: Vec<TaiListEntry>,
        /// NR CGI entries.
        nr_cgis: Vec<MbsNrCgi>,
    },
}

/// Optional MBS timer.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MbsTimer {
    /// Six-octet TS 24.008 MBS start time.
    StartTime([u8; 6]),
    /// One-octet TS 24.008 GPRS Timer 3 back-off timer.
    Backoff(u8),
}

/// One MBS security key set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MbsSecurityKeySet {
    /// Key-domain identifier.
    pub key_domain_id: [u8; 3],
    /// MBS Service Key identifier.
    pub msk_id: [u8; 4],
    /// MBS Service Key.
    pub msk: [u8; 16],
    /// Optional MBS Traffic Key identifier.
    pub mtk_id: Option<[u8; 2]>,
    /// Optional encrypted MBS Traffic Key.
    pub encrypted_mtk: Option<[u8; 16]>,
}

/// One received MBS session record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceivedMbsSession {
    /// Network decision.
    pub decision: MbsDecision,
    /// Rejection/removal cause, present only for the corresponding decisions.
    pub rejection_cause: Option<MbsRejectionCause>,
    /// Temporary Mobile Group Identity.
    pub tmgi: MbsTmgi,
    /// Optional source/destination IPv4 pair.
    pub ipv4: Option<([u8; 4], [u8; 4])>,
    /// Optional source/destination IPv6 pair.
    pub ipv6: Option<([u8; 16], [u8; 16])>,
    /// Optional local MBS service area.
    pub service_area: Option<MbsServiceArea>,
    /// Optional start/back-off timer.
    pub timer: Option<MbsTimer>,
    /// MBS security key sets.
    pub security_keys: Vec<MbsSecurityKeySet>,
}

fn parse_mbs_tmgi(data: &[u8], pos: &mut usize) -> Option<MbsTmgi> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    if !matches!(len, 3 | 6) {
        return None;
    }
    let end = pos.checked_add(len)?;
    let contents = data.get(*pos..end)?;
    let service_id = contents[..3].try_into().ok()?;
    let plmn = (len == 6)
        .then(|| PlmnId::from_tbcd(&contents[3..6]))
        .flatten();
    if len == 6 && plmn.is_none() {
        return None;
    }
    *pos = end;
    Some(MbsTmgi { service_id, plmn })
}

fn encode_mbs_tmgi(tmgi: &MbsTmgi, out: &mut Vec<u8>) -> Option<()> {
    out.push(if tmgi.plmn.is_some() { 6 } else { 3 });
    out.extend_from_slice(&tmgi.service_id);
    if let Some(plmn) = tmgi.plmn {
        out.extend_from_slice(&plmn.try_to_tbcd()?);
    }
    Some(())
}

fn parse_mbs_tai_list(data: &[u8], pos: &mut usize) -> Option<Vec<TaiListEntry>> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    let end = pos.checked_add(len)?;
    let ie = NasFGsTrackingAreaIdentityList::new(data.get(*pos..end)?.to_vec());
    let entries = ie.parse();
    if entries.is_empty() {
        return None;
    }
    *pos = end;
    Some(entries)
}

fn encode_mbs_tai_list(entries: &[TaiListEntry], out: &mut Vec<u8>) -> Option<()> {
    if entries.is_empty() {
        return None;
    }
    let ie = NasFGsTrackingAreaIdentityList::try_from_entries(entries)?;
    out.push(ie.value.len().try_into().ok()?);
    out.extend_from_slice(&ie.value);
    Some(())
}

fn parse_mbs_nr_cgis(data: &[u8], pos: &mut usize) -> Option<Vec<MbsNrCgi>> {
    let len = *data.get(*pos)? as usize;
    *pos += 1;
    if len == 0 || !len.is_multiple_of(8) {
        return None;
    }
    let end = pos.checked_add(len)?;
    let contents = data.get(*pos..end)?;
    let mut result = Vec::with_capacity(len / 8);
    for value in contents.chunks_exact(8) {
        if value[4] & 0x0f != 0 {
            return None;
        }
        let encoded =
            u64::from_be_bytes([0, 0, 0, value[0], value[1], value[2], value[3], value[4]]);
        result.push(MbsNrCgi {
            nr_cell_id: encoded >> 4,
            plmn: PlmnId::from_tbcd(&value[5..8])?,
        });
    }
    *pos = end;
    Some(result)
}

fn encode_mbs_nr_cgis(entries: &[MbsNrCgi], out: &mut Vec<u8>) -> Option<()> {
    if entries.is_empty() || entries.len() > 31 {
        return None;
    }
    out.push((entries.len() * 8).try_into().ok()?);
    for entry in entries {
        if entry.nr_cell_id > 0x0f_ffff_ffff {
            return None;
        }
        let encoded = (entry.nr_cell_id << 4).to_be_bytes();
        out.extend_from_slice(&encoded[3..8]);
        out.extend_from_slice(&entry.plmn.try_to_tbcd()?);
    }
    Some(())
}

impl NasReceivedMbsContainer {
    /// The raw received MBS container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Parse all received-session records with receiver fallbacks.
    pub fn try_sessions(&self) -> Option<Vec<ReceivedMbsSession>> {
        if self.value.len() < 6 {
            return None;
        }
        let data = &self.value;
        let mut pos = 0;
        let mut records = Vec::new();
        while pos < data.len() {
            let header = *data.get(pos)?;
            let flags = *data.get(pos + 1)?;
            pos += 2;

            let decision = MbsDecision::from_received(header & 0x07);
            let area_kind = header >> 3 & 0x03;
            let rejection_cause =
                matches!(decision, MbsDecision::JoinRejected | MbsDecision::RemoveUe)
                    .then(|| MbsRejectionCause::from_received(header >> 5));

            let ip_present = flags & 0x01 != 0;
            let timer_kind = match flags >> 1 & 0x03 {
                1 => 1,
                2 => 2,
                _ => 0,
            };
            let security_present = flags & 0x08 != 0;
            let ipv6 = flags & 0x10 != 0;
            let tmgi = parse_mbs_tmgi(data, &mut pos)?;

            let (ipv4, ipv6_pair) = if ip_present && ipv6 {
                let source: [u8; 16] = data.get(pos..pos + 16)?.try_into().ok()?;
                pos += 16;
                let destination: [u8; 16] = data.get(pos..pos + 16)?.try_into().ok()?;
                pos += 16;
                (None, Some((source, destination)))
            } else if ip_present {
                let source: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
                pos += 4;
                let destination: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
                pos += 4;
                (Some((source, destination)), None)
            } else {
                (None, None)
            };

            let service_area = match area_kind {
                0 => None,
                1 => Some(MbsServiceArea::TaiList(parse_mbs_tai_list(data, &mut pos)?)),
                2 => Some(MbsServiceArea::NrCgiList(parse_mbs_nr_cgis(
                    data, &mut pos,
                )?)),
                3 => Some(MbsServiceArea::TaiAndNrCgi {
                    tais: parse_mbs_tai_list(data, &mut pos)?,
                    nr_cgis: parse_mbs_nr_cgis(data, &mut pos)?,
                }),
                _ => unreachable!(),
            };

            let timer = match timer_kind {
                1 => {
                    let value: [u8; 6] = data.get(pos..pos + 6)?.try_into().ok()?;
                    pos += 6;
                    Some(MbsTimer::StartTime(value))
                }
                2 => {
                    let value = *data.get(pos)?;
                    pos += 1;
                    Some(MbsTimer::Backoff(value))
                }
                _ => None,
            };

            let mut security_keys = Vec::new();
            if security_present {
                let count = *data.get(pos)? as usize;
                pos += 1;
                for _ in 0..count {
                    let key_flags = *data.get(pos)?;
                    pos += 1;
                    let key_domain_id = data.get(pos..pos + 3)?.try_into().ok()?;
                    pos += 3;
                    let msk_id = data.get(pos..pos + 4)?.try_into().ok()?;
                    pos += 4;
                    let msk = data.get(pos..pos + 16)?.try_into().ok()?;
                    pos += 16;
                    let (mtk_id, encrypted_mtk) = if key_flags & 0x01 != 0 {
                        let id = data.get(pos..pos + 2)?.try_into().ok()?;
                        pos += 2;
                        let key = data.get(pos..pos + 16)?.try_into().ok()?;
                        pos += 16;
                        (Some(id), Some(key))
                    } else {
                        (None, None)
                    };
                    security_keys.push(MbsSecurityKeySet {
                        key_domain_id,
                        msk_id,
                        msk,
                        mtk_id,
                        encrypted_mtk,
                    });
                }
            }

            records.push(ReceivedMbsSession {
                decision,
                rejection_cause,
                tmgi,
                ipv4,
                ipv6: ipv6_pair,
                service_area,
                timer,
                security_keys,
            });
        }
        (!records.is_empty()).then_some(records)
    }

    /// Parsed received-session records, or an empty list for malformed data.
    pub fn sessions(&self) -> Vec<ReceivedMbsSession> {
        self.try_sessions().unwrap_or_default()
    }

    /// Build a received MBS container from sender-valid records.
    pub fn try_from_sessions(records: &[ReceivedMbsSession]) -> Option<Self> {
        if records.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for record in records {
            if record.decision == MbsDecision::NoIndication {
                return None;
            }
            let cause = if matches!(
                record.decision,
                MbsDecision::JoinRejected | MbsDecision::RemoveUe
            ) {
                record.rejection_cause?
            } else {
                if record.rejection_cause.is_some() {
                    return None;
                }
                MbsRejectionCause::NoAdditionalInformation
            };
            let area_kind = match &record.service_area {
                None => 0,
                Some(MbsServiceArea::TaiList(_)) => 1,
                Some(MbsServiceArea::NrCgiList(_)) => 2,
                Some(MbsServiceArea::TaiAndNrCgi { .. }) => 3,
            };
            let header = record.decision as u8 | (area_kind << 3) | ((cause as u8) << 5);

            let (ip_present, ip_is_v6) = match (&record.ipv4, &record.ipv6) {
                (None, None) => (false, false),
                (Some(_), None) => (true, false),
                (None, Some(_)) => (true, true),
                (Some(_), Some(_)) => return None,
            };
            if record.decision == MbsDecision::RemoveUe && ip_present {
                return None;
            }
            let timer_kind = match record.timer {
                None => 0,
                Some(MbsTimer::StartTime(_)) => 1,
                Some(MbsTimer::Backoff(_)) => 2,
            };
            let flags = u8::from(ip_present)
                | (timer_kind << 1)
                | (u8::from(!record.security_keys.is_empty()) << 3)
                | (u8::from(ip_is_v6) << 4);
            value.extend_from_slice(&[header, flags]);
            encode_mbs_tmgi(&record.tmgi, &mut value)?;
            if let Some((source, destination)) = record.ipv4 {
                value.extend_from_slice(&source);
                value.extend_from_slice(&destination);
            }
            if let Some((source, destination)) = record.ipv6 {
                value.extend_from_slice(&source);
                value.extend_from_slice(&destination);
            }
            match &record.service_area {
                None => {}
                Some(MbsServiceArea::TaiList(tais)) => {
                    encode_mbs_tai_list(tais, &mut value)?;
                }
                Some(MbsServiceArea::NrCgiList(cgis)) => {
                    encode_mbs_nr_cgis(cgis, &mut value)?;
                }
                Some(MbsServiceArea::TaiAndNrCgi { tais, nr_cgis }) => {
                    encode_mbs_tai_list(tais, &mut value)?;
                    encode_mbs_nr_cgis(nr_cgis, &mut value)?;
                }
            }
            match record.timer {
                None => {}
                Some(MbsTimer::StartTime(start)) => value.extend_from_slice(&start),
                Some(MbsTimer::Backoff(timer)) => value.push(timer),
            }
            if !record.security_keys.is_empty() {
                value.push(record.security_keys.len().try_into().ok()?);
                for key in &record.security_keys {
                    let has_mtk = match (key.mtk_id, key.encrypted_mtk) {
                        (None, None) => false,
                        (Some(_), Some(_)) => true,
                        _ => return None,
                    };
                    value.push(u8::from(has_mtk));
                    value.extend_from_slice(&key.key_domain_id);
                    value.extend_from_slice(&key.msk_id);
                    value.extend_from_slice(&key.msk);
                    if has_mtk {
                        value.extend_from_slice(&key.mtk_id?);
                        value.extend_from_slice(&key.encrypted_mtk?);
                    }
                }
            }
        }
        (value.len() <= u16::MAX as usize).then(|| Self::new(value))
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        let Some(records) = self.try_sessions() else {
            return false;
        };
        Self::try_from_sessions(&records).is_some_and(|rebuilt| rebuilt.value == self.value)
    }

    /// Build from raw container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasRequestedMbsContainer {
    /// The raw requested MBS container bytes.
    pub fn container_data(&self) -> &[u8] {
        &self.value
    }

    /// Parse all requested-session records.
    pub fn try_sessions(&self) -> Option<Vec<RequestedMbsSession>> {
        if self.value.len() < 5 {
            return None;
        }
        let data = &self.value;
        let mut pos = 0;
        let mut records = Vec::new();
        while pos < data.len() {
            let control = *data.get(pos)?;
            pos += 1;
            if control & 0xf0 != 0 {
                return None;
            }
            let operation = match control >> 2 & 0x03 {
                1 => RequestedMbsOperation::Join,
                2 => RequestedMbsOperation::Leave,
                _ => return None,
            };
            let session_id = match control & 0x03 {
                1 => RequestedMbsSessionId::Tmgi(parse_mbs_tmgi(data, &mut pos)?),
                2 => {
                    let source = data.get(pos..pos + 4)?.try_into().ok()?;
                    pos += 4;
                    let destination = data.get(pos..pos + 4)?.try_into().ok()?;
                    pos += 4;
                    RequestedMbsSessionId::Ipv4 {
                        source,
                        destination,
                    }
                }
                3 => {
                    let source = data.get(pos..pos + 16)?.try_into().ok()?;
                    pos += 16;
                    let destination = data.get(pos..pos + 16)?.try_into().ok()?;
                    pos += 16;
                    RequestedMbsSessionId::Ipv6 {
                        source,
                        destination,
                    }
                }
                _ => return None,
            };
            records.push(RequestedMbsSession {
                operation,
                session_id,
            });
        }
        (!records.is_empty()).then_some(records)
    }

    /// Parsed requested-session records, or an empty list for malformed data.
    pub fn sessions(&self) -> Vec<RequestedMbsSession> {
        self.try_sessions().unwrap_or_default()
    }

    /// Build from sender-valid requested-session records.
    pub fn try_from_sessions(records: &[RequestedMbsSession]) -> Option<Self> {
        if records.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for record in records {
            let id_type = match record.session_id {
                RequestedMbsSessionId::Tmgi(_) => 1,
                RequestedMbsSessionId::Ipv4 { .. } => 2,
                RequestedMbsSessionId::Ipv6 { .. } => 3,
            };
            value.push(id_type | (record.operation as u8) << 2);
            match &record.session_id {
                RequestedMbsSessionId::Tmgi(tmgi) => encode_mbs_tmgi(tmgi, &mut value)?,
                RequestedMbsSessionId::Ipv4 {
                    source,
                    destination,
                } => {
                    value.extend_from_slice(source);
                    value.extend_from_slice(destination);
                }
                RequestedMbsSessionId::Ipv6 {
                    source,
                    destination,
                } => {
                    value.extend_from_slice(source);
                    value.extend_from_slice(destination);
                }
            }
        }
        (value.len() <= u16::MAX as usize).then(|| Self::new(value))
    }

    /// Whether the complete container is sender-valid.
    pub fn is_well_formed(&self) -> bool {
        let Some(records) = self.try_sessions() else {
            return false;
        };
        Self::try_from_sessions(&records).is_some_and(|rebuilt| rebuilt.value == self.value)
    }

    /// Build from raw container bytes.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── NSSAI / Slice related IEs ───────────────────────────────────────────────

/// Cause value for an entry in [`NasExtendedRejectedNssai`] per TS 24.501 §9.11.3.75.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ExtendedRejectedSNssaiCause {
    /// S-NSSAI not available in the current PLMN or SNPN.
    NotAvailableInPlmn = 0x00,
    /// S-NSSAI not available in the current registration area.
    NotAvailableInRegArea = 0x01,
    /// S-NSSAI not available due to failed/revoked NSSAA.
    FailedOrRevokedAuth = 0x02,
    /// S-NSSAI not available due to maximum number of UEs reached.
    MaxUesReached = 0x03,
}

impl ExtendedRejectedSNssaiCause {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NotAvailableInPlmn),
            0x01 => Some(Self::NotAvailableInRegArea),
            0x02 => Some(Self::FailedOrRevokedAuth),
            0x03 => Some(Self::MaxUesReached),
            _ => None,
        }
    }
}

/// One rejected S-NSSAI entry inside an extended rejected NSSAI partial list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedRejectedSNssai {
    /// Raw cause value (use [`ExtendedRejectedSNssaiCause::from_u8`] for typed value).
    pub cause: u8,
    /// S-NSSAI bytes (raw value, see [`SNssaiContents`]).
    pub s_nssai: Vec<u8>,
}

impl ExtendedRejectedSNssai {
    /// Typed cause, or `None` when a receiver preserved a reserved value.
    pub fn cause_value(&self) -> Option<ExtendedRejectedSNssaiCause> {
        ExtendedRejectedSNssaiCause::from_u8(self.cause)
    }

    /// Parsed S-NSSAI including an optional mapped HPLMN value.
    pub fn parsed_s_nssai(&self) -> Option<SNssaiContents> {
        NasSNssai::from_value(self.s_nssai.clone())?.parse()
    }
}

/// One partial list inside [`NasExtendedRejectedNssai`] per TS 24.501 §9.11.3.75.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedRejectedNssaiPartialList {
    /// Type of list (bits 5-7 of the header octet, mask 0x70):
    /// 0 = no associated back-off timer, 1 = one timer applied to all entries.
    pub type_of_list: u8,
    /// Optional GPRS Timer 3 back-off timer octet (only present when `type_of_list != 0`).
    pub back_off_timer: Option<NasGprsTimer3>,
    /// Rejected S-NSSAI entries.
    pub rejected: Vec<ExtendedRejectedSNssai>,
}

impl NasExtendedRejectedNssai {
    /// The raw extended rejected NSSAI bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    fn try_partial_lists(&self) -> Option<Vec<ExtendedRejectedNssaiPartialList>> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        let mut total = 0usize;
        while pos < data.len() && total < 8 {
            let header = *data.get(pos)?;
            if header & 0x80 != 0 {
                return None;
            }
            let type_of_list = (header >> 4) & 0x07;
            if type_of_list > 1 {
                return None;
            }
            let num_elements = match header & 0x0f {
                count @ 0..=7 => usize::from(count) + 1,
                _ => 8,
            };
            pos += 1;
            let back_off_timer = if type_of_list == 1 {
                Some(NasGprsTimer3::new(vec![*data.get(pos)?]))
            } else {
                None
            };
            pos += usize::from(type_of_list == 1);
            let retained = num_elements.min(8 - total);
            let mut rejected = Vec::with_capacity(retained);
            for _ in 0..retained {
                let len_cause = *data.get(pos)?;
                let nssai_len = usize::from(len_cause >> 4);
                let cause = len_cause & 0x0f;
                pos += 1;
                let end = pos.checked_add(nssai_len)?;
                let s_nssai = data.get(pos..end)?.to_vec();
                NasSNssai::from_value(s_nssai.clone())?.parse()?;
                rejected.push(ExtendedRejectedSNssai { cause, s_nssai });
                total += 1;
                pos = end;
            }
            out.push(ExtendedRejectedNssaiPartialList {
                type_of_list,
                back_off_timer,
                rejected,
            });
            if retained < num_elements {
                return Some(out);
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// Parse at most the first eight rejected S-NSSAIs, as required on receipt.
    pub fn partial_lists(&self) -> Vec<ExtendedRejectedNssaiPartialList> {
        self.try_partial_lists().unwrap_or_default()
    }

    /// Build one through eight rejected S-NSSAIs in structured partial lists.
    pub fn try_from_partial_lists(lists: &[ExtendedRejectedNssaiPartialList]) -> Option<Self> {
        if lists.is_empty() {
            return None;
        }
        let mut total = 0usize;
        let mut value = Vec::new();
        for list in lists {
            let count = list.rejected.len();
            total = total.checked_add(count)?;
            if !(1..=8).contains(&count)
                || total > 8
                || !matches!(list.type_of_list, 0 | 1)
                || list.type_of_list == 0 && list.back_off_timer.is_some()
                || list.type_of_list == 1
                    && !list
                        .back_off_timer
                        .as_ref()
                        .is_some_and(|timer| timer.value.len() == 1 && timer.is_well_formed())
            {
                return None;
            }
            value.push((list.type_of_list << 4) | u8::try_from(count - 1).ok()?);
            if let Some(timer) = &list.back_off_timer {
                value.push(timer.value[0]);
            }
            for rejected in &list.rejected {
                if rejected.cause_value().is_none()
                    || NasSNssai::from_value(rejected.s_nssai.clone())
                        .and_then(|s_nssai| s_nssai.parse())
                        .is_none()
                    || rejected.s_nssai.len() > 0x0f
                {
                    return None;
                }
                value.push((u8::try_from(rejected.s_nssai.len()).ok()? << 4) | rejected.cause);
                value.extend_from_slice(&rejected.s_nssai);
            }
        }
        (value.len() <= 88).then(|| Self::new(value))
    }

    /// Build from structured partial lists.
    ///
    /// # Panics
    ///
    /// Panics for invalid list types, timer presence, causes, S-NSSAIs, or counts.
    pub fn from_partial_lists(lists: &[ExtendedRejectedNssaiPartialList]) -> Self {
        Self::try_from_partial_lists(lists)
            .expect("extended rejected NSSAI partial lists must meet TS 24.501 sender rules")
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.try_partial_lists().is_some_and(|lists| {
            Self::try_from_partial_lists(&lists)
                .is_some_and(|canonical| canonical.value == self.value)
        })
    }

    /// Whether a receiver can parse the required first eight entries.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.try_partial_lists().is_some()
    }

    /// Build from raw bytes without applying sender validation.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

fn tai_list_value_is_well_formed(value: &[u8]) -> bool {
    if value.is_empty() {
        return false;
    }
    let parsed = NasFGsTrackingAreaIdentityList::new(value.to_vec()).parse();
    NasFGsTrackingAreaIdentityList::try_from_entries(&parsed)
        .is_some_and(|canonical| canonical.value == value)
}

fn snssai_list_is_well_formed(value: &[u8], allow_mapped: bool) -> bool {
    let mut pos = 0usize;
    let mut count = 0usize;
    while pos < value.len() {
        let length = usize::from(value[pos]);
        pos += 1;
        if !(matches!(length, 1 | 4) || allow_mapped && matches!(length, 2 | 5 | 8)) {
            return false;
        }
        let Some(end) = pos.checked_add(length) else {
            return false;
        };
        if end > value.len() || NasSNssai::new(value[pos..end].to_vec()).parse().is_none() {
            return false;
        }
        count += 1;
        pos = end;
    }
    count > 0 && count <= 8
}

/// One Network Slice AS Group entry per TS 24.501 §9.11.3.87.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NsagInfoEntry {
    /// NSAG identifier.
    pub nsag_id: u8,
    /// S-NSSAI raw bytes (length-prefixed S-NSSAI value, see [`SNssaiContents`]).
    pub s_nssai: Vec<u8>,
    /// NSAG priority.
    pub priority: u8,
    /// Optional 5GS Tracking Area Identity list bytes (TAI list value, may be empty).
    pub tai_list: Vec<u8>,
}

impl NasNsagInformation {
    /// The raw NSAG information bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the first 32 complete NSAG entries.
    pub fn entries(&self) -> Vec<NsagInfoEntry> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut entries_with_tai = 0usize;
        while pos < self.value.len() && out.len() < 32 {
            let length = usize::from(self.value[pos]);
            pos += 1;
            let Some(end) = pos.checked_add(length) else {
                break;
            };
            if length < 5 || end > self.value.len() {
                break;
            }
            let nsag_id = self.value[pos];
            pos += 1;
            let snssai_length = usize::from(self.value[pos]);
            pos += 1;
            let Some(snssai_end) = pos.checked_add(snssai_length) else {
                break;
            };
            if snssai_end >= end {
                break;
            }
            let s_nssai = self.value[pos..snssai_end].to_vec();
            if !snssai_list_is_well_formed(&s_nssai, false) {
                break;
            }
            pos = snssai_end;
            let priority = self.value[pos];
            pos += 1;
            let tai_list = if pos < end {
                let tai_length = usize::from(self.value[pos]);
                pos += 1;
                let Some(tai_end) = pos.checked_add(tai_length) else {
                    break;
                };
                if tai_end != end {
                    break;
                }
                let value = self.value[pos..tai_end].to_vec();
                if !tai_list_value_is_well_formed(&value) {
                    break;
                }
                entries_with_tai += 1;
                if entries_with_tai > 4 {
                    break;
                }
                value
            } else {
                Vec::new()
            };
            out.push(NsagInfoEntry {
                nsag_id,
                s_nssai,
                priority,
                tai_list,
            });
            pos = end;
        }
        out
    }

    /// Build one to 32 NSAG entries; at most four may contain a TAI list.
    pub fn from_entries(entries: &[NsagInfoEntry]) -> Option<Self> {
        if entries.is_empty()
            || entries.len() > 32
            || entries
                .iter()
                .filter(|entry| !entry.tai_list.is_empty())
                .count()
                > 4
        {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if !snssai_list_is_well_formed(&entry.s_nssai, false)
                || !entry.tai_list.is_empty() && !tai_list_value_is_well_formed(&entry.tai_list)
            {
                return None;
            }
            let mut body = Vec::new();
            body.push(entry.nsag_id);
            body.push(u8::try_from(entry.s_nssai.len()).ok()?);
            body.extend_from_slice(&entry.s_nssai);
            body.push(entry.priority);
            if !entry.tai_list.is_empty() {
                body.push(u8::try_from(entry.tai_list.len()).ok()?);
                body.extend_from_slice(&entry.tai_list);
            }
            value.push(u8::try_from(body.len()).ok()?);
            value.extend_from_slice(&body);
        }
        (value.len() <= 3140).then(|| Self::new(value))
    }

    /// Sender check for all entry counts, nested lists, and exact boundaries.
    pub fn is_well_formed(&self) -> bool {
        Self::from_entries(&self.entries()).is_some_and(|canonical| canonical.value == self.value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// One NSSRG-per-S-NSSAI entry per TS 24.501 §9.11.3.82.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NssrgInfoEntry {
    /// S-NSSAI content octets (without its length octet).
    pub s_nssai: Vec<u8>,
    /// One byte per NSSRG value (each NSSRG identifier is a single octet).
    pub nssrg_values: Vec<u8>,
}

impl NasNssrgInformation {
    /// The raw NSSRG information bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse complete entries, retaining at most the first sixteen NSSRG
    /// values for each S-NSSAI as required on reception.
    pub fn entries(&self) -> Vec<NssrgInfoEntry> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() && out.len() < 8 {
            let length = usize::from(self.value[pos]);
            pos += 1;
            let Some(end) = pos.checked_add(length) else {
                break;
            };
            if length < 3 || end > self.value.len() {
                break;
            }
            let snssai_length = usize::from(self.value[pos]);
            pos += 1;
            let Some(snssai_end) = pos.checked_add(snssai_length) else {
                break;
            };
            if snssai_end >= end {
                break;
            }
            let s_nssai = self.value[pos..snssai_end].to_vec();
            if NasSNssai::new(s_nssai.clone()).parse().is_none() {
                break;
            }
            let nssrg_values = self.value[snssai_end..end]
                .iter()
                .copied()
                .take(16)
                .collect();
            out.push(NssrgInfoEntry {
                s_nssai,
                nssrg_values,
            });
            pos = end;
        }
        out
    }

    /// Build one to eight S-NSSAI entries with one to sixteen NSSRG values each.
    pub fn from_entries(entries: &[NssrgInfoEntry]) -> Option<Self> {
        if !(1..=8).contains(&entries.len()) {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if NasSNssai::new(entry.s_nssai.clone()).parse().is_none()
                || !(1..=16).contains(&entry.nssrg_values.len())
            {
                return None;
            }
            let body_length = 1usize
                .checked_add(entry.s_nssai.len())?
                .checked_add(entry.nssrg_values.len())?;
            value.push(u8::try_from(body_length).ok()?);
            value.push(u8::try_from(entry.s_nssai.len()).ok()?);
            value.extend_from_slice(&entry.s_nssai);
            value.extend_from_slice(&entry.nssrg_values);
        }
        (value.len() <= 4096).then(|| Self::new(value))
    }

    /// Sender check for entry/value counts, S-NSSAI syntax, and boundaries.
    pub fn is_well_formed(&self) -> bool {
        Self::from_entries(&self.entries()).is_some_and(|canonical| canonical.value == self.value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// One criteria component of an operator-defined access category per
/// TS 24.501 §9.11.3.38.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OperatorAccessCategoryCriterion {
    /// Type 0 — list of DNNs (each DNN as label-form bytes).
    Dnns(Vec<Vec<u8>>),
    /// Type 1 — list of (16-byte OS ID, OS App ID) pairs.
    OsApps(Vec<(Vec<u8>, Vec<u8>)>),
    /// Type 2 — list of S-NSSAIs (each S-NSSAI as raw value bytes).
    SNssais(Vec<Vec<u8>>),
}

/// One operator-defined access category definition per TS 24.501 §9.11.3.38.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OperatorAccessCategoryDefinition {
    /// Precedence value (octet 1 of the entry body).
    pub precedence: u8,
    /// PSAC flag — when true, a standardised access category number is also present.
    pub psac: bool,
    /// Raw operator-defined access category number (lower 5 bits of the PSAC byte).
    pub category_number_raw: u8,
    /// Criteria components.
    pub criteria: Vec<OperatorAccessCategoryCriterion>,
    /// Standardised access category number (only present when `psac == true`).
    pub standardised_category: Option<u8>,
}

impl OperatorAccessCategoryDefinition {
    /// Operator-defined access category number as displayed by the NAS dissector.
    pub fn category_number(&self) -> u8 {
        self.category_number_raw.saturating_add(32)
    }
}

impl NasOperatorDefinedAccessCategoryDefinitions {
    /// The raw operator-defined access category definitions bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse all definitions, returning `None` for incomplete/reserved grammar.
    pub fn try_definitions(&self) -> Option<Vec<OperatorAccessCategoryDefinition>> {
        let data = &self.value;
        let mut definitions = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            if definitions.len() == 32 {
                return None;
            }
            let entry_length = usize::from(*data.get(pos)?);
            pos += 1;
            if entry_length < 3 {
                return None;
            }
            let entry_end = pos.checked_add(entry_length)?;
            if entry_end > data.len() {
                return None;
            }
            let precedence = *data.get(pos)?;
            let psac_octet = *data.get(pos + 1)?;
            if psac_octet & 0x60 != 0 {
                return None;
            }
            let psac = psac_octet & 0x80 != 0;
            let category_number_raw = psac_octet & 0x1f;
            let criteria_length = usize::from(*data.get(pos + 2)?);
            pos += 3;
            if criteria_length == 0 {
                return None;
            }
            let criteria_end = pos.checked_add(criteria_length)?;
            if criteria_end > entry_end || entry_end != criteria_end + usize::from(psac) {
                return None;
            }
            let mut criteria = Vec::new();
            while pos < criteria_end {
                let criterion_type = *data.get(pos)?;
                let count = usize::from(*data.get(pos + 1)?);
                pos += 2;
                if count == 0 {
                    return None;
                }
                match criterion_type {
                    0 => {
                        let mut dnns = Vec::with_capacity(count);
                        for _ in 0..count {
                            let length = usize::from(*data.get(pos)?);
                            pos += 1;
                            let end = pos.checked_add(length)?;
                            let dnn = data.get(pos..end)?.to_vec();
                            if end > criteria_end || crate::common::decode_labels(&dnn).is_none() {
                                return None;
                            }
                            dnns.push(dnn);
                            pos = end;
                        }
                        criteria.push(OperatorAccessCategoryCriterion::Dnns(dnns));
                    }
                    1 => {
                        let mut apps = Vec::with_capacity(count);
                        for _ in 0..count {
                            let os_id = data.get(pos..pos.checked_add(16)?)?.to_vec();
                            pos += 16;
                            let app_length = usize::from(*data.get(pos)?);
                            pos += 1;
                            let end = pos.checked_add(app_length)?;
                            if end > criteria_end {
                                return None;
                            }
                            apps.push((os_id, data[pos..end].to_vec()));
                            pos = end;
                        }
                        criteria.push(OperatorAccessCategoryCriterion::OsApps(apps));
                    }
                    2 => {
                        let mut snssais = Vec::with_capacity(count);
                        for _ in 0..count {
                            let length = usize::from(*data.get(pos)?);
                            pos += 1;
                            let end = pos.checked_add(length)?;
                            let s_nssai = data.get(pos..end)?.to_vec();
                            if end > criteria_end
                                || !matches!(length, 1 | 4)
                                || NasSNssai::from_value(s_nssai.clone())
                                    .and_then(|value| value.parse())
                                    .is_none()
                            {
                                return None;
                            }
                            snssais.push(s_nssai);
                            pos = end;
                        }
                        criteria.push(OperatorAccessCategoryCriterion::SNssais(snssais));
                    }
                    _ => return None,
                }
            }
            if pos != criteria_end {
                return None;
            }
            let standardised_category = if psac {
                let octet = *data.get(pos)?;
                if octet & 0xe0 != 0 || !matches!(octet, 0..=7 | 9 | 10) {
                    return None;
                }
                pos += 1;
                Some(octet)
            } else {
                None
            };
            if pos != entry_end {
                return None;
            }
            definitions.push(OperatorAccessCategoryDefinition {
                precedence,
                psac,
                category_number_raw,
                criteria,
                standardised_category,
            });
        }
        Some(definitions)
    }

    /// Parse all definitions, returning an empty list for malformed data.
    pub fn definitions(&self) -> Vec<OperatorAccessCategoryDefinition> {
        self.try_definitions().unwrap_or_default()
    }

    /// Build zero through 32 sender-valid definitions.
    pub fn try_from_definitions(definitions: &[OperatorAccessCategoryDefinition]) -> Option<Self> {
        if definitions.len() > 32 {
            return None;
        }
        let mut value = Vec::new();
        for definition in definitions {
            if definition.category_number_raw > 0x1f
                || definition.criteria.is_empty()
                || definition.psac != definition.standardised_category.is_some()
                || definition
                    .standardised_category
                    .is_some_and(|category| !matches!(category, 0..=7 | 9 | 10))
            {
                return None;
            }
            let mut criteria = Vec::new();
            for criterion in &definition.criteria {
                match criterion {
                    OperatorAccessCategoryCriterion::Dnns(dnns) => {
                        if dnns.is_empty() || dnns.len() > usize::from(u8::MAX) {
                            return None;
                        }
                        criteria.extend_from_slice(&[0, u8::try_from(dnns.len()).ok()?]);
                        for dnn in dnns {
                            crate::common::decode_labels(dnn)?;
                            criteria.push(u8::try_from(dnn.len()).ok()?);
                            criteria.extend_from_slice(dnn);
                        }
                    }
                    OperatorAccessCategoryCriterion::OsApps(apps) => {
                        if apps.is_empty() || apps.len() > usize::from(u8::MAX) {
                            return None;
                        }
                        criteria.extend_from_slice(&[1, u8::try_from(apps.len()).ok()?]);
                        for (os_id, app_id) in apps {
                            if os_id.len() != 16 {
                                return None;
                            }
                            criteria.extend_from_slice(os_id);
                            criteria.push(u8::try_from(app_id.len()).ok()?);
                            criteria.extend_from_slice(app_id);
                        }
                    }
                    OperatorAccessCategoryCriterion::SNssais(snssais) => {
                        if snssais.is_empty() || snssais.len() > usize::from(u8::MAX) {
                            return None;
                        }
                        criteria.extend_from_slice(&[2, u8::try_from(snssais.len()).ok()?]);
                        for s_nssai in snssais {
                            if !matches!(s_nssai.len(), 1 | 4)
                                || NasSNssai::from_value(s_nssai.clone())
                                    .and_then(|value| value.parse())
                                    .is_none()
                            {
                                return None;
                            }
                            criteria.push(u8::try_from(s_nssai.len()).ok()?);
                            criteria.extend_from_slice(s_nssai);
                        }
                    }
                }
            }
            let criteria_length = u8::try_from(criteria.len()).ok()?;
            let mut body = Vec::with_capacity(3 + criteria.len() + usize::from(definition.psac));
            body.push(definition.precedence);
            body.push((if definition.psac { 0x80 } else { 0 }) | definition.category_number_raw);
            body.push(criteria_length);
            body.extend_from_slice(&criteria);
            if let Some(category) = definition.standardised_category {
                body.push(category);
            }
            value.push(u8::try_from(body.len()).ok()?);
            value.extend_from_slice(&body);
        }
        (value.len() <= 8320).then(|| Self::new(value))
    }

    /// Build from structured definitions.
    ///
    /// # Panics
    ///
    /// Panics when a definition cannot be represented without truncation or
    /// violates TS 24.501 §9.11.3.38 sender rules.
    pub fn from_definitions(definitions: &[OperatorAccessCategoryDefinition]) -> Self {
        Self::try_from_definitions(definitions)
            .expect("operator-defined access category definitions must meet sender rules")
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.try_definitions().is_some_and(|definitions| {
            Self::try_from_definitions(&definitions)
                .is_some_and(|canonical| canonical.value == self.value)
        })
    }

    /// Build from raw bytes without applying sender validation.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── LADN IEs ────────────────────────────────────────────────────────────────

impl NasLadnIndication {
    /// The raw LADN indication bytes (length-prefixed list of DNN values).
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the first eight complete DNN values. Malformed/trailing octets
    /// remain available through [`Self::data`].
    pub fn dnn_values(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() && out.len() < 8 {
            let length = usize::from(self.value[pos]);
            pos += 1;
            let Some(end) = pos.checked_add(length) else {
                break;
            };
            if end > self.value.len() {
                break;
            }
            let dnn = self.value[pos..end].to_vec();
            if !NasDnn::new(dnn.clone()).is_well_formed() {
                break;
            }
            out.push(dnn);
            pos = end;
        }
        out
    }

    /// Build zero to eight DNN values encoded in TS 23.003 label form.
    pub fn from_dnn_values(dnns: &[Vec<u8>]) -> Option<Self> {
        if dnns.len() > 8 {
            return None;
        }
        let mut value = Vec::new();
        for dnn in dnns {
            if !NasDnn::new(dnn.clone()).is_well_formed() {
                return None;
            }
            value.push(u8::try_from(dnn.len()).ok()?);
            value.extend_from_slice(dnn);
        }
        (value.len() <= 808).then(|| Self::new(value))
    }

    /// Sender check for count, DNN label syntax, lengths, and exact boundaries.
    pub fn is_well_formed(&self) -> bool {
        Self::from_dnn_values(&self.dnn_values())
            .is_some_and(|canonical| canonical.value == self.value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// One LADN entry — a DNN paired with the 5GS Tracking Area Identity list in which the
/// LADN is available. Per TS 24.501 §9.11.3.30.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LadnInfoEntry {
    /// DNN value (label-form bytes — same as the value part of a DNN IE starting at octet 2).
    pub dnn: Vec<u8>,
    /// 5GS Tracking Area Identity list content octets (without its length octet).
    /// Construct a [`NasFGsTrackingAreaIdentityList`] with
    /// [`NasFGsTrackingAreaIdentityList::new`] and call
    /// [`NasFGsTrackingAreaIdentityList::parse`] to decode the partial list entries.
    pub tai_list: Vec<u8>,
}

impl NasLadnInformation {
    /// The raw LADN information bytes (DNN + TAI list pairs).
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the first eight complete LADNs. Malformed/trailing octets remain
    /// available through [`Self::data`].
    pub fn entries(&self) -> Vec<LadnInfoEntry> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < self.value.len() && out.len() < 8 {
            let dnn_length = usize::from(self.value[pos]);
            pos += 1;
            let Some(dnn_end) = pos.checked_add(dnn_length) else {
                break;
            };
            if dnn_end > self.value.len() {
                break;
            }
            let dnn = self.value[pos..dnn_end].to_vec();
            if !NasDnn::new(dnn.clone()).is_well_formed() {
                break;
            }
            pos = dnn_end;
            let Some(&tai_length) = self.value.get(pos) else {
                break;
            };
            pos += 1;
            let Some(tai_end) = pos.checked_add(usize::from(tai_length)) else {
                break;
            };
            if tai_end > self.value.len() {
                break;
            }
            let tai_list = self.value[pos..tai_end].to_vec();
            if !tai_list_value_is_well_formed(&tai_list) {
                break;
            }
            out.push(LadnInfoEntry { dnn, tai_list });
            pos = tai_end;
        }
        out
    }

    /// Build one to eight DNN/TAI-list pairs.
    pub fn from_entries(entries: &[LadnInfoEntry]) -> Option<Self> {
        if !(1..=8).contains(&entries.len()) {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if !NasDnn::new(entry.dnn.clone()).is_well_formed()
                || !tai_list_value_is_well_formed(&entry.tai_list)
            {
                return None;
            }
            value.push(u8::try_from(entry.dnn.len()).ok()?);
            value.extend_from_slice(&entry.dnn);
            value.push(u8::try_from(entry.tai_list.len()).ok()?);
            value.extend_from_slice(&entry.tai_list);
        }
        (value.len() <= 1712).then(|| Self::new(value))
    }

    /// Sender check for count, nested DNN/TAI syntax, and exact boundaries.
    pub fn is_well_formed(&self) -> bool {
        Self::from_entries(&self.entries()).is_some_and(|canonical| canonical.value == self.value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── CAG / CipheringKeyData IEs ──────────────────────────────────────────────

/// One CAG information entry per TS 24.501 §9.11.3.18A / §9.11.3.86.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CagInformationEntry {
    /// PLMN identifier.
    pub plmn: PlmnId,
    /// "CAG only" flag (octet after PLMN, bit 1, mask 0x01) — when true, the UE is only
    /// allowed to access cells of the PLMN through CAG cells.
    pub cag_only: bool,
    /// CAILI flag — only meaningful for the extended variant. Indicates that
    /// "CAG-IDs with additional information" are present.
    pub caili: bool,
    /// LCI flag — only meaningful for the extended variant. Indicates that the
    /// "CAG-IDs without additional information list" length field is present.
    pub lci: bool,
    /// CAG identifiers (4 bytes each) without additional information.
    pub cag_ids: Vec<u32>,
    /// CAG-ID-with-additional-information entries (extended variant, when CAILI is set).
    pub cag_ids_with_info: Vec<CagIdWithAdditionalInfo>,
}

/// One CAG-ID-with-additional-information entry inside an extended CAG list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CagIdWithAdditionalInfo {
    /// CAG identifier (4 bytes, big-endian).
    pub cag_id: u32,
    /// SVII bits (bits 1-6 of the byte after the CAG-ID).
    pub svii_bits: u8,
    /// TVII flag — when true, time period entries follow.
    pub tvii: bool,
    /// Time period entries (16 bytes each), only present when `tvii` is set.
    pub time_periods: Vec<[u8; 16]>,
}

/// Internal helper that parses both the basic and extended CAG information lists.
/// `is_ext` selects whether the entry length is 1 or 2 bytes and whether the per-entry
/// flag byte includes the CAILI/LCI bits.
fn parse_cag_information_list(value: &[u8], is_extended: bool) -> Vec<CagInformationEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < value.len() {
        let entry_length = if is_extended {
            let Some(length) = value.get(pos..pos + 2) else {
                break;
            };
            pos += 2;
            usize::from(u16::from_be_bytes([length[0], length[1]]))
        } else {
            let Some(&length) = value.get(pos) else {
                break;
            };
            pos += 1;
            usize::from(length)
        };
        let Some(entry_end) = pos.checked_add(entry_length) else {
            break;
        };
        if entry_length < 4 || entry_end > value.len() {
            break;
        }
        let Some(plmn) = PlmnId::from_tbcd(&value[pos..entry_end]) else {
            break;
        };
        pos += 3;
        let Some(&flags) = value.get(pos) else {
            break;
        };
        pos += 1;
        let cag_only = flags & 0x01 != 0;
        let lci = is_extended && flags & 0x04 != 0;
        let caili = is_extended && flags & 0x08 != 0;
        if flags & !0x0d != 0 || caili && !lci {
            break;
        }

        let cag_ids_end = if lci {
            let Some(length) = value.get(pos..pos + 2) else {
                break;
            };
            pos += 2;
            let Some(end) =
                pos.checked_add(usize::from(u16::from_be_bytes([length[0], length[1]])))
            else {
                break;
            };
            if end > entry_end {
                break;
            }
            end
        } else {
            entry_end
        };
        let mut cag_ids = Vec::new();
        while pos + 4 <= cag_ids_end {
            cag_ids.push(u32::from_be_bytes(
                value[pos..pos + 4].try_into().expect("four CAG-ID octets"),
            ));
            pos += 4;
        }
        if pos != cag_ids_end {
            break;
        }

        let mut cag_ids_with_info = Vec::new();
        if caili {
            let Some(length) = value.get(pos..pos + 2) else {
                break;
            };
            pos += 2;
            let Some(list_end) =
                pos.checked_add(usize::from(u16::from_be_bytes([length[0], length[1]])))
            else {
                break;
            };
            if list_end > entry_end {
                break;
            }
            while pos < list_end {
                let Some(length) = value.get(pos..pos + 2) else {
                    break;
                };
                pos += 2;
                let Some(item_end) =
                    pos.checked_add(usize::from(u16::from_be_bytes([length[0], length[1]])))
                else {
                    break;
                };
                if item_end > list_end || item_end < pos + 5 {
                    pos = list_end + 1;
                    break;
                }
                let cag_id =
                    u32::from_be_bytes(value[pos..pos + 4].try_into().expect("four CAG-ID octets"));
                pos += 4;
                let flags = value[pos];
                pos += 1;
                let svii_bits = (flags >> 1) & 0x3f;
                let tvii = flags & 0x01 != 0;
                let mut time_periods = Vec::new();
                if tvii {
                    let Some(&count) = value.get(pos) else {
                        pos = list_end + 1;
                        break;
                    };
                    pos += 1;
                    let Some(periods_end) = pos.checked_add(usize::from(count) * 16) else {
                        pos = list_end + 1;
                        break;
                    };
                    if periods_end > item_end {
                        pos = list_end + 1;
                        break;
                    }
                    for period in value[pos..periods_end].chunks_exact(16) {
                        time_periods.push(period.try_into().expect("16 time-period octets"));
                    }
                }
                // SVII denotes a future validity format. Release 19 requires the
                // receiver to ignore that CAG-ID-with-additional-information.
                if svii_bits == 0 {
                    cag_ids_with_info.push(CagIdWithAdditionalInfo {
                        cag_id,
                        svii_bits,
                        tvii,
                        time_periods,
                    });
                }
                pos = item_end;
            }
            if pos != list_end {
                break;
            }
        }

        entries.push(CagInformationEntry {
            plmn,
            cag_only,
            caili,
            lci,
            cag_ids,
            cag_ids_with_info,
        });
        // TS 24.501 permits superfluous octets at the end of an extended
        // entry; typed parsing ignores them while the IE retains its raw value.
        pos = entry_end;
    }
    entries
}

fn build_cag_information_list(
    entries: &[CagInformationEntry],
    is_extended: bool,
) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for entry in entries {
        let mut body = Vec::new();
        body.extend_from_slice(&entry.plmn.try_to_tbcd()?);
        if !is_extended && (entry.caili || entry.lci || !entry.cag_ids_with_info.is_empty()) {
            return None;
        }
        if entry.caili == entry.cag_ids_with_info.is_empty() || entry.caili && !entry.lci {
            return None;
        }
        let mut flags = u8::from(entry.cag_only);
        if entry.lci {
            flags |= 0x04;
        }
        if entry.caili {
            flags |= 0x08;
        }
        body.push(flags);

        if entry.lci {
            let byte_length = entry.cag_ids.len().checked_mul(4)?;
            body.extend_from_slice(&u16::try_from(byte_length).ok()?.to_be_bytes());
        }
        for cag_id in &entry.cag_ids {
            body.extend_from_slice(&cag_id.to_be_bytes());
        }

        if entry.caili {
            let mut with_info = Vec::new();
            for info in &entry.cag_ids_with_info {
                if info.svii_bits != 0 || info.tvii == info.time_periods.is_empty() {
                    return None;
                }
                let mut item = Vec::new();
                item.extend_from_slice(&info.cag_id.to_be_bytes());
                item.push(u8::from(info.tvii));
                if info.tvii {
                    item.push(u8::try_from(info.time_periods.len()).ok()?);
                    for period in &info.time_periods {
                        item.extend_from_slice(period);
                    }
                }
                with_info.extend_from_slice(&u16::try_from(item.len()).ok()?.to_be_bytes());
                with_info.extend_from_slice(&item);
            }
            body.extend_from_slice(&u16::try_from(with_info.len()).ok()?.to_be_bytes());
            body.extend_from_slice(&with_info);
        }

        if is_extended {
            value.extend_from_slice(&u16::try_from(body.len()).ok()?.to_be_bytes());
        } else {
            value.push(u8::try_from(body.len()).ok()?);
        }
        value.extend_from_slice(&body);
    }
    (value.len() <= u16::MAX as usize).then_some(value)
}

impl NasCagInformationList {
    /// The raw CAG information list bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the IE per TS 24.501 §9.11.3.18A.
    pub fn entries(&self) -> Vec<CagInformationEntry> {
        parse_cag_information_list(&self.value, false)
    }

    /// Build from structured entries.
    pub fn from_entries(entries: &[CagInformationEntry]) -> Option<Self> {
        Some(Self::new(build_cag_information_list(entries, false)?))
    }

    /// Sender check: every entry boundary, PLMN, flag, and CAG-ID is canonical.
    pub fn is_well_formed(&self) -> bool {
        build_cag_information_list(&self.entries(), false).as_deref() == Some(self.value.as_slice())
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasExtendedCagInformationList {
    /// The raw extended CAG information list bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the IE per TS 24.501 §9.11.3.86.
    pub fn entries(&self) -> Vec<CagInformationEntry> {
        parse_cag_information_list(&self.value, true)
    }

    /// Build from structured entries.
    pub fn from_entries(entries: &[CagInformationEntry]) -> Option<Self> {
        Some(Self::new(build_cag_information_list(entries, true)?))
    }

    /// Sender check: every entry boundary, flag, optional list, and validity field is canonical.
    pub fn is_well_formed(&self) -> bool {
        build_cag_information_list(&self.entries(), true).as_deref() == Some(self.value.as_slice())
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// One ciphering data set entry inside [`NasCipheringKeyData`] per TS 24.501 §9.11.3.18C.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CipheringDataSet {
    /// Ciphering set identifier (2 bytes, big-endian).
    pub set_id: u16,
    /// Ciphering key (16 bytes).
    pub ciphering_key: [u8; 16],
    /// c0 value bytes (length-prefixed in the wire format, may be empty).
    pub c0: Vec<u8>,
    /// E-UTRA positioning SIB type bitmap bytes (variable length).
    pub eutra_pos_sib_types: Vec<u8>,
    /// NR positioning SIB type bitmap bytes (variable length).
    pub nr_pos_sib_types: Vec<u8>,
    /// Validity start time as raw 5 BCD bytes [year, month, day, hour, minute].
    /// Year is offset from 2000. Each byte encodes two BCD digits in semi-octet form
    /// (low nibble = tens, high nibble = units) per TS 24.008 §10.5.3.9.
    pub validity_start_time: [u8; 5],
    /// Validity duration in minutes (2 bytes, big-endian).
    pub validity_duration: u16,
    /// Optional 5GS Tracking Area Identity list bytes (TAI list value, may be empty).
    pub tai_list: Vec<u8>,
}

fn valid_ciphering_start_time(value: [u8; 5]) -> bool {
    fn bcd(octet: u8) -> Option<u8> {
        let tens = octet & 0x0f;
        let units = octet >> 4;
        (tens <= 9 && units <= 9).then_some(tens * 10 + units)
    }
    bcd(value[0]).is_some()
        && bcd(value[1]).is_some_and(|month| (1..=12).contains(&month))
        && bcd(value[2]).is_some_and(|day| (1..=31).contains(&day))
        && bcd(value[3]).is_some_and(|hour| hour <= 23)
        && bcd(value[4]).is_some_and(|minute| minute <= 59)
}

impl NasCipheringKeyData {
    /// The raw ciphering key data bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Decode up to the first sixteen complete ciphering data sets.
    ///
    /// Spare bits and future bitmap octets are tolerated on reception. Decoding
    /// stops at the first incomplete set; the IE retains every raw octet.
    pub fn data_sets(&self) -> Vec<CipheringDataSet> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() && out.len() < 16 {
            if pos + 29 > data.len() {
                break;
            }
            let set_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let mut ciphering_key = [0u8; 16];
            ciphering_key.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;

            let c0_len = usize::from(data[pos] & 0x1f);
            pos += 1;
            if c0_len > 16 || pos + c0_len > data.len() {
                break;
            }
            let c0 = data[pos..pos + c0_len].to_vec();
            pos += c0_len;

            let Some(&eutra_length) = data.get(pos) else {
                break;
            };
            pos += 1;
            let eutra_length = usize::from(eutra_length & 0x0f);
            if pos + eutra_length > data.len() {
                break;
            }
            let eutra_pos_sib_types = data[pos..pos + eutra_length].to_vec();
            pos += eutra_length;

            let Some(&nr_length) = data.get(pos) else {
                break;
            };
            pos += 1;
            let nr_length = usize::from(nr_length & 0x0f);
            if pos + nr_length + 8 > data.len() {
                break;
            }
            let nr_pos_sib_types = data[pos..pos + nr_length].to_vec();
            pos += nr_length;

            let mut validity_start_time = [0u8; 5];
            validity_start_time.copy_from_slice(&data[pos..pos + 5]);
            pos += 5;
            let validity_duration = u16::from_be_bytes([data[pos], data[pos + 1]]);
            pos += 2;
            let tai_length = usize::from(data[pos]);
            pos += 1;
            if pos + tai_length > data.len() {
                break;
            }
            let tai_list = data[pos..pos + tai_length].to_vec();
            pos += tai_length;
            out.push(CipheringDataSet {
                set_id,
                ciphering_key,
                c0,
                eutra_pos_sib_types,
                nr_pos_sib_types,
                validity_start_time,
                validity_duration,
                tai_list,
            });
        }
        out
    }

    /// Encode one to sixteen Release 19 ciphering data sets.
    ///
    /// Returns `None` for an invalid count, bitmap width/spare bit, start
    /// time, TAI list, or length. At least one E-UTRA or NR positioning SIB
    /// bitmap octet is required by TS 24.501 §9.11.3.18C.
    pub fn from_data_sets(sets: &[CipheringDataSet]) -> Option<Self> {
        if !(1..=16).contains(&sets.len()) {
            return None;
        }
        let mut value = Vec::new();
        for set in sets {
            let tai_is_valid = set.tai_list.is_empty()
                || NasFGsTrackingAreaIdentityList::try_from_entries(
                    &NasFGsTrackingAreaIdentityList::new(set.tai_list.clone()).parse(),
                )
                .is_some_and(|canonical| canonical.value == set.tai_list);
            if set.c0.len() > 16
                || set.eutra_pos_sib_types.len() > 6
                || set.nr_pos_sib_types.len() > 7
                || set.eutra_pos_sib_types.is_empty() && set.nr_pos_sib_types.is_empty()
                || set
                    .eutra_pos_sib_types
                    .get(5)
                    .is_some_and(|last| last & 0x07 != 0)
                || !valid_ciphering_start_time(set.validity_start_time)
                || !tai_is_valid
            {
                return None;
            }
            value.extend_from_slice(&set.set_id.to_be_bytes());
            value.extend_from_slice(&set.ciphering_key);
            value.push(u8::try_from(set.c0.len()).ok()?);
            value.extend_from_slice(&set.c0);
            value.push(u8::try_from(set.eutra_pos_sib_types.len()).ok()?);
            value.extend_from_slice(&set.eutra_pos_sib_types);
            value.push(u8::try_from(set.nr_pos_sib_types.len()).ok()?);
            value.extend_from_slice(&set.nr_pos_sib_types);
            value.extend_from_slice(&set.validity_start_time);
            value.extend_from_slice(&set.validity_duration.to_be_bytes());
            value.push(u8::try_from(set.tai_list.len()).ok()?);
            value.extend_from_slice(&set.tai_list);
        }
        (value.len() <= 2672).then(|| Self::new(value))
    }

    /// Sender check for set count, current bitmap widths/spares, time values,
    /// nested TAI syntax, and exact set boundaries.
    pub fn is_well_formed(&self) -> bool {
        Self::from_data_sets(&self.data_sets())
            .is_some_and(|canonical| canonical.value == self.value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── Emergency Number IEs ────────────────────────────────────────────────────

// ── PDU Session IEs ─────────────────────────────────────────────────────────

impl NasPduSessionPairId {
    /// The PDU session pair ID value.
    pub fn pair_id(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Build from a pair ID value.
    pub fn from_pair_id(id: u8) -> Self {
        Self::new(vec![id])
    }
}

impl NasPduSessionReactivationResultErrorCause {
    /// The raw error-cause bytes (PDU-session-ID and 5GMM-cause pairs).
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse known causes from a completely framed value.
    ///
    /// Unknown cause octets are omitted from the typed view and remain visible
    /// through [`Self::entries_raw`].
    pub fn entries(&self) -> Vec<(u8, GmmCause)> {
        if !self.receiver_syntax_is_valid() {
            return Vec::new();
        }
        self.value
            .chunks_exact(2)
            .filter_map(|pair| GmmCause::from_u8(pair[1]).map(|cause| (pair[0], cause)))
            .collect()
    }

    /// Parse including unknown cause values.
    pub fn entries_raw(&self) -> Vec<(u8, u8)> {
        if !self.receiver_syntax_is_valid() {
            return Vec::new();
        }
        self.value
            .chunks_exact(2)
            .map(|pair| (pair[0], pair[1]))
            .collect()
    }

    /// Build one through fifteen unique typed `(PDU session ID, cause)` pairs.
    pub fn from_entries(entries: &[(u8, GmmCause)]) -> Option<Self> {
        let raw = entries
            .iter()
            .map(|(psi, cause)| (*psi, *cause as u8))
            .collect::<Vec<_>>();
        Self::from_entries_raw(&raw)
    }

    /// Build one through fifteen unique raw pairs.
    ///
    /// Raw construction preserves the cause octet but still validates the PDU
    /// session identifiers and duplicate constraint.
    pub fn from_entries_raw(entries: &[(u8, u8)]) -> Option<Self> {
        if !(1..=15).contains(&entries.len()) {
            return None;
        }
        let mut seen = [false; 16];
        let mut value = Vec::with_capacity(entries.len() * 2);
        for &(psi, cause) in entries {
            if !(1..=15).contains(&psi) || std::mem::replace(&mut seen[usize::from(psi)], true) {
                return None;
            }
            value.push(psi);
            value.push(cause);
        }
        Some(Self::new(value))
    }

    /// Build from raw bytes without applying sender validation.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Whether the complete list framing and every PDU session ID are valid for a receiver.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        !self.value.is_empty()
            && self.value.len().is_multiple_of(2)
            && self
                .value
                .chunks_exact(2)
                .all(|pair| (1..=15).contains(&pair[0]))
    }

    /// Whether this is a canonical sender list of unique IDs and known causes.
    pub fn is_well_formed(&self) -> bool {
        let entries = self.entries_raw();
        !entries.is_empty()
            && entries.len() <= 15
            && entries
                .iter()
                .all(|(_, cause)| GmmCause::from_u8(*cause).is_some())
            && Self::from_entries_raw(&entries)
                .is_some_and(|canonical| canonical.value == self.value)
    }
}

// ── Registration / Paging IEs ───────────────────────────────────────────────

/// Paging restriction type per TS 24.501 §9.11.3.77.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PagingRestrictionType {
    /// Reserved value.
    Reserved = 0x00,
    /// All paging is restricted.
    AllRestricted = 0x01,
    /// All paging is restricted except for voice service.
    AllRestrictedExceptVoice = 0x02,
    /// All paging is restricted except for specified PDU session(s) (TS 24.501 §9.11.3.77).
    AllRestrictedExceptSpecifiedPduSessions = 0x03,
    /// All paging is restricted except for voice service and specified PDU session(s).
    AllRestrictedExceptVoiceAndSpecifiedPduSessions = 0x04,
}

impl PagingRestrictionType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::Reserved),
            0x01 => Some(Self::AllRestricted),
            0x02 => Some(Self::AllRestrictedExceptVoice),
            0x03 => Some(Self::AllRestrictedExceptSpecifiedPduSessions),
            0x04 => Some(Self::AllRestrictedExceptVoiceAndSpecifiedPduSessions),
            _ => None,
        }
    }
}

impl NasPagingRestriction {
    /// Typed paging restriction type (bits 1-4 of first byte). TS 24.501 §9.11.3.77.
    pub fn restriction_type(&self) -> Option<PagingRestrictionType> {
        self.value
            .first()
            .and_then(|b| PagingRestrictionType::from_u8(b & 0x0F))
    }

    /// Raw paging restriction type (bits 1-4 of first byte).
    pub fn restriction_type_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x0F).unwrap_or(0)
    }

    /// Set the paging restriction type (bits 1-4 of the first byte).
    pub fn set_restriction_type(&mut self, restriction_type: PagingRestrictionType) {
        if self.value.is_empty() {
            self.value.resize(1, 0);
        }
        self.value[0] = (self.value[0] & !0x0F) | (restriction_type as u8);
        if !matches!(
            restriction_type,
            PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions
                | PagingRestrictionType::AllRestrictedExceptVoiceAndSpecifiedPduSessions
        ) {
            self.value.truncate(1);
        }
        self.length = self.value.len() as _;
    }

    /// Set restriction type and return the updated value.
    pub fn with_restriction_type(mut self, restriction_type: PagingRestrictionType) -> Self {
        self.set_restriction_type(restriction_type);
        self
    }

    /// Bitmap of PDU sessions exempt from paging restriction for restriction types 0x03/0x04.
    pub fn unrestricted_psi_bitmap(&self) -> Option<[u8; 2]> {
        if !matches!(self.restriction_type_raw(), 0x03 | 0x04) {
            return None;
        }
        Some([
            self.value.get(1).copied().unwrap_or(0) & !0x01,
            self.value.get(2).copied().unwrap_or(0),
        ])
    }

    /// Compatibility alias for [`Self::unrestricted_psi_bitmap`].
    pub fn restricted_psi_bitmap(&self) -> Option<[u8; 2]> {
        self.unrestricted_psi_bitmap()
    }

    /// PDU Session Identity bitmap for restriction types 0x03/0x04. TS 24.501 §9.11.3.77:
    /// octet 2 bit 1 = PSI0, octet 2 bit 8 = PSI7, octet 3 bit 1 = PSI8, octet 3 bit 8 = PSI15.
    /// Returns PSIs whose set bits mean paging is not restricted for the PDU session.
    pub fn unrestricted_psi_list(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let Some(bitmap) = self.unrestricted_psi_bitmap() else {
            return out;
        };
        for (byte_idx, byte) in bitmap.into_iter().enumerate() {
            for bit in 0..8u8 {
                let psi = (byte_idx as u8) * 8 + bit;
                if psi != 0 && (byte >> bit) & 1 != 0 {
                    out.push(psi);
                }
            }
        }
        out
    }

    /// Compatibility alias for [`Self::unrestricted_psi_list`].
    pub fn restricted_psi_list(&self) -> Vec<u8> {
        self.unrestricted_psi_list()
    }

    /// Set the unrestricted PSI bitmap for restriction types 0x03/0x04.
    pub fn set_unrestricted_psi_list(&mut self, psis: &[u8]) {
        if !matches!(self.restriction_type_raw(), 0x03 | 0x04) {
            return;
        }
        if self.value.len() < 3 {
            self.value.resize(3, 0);
        }
        self.value[1] = 0;
        self.value[2] = 0;
        for &psi in psis {
            if (1..=15).contains(&psi) {
                self.value[1 + (psi / 8) as usize] |= 1 << (psi % 8);
            }
        }
        self.length = self.value.len() as _;
    }

    /// Compatibility alias for [`Self::set_unrestricted_psi_list`].
    pub fn set_restricted_psi_list(&mut self, psis: &[u8]) {
        self.set_unrestricted_psi_list(psis);
    }

    /// Set unrestricted psi list and return the updated value.
    pub fn with_unrestricted_psi_list(mut self, psis: &[u8]) -> Self {
        self.set_unrestricted_psi_list(psis);
        self
    }

    /// Compatibility alias for [`Self::with_unrestricted_psi_list`].
    pub fn with_restricted_psi_list(mut self, psis: &[u8]) -> Self {
        self.set_unrestricted_psi_list(psis);
        self
    }

    /// The raw paging restriction bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Build from a typed restriction without any PSI bitmap.
    pub fn from_restriction_type(restriction_type: PagingRestrictionType) -> Self {
        Self::new(vec![restriction_type as u8])
    }

    /// Build from a typed restriction and optional unrestricted PSI values.
    pub fn from_restriction_type_with_unrestricted_psis(
        restriction_type: PagingRestrictionType,
        psis: &[u8],
    ) -> Self {
        let mut value = vec![restriction_type as u8];
        if matches!(
            restriction_type,
            PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions
                | PagingRestrictionType::AllRestrictedExceptVoiceAndSpecifiedPduSessions
        ) {
            value.resize(3, 0);
            for &psi in psis {
                if (1..=15).contains(&psi) {
                    value[1 + (psi / 8) as usize] |= 1 << (psi % 8);
                }
            }
        }
        Self::new(value)
    }

    /// Compatibility alias for [`Self::from_restriction_type_with_unrestricted_psis`].
    pub fn from_restriction_type_with_psis(
        restriction_type: PagingRestrictionType,
        psis: &[u8],
    ) -> Self {
        Self::from_restriction_type_with_unrestricted_psis(restriction_type, psis)
    }

    /// Sender check for the restriction type, length, spare half octet, and
    /// reserved PSI zero bit (TS 24.501 §9.11.3.77).
    pub fn is_well_formed(&self) -> bool {
        let spare_bits_clear = self.value.first().is_some_and(|octet| octet & 0xf0 == 0);
        match self.restriction_type_raw() {
            0x01 | 0x02 => self.value.len() == 1 && spare_bits_clear,
            0x03 | 0x04 => {
                self.value.len() == 3
                    && spare_bits_clear
                    && self.value.get(1).is_some_and(|octet| octet & 0x01 == 0)
            }
            _ => false,
        }
    }
}

// ── Header Compression IEs ──────────────────────────────────────────────────

/// Ethernet header compression CID length per TS 24.501 §9.11.4.28.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EthHdrCompCidLen {
    /// Ethernet header compression not used.
    NotUsed = 0x00,
    /// 7-bit context identifiers.
    SevenBits = 0x01,
    /// 15-bit context identifiers.
    FifteenBits = 0x02,
}

impl EthHdrCompCidLen {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NotUsed),
            0x01 => Some(Self::SevenBits),
            0x02 => Some(Self::FifteenBits),
            _ => Some(Self::SevenBits),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x03 {
            0x00 => Some(Self::NotUsed),
            0x01 => Some(Self::SevenBits),
            0x02 => Some(Self::FifteenBits),
            _ => None,
        }
    }
}

impl NasEthernetHeaderCompressionConfiguration {
    /// The raw Ethernet header compression configuration bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Typed CID length value (octet 1 bits 1–2, mask 0x03).
    pub fn cid_length(&self) -> Option<EthHdrCompCidLen> {
        self.value
            .first()
            .and_then(|b| EthHdrCompCidLen::from_u8(*b))
    }

    /// Raw CID length value.
    pub fn cid_length_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x03).unwrap_or(0)
    }

    /// Build from a typed CID length value.
    pub fn from_cid_length(cid: EthHdrCompCidLen) -> Self {
        Self::new(vec![cid as u8])
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ── Additional / Misc TLV IEs ───────────────────────────────────────────────

impl NasAdditionalInformationRequested {
    /// Whether ciphering key data is requested (bit 0).
    pub fn cipher_key_data_requested(&self) -> bool {
        !self.value.is_empty() && (self.value[0] & 0x01) != 0
    }

    /// Set the ciphering-key-data-requested flag.
    pub fn set_cipher_key_data_requested(&mut self, requested: bool) {
        let mut byte = self.value.first().copied().unwrap_or(0);
        if requested {
            byte |= 0x01;
        } else {
            byte &= !0x01;
        }
        if self.value.is_empty() {
            self.value.push(byte);
        } else {
            self.value[0] = byte;
        }
        self.length = self.value.len() as _;
    }

    /// Return `self` with the ciphering-key-data-requested flag updated.
    pub fn with_cipher_key_data_requested(mut self, requested: bool) -> Self {
        self.set_cipher_key_data_requested(requested);
        self
    }

    /// Build from the ciphering-key-data-requested flag.
    pub fn from_cipher_key_data_requested(requested: bool) -> Self {
        Self::new(vec![if requested { 0x01 } else { 0x00 }])
    }

    /// The raw bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    /// Sender check: one value octet with bits 8 to 2 spare and clear.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0xfe == 0)
    }
}

impl NasDsTtEthernetPortMacAddress {
    /// The 6-byte DS-TT Ethernet port MAC address.
    pub fn mac_address(&self) -> Option<[u8; 6]> {
        if self.value.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.value[..6]);
            Some(mac)
        } else {
            None
        }
    }

    /// Build from a 6-byte MAC address.
    pub fn from_mac_address(mac: [u8; 6]) -> Self {
        Self::new(mac.to_vec())
    }
}

/// "Allowed type" for a partial service area list per TS 24.501 §9.11.3.49.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ServiceAreaListAllowedType {
    /// TAIs in the list are in the allowed area.
    Allowed = 0,
    /// TAIs in the list are in the non-allowed area.
    NonAllowed = 1,
}

/// One partial service area list entry per TS 24.501 §9.11.3.49.
///
/// This preserves the four on-wire list forms the C dissector handles instead of
/// normalizing them into a single shape.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceAreaListEntry {
    /// Type `00`: one PLMN with non-consecutive TAC values.
    OnePlmnNonConsecutive {
        /// Allowed.
        allowed: ServiceAreaListAllowedType,
        /// PLMN.
        plmn: PlmnId,
        /// Tacs.
        tacs: Vec<[u8; 3]>,
    },
    /// Type `01`: one PLMN with consecutive TAC values starting from `first_tac`.
    OnePlmnConsecutive {
        /// Allowed.
        allowed: ServiceAreaListAllowedType,
        /// PLMN.
        plmn: PlmnId,
        /// First TAC.
        first_tac: [u8; 3],
        /// Count.
        count: u8,
    },
    /// Type `02`: TAIs from different PLMNs.
    DifferentPlmns {
        /// Allowed.
        allowed: ServiceAreaListAllowedType,
        /// Tais.
        tais: Vec<TrackingAreaIdentity>,
    },
    /// Type `03`: all TAIs belonging to one PLMN.
    PlmnOnly {
        /// Allowed.
        allowed: ServiceAreaListAllowedType,
        /// PLMN.
        plmn: PlmnId,
    },
}

impl NasServiceAreaList {
    /// The raw service area list bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the IE into typed partial service area list entries per TS 24.501 §9.11.3.49.
    /// The returned entries preserve the exact wire form of each partial list.
    pub fn entries(&self) -> Vec<ServiceAreaListEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        let mut total_tais = 0usize;

        while pos < data.len() {
            let remaining_tais = 16usize.saturating_sub(total_tais);
            if remaining_tais == 0 {
                break;
            }
            let header = data[pos];
            let allowed = if (header & 0x80) != 0 {
                ServiceAreaListAllowedType::NonAllowed
            } else {
                ServiceAreaListAllowedType::Allowed
            };
            let list_type = (header >> 5) & 0x03;
            let count_field = (header & 0x1F) as usize;
            let num_elements = if count_field <= 0x0F {
                count_field + 1
            } else {
                16
            };
            pos += 1;

            match list_type {
                0x00 => {
                    if pos + 3 > data.len() {
                        break;
                    }
                    let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                        Some(p) => p,
                        None => break,
                    };
                    pos += 3;
                    let mut tacs = Vec::with_capacity(num_elements.min(remaining_tais));
                    for index in 0..num_elements {
                        if pos + 3 > data.len() {
                            break;
                        }
                        if index < remaining_tais {
                            tacs.push([data[pos], data[pos + 1], data[pos + 2]]);
                            total_tais += 1;
                        }
                        pos += 3;
                    }
                    out.push(ServiceAreaListEntry::OnePlmnNonConsecutive {
                        allowed,
                        plmn,
                        tacs,
                    });
                }
                0x01 => {
                    if pos + 6 > data.len() {
                        break;
                    }
                    let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                        Some(p) => p,
                        None => break,
                    };
                    pos += 3;
                    let first_tac = [data[pos], data[pos + 1], data[pos + 2]];
                    pos += 3;
                    let count = num_elements.min(remaining_tais);
                    total_tais += count;
                    out.push(ServiceAreaListEntry::OnePlmnConsecutive {
                        allowed,
                        plmn,
                        first_tac,
                        count: count as u8,
                    });
                }
                0x02 => {
                    let mut tais = Vec::with_capacity(num_elements.min(remaining_tais));
                    for index in 0..num_elements {
                        if pos + 6 > data.len() {
                            break;
                        }
                        let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                            Some(p) => p,
                            None => break,
                        };
                        let tac = [data[pos + 3], data[pos + 4], data[pos + 5]];
                        pos += 6;
                        if index < remaining_tais {
                            tais.push(TrackingAreaIdentity { plmn, tac });
                            total_tais += 1;
                        }
                    }
                    out.push(ServiceAreaListEntry::DifferentPlmns { allowed, tais });
                }
                0x03 => {
                    if pos + 3 > data.len() {
                        break;
                    }
                    let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                        Some(p) => p,
                        None => break,
                    };
                    pos += 3;
                    out.push(ServiceAreaListEntry::PlmnOnly {
                        allowed: ServiceAreaListAllowedType::Allowed,
                        plmn,
                    });
                }
                _ => break,
            }
        }
        out
    }

    fn receiver_prefix_length(&self) -> Option<usize> {
        let data = self.value.as_slice();
        let mut pos = 0usize;
        let mut total_tais = 0usize;
        let mut expected_allowed = None;
        let mut saw_entry = false;
        while pos < data.len() {
            if total_tais == 16 {
                return Some(pos);
            }
            let header = *data.get(pos)?;
            let list_type = (header >> 5) & 0x03;
            let allowed = if list_type == 3 || header & 0x80 == 0 {
                ServiceAreaListAllowedType::Allowed
            } else {
                ServiceAreaListAllowedType::NonAllowed
            };
            if expected_allowed.is_some_and(|expected| expected != allowed) {
                return None;
            }
            expected_allowed = Some(allowed);
            saw_entry = true;
            let count = if header & 0x1F <= 0x0F {
                usize::from(header & 0x1F) + 1
            } else {
                16
            };
            let take = count.min(16 - total_tais);
            pos += 1;
            match list_type {
                0 => {
                    PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                    pos += 3 + 3usize.checked_mul(take)?;
                    data.get(..pos)?;
                    total_tais += take;
                }
                1 => {
                    PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                    pos += 6;
                    data.get(..pos)?;
                    total_tais += take;
                }
                2 => {
                    for _ in 0..take {
                        PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                        pos += 6;
                        data.get(..pos)?;
                    }
                    total_tais += take;
                }
                3 => {
                    PlmnId::from_tbcd(data.get(pos..pos + 3)?)?;
                    pos += 3;
                }
                _ => unreachable!(),
            }
        }
        saw_entry.then_some(pos)
    }

    /// Whether the receiver can parse every required entry prefix. Receiver
    /// fallbacks for count values 16..31 and type-11 Allowed are applied.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        self.receiver_prefix_length().is_some()
    }

    /// Whether this is a canonical sender encoding with one Allowed type.
    pub fn is_well_formed(&self) -> bool {
        let entries = self.entries();
        self.receiver_prefix_length() == Some(self.value.len())
            && !entries.is_empty()
            && Self::from_entries(&entries).value == self.value
    }

    /// Build a single-entry type `00` partial list.
    pub fn from_plmn_tacs(
        allowed: ServiceAreaListAllowedType,
        plmn: &PlmnId,
        tacs: &[[u8; 3]],
    ) -> Self {
        Self::from_entries(&[ServiceAreaListEntry::OnePlmnNonConsecutive {
            allowed,
            plmn: *plmn,
            tacs: tacs.to_vec(),
        }])
    }

    /// Build a single-entry type `01` partial list.
    pub fn from_consecutive_tacs(
        allowed: ServiceAreaListAllowedType,
        plmn: &PlmnId,
        first_tac: [u8; 3],
        count: u8,
    ) -> Self {
        Self::from_entries(&[ServiceAreaListEntry::OnePlmnConsecutive {
            allowed,
            plmn: *plmn,
            first_tac,
            count,
        }])
    }

    /// Build a single-entry type `02` partial list.
    pub fn from_different_plmns(
        allowed: ServiceAreaListAllowedType,
        tais: &[TrackingAreaIdentity],
    ) -> Self {
        Self::from_entries(&[ServiceAreaListEntry::DifferentPlmns {
            allowed,
            tais: tais.to_vec(),
        }])
    }

    /// Build a single-entry type `03` partial list.
    pub fn from_plmn_only(allowed: ServiceAreaListAllowedType, plmn: &PlmnId) -> Self {
        Self::from_entries(&[ServiceAreaListEntry::PlmnOnly {
            allowed,
            plmn: *plmn,
        }])
    }

    /// Build from typed partial service area list entries.
    pub fn from_entries(entries: &[ServiceAreaListEntry]) -> Self {
        assert!(!entries.is_empty(), "service area list must not be empty");
        let allowed = match &entries[0] {
            ServiceAreaListEntry::OnePlmnNonConsecutive { allowed, .. }
            | ServiceAreaListEntry::OnePlmnConsecutive { allowed, .. }
            | ServiceAreaListEntry::DifferentPlmns { allowed, .. }
            | ServiceAreaListEntry::PlmnOnly { allowed, .. } => *allowed,
        };
        assert!(
            entries.iter().all(|entry| match entry {
                ServiceAreaListEntry::OnePlmnNonConsecutive { allowed: value, .. }
                | ServiceAreaListEntry::OnePlmnConsecutive { allowed: value, .. }
                | ServiceAreaListEntry::DifferentPlmns { allowed: value, .. } => *value == allowed,
                ServiceAreaListEntry::PlmnOnly { allowed: value, .. } => {
                    *value == allowed && *value == ServiceAreaListAllowedType::Allowed
                }
            }),
            "all service area partial lists must use the same Allowed type"
        );
        fn header(allowed: ServiceAreaListAllowedType, list_type: u8, count: usize) -> u8 {
            assert!(
                (1..=16).contains(&count),
                "service area list partial list count must be 1..=16"
            );
            let mut header = ((count.saturating_sub(1)) as u8 & 0x1F) | ((list_type & 0x03) << 5);
            if matches!(allowed, ServiceAreaListAllowedType::NonAllowed) {
                header |= 0x80;
            }
            header
        }

        let mut value = Vec::new();
        let mut total_tais = 0usize;
        for entry in entries {
            match entry {
                ServiceAreaListEntry::OnePlmnNonConsecutive {
                    allowed,
                    plmn,
                    tacs,
                } => {
                    assert!(
                        !tacs.is_empty(),
                        "service area list must contain at least one TAC"
                    );
                    assert!(tacs.len() <= 16, "service area list TAC count exceeds 16");
                    total_tais += tacs.len();
                    assert!(
                        total_tais <= 16,
                        "service area list contains more than 16 TAIs"
                    );
                    value.push(header(*allowed, 0x00, tacs.len()));
                    value.extend_from_slice(&plmn.to_tbcd());
                    for tac in tacs {
                        value.extend_from_slice(tac);
                    }
                }
                ServiceAreaListEntry::OnePlmnConsecutive {
                    allowed,
                    plmn,
                    first_tac,
                    count,
                } => {
                    let count = *count as usize;
                    assert!(
                        (1..=16).contains(&count),
                        "service area list consecutive count must be 1..=16"
                    );
                    total_tais += count;
                    assert!(
                        total_tais <= 16,
                        "service area list contains more than 16 TAIs"
                    );
                    value.push(header(*allowed, 0x01, count));
                    value.extend_from_slice(&plmn.to_tbcd());
                    value.extend_from_slice(first_tac);
                }
                ServiceAreaListEntry::DifferentPlmns { allowed, tais } => {
                    assert!(
                        !tais.is_empty(),
                        "service area list must contain at least one TAI"
                    );
                    assert!(tais.len() <= 16, "service area list TAI count exceeds 16");
                    total_tais += tais.len();
                    assert!(
                        total_tais <= 16,
                        "service area list contains more than 16 TAIs"
                    );
                    value.push(header(*allowed, 0x02, tais.len()));
                    for tai in tais {
                        value.extend_from_slice(&tai.plmn.to_tbcd());
                        value.extend_from_slice(&tai.tac);
                    }
                }
                ServiceAreaListEntry::PlmnOnly { plmn, .. } => {
                    value.push(header(ServiceAreaListAllowedType::Allowed, 0x03, 1));
                    value.extend_from_slice(&plmn.to_tbcd());
                }
            }
        }
        Self::new(value)
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

pub use crate::common::ts24008::MsRevisionLevel;
crate::common::ts24008::mobile_station_classmark_2_ie!(NasMobileStationClassmark2);

/// NB-N1 mode DRX value per TS 24.501 §9.11.3.73.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NbN1DrxValue {
    /// DRX value not specified.
    NotSpecified = 0x00,
    /// DRX cycle parameter T = 32.
    T32 = 0x01,
    /// DRX cycle parameter T = 64.
    T64 = 0x02,
    /// DRX cycle parameter T = 128.
    T128 = 0x03,
    /// DRX cycle parameter T = 256.
    T256 = 0x04,
    /// DRX cycle parameter T = 512.
    T512 = 0x05,
    /// DRX cycle parameter T = 1024.
    T1024 = 0x07,
}

impl NbN1DrxValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::NotSpecified),
            0x01 => Some(Self::T32),
            0x02 => Some(Self::T64),
            0x03 => Some(Self::T128),
            0x04 => Some(Self::T256),
            0x05 => Some(Self::T512),
            0x07 => Some(Self::T1024),
            _ => Some(Self::NotSpecified),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::NotSpecified),
            0x01 => Some(Self::T32),
            0x02 => Some(Self::T64),
            0x03 => Some(Self::T128),
            0x04 => Some(Self::T256),
            0x05 => Some(Self::T512),
            0x07 => Some(Self::T1024),
            _ => None,
        }
    }
}

impl NasNbN1ModeDrxParameters {
    /// Typed NB-N1 mode DRX value (bits 0-3 of first byte).
    pub fn drx_value(&self) -> Option<NbN1DrxValue> {
        self.value
            .first()
            .and_then(|b| NbN1DrxValue::from_u8(b & 0x0F))
    }

    /// Raw NB-N1 mode DRX value (bits 0-3 of first byte).
    pub fn drx_value_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x0F).unwrap_or(0)
    }

    /// The raw bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Build from typed DRX value.
    pub fn from_drx_value(drx: NbN1DrxValue) -> Self {
        Self::new(vec![drx as u8])
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasNid {
    /// Raw assignment mode (low nibble of octet 1).
    pub fn assignment_mode_raw(&self) -> u8 {
        self.value.first().map(|b| b & 0x0F).unwrap_or(0)
    }

    /// Render the six raw NID octets as hexadecimal digits in little-endian nibble order.
    pub fn nid_value(&self) -> String {
        decode_hex_digit_string(&self.value)
    }

    /// Build from a 12-digit hexadecimal NID string in little-endian nibble order.
    pub fn from_nid_value(nid_value: &str) -> Option<Self> {
        if nid_value.len() != 12 {
            return None;
        }
        let mut value = Vec::with_capacity(6);
        let mut chars = nid_value.chars();
        while let (Some(lo), Some(hi)) = (chars.next(), chars.next()) {
            value.push((hex_digit_value(hi)? << 4) | hex_digit_value(lo)?);
        }
        Some(Self::new(value))
    }

    /// Update the raw assignment-mode nibble in octet 1.
    pub fn set_assignment_mode_raw(&mut self, assignment_mode_raw: u8) {
        if self.value.is_empty() {
            self.value.resize(6, 0);
        }
        self.value[0] = (self.value[0] & 0xF0) | (assignment_mode_raw & 0x0F);
        self.length = self.value.len() as _;
    }

    /// Builder-style raw assignment-mode setter.
    pub fn with_assignment_mode_raw(mut self, assignment_mode_raw: u8) -> Self {
        self.set_assignment_mode_raw(assignment_mode_raw);
        self
    }

    /// The raw NID bytes (6 bytes total).
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasTruncatedFGSTmsiConfiguration {
    /// Raw truncated AMF Set ID length field (bits 8 through 5).
    pub fn truncated_amf_set_id_length(&self) -> Option<u8> {
        self.value.first().map(|octet| octet >> 4)
    }

    /// Raw truncated AMF Pointer length field (bits 4 through 1).
    pub fn truncated_amf_pointer_length(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x0f)
    }

    /// Receiver interpretation of the AMF Set ID length.
    pub fn effective_amf_set_id_length(&self) -> Option<u8> {
        self.truncated_amf_set_id_length().map(|length| {
            if (1..=10).contains(&length) {
                length
            } else {
                10
            }
        })
    }

    /// Receiver interpretation of the AMF Pointer length.
    pub fn effective_amf_pointer_length(&self) -> Option<u8> {
        self.truncated_amf_pointer_length()
            .map(|length| if (1..=6).contains(&length) { length } else { 6 })
    }

    /// Build sender-valid component lengths.
    ///
    /// TS 23.003 §2.12 additionally requires their sum to be at least eight.
    pub fn try_from_lengths(set_id_length: u8, pointer_length: u8) -> Option<Self> {
        ((1..=10).contains(&set_id_length)
            && (1..=6).contains(&pointer_length)
            && set_id_length.checked_add(pointer_length)? >= 8)
            .then(|| Self::new(vec![(set_id_length << 4) | pointer_length]))
    }

    /// The raw value bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Build from raw bytes without applying sender validation.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }

    fn first_byte_or_zero(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// Set the AMF Set ID length.
    ///
    /// # Panics
    ///
    /// Panics unless `set_id_length` is in 1 through 10.
    pub fn with_set_id_length(mut self, set_id_length: u8) -> Self {
        self.set_set_id_length(set_id_length);
        self
    }

    /// Set the AMF Set ID length.
    ///
    /// # Panics
    ///
    /// Panics unless `set_id_length` is in 1 through 10.
    pub fn set_set_id_length(&mut self, set_id_length: u8) {
        assert!(
            (1..=10).contains(&set_id_length),
            "AMF Set ID length must be in 1..=10"
        );
        let octet = (self.first_byte_or_zero() & 0x0f) | (set_id_length << 4);
        if self.value.is_empty() {
            self.value.push(octet);
        } else {
            self.value[0] = octet;
        }
        self.length = self.value.len() as _;
    }

    /// Set the AMF Pointer length.
    ///
    /// # Panics
    ///
    /// Panics unless `pointer_length` is in 1 through 6.
    pub fn with_pointer_length(mut self, pointer_length: u8) -> Self {
        self.set_pointer_length(pointer_length);
        self
    }

    /// Set the AMF Pointer length.
    ///
    /// # Panics
    ///
    /// Panics unless `pointer_length` is in 1 through 6.
    pub fn set_pointer_length(&mut self, pointer_length: u8) {
        assert!(
            (1..=6).contains(&pointer_length),
            "AMF Pointer length must be in 1..=6"
        );
        let octet = (self.first_byte_or_zero() & 0xf0) | pointer_length;
        if self.value.is_empty() {
            self.value.push(octet);
        } else {
            self.value[0] = octet;
        }
        self.length = self.value.len() as _;
    }

    /// Whether both component lengths satisfy TS 24.501 and TS 23.003 sender rules.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 1
            && Self::try_from_lengths(
                self.truncated_amf_set_id_length().unwrap_or(0),
                self.truncated_amf_pointer_length().unwrap_or(0),
            )
            .is_some_and(|canonical| canonical.value == self.value)
    }
}

impl Default for NasTruncatedFGSTmsiConfiguration {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

/// Fixed-width IEEE 1588 correctionField encoding carried by the UE DS-TT IE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DsTtCorrectionField([u8; 8]);

impl DsTtCorrectionField {
    /// TS 24.501 overflow sentinel in wire order.
    pub const OVERFLOW: Self = Self([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);

    /// Preserve an IEEE 1588 correctionField wire encoding.
    pub const fn from_wire_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Exact eight wire octets.
    pub const fn wire_bytes(self) -> [u8; 8] {
        self.0
    }

    /// Whether this is the TS 24.501 overflow indication.
    pub const fn is_overflow(self) -> bool {
        self.0[0] == 0xff
            && self.0[1] == 0xff
            && self.0[2] == 0xff
            && self.0[3] == 0xff
            && self.0[4] == 0xff
            && self.0[5] == 0xff
            && self.0[6] == 0xff
            && self.0[7] == 0x7f
    }
}

impl NasUeDsTtResidenceTime {
    /// The raw UE DS-TT residence time bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Typed correctionField, ignoring receiver-tolerated excess octets.
    pub fn correction_field(&self) -> Option<DsTtCorrectionField> {
        Some(DsTtCorrectionField::from_wire_bytes(
            self.value.get(..8)?.try_into().ok()?,
        ))
    }

    /// Whether the value carries the specified overflow sentinel.
    pub fn is_overflow(&self) -> bool {
        self.correction_field()
            .is_some_and(DsTtCorrectionField::is_overflow)
    }

    /// Build from an IEEE 1588 correctionField wire value.
    pub fn from_correction_field(value: DsTtCorrectionField) -> Self {
        Self::new(value.wire_bytes().to_vec())
    }

    /// Build the specified overflow indication.
    pub fn overflow() -> Self {
        Self::from_correction_field(DsTtCorrectionField::OVERFLOW)
    }

    /// Whether this IE has the exact sender width.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 8
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl NasPeipsAssistanceInformation {
    /// The raw PEIPS assistance information bytes.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Parse the single PEIPS assistance information parameter.
    pub fn entry(&self) -> Option<PeipsAssistanceInformationEntry> {
        (self.value.len() == 1).then(|| PeipsAssistanceInformationEntry::from_byte(self.value[0]))
    }

    /// Parse the PEIPS assistance information into typed one-octet entries.
    ///
    /// TS 24.501 §9.11.3.80 defines exactly one parameter; this compatibility
    /// helper returns an empty list for malformed multi-octet values.
    pub fn entries(&self) -> Vec<PeipsAssistanceInformationEntry> {
        self.entry().into_iter().collect()
    }

    /// Build from typed PEIPS assistance information entries.
    pub fn from_entries(entries: &[PeipsAssistanceInformationEntry]) -> Self {
        assert!(
            entries.len() == 1,
            "PEIPS assistance information contains exactly one parameter"
        );
        Self::from_entry(entries[0])
    }

    /// Build from a typed PEIPS assistance information parameter.
    pub fn from_entry(entry: PeipsAssistanceInformationEntry) -> Self {
        Self::new(vec![entry.to_validated_byte()])
    }

    /// Build a paging subgroup ID parameter.
    pub fn from_paging_subgroup_id(value: u8) -> Self {
        Self::from_entry(PeipsAssistanceInformationEntry::PagingSubgroupId(value))
    }

    /// Build a UE paging probability information parameter.
    pub fn from_ue_paging_probability_information(value: u8) -> Self {
        Self::from_entry(PeipsAssistanceInformationEntry::UePagingProbabilityInformation(value))
    }

    /// Build from raw bytes.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

/// PEIPS assistance information type per TS 24.501 §9.11.3.80.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PeipsAssistanceInformationType {
    /// Paging subgroup identifier.
    PagingSubgroupId = 0x00,
    /// UE paging probability information.
    UePagingProbabilityInformation = 0x01,
}

impl PeipsAssistanceInformationType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::PagingSubgroupId),
            0x01 => Some(Self::UePagingProbabilityInformation),
            _ => None,
        }
    }
}

/// One PEIPS assistance information entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PeipsAssistanceInformationEntry {
    /// Paging subgroup identifier.
    PagingSubgroupId(u8),
    /// UE paging probability information.
    UePagingProbabilityInformation(u8),
    /// Reserved.
    Reserved {
        /// Info type raw.
        info_type_raw: u8,
        /// Raw information-element contents.
        value: u8,
    },
}

impl PeipsAssistanceInformationEntry {
    fn from_byte(byte: u8) -> Self {
        let info_type_raw = (byte >> 5) & 0x07;
        let value = byte & 0x1F;
        match PeipsAssistanceInformationType::from_u8(info_type_raw) {
            Some(PeipsAssistanceInformationType::PagingSubgroupId) => {
                Self::PagingSubgroupId(if value <= 7 { value } else { 0 })
            }
            Some(PeipsAssistanceInformationType::UePagingProbabilityInformation) => {
                Self::UePagingProbabilityInformation(value.min(20))
            }
            None => Self::Reserved {
                info_type_raw,
                value,
            },
        }
    }

    fn to_validated_byte(self) -> u8 {
        match self {
            Self::PagingSubgroupId(value) => {
                assert!(value <= 7, "PEIPS paging subgroup ID must be 0..=7");
                value
            }
            Self::UePagingProbabilityInformation(value) => {
                assert!(
                    value <= 20,
                    "PEIPS UE paging probability information must be 0..=20"
                );
                0x20 | value
            }
            Self::Reserved { .. } => {
                panic!("reserved PEIPS assistance information types cannot be built")
            }
        }
    }
}

// ============================================================================
// Later-release and extended IE accessors
// ============================================================================
//
// Each of these IEs is defined in TS 24.501 but the inner structure varies,
// and several are best treated as opaque byte containers at this layer.
// They expose `data()` and `from_data()` so callers can construct, transmit,
// and inspect them.

nas_opaque_ie!(NasExtendedFGmmCause, "24.501", "9.11.3.109");
nas_opaque_ie!(NasIpHeaderCompressionConfiguration, "24.501", "9.11.4.24");
nas_opaque_ie!(NasAlternativeNssai, "24.501", "9.11.3.97");
nas_opaque_ie!(NasAun3Indication, "24.501", "9.11.3.104");
nas_opaque_ie!(NasAun3DeviceSecurityKey, "24.501", "9.11.3.107");
nas_opaque_ie!(NasCiotSmallDataContainer, "24.501", "9.11.3.18B");
nas_opaque_ie!(NasExtendedLadnInformation, "24.501", "9.11.3.96");
nas_opaque_ie!(NasFeatureAuthorizationIndication, "24.501", "9.11.3.105");
nas_opaque_ie!(NasLpWuspsAssistanceInformation, "24.501", "9.11.3.111");
nas_opaque_ie!(
    NasNon3GppAccessPathSwitchingIndication,
    "24.501",
    "9.11.3.99"
);
nas_opaque_ie!(NasNon3GppPathSwitchingInformation, "24.501", "9.11.3.102");
nas_opaque_ie!(NasN3iwfIdentifier, "24.501", "9.11.3.93");
nas_opaque_ie!(NasOnDemandNssai, "24.501", "9.11.3.108");
nas_opaque_ie!(NasPartialNssai, "24.501", "9.11.3.103");
nas_opaque_ie!(NasRanTimingSynchronization, "24.501", "9.11.3.95");
nas_opaque_ie!(NasRelayKeyRequestParameters, "24.501", "9.11.3.89");
nas_opaque_ie!(NasRelayKeyResponseParameters, "24.501", "9.11.3.90");
nas_opaque_ie!(NasSnpnList, "24.501", "9.11.3.92");
nas_opaque_ie!(NasSNssaiLocationValidityInformation, "24.501", "9.11.3.100");
nas_opaque_ie!(NasSNssaiTimeValidityInformation, "24.501", "9.11.3.101");
nas_opaque_ie!(NasTnanInformation, "24.501", "9.11.3.94");
nas_opaque_ie!(NasType6IeContainer, "24.501", "9.11.3.98");
nas_opaque_ie!(
    NasUeParametersUpdateTransparentContainer,
    "24.501",
    "9.11.3.53A"
);
nas_opaque_ie!(NasEcsAddress, "24.501", "9.11.4.34");
nas_opaque_ie!(NasEcnMarkingL4sIndication, "24.501", "9.11.4.40");
nas_opaque_ie!(NasNon3GppDelayBudget, "24.501", "9.11.4.37");
nas_opaque_ie!(NasNon3GppDeviceInformation, "24.501", "9.11.4.41");
nas_opaque_ie!(NasN3Qai, "24.501", "9.11.4.36");
nas_opaque_ie!(NasProtocolDescription, "24.501", "9.11.4.39");
nas_opaque_ie!(NasRemoteUeContextList, "24.501", "9.11.4.29");
nas_opaque_ie!(NasUrspRuleEnforcementReports, "24.501", "9.11.4.38");

impl NasUeParametersUpdateTransparentContainer {
    /// Return container data.
    pub fn container_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from container data.
    pub fn from_container_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set container data.
    pub fn set_container_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set container data and return the updated value.
    pub fn with_container_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// UE parameters update data type values.
pub enum UeParametersUpdateDataType {
    /// Update list.
    UpdateList = 0x00,
    /// Acknowledgement.
    Acknowledgement = 0x01,
}

impl UeParametersUpdateDataType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x01 {
            0x00 => Some(Self::UpdateList),
            0x01 => Some(Self::Acknowledgement),
            _ => None,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UE parameters update data set type values.
pub enum UeParametersUpdateDataSetType {
    /// Routing indicator update data.
    RoutingIndicatorUpdateData,
    /// Default configured NSSAI update data.
    DefaultConfiguredNssaiUpdateData,
    /// Disaster roaming information update data.
    DisasterRoamingInformationUpdateData,
    /// Me routing indicator update data.
    MeRoutingIndicatorUpdateData,
    /// Protected UE parameters update header information.
    ProtectedUeParametersUpdateHeaderInformation,
    /// Unknown.
    Unknown(u8),
}

impl UeParametersUpdateDataSetType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x01 => Self::RoutingIndicatorUpdateData,
            0x02 => Self::DefaultConfiguredNssaiUpdateData,
            0x03 => Self::DisasterRoamingInformationUpdateData,
            0x04 => Self::MeRoutingIndicatorUpdateData,
            0x05 => Self::ProtectedUeParametersUpdateHeaderInformation,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::RoutingIndicatorUpdateData => 0x01,
            Self::DefaultConfiguredNssaiUpdateData => 0x02,
            Self::DisasterRoamingInformationUpdateData => 0x03,
            Self::MeRoutingIndicatorUpdateData => 0x04,
            Self::ProtectedUeParametersUpdateHeaderInformation => 0x05,
            Self::Unknown(value) => value & 0x0F,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE parameters update protected header information.
pub struct UeParametersUpdateProtectedHeaderInformation {
    /// Acknowledgement requested.
    pub acknowledgement_requested: bool,
    /// Re registration requested.
    pub re_registration_requested: bool,
    /// Data type.
    pub data_type: UeParametersUpdateDataType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE parameters update disaster roaming information.
pub struct UeParametersUpdateDisasterRoamingInformation {
    /// Disaster roaming enabled in 5 gs.
    pub disaster_roaming_enabled_in_5gs: bool,
    /// VPLMN disaster condition lists applicable.
    pub vplmn_disaster_condition_lists_applicable: bool,
    /// Disaster roaming enabled in EPS.
    pub disaster_roaming_enabled_in_eps: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UE parameters update data set values.
pub enum UeParametersUpdateDataSet {
    /// TS 31.115 secured packet carrying routing-indicator update data.
    ///
    /// The secured packet is intentionally opaque at the NAS layer.
    RoutingIndicatorUpdateData(Vec<u8>),
    /// Default configured NSSAI update data.
    DefaultConfiguredNssaiUpdateData(NasNssai),
    /// Disaster roaming information update data.
    DisasterRoamingInformationUpdateData(UeParametersUpdateDisasterRoamingInformation),
    /// Me routing indicator update data.
    MeRoutingIndicatorUpdateData([u8; 2]),
    /// Protected UE parameters update header information.
    ProtectedUeParametersUpdateHeaderInformation(UeParametersUpdateProtectedHeaderInformation),
    /// Unknown.
    Unknown {
        /// Data set type.
        data_set_type: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE parameters update list contents.
pub struct UeParametersUpdateListContents {
    /// Acknowledgement requested.
    pub acknowledgement_requested: bool,
    /// Re registration requested.
    pub re_registration_requested: bool,
    /// Upu mac iausf.
    pub upu_mac_iausf: [u8; 16],
    /// Counter upu.
    pub counter_upu: u16,
    /// Data sets.
    pub data_sets: Vec<UeParametersUpdateDataSet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE parameters update acknowledgement contents.
pub struct UeParametersUpdateAcknowledgementContents {
    /// Header protection supported.
    pub header_protection_supported: bool,
    /// Upu mac iue.
    pub upu_mac_iue: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UE parameters update transparent container contents values.
pub enum UeParametersUpdateTransparentContainerContents {
    /// Update list.
    UpdateList(UeParametersUpdateListContents),
    /// Acknowledgement.
    Acknowledgement(UeParametersUpdateAcknowledgementContents),
}

impl NasUeParametersUpdateTransparentContainer {
    /// Return header octet.
    pub fn header_octet(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Return data type.
    pub fn data_type(&self) -> Option<UeParametersUpdateDataType> {
        UeParametersUpdateDataType::from_u8(self.header_octet()?)
    }

    /// Return acknowledgement requested.
    pub fn acknowledgement_requested(&self) -> Option<bool> {
        (self.data_type() == Some(UeParametersUpdateDataType::UpdateList))
            .then_some(self.header_octet()? & 0x02 != 0)
    }

    /// Return re registration requested.
    pub fn re_registration_requested(&self) -> Option<bool> {
        (self.data_type() == Some(UeParametersUpdateDataType::UpdateList))
            .then_some(self.header_octet()? & 0x04 != 0)
    }

    /// Return header protection supported.
    pub fn header_protection_supported(&self) -> Option<bool> {
        (self.data_type() == Some(UeParametersUpdateDataType::Acknowledgement))
            .then_some(self.header_octet()? & 0x02 != 0)
    }

    /// Parse the typed contents.
    pub fn parse(&self) -> Option<UeParametersUpdateTransparentContainerContents> {
        let header = self.header_octet()?;
        match self.data_type()? {
            UeParametersUpdateDataType::UpdateList => {
                if self.value.len() < 19 {
                    return None;
                }
                let upu_mac_iausf = copy_array::<16>(&self.value[1..17])?;
                let counter_upu = u16::from_be_bytes([self.value[17], self.value[18]]);
                let mut data_sets = Vec::new();
                let mut pos = 19usize;
                while pos < self.value.len() {
                    if pos + 3 > self.value.len() {
                        return None;
                    }
                    let data_set_type_raw = self.value[pos] & 0x0F;
                    pos += 1;
                    let data_set_len =
                        u16::from_be_bytes([self.value[pos], self.value[pos + 1]]) as usize;
                    pos += 2;
                    if pos + data_set_len > self.value.len() {
                        return None;
                    }
                    let contents = &self.value[pos..pos + data_set_len];
                    pos += data_set_len;
                    let data_set = match UeParametersUpdateDataSetType::from_u8(data_set_type_raw) {
                        UeParametersUpdateDataSetType::RoutingIndicatorUpdateData => {
                            if contents.is_empty() {
                                return None;
                            }
                            UeParametersUpdateDataSet::RoutingIndicatorUpdateData(contents.to_vec())
                        }
                        UeParametersUpdateDataSetType::DefaultConfiguredNssaiUpdateData => {
                            let nssai = NasNssai::new(contents.to_vec());
                            nssai.try_parse_all()?;
                            UeParametersUpdateDataSet::DefaultConfiguredNssaiUpdateData(nssai)
                        }
                        UeParametersUpdateDataSetType::DisasterRoamingInformationUpdateData => {
                            if contents.len() != 1 {
                                return None;
                            }
                            UeParametersUpdateDataSet::DisasterRoamingInformationUpdateData(
                                UeParametersUpdateDisasterRoamingInformation {
                                    disaster_roaming_enabled_in_5gs: contents[0] & 0x01 != 0,
                                    vplmn_disaster_condition_lists_applicable: contents[0] & 0x02
                                        != 0,
                                    disaster_roaming_enabled_in_eps: contents[0] & 0x04 != 0,
                                },
                            )
                        }
                        UeParametersUpdateDataSetType::MeRoutingIndicatorUpdateData => {
                            if !valid_routing_indicator(contents) {
                                return None;
                            }
                            UeParametersUpdateDataSet::MeRoutingIndicatorUpdateData(
                                copy_array::<2>(contents)?,
                            )
                        }
                        UeParametersUpdateDataSetType::ProtectedUeParametersUpdateHeaderInformation => {
                            if contents.len() != 1
                                || UeParametersUpdateDataType::from_u8(contents[0])
                                    != Some(UeParametersUpdateDataType::UpdateList)
                            {
                                return None;
                            }
                            UeParametersUpdateDataSet::ProtectedUeParametersUpdateHeaderInformation(
                                UeParametersUpdateProtectedHeaderInformation {
                                    acknowledgement_requested: contents[0] & 0x02 != 0,
                                    re_registration_requested: contents[0] & 0x04 != 0,
                                    data_type: UeParametersUpdateDataType::UpdateList,
                                },
                            )
                        }
                        UeParametersUpdateDataSetType::Unknown(data_set_type) => {
                            UeParametersUpdateDataSet::Unknown {
                                data_set_type,
                                contents: contents.to_vec(),
                            }
                        }
                    };
                    data_sets.push(data_set);
                }
                Some(UeParametersUpdateTransparentContainerContents::UpdateList(
                    UeParametersUpdateListContents {
                        acknowledgement_requested: header & 0x02 != 0,
                        re_registration_requested: header & 0x04 != 0,
                        upu_mac_iausf,
                        counter_upu,
                        data_sets,
                    },
                ))
            }
            UeParametersUpdateDataType::Acknowledgement => {
                if self.value.len() != 17 {
                    return None;
                }
                Some(
                    UeParametersUpdateTransparentContainerContents::Acknowledgement(
                        UeParametersUpdateAcknowledgementContents {
                            header_protection_supported: header & 0x02 != 0,
                            upu_mac_iue: copy_array::<16>(&self.value[1..17])?,
                        },
                    ),
                )
            }
        }
    }

    /// Construct a value from parsed.
    pub fn from_parsed(contents: &UeParametersUpdateTransparentContainerContents) -> Option<Self> {
        let mut value = Vec::new();
        match contents {
            UeParametersUpdateTransparentContainerContents::UpdateList(update) => {
                let mut header = UeParametersUpdateDataType::UpdateList as u8;
                if update.acknowledgement_requested {
                    header |= 0x02;
                }
                if update.re_registration_requested {
                    header |= 0x04;
                }
                value.push(header);
                value.extend_from_slice(&update.upu_mac_iausf);
                value.extend_from_slice(&update.counter_upu.to_be_bytes());
                for data_set in &update.data_sets {
                    let (data_set_type, data_set_contents) = match data_set {
                        UeParametersUpdateDataSet::RoutingIndicatorUpdateData(secured_packet) => {
                            if secured_packet.is_empty() {
                                return None;
                            }
                            (
                                UeParametersUpdateDataSetType::RoutingIndicatorUpdateData.as_u8(),
                                secured_packet.clone(),
                            )
                        }
                        UeParametersUpdateDataSet::DefaultConfiguredNssaiUpdateData(nssai) => {
                            if nssai.value.len() > 144
                                || nssai
                                    .try_parse_all()
                                    .is_none_or(|entries| entries.len() > 16)
                            {
                                return None;
                            }
                            (
                                UeParametersUpdateDataSetType::DefaultConfiguredNssaiUpdateData
                                    .as_u8(),
                                nssai.value.clone(),
                            )
                        }
                        UeParametersUpdateDataSet::DisasterRoamingInformationUpdateData(info) => {
                            let mut octet = 0u8;
                            if info.disaster_roaming_enabled_in_5gs {
                                octet |= 0x01;
                            }
                            if info.vplmn_disaster_condition_lists_applicable {
                                octet |= 0x02;
                            }
                            if info.disaster_roaming_enabled_in_eps {
                                octet |= 0x04;
                            }
                            (
                                UeParametersUpdateDataSetType::DisasterRoamingInformationUpdateData
                                    .as_u8(),
                                vec![octet],
                            )
                        }
                        UeParametersUpdateDataSet::MeRoutingIndicatorUpdateData(
                            routing_indicator,
                        ) => {
                            if !valid_routing_indicator(routing_indicator) {
                                return None;
                            }
                            (
                                UeParametersUpdateDataSetType::MeRoutingIndicatorUpdateData.as_u8(),
                                routing_indicator.to_vec(),
                            )
                        }
                        UeParametersUpdateDataSet::ProtectedUeParametersUpdateHeaderInformation(
                            protected_header,
                        ) => {
                            if protected_header.data_type != UeParametersUpdateDataType::UpdateList
                            {
                                return None;
                            }
                            let mut octet = protected_header.data_type as u8;
                            if protected_header.acknowledgement_requested {
                                octet |= 0x02;
                            }
                            if protected_header.re_registration_requested {
                                octet |= 0x04;
                            }
                            (
                                UeParametersUpdateDataSetType::ProtectedUeParametersUpdateHeaderInformation
                                    .as_u8(),
                                vec![octet],
                            )
                        }
                        UeParametersUpdateDataSet::Unknown { .. } => return None,
                    };
                    value.push(data_set_type);
                    value.extend_from_slice(
                        &(u16::try_from(data_set_contents.len()).ok()?).to_be_bytes(),
                    );
                    value.extend_from_slice(&data_set_contents);
                }
            }
            UeParametersUpdateTransparentContainerContents::Acknowledgement(ack) => {
                let mut header = UeParametersUpdateDataType::Acknowledgement as u8;
                if ack.header_protection_supported {
                    header |= 0x02;
                }
                value.push(header);
                value.extend_from_slice(&ack.upu_mac_iue);
            }
        }
        (value.len() <= u16::MAX as usize).then(|| Self::new(value))
    }
}

// ── 9.11.4.34 ECS address ───────────────────────────────────────────────────

/// Type of ECS address (TS 24.501 §9.11.4.34, octet 4 bits 1-4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EcsAddressType {
    /// Ipv 4.
    Ipv4 = 0x00,
    /// Ipv 6.
    Ipv6 = 0x01,
    /// Fqdn.
    Fqdn = 0x02,
    /// Unspecified.
    Unspecified = 0x0F,
}

impl EcsAddressType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::Ipv4),
            0x01 => Some(Self::Ipv6),
            0x02 => Some(Self::Fqdn),
            0x0F => Some(Self::Unspecified),
            _ => None,
        }
    }
}

/// Type of spatial validity condition (TS 24.501 §9.11.4.34, octet 4 bits 5-8).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EcsSpatialValidityType {
    /// None.
    None = 0x00,
    /// Geographical service area.
    GeographicalServiceArea = 0x01,
    /// Tracking area.
    TrackingArea = 0x02,
    /// Country wide.
    CountryWide = 0x03,
}

impl EcsSpatialValidityType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x00 => Some(Self::None),
            0x01 => Some(Self::GeographicalServiceArea),
            0x02 => Some(Self::TrackingArea),
            0x03 => Some(Self::CountryWide),
            _ => None,
        }
    }
}

impl NasEcsAddress {
    /// Return address data.
    pub fn address_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from address data.
    pub fn from_address_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set address data.
    pub fn set_address_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set address data and return the updated value.
    pub fn with_address_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }

    /// First content octet (octet 4 in the wire format) — type fields.
    fn type_octet(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Type of ECS address (octet 4 bits 1-4).
    pub fn address_type(&self) -> Option<EcsAddressType> {
        EcsAddressType::from_u8(self.type_octet()? & 0x0F)
    }

    /// Type of spatial validity condition (octet 4 bits 5-8).
    pub fn spatial_validity_type(&self) -> Option<EcsSpatialValidityType> {
        EcsSpatialValidityType::from_u8((self.type_octet()? >> 4) & 0x0F)
    }

    /// Bytes of the ECS address itself (octets 5..a), without spatial validity or trailing fields.
    /// Returns `None` if the type is unknown or the buffer is too short.
    /// For `Fqdn`, the leading FQDN length octet is consumed and only the FQDN value is returned.
    /// For `Unspecified`, the remaining fields are returned for upper-layer handling.
    pub fn ecs_address_bytes(&self) -> Option<&[u8]> {
        let body = self.value.get(1..)?;
        match self.address_type()? {
            EcsAddressType::Ipv4 => body.get(..4),
            EcsAddressType::Ipv6 => body.get(..16),
            EcsAddressType::Fqdn => {
                let len = *body.first()? as usize;
                body.get(1..1 + len)
            }
            EcsAddressType::Unspecified => Some(body),
        }
    }
}

impl NasNon3GppDelayBudget {
    /// Return budget data.
    pub fn budget_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from budget data.
    pub fn from_budget_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set budget data.
    pub fn set_budget_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set budget data and return the updated value.
    pub fn with_budget_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

impl NasNon3GppDeviceInformation {
    /// Return device information data.
    pub fn device_information_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from device information data.
    pub fn from_device_information_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set device information data.
    pub fn set_device_information_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set device information data and return the updated value.
    pub fn with_device_information_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

impl NasN3Qai {
    /// Return qai data.
    pub fn qai_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from qai data.
    pub fn from_qai_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set qai data.
    pub fn set_qai_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set qai data and return the updated value.
    pub fn with_qai_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

impl NasProtocolDescription {
    /// Return description data.
    pub fn description_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from description data.
    pub fn from_description_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set description data.
    pub fn set_description_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set description data and return the updated value.
    pub fn with_description_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

impl NasRemoteUeContextList {
    /// Return context list data.
    pub fn context_list_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from context list data.
    pub fn from_context_list_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set context list data.
    pub fn set_context_list_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set context list data and return the updated value.
    pub fn with_context_list_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

impl NasUrspRuleEnforcementReports {
    /// Return report data.
    pub fn report_data(&self) -> &[u8] {
        self.data()
    }

    /// Construct a value from report data.
    pub fn from_report_data(data: Vec<u8>) -> Self {
        Self::from_data(data)
    }

    /// Set report data.
    pub fn set_report_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.set_data(data)
    }

    /// Set report data and return the updated value.
    pub fn with_report_data(self, data: Vec<u8>) -> Self {
        self.with_data(data)
    }
}

// ============================================================================
// Structured parsers for the Rel-17/18 IEs
// ============================================================================
//
// The IEs above expose `data()` / `from_data()` for raw byte access. The impls
// below add typed accessors and builders for the IEs whose structure this crate
// exposes directly. Each structured impl is paired with the 3GPP TS 24.501
// reference for the exact field layout.

pub use crate::common::ts24501::PortRange;

// ── 9.11.4.36 N3QAI ─────────────────────────────────────────────────────────

/// N3QAI parameter identifier per TS 24.501 §9.11.4.36.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum N3QaiParameterIdentifier {
    /// Five qi.
    FiveQi,
    /// Gfbr uplink.
    GfbrUplink,
    /// Gfbr downlink.
    GfbrDownlink,
    /// Mfbr uplink.
    MfbrUplink,
    /// Mfbr downlink.
    MfbrDownlink,
    /// Averaging window.
    AveragingWindow,
    /// Resource type.
    ResourceType,
    /// Priority level.
    PriorityLevel,
    /// Packet delay budget.
    PacketDelayBudget,
    /// Packet error rate.
    PacketErrorRate,
    /// Maximum data burst volume.
    MaximumDataBurstVolume,
    /// Maximum packet loss rate downlink.
    MaximumPacketLossRateDownlink,
    /// Maximum packet loss rate uplink.
    MaximumPacketLossRateUplink,
    /// Arp.
    Arp,
    /// Periodicity.
    Periodicity,
    /// Unknown.
    Unknown(u8),
}

impl N3QaiParameterIdentifier {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::FiveQi,
            0x02 => Self::GfbrUplink,
            0x03 => Self::GfbrDownlink,
            0x04 => Self::MfbrUplink,
            0x05 => Self::MfbrDownlink,
            0x06 => Self::AveragingWindow,
            0x07 => Self::ResourceType,
            0x08 => Self::PriorityLevel,
            0x09 => Self::PacketDelayBudget,
            0x0A => Self::PacketErrorRate,
            0x0B => Self::MaximumDataBurstVolume,
            0x0C => Self::MaximumPacketLossRateDownlink,
            0x0D => Self::MaximumPacketLossRateUplink,
            0x0E => Self::Arp,
            0x0F => Self::Periodicity,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::FiveQi => 0x01,
            Self::GfbrUplink => 0x02,
            Self::GfbrDownlink => 0x03,
            Self::MfbrUplink => 0x04,
            Self::MfbrDownlink => 0x05,
            Self::AveragingWindow => 0x06,
            Self::ResourceType => 0x07,
            Self::PriorityLevel => 0x08,
            Self::PacketDelayBudget => 0x09,
            Self::PacketErrorRate => 0x0A,
            Self::MaximumDataBurstVolume => 0x0B,
            Self::MaximumPacketLossRateDownlink => 0x0C,
            Self::MaximumPacketLossRateUplink => 0x0D,
            Self::Arp => 0x0E,
            Self::Periodicity => 0x0F,
            Self::Unknown(value) => value,
        }
    }
}

/// One N3QAI parameter entry per TS 24.501 §9.11.4.36.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct N3QaiParameter {
    /// Identifier.
    pub identifier: N3QaiParameterIdentifier,
    /// Encoded contents.
    pub contents: Vec<u8>,
}

/// Resource type carried by an N3QAI resource-type parameter.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum N3QaiResourceType {
    /// Guaranteed bit rate.
    Gbr,
    /// Delayed-critical guaranteed bit rate.
    DelayedCriticalGbr,
    /// Non-guaranteed bit rate.
    NonGbr,
}

/// Typed N3QAI parameter contents from TS 24.501 §9.11.4.36 and the
/// incorporated TS 24.502 §9.3.1.1 table.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum N3QaiParameterValue {
    /// 5G QoS identifier.
    FiveQi(u8),
    /// Guaranteed flow bit rate, uplink.
    GfbrUplink(QosFlowBitRate),
    /// Guaranteed flow bit rate, downlink.
    GfbrDownlink(QosFlowBitRate),
    /// Maximum flow bit rate, uplink.
    MfbrUplink(QosFlowBitRate),
    /// Maximum flow bit rate, downlink.
    MfbrDownlink(QosFlowBitRate),
    /// Averaging-window factor, in units of 0.5 ms.
    AveragingWindow(u16),
    /// Resource type.
    ResourceType(N3QaiResourceType),
    /// Priority level.
    PriorityLevel(u8),
    /// Packet-delay-budget factor, in units of 0.5 ms.
    PacketDelayBudget(u16),
    /// Packet error rate as scalar and base-10 exponent.
    PacketErrorRate {
        /// Scalar from zero through nine.
        scalar: u8,
        /// Base-10 exponent from zero through nine.
        exponent: u8,
    },
    /// Maximum data burst volume in bytes.
    MaximumDataBurstVolume(u16),
    /// Maximum packet-loss rate downlink, in tenths of a percent.
    MaximumPacketLossRateDownlink(u16),
    /// Maximum packet-loss rate uplink, in tenths of a percent.
    MaximumPacketLossRateUplink(u16),
    /// Allocation and retention priority level.
    Arp(u8),
    /// Big-endian periodicity in microseconds. The TS leaves its octet length
    /// variable, so the exact bytes are retained.
    Periodicity(Vec<u8>),
    /// Unsupported future parameter, retained for receiver interpretation.
    Unsupported {
        /// Unsupported identifier.
        identifier: u8,
        /// Preserved encoded contents.
        contents: Vec<u8>,
    },
}

impl N3QaiParameter {
    /// Decode typed parameter contents, returning `None` for a known identifier
    /// with the wrong contents length.
    pub fn value(&self) -> Option<N3QaiParameterValue> {
        let value = match self.identifier {
            N3QaiParameterIdentifier::FiveQi if self.contents.len() == 1 => {
                N3QaiParameterValue::FiveQi(self.contents[0])
            }
            N3QaiParameterIdentifier::GfbrUplink if self.contents.len() == 3 => {
                N3QaiParameterValue::GfbrUplink(decode_n3qai_bit_rate(&self.contents))
            }
            N3QaiParameterIdentifier::GfbrDownlink if self.contents.len() == 3 => {
                N3QaiParameterValue::GfbrDownlink(decode_n3qai_bit_rate(&self.contents))
            }
            N3QaiParameterIdentifier::MfbrUplink if self.contents.len() == 3 => {
                N3QaiParameterValue::MfbrUplink(decode_n3qai_bit_rate(&self.contents))
            }
            N3QaiParameterIdentifier::MfbrDownlink if self.contents.len() == 3 => {
                N3QaiParameterValue::MfbrDownlink(decode_n3qai_bit_rate(&self.contents))
            }
            N3QaiParameterIdentifier::AveragingWindow if self.contents.len() == 2 => {
                N3QaiParameterValue::AveragingWindow(u16::from_be_bytes([
                    self.contents[0],
                    self.contents[1],
                ]))
            }
            N3QaiParameterIdentifier::ResourceType if self.contents.len() == 1 => {
                N3QaiParameterValue::ResourceType(match self.contents[0] {
                    0 => N3QaiResourceType::Gbr,
                    1 => N3QaiResourceType::DelayedCriticalGbr,
                    2 => N3QaiResourceType::NonGbr,
                    _ => return None,
                })
            }
            N3QaiParameterIdentifier::PriorityLevel if self.contents.len() == 1 => {
                N3QaiParameterValue::PriorityLevel(self.contents[0])
            }
            N3QaiParameterIdentifier::PacketDelayBudget if self.contents.len() == 2 => {
                N3QaiParameterValue::PacketDelayBudget(u16::from_be_bytes([
                    self.contents[0],
                    self.contents[1],
                ]))
            }
            N3QaiParameterIdentifier::PacketErrorRate if self.contents.len() == 2 => {
                N3QaiParameterValue::PacketErrorRate {
                    scalar: self.contents[0],
                    exponent: self.contents[1],
                }
            }
            N3QaiParameterIdentifier::MaximumDataBurstVolume if self.contents.len() == 2 => {
                N3QaiParameterValue::MaximumDataBurstVolume(u16::from_be_bytes([
                    self.contents[0],
                    self.contents[1],
                ]))
            }
            N3QaiParameterIdentifier::MaximumPacketLossRateDownlink if self.contents.len() == 2 => {
                N3QaiParameterValue::MaximumPacketLossRateDownlink(u16::from_be_bytes([
                    self.contents[0],
                    self.contents[1],
                ]))
            }
            N3QaiParameterIdentifier::MaximumPacketLossRateUplink if self.contents.len() == 2 => {
                N3QaiParameterValue::MaximumPacketLossRateUplink(u16::from_be_bytes([
                    self.contents[0],
                    self.contents[1],
                ]))
            }
            N3QaiParameterIdentifier::Arp if self.contents.len() == 1 => {
                N3QaiParameterValue::Arp(self.contents[0])
            }
            N3QaiParameterIdentifier::Periodicity if !self.contents.is_empty() => {
                N3QaiParameterValue::Periodicity(self.contents.clone())
            }
            N3QaiParameterIdentifier::Unknown(identifier) => N3QaiParameterValue::Unsupported {
                identifier,
                contents: self.contents.clone(),
            },
            _ => return None,
        };
        Some(value)
    }

    /// Construct a parameter from typed contents.
    pub fn from_value(value: N3QaiParameterValue) -> Option<Self> {
        let (identifier, contents) = match value {
            N3QaiParameterValue::FiveQi(value) if (1..=254).contains(&value) => {
                (N3QaiParameterIdentifier::FiveQi, vec![value])
            }
            N3QaiParameterValue::GfbrUplink(rate) if rate.unit_value().is_some() => (
                N3QaiParameterIdentifier::GfbrUplink,
                encode_n3qai_bit_rate(rate),
            ),
            N3QaiParameterValue::GfbrDownlink(rate) if rate.unit_value().is_some() => (
                N3QaiParameterIdentifier::GfbrDownlink,
                encode_n3qai_bit_rate(rate),
            ),
            N3QaiParameterValue::MfbrUplink(rate) if rate.unit_value().is_some() => (
                N3QaiParameterIdentifier::MfbrUplink,
                encode_n3qai_bit_rate(rate),
            ),
            N3QaiParameterValue::MfbrDownlink(rate) if rate.unit_value().is_some() => (
                N3QaiParameterIdentifier::MfbrDownlink,
                encode_n3qai_bit_rate(rate),
            ),
            N3QaiParameterValue::AveragingWindow(value) if value <= 0x0fff => (
                N3QaiParameterIdentifier::AveragingWindow,
                value.to_be_bytes().to_vec(),
            ),
            N3QaiParameterValue::ResourceType(value) => (
                N3QaiParameterIdentifier::ResourceType,
                vec![match value {
                    N3QaiResourceType::Gbr => 0,
                    N3QaiResourceType::DelayedCriticalGbr => 1,
                    N3QaiResourceType::NonGbr => 2,
                }],
            ),
            N3QaiParameterValue::PriorityLevel(value) if (1..=127).contains(&value) => {
                (N3QaiParameterIdentifier::PriorityLevel, vec![value])
            }
            N3QaiParameterValue::PacketDelayBudget(value) if value <= 0x03ff => (
                N3QaiParameterIdentifier::PacketDelayBudget,
                value.to_be_bytes().to_vec(),
            ),
            N3QaiParameterValue::PacketErrorRate { scalar, exponent }
                if scalar <= 9 && exponent <= 9 =>
            {
                (
                    N3QaiParameterIdentifier::PacketErrorRate,
                    vec![scalar, exponent],
                )
            }
            N3QaiParameterValue::MaximumDataBurstVolume(value) if value <= 0x0fff => (
                N3QaiParameterIdentifier::MaximumDataBurstVolume,
                value.to_be_bytes().to_vec(),
            ),
            N3QaiParameterValue::MaximumPacketLossRateDownlink(value) if value <= 1000 => (
                N3QaiParameterIdentifier::MaximumPacketLossRateDownlink,
                value.to_be_bytes().to_vec(),
            ),
            N3QaiParameterValue::MaximumPacketLossRateUplink(value) if value <= 1000 => (
                N3QaiParameterIdentifier::MaximumPacketLossRateUplink,
                value.to_be_bytes().to_vec(),
            ),
            N3QaiParameterValue::Arp(value) if (1..=15).contains(&value) => {
                (N3QaiParameterIdentifier::Arp, vec![value])
            }
            N3QaiParameterValue::Periodicity(contents)
                if !contents.is_empty() && contents.len() <= u8::MAX as usize =>
            {
                (N3QaiParameterIdentifier::Periodicity, contents)
            }
            _ => return None,
        };
        Some(Self {
            identifier,
            contents,
        })
    }

    fn sender_is_valid(&self) -> bool {
        self.value()
            .is_some_and(|value| Self::from_value(value).is_some_and(|rebuilt| rebuilt == *self))
    }
}

fn decode_n3qai_bit_rate(contents: &[u8]) -> QosFlowBitRate {
    QosFlowBitRate {
        unit: contents[0],
        value: u16::from_be_bytes([contents[1], contents[2]]),
    }
}

fn encode_n3qai_bit_rate(rate: QosFlowBitRate) -> Vec<u8> {
    let mut contents = vec![rate.unit];
    contents.extend_from_slice(&rate.value.to_be_bytes());
    contents
}

/// One N3QAI entry per TS 24.501 §9.11.4.36.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct N3QaiEntry {
    /// Qfis.
    pub qfis: Vec<u8>,
    /// Parameters.
    pub parameters: Vec<N3QaiParameter>,
}

impl NasN3Qai {
    /// Spec-tolerant N3QAI entries.
    ///
    /// Unsupported N3QAI parameter identifiers are discarded as required by
    /// TS 24.501 §9.11.4.36. Use [`Self::entries`] when lossless preservation of
    /// unknown parameter identifiers is more important than receive-side
    /// interpretation.
    pub fn entries_spec(&self) -> Vec<N3QaiEntry> {
        self.entries()
            .into_iter()
            .map(|mut entry| {
                entry.parameters.retain(|parameter| {
                    !matches!(parameter.identifier, N3QaiParameterIdentifier::Unknown(_))
                });
                entry
            })
            .collect()
    }

    /// Parse all entries, returning `None` if any nested count or length does
    /// not consume exactly the N3QAI value.
    ///
    /// Spare QFI values and unsupported parameter identifiers remain
    /// receiver-tolerated; [`Self::is_well_formed`] applies the stricter sender
    /// domains.
    pub fn try_entries(&self) -> Option<Vec<N3QaiEntry>> {
        let data = &self.value;
        if data.len() < 6 {
            return None;
        }
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let qfi_count = *data.get(pos)? as usize;
            pos += 1;
            if pos + qfi_count >= data.len() {
                return None;
            }
            let qfis = data[pos..pos + qfi_count]
                .iter()
                .copied()
                .filter(|qfi| (1..=63).contains(qfi))
                .collect();
            pos += qfi_count;

            let parameter_count = data[pos] as usize;
            pos += 1;
            let mut parameters = Vec::with_capacity(parameter_count);
            for _ in 0..parameter_count {
                if pos + 2 > data.len() {
                    return None;
                }
                let identifier = N3QaiParameterIdentifier::from_u8(data[pos]);
                let contents_len = data[pos + 1] as usize;
                pos += 2;
                if pos + contents_len > data.len() {
                    return None;
                }
                let parameter = N3QaiParameter {
                    identifier,
                    contents: data[pos..pos + contents_len].to_vec(),
                };
                parameter.value()?;
                parameters.push(parameter);
                pos += contents_len;
            }
            entries.push(N3QaiEntry { qfis, parameters });
        }
        (!entries.is_empty()).then_some(entries)
    }

    /// Return all exactly framed entries, or an empty list for malformed data.
    pub fn entries(&self) -> Vec<N3QaiEntry> {
        self.try_entries().unwrap_or_default()
    }

    /// Construct a sender-valid value from entries.
    pub fn from_entries(entries: &[N3QaiEntry]) -> Option<Self> {
        if entries.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if entry.qfis.is_empty() || entry.parameters.is_empty() {
                return None;
            }
            value.push(entry.qfis.len().try_into().ok()?);
            for &qfi in &entry.qfis {
                if !(1..=63).contains(&qfi) {
                    return None;
                }
                value.push(qfi);
            }
            value.push(entry.parameters.len().try_into().ok()?);
            let mut seen = Vec::new();
            for parameter in &entry.parameters {
                let identifier = parameter.identifier.as_u8();
                if seen.contains(&identifier) || !parameter.sender_is_valid() {
                    return None;
                }
                seen.push(identifier);
                value.push(identifier);
                value.push(parameter.contents.len().try_into().ok()?);
                value.extend_from_slice(&parameter.contents);
            }
        }
        (value.len() >= 6).then(|| Self::new(value))
    }

    /// Whether the value is an exact current-release sender encoding.
    pub fn is_well_formed(&self) -> bool {
        self.try_entries().is_some_and(|entries| {
            Self::from_entries(&entries).is_some_and(|rebuilt| rebuilt.value == self.value)
        })
    }
}

// ── 9.11.4.41 Non-3GPP device information ──────────────────────────────────

/// IPv4 applicability encoding for TS 24.501 §9.11.4.41 IPv4v6 connection info.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Non3GppIpv4AddressInformation {
    /// Not applicable.
    NotApplicable,
    /// Address.
    Address([u8; 4]),
    /// PDU session address applies.
    PduSessionAddressApplies,
}

/// IPv6 address or prefix encoding for TS 24.501 §9.11.4.41.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Non3GppIpv6AddressInformation {
    /// Address.
    Address([u8; 16]),
    /// Prefix.
    Prefix {
        /// Address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
}

/// Connection information for one non-3GPP device per TS 24.501 §9.11.4.41.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Non3GppDeviceConnectionInformation {
    /// Ipv 4.
    Ipv4 {
        /// Ipv 4 address.
        ipv4_address: Option<[u8; 4]>,
        /// Ipv 4 port ranges.
        ipv4_port_ranges: Vec<PortRange>,
    },
    /// Ipv 6.
    Ipv6 {
        /// Ipv 6.
        ipv6: Non3GppIpv6AddressInformation,
        /// Ipv 6 port ranges.
        ipv6_port_ranges: Vec<PortRange>,
    },
    /// Ipv 4 v 6.
    Ipv4v6 {
        /// Ipv 4.
        ipv4: Non3GppIpv4AddressInformation,
        /// Ipv 4 port ranges.
        ipv4_port_ranges: Vec<PortRange>,
        /// Ipv 6.
        ipv6: Option<Non3GppIpv6AddressInformation>,
        /// Ipv 6 port ranges.
        ipv6_port_ranges: Vec<PortRange>,
    },
    /// Ethernet.
    Ethernet {
        /// Mac address.
        mac_address: [u8; 6],
        /// Vlan tag identifier.
        vlan_tag_id: Option<u16>,
    },
}

/// One non-3GPP device entry per TS 24.501 §9.11.4.41.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Non3GppDeviceInformationEntry {
    /// Device identifier.
    pub device_identifier: Vec<u8>,
    /// Connection information.
    pub connection_information: Option<Non3GppDeviceConnectionInformation>,
}

impl Non3GppDeviceInformationEntry {
    /// Build an entry that carries only the device identifier and omits
    /// connection information.
    ///
    /// In TS 24.501 §9.11.4.41, the absence of connection information is the
    /// encoding used to suspend QoS differentiation for this non-3GPP device.
    pub fn without_connection_information(device_identifier: Vec<u8>) -> Self {
        Self {
            device_identifier,
            connection_information: None,
        }
    }

    /// Whether this entry omits connection information.
    pub fn has_connection_information(&self) -> bool {
        self.connection_information.is_some()
    }

    /// Whether this entry carries the suspend-QoS-differentiation form.
    pub fn is_qos_differentiation_suspended(&self) -> bool {
        self.connection_information.is_none()
    }
}

impl NasNon3GppDeviceInformation {
    /// Return PDU session type.
    pub fn pdu_session_type(&self) -> Option<PduSessionTypeValue> {
        match self.value.first().copied().unwrap_or(0) & 0x07 {
            0x01 => Some(PduSessionTypeValue::IPv4),
            0x02 => Some(PduSessionTypeValue::IPv6),
            0x03 => Some(PduSessionTypeValue::IPv4v6),
            0x05 => Some(PduSessionTypeValue::Ethernet),
            _ => None,
        }
    }

    /// Return entries.
    pub fn entries(&self) -> Vec<Non3GppDeviceInformationEntry> {
        let Some(session_type) = self.pdu_session_type() else {
            return Vec::new();
        };
        let data = &self.value;
        let mut entries = Vec::new();
        let mut pos = 1usize;
        while pos + 2 <= data.len() {
            let entry_len = data[pos] as usize;
            pos += 1;
            if entry_len == 0 || pos + entry_len > data.len() {
                break;
            }
            let entry_end = pos + entry_len;
            if data[pos] & 0xC0 != 0 {
                break;
            }
            let identifier_len = (data[pos] & 0x3F) as usize;
            pos += 1;
            if pos + identifier_len > entry_end {
                break;
            }
            let device_identifier = data[pos..pos + identifier_len].to_vec();
            pos += identifier_len;
            let connection_information = if pos == entry_end {
                None
            } else {
                let parsed = parse_non_3gpp_device_connection_information(
                    session_type,
                    &data[pos..entry_end],
                );
                if parsed.is_none() {
                    break;
                }
                parsed
            };
            pos = entry_end;
            entries.push(Non3GppDeviceInformationEntry {
                device_identifier,
                connection_information,
            });
        }
        entries
    }

    /// Construct a value from entries.
    pub fn from_entries(
        session_type: PduSessionTypeValue,
        entries: &[Non3GppDeviceInformationEntry],
    ) -> Option<Self> {
        if !matches!(
            session_type,
            PduSessionTypeValue::IPv4
                | PduSessionTypeValue::IPv6
                | PduSessionTypeValue::IPv4v6
                | PduSessionTypeValue::Ethernet
        ) {
            return None;
        }
        let mut value = vec![session_type as u8 & 0x07];
        for entry in entries {
            if entry.device_identifier.len() > 0x3F {
                return None;
            }
            let mut body = Vec::new();
            body.push(entry.device_identifier.len().try_into().ok()?);
            body.extend_from_slice(&entry.device_identifier);
            if let Some(connection_information) = &entry.connection_information {
                body.extend_from_slice(&encode_non_3gpp_device_connection_information(
                    session_type,
                    connection_information,
                )?);
            }
            if body.len() > u8::MAX as usize {
                return None;
            }
            value.push(body.len().try_into().ok()?);
            value.extend_from_slice(&body);
        }
        Some(Self::new(value))
    }

    /// Strict structural and spare-bit validation for TS 24.501 §9.11.4.41.
    pub fn validate_strict(&self) -> Result<()> {
        let Some(first) = self.value.first().copied() else {
            return Err(NasError::DecodingError(
                "Non-3GPP device information must not be empty".into(),
            ));
        };
        if first & !0x07 != 0 {
            return Err(NasError::DecodingError(
                "Non-3GPP device information PDU-session-type spare bits shall be zero".into(),
            ));
        }
        let session_type = self.pdu_session_type().ok_or_else(|| {
            NasError::DecodingError(
                "Non-3GPP device information PDU session type is unsupported".into(),
            )
        })?;

        let data = &self.value;
        let mut pos = 1usize;
        while pos < data.len() {
            let Some(entry_len) = data.get(pos).copied() else {
                return Err(NasError::BufferTooShort);
            };
            let entry_len = entry_len as usize;
            pos += 1;
            if entry_len == 0 || pos + entry_len > data.len() {
                return Err(NasError::DecodingError(
                    "Non-3GPP device information entry length is invalid".into(),
                ));
            }
            let entry_end = pos + entry_len;
            let header = data[pos];
            if header & 0xC0 != 0 {
                return Err(NasError::DecodingError(
                    "Non-3GPP device information per-device header spare bits shall be zero".into(),
                ));
            }
            let identifier_len = (header & 0x3F) as usize;
            pos += 1;
            if pos + identifier_len > entry_end {
                return Err(NasError::BufferTooShort);
            }
            pos += identifier_len;
            if pos < entry_end {
                let connection_data = &data[pos..entry_end];
                if !non_3gpp_device_connection_flags_spare_bits_are_zero(
                    session_type,
                    connection_data,
                ) {
                    return Err(NasError::DecodingError(
                        "Non-3GPP device information connection flag spare bits shall be zero"
                            .into(),
                    ));
                }
                parse_non_3gpp_device_connection_information(session_type, connection_data)
                    .ok_or_else(|| {
                        NasError::DecodingError(
                            "Non-3GPP device information connection data is invalid".into(),
                        )
                    })?;
            }
            pos = entry_end;
        }
        Ok(())
    }
}

fn parse_port_ranges(data: &[u8], count: usize) -> Option<(Vec<PortRange>, usize)> {
    if count.checked_mul(4)? > data.len() {
        return None;
    }
    let mut port_ranges = Vec::with_capacity(count);
    let mut pos = 0usize;
    for _ in 0..count {
        let low = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
        pos += 2;
        let high = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
        pos += 2;
        port_ranges.push(PortRange { low, high });
    }
    Some((port_ranges, pos))
}

fn encode_port_ranges(port_ranges: &[PortRange]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.push(port_ranges.len().try_into().ok()?);
    for port_range in port_ranges {
        out.extend_from_slice(&port_range.low.to_be_bytes());
        out.extend_from_slice(&port_range.high.to_be_bytes());
    }
    Some(out)
}

fn parse_non_3gpp_device_connection_information(
    session_type: PduSessionTypeValue,
    data: &[u8],
) -> Option<Non3GppDeviceConnectionInformation> {
    let flags = *data.first()?;
    let mut pos = 1usize;
    let parsed = match session_type {
        PduSessionTypeValue::IPv4 => {
            let ipv4_address = if flags & 0x01 != 0 {
                let address = copy_array::<4>(&data[pos..])?;
                pos += 4;
                Some(address)
            } else {
                None
            };
            let ipv4_port_ranges = if flags & 0x02 != 0 {
                let range_count = *data.get(pos)? as usize;
                pos += 1;
                let (port_ranges, consumed) = parse_port_ranges(&data[pos..], range_count)?;
                pos += consumed;
                port_ranges
            } else {
                Vec::new()
            };
            Non3GppDeviceConnectionInformation::Ipv4 {
                ipv4_address,
                ipv4_port_ranges,
            }
        }
        PduSessionTypeValue::IPv6 => {
            let ipv6 = if flags & 0x01 != 0 {
                let address = copy_array::<16>(&data[pos..])?;
                pos += 16;
                let prefix_length = *data.get(pos)?;
                pos += 1;
                Non3GppIpv6AddressInformation::Prefix {
                    address,
                    prefix_length,
                }
            } else {
                let address = copy_array::<16>(&data[pos..])?;
                pos += 16;
                Non3GppIpv6AddressInformation::Address(address)
            };
            let ipv6_port_ranges = if flags & 0x02 != 0 {
                let range_count = *data.get(pos)? as usize;
                pos += 1;
                let (port_ranges, consumed) = parse_port_ranges(&data[pos..], range_count)?;
                pos += consumed;
                port_ranges
            } else {
                Vec::new()
            };
            Non3GppDeviceConnectionInformation::Ipv6 {
                ipv6,
                ipv6_port_ranges,
            }
        }
        PduSessionTypeValue::IPv4v6 => {
            let ipv4 = match flags & 0x03 {
                0x00 => Non3GppIpv4AddressInformation::NotApplicable,
                0x01 => {
                    let address = copy_array::<4>(&data[pos..])?;
                    pos += 4;
                    Non3GppIpv4AddressInformation::Address(address)
                }
                0x02 => Non3GppIpv4AddressInformation::PduSessionAddressApplies,
                _ => return None,
            };
            let ipv4_port_ranges = if flags & 0x04 != 0 {
                let range_count = *data.get(pos)? as usize;
                pos += 1;
                let (port_ranges, consumed) = parse_port_ranges(&data[pos..], range_count)?;
                pos += consumed;
                port_ranges
            } else {
                Vec::new()
            };
            let ipv6 = match (flags >> 3) & 0x03 {
                0x00 => None,
                0x01 => {
                    let address = copy_array::<16>(&data[pos..])?;
                    pos += 16;
                    Some(Non3GppIpv6AddressInformation::Address(address))
                }
                0x02 => {
                    let address = copy_array::<16>(&data[pos..])?;
                    pos += 16;
                    let prefix_length = *data.get(pos)?;
                    pos += 1;
                    Some(Non3GppIpv6AddressInformation::Prefix {
                        address,
                        prefix_length,
                    })
                }
                _ => return None,
            };
            let ipv6_port_ranges = if flags & 0x20 != 0 {
                let range_count = *data.get(pos)? as usize;
                pos += 1;
                let (port_ranges, consumed) = parse_port_ranges(&data[pos..], range_count)?;
                pos += consumed;
                port_ranges
            } else {
                Vec::new()
            };
            Non3GppDeviceConnectionInformation::Ipv4v6 {
                ipv4,
                ipv4_port_ranges,
                ipv6,
                ipv6_port_ranges,
            }
        }
        PduSessionTypeValue::Ethernet => {
            let mac_address = copy_array::<6>(&data[pos..])?;
            pos += 6;
            let vlan_tag_id = if flags & 0x01 != 0 {
                let vlan_tag_id = u16::from_be_bytes(copy_array::<2>(&data[pos..])?);
                pos += 2;
                Some(vlan_tag_id)
            } else {
                None
            };
            Non3GppDeviceConnectionInformation::Ethernet {
                mac_address,
                vlan_tag_id,
            }
        }
        _ => return None,
    };
    (pos == data.len()).then_some(parsed)
}

fn non_3gpp_device_connection_flags_spare_bits_are_zero(
    session_type: PduSessionTypeValue,
    data: &[u8],
) -> bool {
    let Some(flags) = data.first().copied() else {
        return false;
    };
    match session_type {
        PduSessionTypeValue::IPv4 | PduSessionTypeValue::IPv6 => flags & !0x03 == 0,
        PduSessionTypeValue::IPv4v6 => flags & !0x3F == 0,
        PduSessionTypeValue::Ethernet => flags & !0x01 == 0,
        PduSessionTypeValue::Unstructured => false,
    }
}

fn encode_non_3gpp_device_connection_information(
    session_type: PduSessionTypeValue,
    connection_information: &Non3GppDeviceConnectionInformation,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match (session_type, connection_information) {
        (
            PduSessionTypeValue::IPv4,
            Non3GppDeviceConnectionInformation::Ipv4 {
                ipv4_address,
                ipv4_port_ranges,
            },
        ) => {
            let mut flags = 0u8;
            if ipv4_address.is_some() {
                flags |= 0x01;
            }
            if !ipv4_port_ranges.is_empty() {
                flags |= 0x02;
            }
            out.push(flags);
            if let Some(ipv4_address) = ipv4_address {
                out.extend_from_slice(ipv4_address);
            }
            if !ipv4_port_ranges.is_empty() {
                out.extend_from_slice(&encode_port_ranges(ipv4_port_ranges)?);
            }
        }
        (
            PduSessionTypeValue::IPv6,
            Non3GppDeviceConnectionInformation::Ipv6 {
                ipv6,
                ipv6_port_ranges,
            },
        ) => {
            let mut flags = 0u8;
            if matches!(ipv6, Non3GppIpv6AddressInformation::Prefix { .. }) {
                flags |= 0x01;
            }
            if !ipv6_port_ranges.is_empty() {
                flags |= 0x02;
            }
            out.push(flags);
            match ipv6 {
                Non3GppIpv6AddressInformation::Address(address) => out.extend_from_slice(address),
                Non3GppIpv6AddressInformation::Prefix {
                    address,
                    prefix_length,
                } => {
                    out.extend_from_slice(address);
                    out.push(*prefix_length);
                }
            }
            if !ipv6_port_ranges.is_empty() {
                out.extend_from_slice(&encode_port_ranges(ipv6_port_ranges)?);
            }
        }
        (
            PduSessionTypeValue::IPv4v6,
            Non3GppDeviceConnectionInformation::Ipv4v6 {
                ipv4,
                ipv4_port_ranges,
                ipv6,
                ipv6_port_ranges,
            },
        ) => {
            let mut flags = match ipv4 {
                Non3GppIpv4AddressInformation::NotApplicable => 0x00,
                Non3GppIpv4AddressInformation::Address(_) => 0x01,
                Non3GppIpv4AddressInformation::PduSessionAddressApplies => 0x02,
            };
            if !ipv4_port_ranges.is_empty() {
                flags |= 0x04;
            }
            flags |= match ipv6 {
                None => 0x00,
                Some(Non3GppIpv6AddressInformation::Address(_)) => 0x08,
                Some(Non3GppIpv6AddressInformation::Prefix { .. }) => 0x10,
            };
            if !ipv6_port_ranges.is_empty() {
                flags |= 0x20;
            }
            out.push(flags);
            if let Non3GppIpv4AddressInformation::Address(address) = ipv4 {
                out.extend_from_slice(address);
            }
            if !ipv4_port_ranges.is_empty() {
                out.extend_from_slice(&encode_port_ranges(ipv4_port_ranges)?);
            }
            if let Some(ipv6) = ipv6 {
                match ipv6 {
                    Non3GppIpv6AddressInformation::Address(address) => {
                        out.extend_from_slice(address);
                    }
                    Non3GppIpv6AddressInformation::Prefix {
                        address,
                        prefix_length,
                    } => {
                        out.extend_from_slice(address);
                        out.push(*prefix_length);
                    }
                }
            }
            if !ipv6_port_ranges.is_empty() {
                out.extend_from_slice(&encode_port_ranges(ipv6_port_ranges)?);
            }
        }
        (
            PduSessionTypeValue::Ethernet,
            Non3GppDeviceConnectionInformation::Ethernet {
                mac_address,
                vlan_tag_id,
            },
        ) => {
            out.push(if vlan_tag_id.is_some() { 0x01 } else { 0x00 });
            out.extend_from_slice(mac_address);
            if let Some(vlan_tag_id) = vlan_tag_id {
                out.extend_from_slice(&vlan_tag_id.to_be_bytes());
            }
        }
        _ => return None,
    }
    Some(out)
}

// ── 9.11.4.29 Remote UE context list ───────────────────────────────────────

/// Remote UE ID format per TS 24.501 §9.11.4.29.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RemoteUeIdFormat {
    /// Nai.
    Nai,
    /// Bit string 64.
    BitString64,
}

impl RemoteUeIdFormat {
    /// Construct a value from bit.
    pub fn from_bit(value: bool) -> Self {
        if value { Self::BitString64 } else { Self::Nai }
    }

    /// Return bit.
    pub fn bit(self) -> u8 {
        match self {
            Self::Nai => 0x00,
            Self::BitString64 => 0x08,
        }
    }
}

/// Remote UE ID type per TS 24.501 §9.11.4.29.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RemoteUeIdType {
    /// Up pruk identifier.
    UpPrukId,
    /// Cp pruk identifier.
    CpPrukId,
    /// Imei.
    Imei,
    /// Imeisv.
    Imeisv,
    /// Unknown.
    Unknown(u8),
}

impl RemoteUeIdType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x07 {
            0x01 => Self::UpPrukId,
            0x02 => Self::CpPrukId,
            0x03 => Self::Imei,
            0x04 => Self::Imeisv,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::UpPrukId => 0x01,
            Self::CpPrukId => 0x02,
            Self::Imei => 0x03,
            Self::Imeisv => 0x04,
            Self::Unknown(value) => value & 0x07,
        }
    }
}

/// Remote UE identifier per TS 24.501 §9.11.4.29.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RemoteUeIdentifier {
    /// Up pruk identifier.
    UpPrukId {
        /// Format.
        format: RemoteUeIdFormat,
        /// Raw information-element contents.
        value: Vec<u8>,
    },
    /// Cp pruk identifier.
    CpPrukId {
        /// Format.
        format: RemoteUeIdFormat,
        /// Raw information-element contents.
        value: Vec<u8>,
    },
    /// Imei.
    Imei {
        /// Raw information-element contents.
        value: Vec<u8>,
    },
    /// Imeisv.
    Imeisv {
        /// Raw information-element contents.
        value: Vec<u8>,
    },
    /// Unknown.
    Unknown {
        /// Identifier type raw.
        id_type_raw: u8,
        /// Format.
        format: RemoteUeIdFormat,
        /// Raw information-element contents.
        value: Vec<u8>,
    },
}

/// Protocol used by remote UE per TS 24.501 §9.11.4.29.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RemoteUeProtocolInformation {
    /// No ip info.
    NoIpInfo,
    /// Ipv 4.
    Ipv4 {
        /// Address.
        address: [u8; 4],
        /// Udp port range.
        udp_port_range: Option<PortRange>,
        /// Tcp port range.
        tcp_port_range: Option<PortRange>,
    },
    /// Ipv 6.
    Ipv6 {
        /// Prefix.
        prefix: [u8; 8],
    },
    /// Unstructured.
    Unstructured,
    /// Ethernet.
    Ethernet {
        /// Mac address.
        mac_address: [u8; 6],
    },
    /// Unknown.
    Unknown {
        /// Protocol raw.
        protocol_raw: u8,
        /// Udp port range present.
        udp_port_range_present: bool,
        /// Tcp port range present.
        tcp_port_range_present: bool,
        /// Address information.
        address_information: Vec<u8>,
    },
}

/// One remote UE context per TS 24.501 §9.11.4.29.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoteUeContext {
    /// Remote UE identifier.
    pub remote_ue_identifier: RemoteUeIdentifier,
    /// Protocol information.
    pub protocol_information: RemoteUeProtocolInformation,
    /// Hplmn identifier.
    pub hplmn_id: Option<PlmnId>,
}

impl NasRemoteUeContextList {
    /// Return contexts.
    pub fn contexts(&self) -> Vec<RemoteUeContext> {
        let data = &self.value;
        let Some(&context_count) = data.first() else {
            return Vec::new();
        };
        let mut contexts = Vec::with_capacity(context_count as usize);
        let mut pos = 1usize;
        for _ in 0..context_count {
            if pos + 2 > data.len() {
                return Vec::new();
            }
            let context_len = data[pos] as usize;
            pos += 1;
            if context_len == 0 || pos + context_len > data.len() {
                return Vec::new();
            }
            let context_end = pos + context_len;
            let id_type_octet = data[pos];
            pos += 1;
            let id_type = RemoteUeIdType::from_u8(id_type_octet & 0x07);
            let id_format = RemoteUeIdFormat::from_bit(id_type_octet & 0x08 != 0);
            let Some(&id_len) = data.get(pos) else {
                return Vec::new();
            };
            let id_len = id_len as usize;
            pos += 1;
            if pos + id_len > context_end {
                return Vec::new();
            }
            let id_value = data[pos..pos + id_len].to_vec();
            pos += id_len;

            let Some(&protocol_octet) = data.get(pos) else {
                return Vec::new();
            };
            pos += 1;
            let protocol_raw = protocol_octet & 0x07;
            let tcp_port_range_present = protocol_octet & 0x08 != 0;
            let udp_port_range_present = protocol_octet & 0x10 != 0;

            let hplmn_expected = matches!(
                (&id_type, id_format),
                (
                    RemoteUeIdType::UpPrukId | RemoteUeIdType::CpPrukId,
                    RemoteUeIdFormat::BitString64
                )
            );
            let hplmn_len = if hplmn_expected { 3 } else { 0 };
            if context_end < pos + hplmn_len {
                return Vec::new();
            }
            let address_end = context_end - hplmn_len;
            let address_information = &data[pos..address_end];
            let protocol_information = match protocol_raw {
                0x00 => {
                    if !address_information.is_empty() {
                        return Vec::new();
                    }
                    RemoteUeProtocolInformation::NoIpInfo
                }
                0x01 => {
                    let mut address_pos = 0usize;
                    let Some(address) = copy_array::<4>(&address_information[address_pos..]) else {
                        return Vec::new();
                    };
                    address_pos += 4;
                    let udp_port_range = if udp_port_range_present {
                        let Some(low_bytes) = copy_array::<2>(&address_information[address_pos..])
                        else {
                            return Vec::new();
                        };
                        let low = u16::from_be_bytes(low_bytes);
                        address_pos += 2;
                        let Some(high_bytes) = copy_array::<2>(&address_information[address_pos..])
                        else {
                            return Vec::new();
                        };
                        let high = u16::from_be_bytes(high_bytes);
                        address_pos += 2;
                        Some(PortRange { low, high })
                    } else {
                        None
                    };
                    let tcp_port_range = if tcp_port_range_present {
                        let Some(low_bytes) = copy_array::<2>(&address_information[address_pos..])
                        else {
                            return Vec::new();
                        };
                        let low = u16::from_be_bytes(low_bytes);
                        address_pos += 2;
                        let Some(high_bytes) = copy_array::<2>(&address_information[address_pos..])
                        else {
                            return Vec::new();
                        };
                        let high = u16::from_be_bytes(high_bytes);
                        address_pos += 2;
                        Some(PortRange { low, high })
                    } else {
                        None
                    };
                    if address_pos != address_information.len() {
                        return Vec::new();
                    }
                    RemoteUeProtocolInformation::Ipv4 {
                        address,
                        udp_port_range,
                        tcp_port_range,
                    }
                }
                0x02 => {
                    if address_information.len() != 8 {
                        return Vec::new();
                    }
                    let Some(prefix) = copy_array::<8>(address_information) else {
                        return Vec::new();
                    };
                    RemoteUeProtocolInformation::Ipv6 { prefix }
                }
                0x04 => {
                    if !address_information.is_empty() {
                        return Vec::new();
                    }
                    RemoteUeProtocolInformation::Unstructured
                }
                0x05 => {
                    if address_information.len() != 6 {
                        return Vec::new();
                    }
                    let Some(mac_address) = copy_array::<6>(address_information) else {
                        return Vec::new();
                    };
                    RemoteUeProtocolInformation::Ethernet { mac_address }
                }
                _ => RemoteUeProtocolInformation::Unknown {
                    protocol_raw,
                    udp_port_range_present,
                    tcp_port_range_present,
                    address_information: address_information.to_vec(),
                },
            };
            pos = address_end;

            let hplmn_id = if hplmn_expected {
                let Some(hplmn) = PlmnId::from_tbcd(&data[pos..pos + 3]) else {
                    return Vec::new();
                };
                pos += 3;
                Some(hplmn)
            } else {
                None
            };

            let remote_ue_identifier = match id_type {
                RemoteUeIdType::UpPrukId => RemoteUeIdentifier::UpPrukId {
                    format: id_format,
                    value: id_value,
                },
                RemoteUeIdType::CpPrukId => RemoteUeIdentifier::CpPrukId {
                    format: id_format,
                    value: id_value,
                },
                RemoteUeIdType::Imei => RemoteUeIdentifier::Imei { value: id_value },
                RemoteUeIdType::Imeisv => RemoteUeIdentifier::Imeisv { value: id_value },
                RemoteUeIdType::Unknown(raw) => RemoteUeIdentifier::Unknown {
                    id_type_raw: raw,
                    format: id_format,
                    value: id_value,
                },
            };

            contexts.push(RemoteUeContext {
                remote_ue_identifier,
                protocol_information,
                hplmn_id,
            });
        }
        contexts
    }

    /// Construct a value from contexts.
    pub fn from_contexts(contexts: &[RemoteUeContext]) -> Option<Self> {
        let mut value = Vec::new();
        value.push(contexts.len().try_into().ok()?);
        for context in contexts {
            let (id_type, id_format, id_value) = match &context.remote_ue_identifier {
                RemoteUeIdentifier::UpPrukId { format, value } => {
                    (RemoteUeIdType::UpPrukId, *format, value)
                }
                RemoteUeIdentifier::CpPrukId { format, value } => {
                    (RemoteUeIdType::CpPrukId, *format, value)
                }
                RemoteUeIdentifier::Imei { value } => {
                    (RemoteUeIdType::Imei, RemoteUeIdFormat::Nai, value)
                }
                RemoteUeIdentifier::Imeisv { value } => {
                    (RemoteUeIdType::Imeisv, RemoteUeIdFormat::Nai, value)
                }
                RemoteUeIdentifier::Unknown {
                    id_type_raw,
                    format,
                    value,
                } => (RemoteUeIdType::Unknown(*id_type_raw), *format, value),
            };
            let mut body = Vec::new();
            body.push(id_type.as_u8() | id_format.bit());
            body.push(id_value.len().try_into().ok()?);
            body.extend_from_slice(id_value);

            let protocol_octet_pos = body.len();
            body.push(0);
            match &context.protocol_information {
                RemoteUeProtocolInformation::NoIpInfo => {}
                RemoteUeProtocolInformation::Ipv4 {
                    address,
                    udp_port_range,
                    tcp_port_range,
                } => {
                    body[protocol_octet_pos] = 0x01
                        | if tcp_port_range.is_some() { 0x08 } else { 0 }
                        | if udp_port_range.is_some() { 0x10 } else { 0 };
                    body.extend_from_slice(address);
                    if let Some(port_range) = udp_port_range {
                        body.extend_from_slice(&port_range.low.to_be_bytes());
                        body.extend_from_slice(&port_range.high.to_be_bytes());
                    }
                    if let Some(port_range) = tcp_port_range {
                        body.extend_from_slice(&port_range.low.to_be_bytes());
                        body.extend_from_slice(&port_range.high.to_be_bytes());
                    }
                }
                RemoteUeProtocolInformation::Ipv6 { prefix } => {
                    body[protocol_octet_pos] = 0x02;
                    body.extend_from_slice(prefix);
                }
                RemoteUeProtocolInformation::Unstructured => {
                    body[protocol_octet_pos] = 0x04;
                }
                RemoteUeProtocolInformation::Ethernet { mac_address } => {
                    body[protocol_octet_pos] = 0x05;
                    body.extend_from_slice(mac_address);
                }
                RemoteUeProtocolInformation::Unknown {
                    protocol_raw,
                    udp_port_range_present,
                    tcp_port_range_present,
                    address_information,
                } => {
                    body[protocol_octet_pos] = (protocol_raw & 0x07)
                        | if *tcp_port_range_present { 0x08 } else { 0 }
                        | if *udp_port_range_present { 0x10 } else { 0 };
                    body.extend_from_slice(address_information);
                }
            }

            if let Some(hplmn_id) = context.hplmn_id {
                body.extend_from_slice(&hplmn_id.to_tbcd());
            }
            value.push(body.len().try_into().ok()?);
            value.extend_from_slice(&body);
        }
        Some(Self::new(value))
    }
}

// ── 9.11.4.37 Non-3GPP delay budget ────────────────────────────────────────

/// One non-3GPP delay budget entry per TS 24.501 §9.11.4.37.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Non3GppDelayBudgetEntry {
    /// Delay budget.
    pub delay_budget: u16,
    /// Qfis.
    pub qfis: Vec<u8>,
    /// Packet filters.
    pub packet_filters: Vec<QosPacketFilter>,
}

impl NasNon3GppDelayBudget {
    /// Return entries.
    pub fn entries(&self) -> Vec<Non3GppDelayBudgetEntry> {
        parse_non_3gpp_delay_budget_entries(&self.value).unwrap_or_default()
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[Non3GppDelayBudgetEntry]) -> Option<Self> {
        let mut value = Vec::new();
        for entry in entries {
            value.extend_from_slice(&entry.delay_budget.to_be_bytes());
            let mut flags = 0u8;
            if !entry.packet_filters.is_empty() {
                flags |= 0x01;
            }
            if !entry.qfis.is_empty() {
                flags |= 0x02;
            }
            value.push(flags);
            if !entry.qfis.is_empty() {
                value.push(entry.qfis.len().try_into().ok()?);
                for &qfi in &entry.qfis {
                    if !(1..=63).contains(&qfi) {
                        return None;
                    }
                    value.push(qfi);
                }
            }
            if !entry.packet_filters.is_empty() {
                value.extend_from_slice(&encode_qos_match_packet_filters(&entry.packet_filters)?);
            }
        }
        Some(Self::new(value))
    }
}

fn parse_non_3gpp_delay_budget_entries(data: &[u8]) -> Option<Vec<Non3GppDelayBudgetEntry>> {
    fn parse_from(data: &[u8], offset: usize) -> Option<Vec<Non3GppDelayBudgetEntry>> {
        if offset == data.len() {
            return Some(Vec::new());
        }
        if offset + 3 > data.len() {
            return None;
        }

        let delay_budget = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let flags = data[offset + 2];
        let packet_filter_present = flags & 0x01 != 0;
        let qfi_present = flags & 0x02 != 0;
        let mut pos = offset + 3;

        let mut qfis = Vec::new();
        if qfi_present {
            let qfi_count = *data.get(pos)? as usize;
            pos += 1;
            if pos + qfi_count > data.len() {
                return None;
            }
            for &qfi in &data[pos..pos + qfi_count] {
                if (1..=63).contains(&qfi) {
                    qfis.push(qfi);
                }
            }
            pos += qfi_count;
        }

        if !packet_filter_present {
            let mut rest = parse_from(data, pos)?;
            rest.insert(
                0,
                Non3GppDelayBudgetEntry {
                    delay_budget,
                    qfis,
                    packet_filters: Vec::new(),
                },
            );
            return Some(rest);
        }

        let mut packet_filters = Vec::new();
        let mut packet_filter_pos = pos;
        while packet_filter_pos < data.len() {
            let (packet_filter, consumed) =
                parse_single_qos_match_packet_filter(&data[packet_filter_pos..])?;
            packet_filters.push(packet_filter);
            packet_filter_pos += consumed;
            if let Some(mut rest) = parse_from(data, packet_filter_pos) {
                rest.insert(
                    0,
                    Non3GppDelayBudgetEntry {
                        delay_budget,
                        qfis: qfis.clone(),
                        packet_filters: packet_filters.clone(),
                    },
                );
                return Some(rest);
            }
        }
        None
    }

    parse_from(data, 0)
}

fn parse_single_qos_match_packet_filter(data: &[u8]) -> Option<(QosPacketFilter, usize)> {
    if data.len() < 2 {
        return None;
    }
    let id_byte = data[0];
    let packet_filter_len = data[1] as usize;
    if data.len() < 2 + packet_filter_len {
        return None;
    }
    let direction = QosPacketFilterDirection::from_u8((id_byte >> 4) & 0x03);
    let identifier = id_byte & 0x0F;
    let components = parse_qos_packet_filter_components(&data[2..2 + packet_filter_len])?;
    Some((
        QosPacketFilter::Match {
            direction,
            identifier,
            components,
        },
        2 + packet_filter_len,
    ))
}

fn encode_qos_match_packet_filters(packet_filters: &[QosPacketFilter]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for packet_filter in packet_filters {
        let QosPacketFilter::Match {
            direction,
            identifier,
            components,
        } = packet_filter
        else {
            return None;
        };
        let mut contents = Vec::new();
        let contents_len = components.iter().try_fold(0usize, |total, component| {
            Some(total + qos_packet_filter_component_len(component)?)
        })?;
        if contents_len > u8::MAX as usize {
            return None;
        }
        for component in components {
            encode_qos_packet_filter_component(&mut contents, component)?;
        }
        out.push(((*direction as u8 & 0x03) << 4) | (*identifier & 0x0F));
        out.push(contents.len().try_into().ok()?);
        out.extend_from_slice(&contents);
    }
    Some(out)
}

// ── 9.11.4.38 URSP rule enforcement reports ────────────────────────────────

/// One URSP rule enforcement report per TS 24.501 §9.11.4.38.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UrspRuleEnforcementReport {
    /// Connection capability identifiers.
    pub connection_capability_identifiers: Vec<u8>,
}

impl NasUrspRuleEnforcementReports {
    /// Return reports.
    pub fn reports(&self) -> Vec<UrspRuleEnforcementReport> {
        let mut reports = Vec::new();
        let mut pos = 0usize;
        while pos < self.value.len() {
            let identifier_count = self.value[pos] as usize;
            pos += 1;
            if identifier_count == 0 || pos + identifier_count > self.value.len() {
                return Vec::new();
            }
            reports.push(UrspRuleEnforcementReport {
                connection_capability_identifiers: self.value[pos..pos + identifier_count].to_vec(),
            });
            pos += identifier_count;
        }
        reports
    }

    /// Construct a value from reports.
    pub fn from_reports(reports: &[UrspRuleEnforcementReport]) -> Option<Self> {
        if reports.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for report in reports {
            if report.connection_capability_identifiers.is_empty() {
                return None;
            }
            value.push(
                report
                    .connection_capability_identifiers
                    .len()
                    .try_into()
                    .ok()?,
            );
            value.extend_from_slice(&report.connection_capability_identifiers);
        }
        Some(Self::new(value))
    }
}

// ── 9.11.4.39 Protocol description ─────────────────────────────────────────

/// Transport protocol field per TS 24.501 §9.11.4.39.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolDescriptionTransportProtocol {
    /// Rtp.
    Rtp,
    /// Srtp.
    Srtp,
    /// Unknown.
    Unknown(u8),
}

impl ProtocolDescriptionTransportProtocol {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x01 => Self::Rtp,
            0x02 => Self::Srtp,
            other => Self::Unknown(other),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x0F {
            0x01 => Some(Self::Rtp),
            0x02 => Some(Self::Srtp),
            _ => None,
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Rtp => 0x01,
            Self::Srtp => 0x02,
            Self::Unknown(value) => value & 0x0F,
        }
    }
}

/// RTP header extension type field per TS 24.501 §9.11.4.39.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolDescriptionRtpHeaderExtensionType {
    /// PDU set marking.
    PduSetMarking,
    /// Unknown.
    Unknown(u8),
}

impl ProtocolDescriptionRtpHeaderExtensionType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::PduSetMarking,
            other => Self::Unknown(other),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::PduSetMarking),
            _ => None,
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::PduSetMarking => 0x01,
            Self::Unknown(value) => value,
        }
    }
}

/// RTP payload format field per TS 24.501 §9.11.4.39.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolDescriptionRtpPayloadFormat {
    /// H 264 avc.
    H264Avc,
    /// H 265 hevc.
    H265Hevc,
    /// Unknown.
    Unknown(u8),
}

impl ProtocolDescriptionRtpPayloadFormat {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::H264Avc,
            0x02 => Self::H265Hevc,
            other => Self::Unknown(other),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::H264Avc),
            0x02 => Some(Self::H265Hevc),
            _ => None,
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::H264Avc => 0x01,
            Self::H265Hevc => 0x02,
            Self::Unknown(value) => value,
        }
    }
}

/// One RTP payload information entry per TS 24.501 §9.11.4.39.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProtocolDescriptionRtpPayloadInformation {
    /// Payload format.
    pub payload_format: ProtocolDescriptionRtpPayloadFormat,
    /// Payload types.
    pub payload_types: Vec<u8>,
}

/// One protocol description entry per TS 24.501 §9.11.4.39.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolDescriptionEntry {
    /// Delete.
    Delete {
        /// Qri.
        qri: u8,
    },
    /// Description.
    Description {
        /// Qri.
        qri: u8,
        /// Transport protocol.
        transport_protocol: ProtocolDescriptionTransportProtocol,
        /// Rtp header extension.
        rtp_header_extension: Option<(ProtocolDescriptionRtpHeaderExtensionType, u8)>,
        /// Rtp payload information list.
        rtp_payload_information_list: Vec<ProtocolDescriptionRtpPayloadInformation>,
    },
}

impl NasProtocolDescription {
    /// Return entries.
    pub fn entries(&self) -> Vec<ProtocolDescriptionEntry> {
        let data = &self.value;
        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos + 3 <= data.len() {
            let entry_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if entry_len == 0 || pos + entry_len > data.len() {
                break;
            }
            let entry_end = pos + entry_len;
            let qri = data[pos];
            pos += 1;
            if entry_len == 1 {
                entries.push(ProtocolDescriptionEntry::Delete { qri });
                continue;
            }

            if pos >= entry_end {
                break;
            }
            let flags = data[pos];
            pos += 1;
            if flags & 0xC0 != 0 {
                break;
            }
            let Some(transport_protocol) =
                ProtocolDescriptionTransportProtocol::from_u8_strict(flags & 0x0F)
            else {
                pos = entry_end;
                continue;
            };
            let header_extension_present = flags & 0x10 != 0;
            let payload_information_present = flags & 0x20 != 0;

            let rtp_header_extension = if header_extension_present {
                if pos + 2 > entry_end {
                    break;
                }
                let Some(extension_type) =
                    ProtocolDescriptionRtpHeaderExtensionType::from_u8_strict(data[pos])
                else {
                    break;
                };
                let extension_id = data[pos + 1];
                if extension_id == 0 {
                    break;
                }
                pos += 2;
                Some((extension_type, extension_id))
            } else {
                None
            };

            let mut rtp_payload_information_list = Vec::new();
            if payload_information_present {
                if pos + 2 > entry_end {
                    break;
                }
                let payload_list_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if pos + payload_list_len > entry_end {
                    break;
                }
                let payload_list_end = pos + payload_list_len;
                while pos < payload_list_end {
                    if pos + 2 > payload_list_end {
                        break;
                    }
                    let payload_format_raw = data[pos];
                    let payload_type_count = data[pos + 1] as usize;
                    pos += 2;
                    if pos + payload_type_count > payload_list_end {
                        break;
                    }
                    if let Some(payload_format) =
                        ProtocolDescriptionRtpPayloadFormat::from_u8_strict(payload_format_raw)
                    {
                        let payload_types = data[pos..pos + payload_type_count]
                            .iter()
                            .copied()
                            .filter(|payload_type| *payload_type <= 127)
                            .collect();
                        rtp_payload_information_list.push(
                            ProtocolDescriptionRtpPayloadInformation {
                                payload_format,
                                payload_types,
                            },
                        );
                    }
                    pos += payload_type_count;
                }
                pos = payload_list_end;
                if pos != payload_list_end {
                    break;
                }
            }

            if pos != entry_end {
                break;
            }
            entries.push(ProtocolDescriptionEntry::Description {
                qri,
                transport_protocol,
                rtp_header_extension,
                rtp_payload_information_list,
            });
        }
        entries
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[ProtocolDescriptionEntry]) -> Option<Self> {
        let mut value = Vec::new();
        for entry in entries {
            let mut body = Vec::new();
            match entry {
                ProtocolDescriptionEntry::Delete { qri } => {
                    body.push(*qri);
                }
                ProtocolDescriptionEntry::Description {
                    qri,
                    transport_protocol,
                    rtp_header_extension,
                    rtp_payload_information_list,
                } => {
                    if matches!(
                        transport_protocol,
                        ProtocolDescriptionTransportProtocol::Unknown(_)
                    ) {
                        return None;
                    }
                    body.push(*qri);
                    let mut flags = transport_protocol.as_u8() & 0x0F;
                    if rtp_header_extension.is_some() {
                        flags |= 0x10;
                    }
                    if !rtp_payload_information_list.is_empty() {
                        flags |= 0x20;
                    }
                    body.push(flags);
                    if let Some((extension_type, extension_id)) = rtp_header_extension {
                        if matches!(
                            extension_type,
                            ProtocolDescriptionRtpHeaderExtensionType::Unknown(_)
                        ) || *extension_id == 0
                        {
                            return None;
                        }
                        body.push(extension_type.as_u8());
                        body.push(*extension_id);
                    }
                    if !rtp_payload_information_list.is_empty() {
                        let mut payload_list = Vec::new();
                        for payload_information in rtp_payload_information_list {
                            if matches!(
                                payload_information.payload_format,
                                ProtocolDescriptionRtpPayloadFormat::Unknown(_)
                            ) || payload_information
                                .payload_types
                                .iter()
                                .any(|payload_type| *payload_type > 127)
                            {
                                return None;
                            }
                            payload_list.push(payload_information.payload_format.as_u8());
                            payload_list
                                .push(payload_information.payload_types.len().try_into().ok()?);
                            payload_list.extend_from_slice(&payload_information.payload_types);
                        }
                        if payload_list.len() > u16::MAX as usize {
                            return None;
                        }
                        body.extend_from_slice(&(payload_list.len() as u16).to_be_bytes());
                        body.extend_from_slice(&payload_list);
                    }
                }
            }
            if body.len() > u16::MAX as usize {
                return None;
            }
            value.extend_from_slice(&(body.len() as u16).to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        let entries = self.entries();
        !entries.is_empty()
            && Self::from_entries(&entries).is_some_and(|canonical| canonical.value == self.value)
    }
}

// ── 9.11.3.18B CIoT small data container ───────────────────────────────────

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// CIoT small data container type values.
pub enum CiotSmallDataContainerType {
    /// Control plane user data.
    ControlPlaneUserData = 0x00,
    /// Sms.
    Sms = 0x01,
    /// Location services message container.
    LocationServicesMessageContainer = 0x02,
}

impl CiotSmallDataContainerType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0x00 => Some(Self::ControlPlaneUserData),
            0x01 => Some(Self::Sms),
            0x02 => Some(Self::LocationServicesMessageContainer),
            _ => None,
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// CIoT small data downlink data expected values.
pub enum CiotSmallDataDownlinkDataExpected {
    /// No information available.
    NoInformationAvailable = 0x00,
    /// No further uplink or downlink.
    NoFurtherUplinkOrDownlink = 0x01,
    /// Single downlink no further uplink.
    SingleDownlinkNoFurtherUplink = 0x02,
    /// Reserved.
    Reserved = 0x03,
}

impl CiotSmallDataDownlinkDataExpected {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0x00 => Self::NoInformationAvailable,
            0x01 => Self::NoFurtherUplinkOrDownlink,
            0x02 => Self::SingleDownlinkNoFurtherUplink,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// CIoT small data container contents values.
pub enum CiotSmallDataContainerContents {
    /// Control plane user data.
    ControlPlaneUserData {
        /// Downlink data expected.
        downlink_data_expected: CiotSmallDataDownlinkDataExpected,
        /// PDU session identifier.
        pdu_session_id: u8,
        /// Raw encoded octets.
        data: Vec<u8>,
    },
    /// Sms.
    Sms {
        /// Raw encoded octets.
        data: Vec<u8>,
    },
    /// Location services message container.
    LocationServicesMessageContainer {
        /// Downlink data expected.
        downlink_data_expected: CiotSmallDataDownlinkDataExpected,
        /// Additional information.
        additional_information: Vec<u8>,
        /// Raw encoded octets.
        data: Vec<u8>,
    },
    /// Unknown.
    Unknown {
        /// Data type raw.
        data_type_raw: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

impl NasCiotSmallDataContainer {
    /// Parse the typed contents.
    pub fn parse(&self) -> Option<CiotSmallDataContainerContents> {
        if self.value.len() > 255 {
            return None;
        }
        let first = *self.value.first()?;
        let data_type_raw = (first >> 5) & 0x07;
        Some(match CiotSmallDataContainerType::from_u8(data_type_raw) {
            Some(CiotSmallDataContainerType::ControlPlaneUserData) => {
                CiotSmallDataContainerContents::ControlPlaneUserData {
                    downlink_data_expected: CiotSmallDataDownlinkDataExpected::from_u8(
                        (first >> 3) & 0x03,
                    ),
                    pdu_session_id: first & 0x07,
                    data: self.value[1..].to_vec(),
                }
            }
            Some(CiotSmallDataContainerType::Sms) => {
                if first & 0x1F != 0 {
                    return None;
                }
                CiotSmallDataContainerContents::Sms {
                    data: self.value[1..].to_vec(),
                }
            }
            Some(CiotSmallDataContainerType::LocationServicesMessageContainer) => {
                if first & 0x07 != 0 {
                    return None;
                }
                let add_info_len = *self.value.get(1)? as usize;
                if 2 + add_info_len > self.value.len() {
                    return None;
                }
                CiotSmallDataContainerContents::LocationServicesMessageContainer {
                    downlink_data_expected: CiotSmallDataDownlinkDataExpected::from_u8(
                        (first >> 3) & 0x03,
                    ),
                    additional_information: self.value[2..2 + add_info_len].to_vec(),
                    data: self.value[2 + add_info_len..].to_vec(),
                }
            }
            None => return None,
        })
    }

    /// Construct a value from parsed.
    pub fn from_parsed(contents: &CiotSmallDataContainerContents) -> Option<Self> {
        let mut value = Vec::new();
        match contents {
            CiotSmallDataContainerContents::ControlPlaneUserData {
                downlink_data_expected,
                pdu_session_id,
                data,
            } => {
                if matches!(
                    downlink_data_expected,
                    CiotSmallDataDownlinkDataExpected::Reserved
                ) {
                    return None;
                }
                value.push(
                    ((CiotSmallDataContainerType::ControlPlaneUserData as u8) << 5)
                        | ((*downlink_data_expected as u8 & 0x03) << 3)
                        | (*pdu_session_id & 0x07),
                );
                value.extend_from_slice(data);
            }
            CiotSmallDataContainerContents::Sms { data } => {
                value.push((CiotSmallDataContainerType::Sms as u8) << 5);
                value.extend_from_slice(data);
            }
            CiotSmallDataContainerContents::LocationServicesMessageContainer {
                downlink_data_expected,
                additional_information,
                data,
            } => {
                if matches!(
                    downlink_data_expected,
                    CiotSmallDataDownlinkDataExpected::Reserved
                ) {
                    return None;
                }
                value.push(
                    ((CiotSmallDataContainerType::LocationServicesMessageContainer as u8) << 5)
                        | ((*downlink_data_expected as u8 & 0x03) << 3),
                );
                value.push(additional_information.len().try_into().ok()?);
                value.extend_from_slice(additional_information);
                value.extend_from_slice(data);
            }
            CiotSmallDataContainerContents::Unknown {
                data_type_raw: _,
                contents: _,
            } => return None,
        }
        if value.len() > 255 {
            return None;
        }
        Some(Self::new(value))
    }

    /// Strict validation for reserved DDE values, spare bits, and length fields.
    pub fn validate_strict(&self) -> Result<()> {
        if self.value.is_empty() || self.value.len() > 255 {
            return Err(NasError::DecodingError(
                "CIoT small data container length is invalid".into(),
            ));
        }
        let first = self.value[0];
        let data_type =
            CiotSmallDataContainerType::from_u8((first >> 5) & 0x07).ok_or_else(|| {
                NasError::DecodingError("CIoT small data container type is reserved".into())
            })?;
        let dde = CiotSmallDataDownlinkDataExpected::from_u8((first >> 3) & 0x03);
        match data_type {
            CiotSmallDataContainerType::ControlPlaneUserData => {
                if matches!(dde, CiotSmallDataDownlinkDataExpected::Reserved) {
                    return Err(NasError::DecodingError(
                        "CIoT small data container DDE value is reserved".into(),
                    ));
                }
            }
            CiotSmallDataContainerType::Sms => {
                if first & 0x1F != 0 {
                    return Err(NasError::DecodingError(
                        "CIoT SMS container spare bits shall be zero".into(),
                    ));
                }
            }
            CiotSmallDataContainerType::LocationServicesMessageContainer => {
                if matches!(dde, CiotSmallDataDownlinkDataExpected::Reserved) {
                    return Err(NasError::DecodingError(
                        "CIoT small data container DDE value is reserved".into(),
                    ));
                }
                if first & 0x07 != 0 {
                    return Err(NasError::DecodingError(
                        "CIoT LCS container spare bits shall be zero".into(),
                    ));
                }
                let add_info_len = *self.value.get(1).ok_or(NasError::BufferTooShort)? as usize;
                if 2 + add_info_len > self.value.len() {
                    return Err(NasError::BufferTooShort);
                }
            }
        }
        self.parse().ok_or_else(|| {
            NasError::DecodingError("CIoT small data container could not be parsed".into())
        })?;
        Ok(())
    }
}

// ── 9.11.3.88 ProSe relay transaction identity ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Prose relay transaction identity value values.
pub enum ProseRelayTransactionIdentityValue {
    /// Unassigned.
    Unassigned,
    /// Assigned.
    Assigned(u8),
    /// Reserved.
    Reserved,
}

impl NasProseRelayTransactionIdentity {
    /// Return identity raw.
    pub fn identity_raw(&self) -> u8 {
        self.value
    }

    /// Return identity.
    pub fn identity(&self) -> Option<ProseRelayTransactionIdentityValue> {
        Some(match self.value {
            0 => ProseRelayTransactionIdentityValue::Unassigned,
            0xFF => ProseRelayTransactionIdentityValue::Reserved,
            value => ProseRelayTransactionIdentityValue::Assigned(value),
        })
    }

    /// Construct a value from identity.
    pub fn from_identity(identity: ProseRelayTransactionIdentityValue) -> Self {
        let value = match identity {
            ProseRelayTransactionIdentityValue::Unassigned => 0,
            ProseRelayTransactionIdentityValue::Assigned(value) => value,
            ProseRelayTransactionIdentityValue::Reserved => 0xFF,
        };
        Self::new(value)
    }

    /// Construct a value from data.
    pub fn from_data(data: Vec<u8>) -> Self {
        Self::new(data.first().copied().unwrap_or(0))
    }
}

// ── 9.11.3.96 Extended LADN information ────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of extended LADN information entry.
pub struct ExtendedLadnInformationEntry {
    /// DNN.
    pub dnn: NasDnn,
    /// S NSSAI.
    pub s_nssai: NasSNssai,
    /// TAI list.
    pub tai_list: NasFGsTrackingAreaIdentityList,
}

impl NasExtendedLadnInformation {
    /// Return entries.
    pub fn entries(&self) -> Vec<ExtendedLadnInformationEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            let dnn_len = match data.get(pos) {
                Some(length) => *length as usize,
                None => break,
            };
            pos += 1;
            if pos + dnn_len > data.len() {
                break;
            }
            let dnn = NasDnn::new(data[pos..pos + dnn_len].to_vec());
            pos += dnn_len;

            let s_nssai_len = match data.get(pos) {
                Some(length) => *length as usize,
                None => break,
            };
            pos += 1;
            if pos + s_nssai_len > data.len() {
                break;
            }
            let s_nssai = match NasSNssai::from_value(data[pos..pos + s_nssai_len].to_vec()) {
                Some(s_nssai) => s_nssai,
                None => break,
            };
            pos += s_nssai_len;

            let tai_list_len = match data.get(pos) {
                Some(length) => *length as usize,
                None => break,
            };
            pos += 1;
            if pos + tai_list_len > data.len() {
                break;
            }
            let tai_list =
                NasFGsTrackingAreaIdentityList::new(data[pos..pos + tai_list_len].to_vec());
            pos += tai_list_len;

            out.push(ExtendedLadnInformationEntry {
                dnn,
                s_nssai,
                tai_list,
            });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[ExtendedLadnInformationEntry]) -> Option<Self> {
        if entries.len() > 8 {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if entry.dnn.value.len() > 100 {
                return None;
            }
            NasSNssai::from_value(entry.s_nssai.value.clone())?;
            value.push(entry.dnn.value.len().try_into().ok()?);
            value.extend_from_slice(&entry.dnn.value);
            value.push(entry.s_nssai.value.len().try_into().ok()?);
            value.extend_from_slice(&entry.s_nssai.value);
            value.push(entry.tai_list.value.len().try_into().ok()?);
            value.extend_from_slice(&entry.tai_list.value);
        }
        if value.len() > 1784 {
            return None;
        }
        Some(Self::new(value))
    }
}

// ── 9.11.3.98 Type 6 IE container ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Type 6 IE container entry values.
pub enum Type6IeContainerEntry {
    /// Extended LADN information.
    ExtendedLadnInformation(NasExtendedLadnInformation),
    /// S NSSAI location validity information.
    SNssaiLocationValidityInformation(NasSNssaiLocationValidityInformation),
    /// Partially allowed NSSAI.
    PartiallyAllowedNssai(NasPartialNssai),
    /// Partially rejected NSSAI.
    PartiallyRejectedNssai(NasPartialNssai),
}

impl NasType6IeContainer {
    /// Return entries.
    pub fn entries(&self) -> Vec<Type6IeContainerEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        let mut last_iei = 0u8;
        while pos + 3 <= data.len() {
            let iei = data[pos];
            let len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
            pos += 3;
            if pos + len > data.len() {
                break;
            }
            let contents = data[pos..pos + len].to_vec();
            pos += len;
            if iei <= last_iei {
                continue;
            }
            let entry = match iei {
                0x01 => Some(Type6IeContainerEntry::ExtendedLadnInformation(
                    NasExtendedLadnInformation::new(contents),
                )),
                0x02 => Some(Type6IeContainerEntry::SNssaiLocationValidityInformation(
                    NasSNssaiLocationValidityInformation::new(contents),
                )),
                0x03 => Some(Type6IeContainerEntry::PartiallyAllowedNssai(
                    NasPartialNssai::new(contents),
                )),
                0x04 => Some(Type6IeContainerEntry::PartiallyRejectedNssai(
                    NasPartialNssai::new(contents),
                )),
                _ => None,
            };
            if let Some(entry) = entry {
                last_iei = iei;
                out.push(entry);
            }
        }
        out
    }

    /// Construct a non-empty list of unique, ordered container entries.
    pub fn from_entries(entries: &[Type6IeContainerEntry]) -> Option<Self> {
        if entries.is_empty() || entries.len() > 4 {
            return None;
        }
        let entry_iei = |entry: &Type6IeContainerEntry| match entry {
            Type6IeContainerEntry::ExtendedLadnInformation(_) => 0x01,
            Type6IeContainerEntry::SNssaiLocationValidityInformation(_) => 0x02,
            Type6IeContainerEntry::PartiallyAllowedNssai(_) => 0x03,
            Type6IeContainerEntry::PartiallyRejectedNssai(_) => 0x04,
        };
        let mut seen = [false; 5];
        for entry in entries {
            let iei = entry_iei(entry);
            if std::mem::replace(&mut seen[usize::from(iei)], true) {
                return None;
            }
        }
        let mut value = Vec::new();
        for iei in [0x01u8, 0x02, 0x03, 0x04] {
            let Some(entry) = entries.iter().find(|entry| entry_iei(entry) == iei) else {
                continue;
            };
            let contents = match entry {
                Type6IeContainerEntry::ExtendedLadnInformation(ie) => &ie.value,
                Type6IeContainerEntry::SNssaiLocationValidityInformation(ie) => &ie.value,
                Type6IeContainerEntry::PartiallyAllowedNssai(ie)
                | Type6IeContainerEntry::PartiallyRejectedNssai(ie) => &ie.value,
            };
            value.push(iei);
            value.extend_from_slice(&u16::try_from(contents.len()).ok()?.to_be_bytes());
            value.extend_from_slice(contents);
        }
        (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
    }

    /// Whether this is a canonical sender encoding without duplicate containers.
    pub fn is_well_formed(&self) -> bool {
        let entries = self.entries();
        Self::from_entries(&entries).is_some_and(|canonical| canonical.value == self.value)
    }
}

// ── 9.11.3.100 S-NSSAI location validity information ───────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of s NSSAI location validity nr cgi.
pub struct SNssaiLocationValidityNrCgi {
    /// Nr cell identifier.
    pub nr_cell_id: [u8; 5],
    /// PLMN.
    pub plmn: PlmnId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of s NSSAI location validity entry.
pub struct SNssaiLocationValidityEntry {
    /// S NSSAI.
    pub s_nssai: NasSNssai,
    /// Nr cgis.
    pub nr_cgis: Vec<SNssaiLocationValidityNrCgi>,
}

impl NasSNssaiLocationValidityInformation {
    /// Return entries.
    pub fn entries(&self) -> Vec<SNssaiLocationValidityEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() && out.len() < 16 {
            let entry_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if entry_len == 0 || pos + entry_len > data.len() {
                break;
            }
            let entry_end = pos + entry_len;
            let s_nssai_len = data[pos] as usize;
            pos += 1;
            if pos + s_nssai_len > entry_end {
                break;
            }
            let s_nssai = match NasSNssai::from_value(data[pos..pos + s_nssai_len].to_vec()) {
                Some(s_nssai) => s_nssai,
                None => break,
            };
            pos += s_nssai_len;
            if pos + 2 > entry_end {
                break;
            }
            let nr_cgi_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if nr_cgi_count == 0 || nr_cgi_count > 300 {
                break;
            }
            let mut nr_cgis = Vec::with_capacity(nr_cgi_count);
            let mut valid = true;
            for _ in 0..nr_cgi_count {
                if pos + 8 > entry_end {
                    valid = false;
                    break;
                }
                let nr_cell_id = copy_array::<5>(&data[pos..]).unwrap();
                if nr_cell_id[4] & 0x0F != 0 {
                    valid = false;
                    break;
                }
                pos += 5;
                let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                    Some(plmn) => plmn,
                    None => {
                        valid = false;
                        break;
                    }
                };
                pos += 3;
                nr_cgis.push(SNssaiLocationValidityNrCgi { nr_cell_id, plmn });
            }
            if !valid {
                break;
            }
            pos = entry_end;
            out.push(SNssaiLocationValidityEntry { s_nssai, nr_cgis });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[SNssaiLocationValidityEntry]) -> Option<Self> {
        if !(1..=16).contains(&entries.len()) {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            if entry.nr_cgis.is_empty() || entry.nr_cgis.len() > 300 {
                return None;
            }
            let mut body = Vec::new();
            body.push(entry.s_nssai.value.len().try_into().ok()?);
            body.extend_from_slice(&entry.s_nssai.value);
            body.extend_from_slice(&(entry.nr_cgis.len() as u16).to_be_bytes());
            for nr_cgi in &entry.nr_cgis {
                if nr_cgi.nr_cell_id[4] & 0x0f != 0 {
                    return None;
                }
                body.extend_from_slice(&nr_cgi.nr_cell_id);
                body.extend_from_slice(&nr_cgi.plmn.try_to_tbcd()?);
            }
            if body.len() > u16::MAX as usize {
                return None;
            }
            value.extend_from_slice(&(body.len() as u16).to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= 38608).then(|| Self::new(value))
    }

    /// Whether this is a canonical sender encoding.
    pub fn is_well_formed(&self) -> bool {
        let entries = self.entries();
        Self::from_entries(&entries).is_some_and(|canonical| canonical.value == self.value)
    }
}

// ── 9.11.3.101 S-NSSAI time validity information ───────────────────────────

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
/// S NSSAI time window recurrence pattern values.
pub enum SNssaiTimeWindowRecurrencePattern {
    /// Everyday.
    Everyday = 0,
    /// Every weekday.
    EveryWeekday = 1,
    /// Every week.
    EveryWeek = 2,
    /// Every two weeks.
    EveryTwoWeeks = 3,
    /// Every month absolute.
    EveryMonthAbsolute = 4,
    /// Every month relative.
    EveryMonthRelative = 5,
    /// Every quarter absolute.
    EveryQuarterAbsolute = 6,
    /// Every quarter relative.
    EveryQuarterRelative = 7,
    /// Every six months absolute.
    EverySixMonthsAbsolute = 8,
    /// Every six months relative.
    EverySixMonthsRelative = 9,
}

impl SNssaiTimeWindowRecurrencePattern {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0F {
            0 => Some(Self::Everyday),
            1 => Some(Self::EveryWeekday),
            2 => Some(Self::EveryWeek),
            3 => Some(Self::EveryTwoWeeks),
            4 => Some(Self::EveryMonthAbsolute),
            5 => Some(Self::EveryMonthRelative),
            6 => Some(Self::EveryQuarterAbsolute),
            7 => Some(Self::EveryQuarterRelative),
            8 => Some(Self::EverySixMonthsAbsolute),
            9 => Some(Self::EverySixMonthsRelative),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of s NSSAI time window.
pub struct SNssaiTimeWindow {
    /// Start time.
    pub start_time: [u8; 8],
    /// Stop time.
    pub stop_time: [u8; 8],
    /// Recurrence pattern.
    pub recurrence_pattern: Option<SNssaiTimeWindowRecurrencePattern>,
    /// Recurrence end time.
    pub recurrence_end_time: Option<[u8; 8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of s NSSAI time validity entry.
pub struct SNssaiTimeValidityEntry {
    /// S NSSAI.
    pub s_nssai: NasSNssai,
    /// Time windows.
    pub time_windows: Vec<SNssaiTimeWindow>,
}

impl NasSNssaiTimeValidityInformation {
    /// Return entries.
    pub fn entries(&self) -> Vec<SNssaiTimeValidityEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 2 <= data.len() {
            let entry_len = data[pos] as usize;
            pos += 1;
            if entry_len == 0 || pos + entry_len > data.len() {
                break;
            }
            let entry_end = pos + entry_len;
            let s_nssai_len = data[pos] as usize;
            pos += 1;
            if pos + s_nssai_len > entry_end {
                break;
            }
            let s_nssai = NasSNssai::new(data[pos..pos + s_nssai_len].to_vec());
            pos += s_nssai_len;
            let time_info_len = match data.get(pos) {
                Some(length) => *length as usize,
                None => break,
            };
            pos += 1;
            if pos + time_info_len > entry_end {
                break;
            }
            let time_info_end = pos + time_info_len;
            let mut time_windows = Vec::new();
            while pos < time_info_end {
                let time_window_len = match data.get(pos) {
                    Some(length) => *length as usize,
                    None => break,
                };
                pos += 1;
                if !matches!(time_window_len, 16 | 17 | 25) || pos + time_window_len > time_info_end
                {
                    break;
                }
                let time_window_end = pos + time_window_len;
                let start_time = copy_array::<8>(&data[pos..]).unwrap();
                pos += 8;
                let stop_time = copy_array::<8>(&data[pos..]).unwrap();
                pos += 8;

                let recurrence_pattern = if time_window_len >= 17 {
                    let pattern = SNssaiTimeWindowRecurrencePattern::from_u8(data[pos] & 0x0F);
                    pos += 1;
                    match pattern {
                        Some(pattern) => Some(pattern),
                        None => break,
                    }
                } else {
                    None
                };

                let recurrence_end_time = if time_window_len == 25 {
                    let value = copy_array::<8>(&data[pos..]).unwrap();
                    Some(value)
                } else {
                    None
                };

                time_windows.push(SNssaiTimeWindow {
                    start_time,
                    stop_time,
                    recurrence_pattern,
                    recurrence_end_time,
                });
                pos = time_window_end;
            }
            pos = entry_end;
            out.push(SNssaiTimeValidityEntry {
                s_nssai,
                time_windows,
            });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[SNssaiTimeValidityEntry]) -> Option<Self> {
        if entries.len() > 16 {
            return None;
        }
        let mut value = Vec::new();
        for entry in entries {
            let mut body = Vec::new();
            NasSNssai::from_value(entry.s_nssai.value.clone())?;
            body.push(entry.s_nssai.value.len().try_into().ok()?);
            body.extend_from_slice(&entry.s_nssai.value);

            let mut time_info = Vec::new();
            for time_window in &entry.time_windows {
                let mut time_window_len = 16u8;
                if time_window.recurrence_pattern.is_some() {
                    time_window_len = 17;
                }
                if time_window.recurrence_end_time.is_some() {
                    time_window.recurrence_pattern?;
                    time_window_len = 25;
                }
                time_info.push(time_window_len);
                time_info.extend_from_slice(&time_window.start_time);
                time_info.extend_from_slice(&time_window.stop_time);
                if let Some(recurrence_pattern) = time_window.recurrence_pattern {
                    time_info.push(recurrence_pattern as u8);
                }
                if let Some(recurrence_end_time) = time_window.recurrence_end_time {
                    time_info.extend_from_slice(&recurrence_end_time);
                }
            }

            body.push(time_info.len().try_into().ok()?);
            body.extend_from_slice(&time_info);
            value.push(body.len().try_into().ok()?);
            value.extend_from_slice(&body);
        }
        Some(Self::new(value))
    }
}

// ── 9.11.3.93 N3IWF identifier ──────────────────────────────────────────────

/// N3IWF identifier address type per TS 24.501 §9.11.3.93.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum N3iwfIdentifierType {
    /// IPv4 address.
    Ipv4 = 0x01,
    /// IPv6 address.
    Ipv6 = 0x02,
    /// Both IPv4 and IPv6 addresses.
    Ipv4v6 = 0x03,
    /// FQDN.
    Fqdn = 0x04,
}

impl N3iwfIdentifierType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Ipv4),
            0x02 => Some(Self::Ipv6),
            0x03 => Some(Self::Ipv4v6),
            0x04 => Some(Self::Fqdn),
            _ => None,
        }
    }
}

/// One decoded N3IWF identifier value per TS 24.501 §9.11.3.93.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum N3iwfAddress {
    /// IPv4 (4 bytes).
    Ipv4([u8; 4]),
    /// IPv6 (16 bytes).
    Ipv6([u8; 16]),
    /// Combined IPv4 + IPv6 addresses.
    Ipv4v6 {
        /// IPv4 address octets.
        ipv4: [u8; 4],
        /// IPv6 address octets.
        ipv6: [u8; 16],
    },
    /// FQDN raw label-encoded bytes (matches the DNN/APN string encoding).
    Fqdn(Vec<u8>),
}

impl NasN3iwfIdentifier {
    /// Decoded address-type discriminant (octet 1).
    pub fn id_type(&self) -> Option<N3iwfIdentifierType> {
        self.value
            .first()
            .and_then(|b| N3iwfIdentifierType::from_u8(*b))
    }

    /// Parse the address payload starting at octet 2.
    pub fn address(&self) -> Option<N3iwfAddress> {
        let id_type = self.id_type()?;
        let body = self.value.get(1..)?;
        match id_type {
            N3iwfIdentifierType::Ipv4 => {
                if body.len() != 4 {
                    return None;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(body);
                Some(N3iwfAddress::Ipv4(ip))
            }
            N3iwfIdentifierType::Ipv6 => {
                if body.len() != 16 {
                    return None;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(body);
                Some(N3iwfAddress::Ipv6(ip))
            }
            N3iwfIdentifierType::Ipv4v6 => {
                if body.len() != 20 {
                    return None;
                }
                let mut ipv4 = [0u8; 4];
                ipv4.copy_from_slice(&body[..4]);
                let mut ipv6 = [0u8; 16];
                ipv6.copy_from_slice(&body[4..20]);
                Some(N3iwfAddress::Ipv4v6 { ipv4, ipv6 })
            }
            N3iwfIdentifierType::Fqdn => Some(N3iwfAddress::Fqdn(body.to_vec())),
        }
    }

    /// Build from a typed address.
    pub fn from_address(addr: &N3iwfAddress) -> Self {
        let mut value = Vec::new();
        match addr {
            N3iwfAddress::Ipv4(ip) => {
                value.push(N3iwfIdentifierType::Ipv4 as u8);
                value.extend_from_slice(ip);
            }
            N3iwfAddress::Ipv6(ip) => {
                value.push(N3iwfIdentifierType::Ipv6 as u8);
                value.extend_from_slice(ip);
            }
            N3iwfAddress::Ipv4v6 { ipv4, ipv6 } => {
                value.push(N3iwfIdentifierType::Ipv4v6 as u8);
                value.extend_from_slice(ipv4);
                value.extend_from_slice(ipv6);
            }
            N3iwfAddress::Fqdn(bytes) => {
                value.push(N3iwfIdentifierType::Fqdn as u8);
                value.extend_from_slice(bytes);
            }
        }
        Self::new(value)
    }
}

// ── 9.11.3.94 TNAN information ──────────────────────────────────────────────

impl NasTnanInformation {
    fn encode_value(tngf_id: Option<&[u8]>, ssid: Option<&[u8]>) -> Vec<u8> {
        assert!(
            tngf_id
                .map(|value| value.len() <= u8::MAX as usize)
                .unwrap_or(true),
            "TNGF ID length exceeds one-octet length field"
        );
        assert!(
            ssid.map(|value| value.len() <= 32).unwrap_or(true),
            "SSID length must be at most 32 octets"
        );
        let mut header: u8 = 0;
        if tngf_id.is_some() {
            header |= 0x01;
        }
        if ssid.is_some() {
            header |= 0x02;
        }
        let mut value = vec![header];
        if let Some(t) = tngf_id {
            value.push(t.len() as u8);
            value.extend_from_slice(t);
        }
        if let Some(s) = ssid {
            value.push(s.len() as u8);
            value.extend_from_slice(s);
        }
        value
    }

    fn first(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// TNGF-ID indicator (bit 1, mask 0x01) — when true, a TNGF identifier is present.
    pub fn tngf_id_indicator(&self) -> bool {
        self.first() & 0x01 != 0
    }

    /// SSID indicator (bit 2, mask 0x02) — when true, an SSID is present.
    pub fn ssid_indicator(&self) -> bool {
        self.first() & 0x02 != 0
    }

    /// Whether spare bits 3-8 of octet 3 are zero.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.first() & !0x03 == 0
    }

    /// Decoded TNGF identifier bytes, if present.
    pub fn tngf_id(&self) -> Option<&[u8]> {
        if !self.spare_bits_are_zero() {
            return None;
        }
        if !self.tngf_id_indicator() || self.value.len() < 3 {
            return None;
        }
        let len = self.value[1] as usize;
        let start = 2;
        if start + len > self.value.len() {
            return None;
        }
        Some(&self.value[start..start + len])
    }

    /// Decoded SSID bytes, if present.
    pub fn ssid(&self) -> Option<&[u8]> {
        if !self.spare_bits_are_zero() {
            return None;
        }
        if !self.ssid_indicator() {
            return None;
        }
        // Skip the TNGF block (if any) before reading the SSID block.
        let mut pos = 1usize;
        if self.tngf_id_indicator() {
            if pos >= self.value.len() {
                return None;
            }
            let len = self.value[pos] as usize;
            pos += 1 + len;
        }
        if pos + 1 > self.value.len() {
            return None;
        }
        let ssid_len = self.value[pos] as usize;
        pos += 1;
        if pos + ssid_len > self.value.len() {
            return None;
        }
        if ssid_len > 32 {
            return None;
        }
        Some(&self.value[pos..pos + ssid_len])
    }

    /// Replace the optional TNGF identifier subfield.
    pub fn set_tngf_id(&mut self, tngf_id: Option<&[u8]>) {
        let ssid = self.ssid().map(|value| value.to_vec());
        self.value = Self::encode_value(tngf_id, ssid.as_deref());
        self.length = self.value.len() as _;
    }

    /// Builder-style TNGF identifier setter.
    pub fn with_tngf_id(mut self, tngf_id: Option<&[u8]>) -> Self {
        self.set_tngf_id(tngf_id);
        self
    }

    /// Replace the optional SSID subfield.
    pub fn set_ssid(&mut self, ssid: Option<&[u8]>) {
        let tngf_id = self.tngf_id().map(|value| value.to_vec());
        self.value = Self::encode_value(tngf_id.as_deref(), ssid);
        self.length = self.value.len() as _;
    }

    /// Builder-style SSID setter.
    pub fn with_ssid(mut self, ssid: Option<&[u8]>) -> Self {
        self.set_ssid(ssid);
        self
    }

    /// Build a TNAN information IE containing only the TNGF identifier.
    pub fn from_tngf_id(tngf_id: &[u8]) -> Self {
        Self::new(Self::encode_value(Some(tngf_id), None))
    }

    /// Build a TNAN information IE containing only the SSID.
    pub fn from_ssid(ssid: &[u8]) -> Self {
        Self::new(Self::encode_value(None, Some(ssid)))
    }
}

// ── 9.11.3.95 RAN timing synchronisation ────────────────────────────────────

impl NasRanTimingSynchronization {
    /// RECREQ — RAN timing recreation request bit (bit 1, mask 0x01).
    pub fn recreation_request(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from recreation request.
    pub fn from_recreation_request(req: bool) -> Self {
        Self::new(vec![if req { 0x01 } else { 0x00 }])
    }
}

// ── 9.11.3.99 Non-3GPP access path switching indication ─────────────────────

impl NasNon3GppAccessPathSwitchingIndication {
    /// NAPS — Non-3GPP Access Path Switch (bit 1, mask 0x01).
    pub fn naps(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from naps.
    pub fn from_naps(naps: bool) -> Self {
        Self::new(vec![if naps { 0x01 } else { 0x00 }])
    }
}

// ── 9.11.3.102 Non-3GPP path switching information ──────────────────────────

impl NasNon3GppPathSwitchingInformation {
    /// NSONR — Non-3GPP-side Selective ONR (bit 1, mask 0x01).
    pub fn nsonr(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from nsonr.
    pub fn from_nsonr(nsonr: bool) -> Self {
        Self::new(vec![if nsonr { 0x01 } else { 0x00 }])
    }
}

// ── 9.11.3.104 AUN3 indication ──────────────────────────────────────────────

impl NasAun3Indication {
    /// AUN3REG — AUN3 device registration indication (bit 1, mask 0x01).
    pub fn aun3reg(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from aun 3 reg.
    pub fn from_aun3reg(aun3reg: bool) -> Self {
        Self::new(vec![if aun3reg { 0x01 } else { 0x00 }])
    }
}

// ── 9.11.3.105 Feature authorization indication ─────────────────────────────

/// MBSRAI — MBS receiver authorization indicator per TS 24.501 §9.11.3.105.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum FeatureAuthMbsraiValue {
    /// 0 — no information.
    NoInformation = 0,
    /// 1 — not authorized to operate as MBSR but allowed to operate as a UE.
    NotAuthorizedAsMbsrAllowedAsUe = 1,
    /// 2 — authorized to operate as MBSR.
    AuthorizedAsMbsr = 2,
}

impl FeatureAuthMbsraiValue {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0 => Some(Self::NoInformation),
            1 => Some(Self::NotAuthorizedAsMbsrAllowedAsUe),
            2 => Some(Self::AuthorizedAsMbsr),
            _ => None,
        }
    }
}

impl NasFeatureAuthorizationIndication {
    fn first(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// HPASE semantic value: true means high-priority access UEs are exempt from restrictions
    /// or the network does not support the operator policy.
    pub fn hpase(&self) -> bool {
        !self.high_priority_access_not_exempt()
    }

    /// Raw HPASE bit: true means high-priority access UEs are not exempt.
    pub fn high_priority_access_not_exempt(&self) -> bool {
        (self.first() >> 2) & 0x01 != 0
    }

    /// MBSRAI — MBS receiver authorization indicator (bits 1-2, mask 0x03).
    pub fn mbsrai(&self) -> Option<FeatureAuthMbsraiValue> {
        FeatureAuthMbsraiValue::from_u8(self.first() & 0x03)
    }

    /// Raw MBSRAI value.
    pub fn mbsrai_raw(&self) -> u8 {
        self.first() & 0x03
    }

    /// Construct a value from flags.
    pub fn from_flags(hpase: bool, mbsrai: FeatureAuthMbsraiValue) -> Self {
        let mut b = mbsrai as u8 & 0x03;
        if !hpase {
            b |= 0x04;
        }
        Self::new(vec![b])
    }

    /// Construct a value from high priority access not exempt.
    pub fn from_high_priority_access_not_exempt(
        not_exempt: bool,
        mbsrai: FeatureAuthMbsraiValue,
    ) -> Self {
        let mut b = mbsrai as u8 & 0x03;
        if not_exempt {
            b |= 0x04;
        }
        Self::new(vec![b])
    }
}

// ── 9.11.3.106 Payload container information ───────────────────────────────

impl NasPayloadContainerInformation {
    /// PRU — payload container related to PRU (bit 1, mask 0x01).
    pub fn pru(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from pru.
    pub fn from_pru(pru: bool) -> Self {
        Self::new(if pru { 0x01 } else { 0x00 })
    }
}

// ── 9.11.3.107 AUN3 device security key ────────────────────────────────────

/// ASKT — AUN3 Security Key Type per TS 24.501 §9.11.3.107.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Aun3DeviceSecurityKeyType {
    /// 0 — Master session key.
    MasterSessionKey = 0,
    /// 1 — K_WAGF key.
    KWagfKey = 1,
}

impl Aun3DeviceSecurityKeyType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x03 {
            0 => Some(Self::MasterSessionKey),
            1 => Some(Self::KWagfKey),
            _ => Some(Self::MasterSessionKey),
        }
    }

    /// Decode a value from a non-reserved wire octet.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x03 {
            0 => Some(Self::MasterSessionKey),
            1 => Some(Self::KWagfKey),
            _ => None,
        }
    }
}

impl NasAun3DeviceSecurityKey {
    /// Decoded ASKT (octet 1, bits 1-2, mask 0x03).
    pub fn askt(&self) -> Option<Aun3DeviceSecurityKeyType> {
        self.value
            .first()
            .and_then(|b| Aun3DeviceSecurityKeyType::from_u8(*b))
    }

    /// Key length (octet 2).
    pub fn key_length(&self) -> Option<u8> {
        self.value.get(1).copied()
    }

    /// Key bytes (octets 3..3+key_length).
    pub fn key(&self) -> Option<&[u8]> {
        let len = self.key_length()? as usize;
        if 2 + len > self.value.len() {
            return None;
        }
        Some(&self.value[2..2 + len])
    }

    /// Build from typed fields.
    pub fn from_typed(askt: Aun3DeviceSecurityKeyType, key: &[u8]) -> Self {
        Self::try_from_typed(askt, key)
            .expect("AUN3 device security key length must be in 32..=253 octets")
    }

    /// Fallible builder from typed fields.
    pub fn try_from_typed(askt: Aun3DeviceSecurityKeyType, key: &[u8]) -> Result<Self> {
        if !(32..=253).contains(&key.len()) {
            return Err(NasError::EncodingError(format!(
                "AUN3 device security key length {} is outside 32..=253",
                key.len()
            )));
        }
        let mut value = Vec::with_capacity(2 + key.len());
        value.push(askt as u8 & 0x03);
        value.push(key.len() as u8);
        value.extend_from_slice(key);
        Ok(Self::new(value))
    }
}

// ── 9.11.3.108 On-demand NSSAI ──────────────────────────────────────────────

/// One on-demand S-NSSAI entry per TS 24.501 §9.11.3.108.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OnDemandNssaiEntry {
    /// S-NSSAI value bytes.
    pub s_nssai: Vec<u8>,
    /// Optional slice deregistration inactivity timer value part (3 octets).
    pub slice_dereg_inactivity_timer: Option<[u8; 3]>,
}

impl NasOnDemandNssai {
    /// Parse the IE per TS 24.501 §9.11.3.108.
    pub fn entries(&self) -> Vec<OnDemandNssaiEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() && out.len() < 16 {
            let start = pos;
            let entry_len = data[pos] as usize;
            pos += 1;
            if entry_len == 0 || start + 1 + entry_len > data.len() {
                break;
            }
            let entry_end = start + 1 + entry_len;
            let s_nssai_len = data[pos] as usize;
            pos += 1;
            if pos + s_nssai_len > entry_end {
                break;
            }
            let s_nssai = data[pos..pos + s_nssai_len].to_vec();
            if NasSNssai::from_value(s_nssai.clone()).is_none() {
                break;
            }
            pos += s_nssai_len;
            let timer = match entry_end - pos {
                0 => None,
                3 => {
                    let t = [data[pos], data[pos + 1], data[pos + 2]];
                    Some(t)
                }
                _ => break,
            };
            out.push(OnDemandNssaiEntry {
                s_nssai,
                slice_dereg_inactivity_timer: timer,
            });
            pos = entry_end;
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[OnDemandNssaiEntry]) -> Self {
        Self::try_from_entries(entries)
            .expect("On-demand NSSAI entries must follow the TS 24.501 wire layout")
    }

    /// Return try from entries.
    pub fn try_from_entries(entries: &[OnDemandNssaiEntry]) -> Result<Self> {
        if entries.len() > 16 {
            return Err(NasError::EncodingError(
                "On-demand NSSAI shall not contain more than 16 entries".into(),
            ));
        }
        let mut value = Vec::new();
        for e in entries {
            if NasSNssai::from_value(e.s_nssai.clone()).is_none() {
                return Err(NasError::EncodingError(
                    "on-demand S-NSSAI must use a valid S-NSSAI value length".into(),
                ));
            }
            let body_len = 1
                + e.s_nssai.len()
                + if e.slice_dereg_inactivity_timer.is_some() {
                    3
                } else {
                    0
                };
            if body_len > u8::MAX as usize {
                return Err(NasError::EncodingError(
                    "on-demand NSSAI entry too long".into(),
                ));
            }
            value.push(body_len as u8);
            value.push(e.s_nssai.len() as u8);
            value.extend_from_slice(&e.s_nssai);
            if let Some(t) = e.slice_dereg_inactivity_timer {
                value.extend_from_slice(&t);
            }
        }
        if value.len() > 208 {
            return Err(NasError::EncodingError(
                "On-demand NSSAI contents exceed TS 24.501 §9.11.3.108 maximum length".into(),
            ));
        }
        Ok(Self::new(value))
    }
}

// ── 9.11.3.109 Extended 5GMM cause ──────────────────────────────────────────

impl NasExtendedFGmmCause {
    /// SAT_NR — Satellite NG-RAN allowed in PLMN (bit 1, mask 0x01).
    pub fn satellite_nr_allowed(&self) -> bool {
        !self.satellite_nr_not_allowed()
    }

    /// Raw Sat-NR bit: true means satellite NG-RAN is not allowed in the PLMN.
    pub fn satellite_nr_not_allowed(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Construct a value from satellite nr allowed.
    pub fn from_satellite_nr_allowed(allowed: bool) -> Self {
        Self::new(vec![if allowed { 0x00 } else { 0x01 }])
    }

    /// Construct a value from satellite nr not allowed.
    pub fn from_satellite_nr_not_allowed(not_allowed: bool) -> Self {
        Self::new(vec![if not_allowed { 0x01 } else { 0x00 }])
    }

    /// Whether spare bits 2-8 are zero.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value.first().copied().unwrap_or(0) & !0x01 == 0
    }

    /// Strict validation for exact length and spare bits.
    pub fn validate_strict(&self) -> Result<()> {
        if self.value.len() != 1 {
            return Err(NasError::DecodingError(
                "Extended 5GMM cause must be exactly one octet".into(),
            ));
        }
        if !self.spare_bits_are_zero() {
            return Err(NasError::DecodingError(
                "Extended 5GMM cause spare bits shall be zero".into(),
            ));
        }
        Ok(())
    }
}

// ── 9.11.3.111 LP-WUSPS assistance information ──────────────────────────────

/// LP-WUSPS assistance information element type per TS 24.501 §9.11.3.111.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum LpWuspsAssistanceInformationType {
    /// 0 — LP-WUSPS paging subgroup ID.
    PagingSubgroupId = 0,
    /// 1 — UE paging probability information.
    UePagingProbability = 1,
}

impl LpWuspsAssistanceInformationType {
    /// Decode a value from its wire octet.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PagingSubgroupId),
            1 => Some(Self::UePagingProbability),
            _ => None,
        }
    }
}

impl NasLpWuspsAssistanceInformation {
    fn first_octet(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// Type field (octet 1 bits 8-6) — see [`LpWuspsAssistanceInformationType`].
    pub fn info_type(&self) -> Option<LpWuspsAssistanceInformationType> {
        LpWuspsAssistanceInformationType::from_u8((self.first_octet() >> 5) & 0x07)
    }

    /// Raw type value (octet 1 bits 8-6).
    pub fn info_type_raw(&self) -> u8 {
        (self.first_octet() >> 5) & 0x07
    }

    /// Paging subgroup identifier value (octet 1 bits 5-1).
    pub fn paging_subgroup_id(&self) -> Option<u8> {
        matches!(
            self.info_type(),
            Some(LpWuspsAssistanceInformationType::PagingSubgroupId)
        )
        .then(|| {
            let value = self.first_octet() & 0x1F;
            (value <= 30).then_some(value)
        })
        .flatten()
    }

    /// UE paging probability information value (octet 1 bits 5-1).
    pub fn ue_paging_probability_information(&self) -> Option<u8> {
        matches!(
            self.info_type(),
            Some(LpWuspsAssistanceInformationType::UePagingProbability)
        )
        .then_some((self.first_octet() & 0x1F).min(20))
    }

    /// Reserved payload bits (octet 1 bits 5-1).
    pub fn reserved_bits(&self) -> Option<u8> {
        (self.info_type_raw() >= 2).then_some(self.first_octet() & 0x1F)
    }

    /// Construct a value from paging subgroup identifier.
    pub fn from_paging_subgroup_id(paging_subgroup_id: u8) -> Self {
        assert!(
            paging_subgroup_id <= 30,
            "LP-WUSPS paging subgroup ID must be in 0..=30"
        );
        Self::new(vec![paging_subgroup_id & 0x1F])
    }

    /// Return try from paging subgroup identifier.
    pub fn try_from_paging_subgroup_id(paging_subgroup_id: u8) -> Result<Self> {
        if paging_subgroup_id > 30 {
            return Err(NasError::EncodingError(
                "LP-WUSPS paging subgroup ID must be in 0..=30".into(),
            ));
        }
        Ok(Self::new(vec![paging_subgroup_id & 0x1F]))
    }

    /// Construct a value from UE paging probability information.
    pub fn from_ue_paging_probability_information(probability_information: u8) -> Self {
        assert!(
            probability_information <= 20,
            "LP-WUSPS UE paging probability information must be in 0..=20"
        );
        Self::new(vec![(1 << 5) | (probability_information & 0x1F)])
    }

    /// Return try from UE paging probability information.
    pub fn try_from_ue_paging_probability_information(probability_information: u8) -> Result<Self> {
        if probability_information > 20 {
            return Err(NasError::EncodingError(
                "LP-WUSPS UE paging probability information must be in 0..=20".into(),
            ));
        }
        Ok(Self::new(vec![(1 << 5) | (probability_information & 0x1F)]))
    }
}

// ── 9.11.3.112 LP-WUS status ────────────────────────────────────────────────

impl NasLpWusStatus {
    /// LP-WUS disabled flag (octet 1, bit 1). `false` means LP-WUS enabled, `true` means disabled.
    pub fn lp_wus_disabled(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Construct a value from disabled.
    pub fn from_disabled(disabled: bool) -> Self {
        Self::new(if disabled { 0x01 } else { 0x00 })
    }

    /// Whether spare bits 2-4 of the TV-1 value are zero.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value & !0x01 == 0
    }

    /// Strict spare-bit validation for TS 24.501 §9.11.3.112.
    pub fn validate_strict(&self) -> Result<()> {
        if !self.spare_bits_are_zero() {
            return Err(NasError::DecodingError(
                "LP-WUS status spare bits shall be zero".into(),
            ));
        }
        Ok(())
    }
}

// ── 9.11.3.103 Partial NSSAI ────────────────────────────────────────────────

/// One partial-NSSAI entry per TS 24.501 §9.11.3.103.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PartialNssaiEntry {
    /// S-NSSAI value bytes (length-prefixed in the wire format).
    pub s_nssai: Vec<u8>,
    /// 5GS Tracking Area Identity list value bytes (length-prefixed in the wire format,
    /// may be empty).
    pub tai_list: Vec<u8>,
}

impl NasPartialNssai {
    /// Return entries.
    pub fn entries(&self) -> Vec<PartialNssaiEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() && out.len() < 7 {
            let s_len = data[pos] as usize;
            pos += 1;
            if pos + s_len > data.len() {
                break;
            }
            let s_nssai = data[pos..pos + s_len].to_vec();
            if NasSNssai::from_value(s_nssai.clone()).is_none() {
                break;
            }
            pos += s_len;
            if pos >= data.len() {
                break;
            }
            let t_len = data[pos] as usize;
            pos += 1;
            if pos + t_len > data.len() {
                break;
            }
            let tai_list = data[pos..pos + t_len].to_vec();
            pos += t_len;
            out.push(PartialNssaiEntry { s_nssai, tai_list });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[PartialNssaiEntry]) -> Self {
        Self::try_from_entries(entries)
            .expect("partial NSSAI entries must follow the TS 24.501 wire layout")
    }

    /// Return try from entries.
    pub fn try_from_entries(entries: &[PartialNssaiEntry]) -> Result<Self> {
        if entries.len() > 7 {
            return Err(NasError::EncodingError(
                "partial NSSAI can contain at most seven S-NSSAIs".into(),
            ));
        }
        let mut value = Vec::new();
        for e in entries {
            if NasSNssai::from_value(e.s_nssai.clone()).is_none() {
                return Err(NasError::EncodingError(
                    "partial NSSAI entry has invalid S-NSSAI length".into(),
                ));
            }
            if e.s_nssai.len() > u8::MAX as usize || e.tai_list.len() > u8::MAX as usize {
                return Err(NasError::EncodingError(
                    "partial NSSAI entry length exceeds one-octet length field".into(),
                ));
            }
            validate_partial_nssai_tai_list(&e.tai_list)?;
            value.push(e.s_nssai.len() as u8);
            value.extend_from_slice(&e.s_nssai);
            value.push(e.tai_list.len() as u8);
            value.extend_from_slice(&e.tai_list);
        }
        Ok(Self::new(value))
    }
}

fn validate_partial_nssai_tai_list(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    let tai_list = NasFGsTrackingAreaIdentityList::new(data.to_vec());
    let entries = tai_list.parse();
    if entries.is_empty() {
        return Err(NasError::EncodingError(
            "partial NSSAI TAI list has invalid 5GS tracking area identity list contents".into(),
        ));
    }

    let tai_count: usize = entries
        .iter()
        .map(|entry| entry.tracking_area_identities().len())
        .sum();
    if tai_count > 15 {
        return Err(NasError::EncodingError(
            "partial NSSAI TAI list can contain at most fifteen tracking areas".into(),
        ));
    }

    let Some(rebuilt) = NasFGsTrackingAreaIdentityList::try_from_entries(&entries) else {
        return Err(NasError::EncodingError(
            "partial NSSAI TAI list has invalid entries".into(),
        ));
    };
    if rebuilt.value != data {
        return Err(NasError::EncodingError(
            "partial NSSAI TAI list has trailing or malformed contents".into(),
        ));
    }

    Ok(())
}

// ── 9.11.3.97 Alternative NSSAI ─────────────────────────────────────────────

/// One alternative-NSSAI entry per TS 24.501 §9.11.3.97 — pairs an S-NSSAI to be
/// replaced with the alternative S-NSSAI value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AlternativeNssaiEntry {
    /// S-NSSAI value bytes that should be replaced.
    pub replaced: Vec<u8>,
    /// Alternative S-NSSAI value bytes.
    pub alternative: Vec<u8>,
}

impl NasAlternativeNssai {
    /// Return entries.
    pub fn entries(&self) -> Vec<AlternativeNssaiEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() && out.len() < 8 {
            if pos >= data.len() {
                break;
            }
            let r_len = data[pos] as usize;
            pos += 1;
            if pos + r_len > data.len() {
                break;
            }
            let replaced = data[pos..pos + r_len].to_vec();
            if NasSNssai::from_value(replaced.clone()).is_none() {
                break;
            }
            pos += r_len;
            if pos >= data.len() {
                break;
            }
            let a_len = data[pos] as usize;
            pos += 1;
            if pos + a_len > data.len() {
                break;
            }
            let alternative = data[pos..pos + a_len].to_vec();
            if NasSNssai::from_value(alternative.clone()).is_none() {
                break;
            }
            pos += a_len;
            out.push(AlternativeNssaiEntry {
                replaced,
                alternative,
            });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[AlternativeNssaiEntry]) -> Self {
        Self::try_from_entries(entries)
            .expect("alternative NSSAI entries must follow the TS 24.501 wire layout")
    }

    /// Return try from entries.
    pub fn try_from_entries(entries: &[AlternativeNssaiEntry]) -> Result<Self> {
        if entries.len() > 8 {
            return Err(NasError::EncodingError(
                "alternative NSSAI can contain at most eight entries".into(),
            ));
        }
        let mut value = Vec::new();
        for e in entries {
            if NasSNssai::from_value(e.replaced.clone()).is_none()
                || NasSNssai::from_value(e.alternative.clone()).is_none()
            {
                return Err(NasError::EncodingError(
                    "alternative NSSAI entry has invalid S-NSSAI length".into(),
                ));
            }
            if e.replaced.len() > u8::MAX as usize || e.alternative.len() > u8::MAX as usize {
                return Err(NasError::EncodingError(
                    "alternative NSSAI entry length exceeds one-octet length field".into(),
                ));
            }
            value.push(e.replaced.len() as u8);
            value.extend_from_slice(&e.replaced);
            value.push(e.alternative.len() as u8);
            value.extend_from_slice(&e.alternative);
        }
        if value.len() > 144 {
            return Err(NasError::EncodingError(
                "alternative NSSAI contents exceed the 144-octet maximum".into(),
            ));
        }
        Ok(Self::new(value))
    }
}

// ── 9.11.3.92 SNPN list ─────────────────────────────────────────────────────

/// One SNPN list entry per TS 24.501 §9.11.3.92 — a PLMN identifier paired with
/// a 6-byte Network Identifier (NID) using hexadecimal digits (`0..9`, `a..f`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SnpnListEntry {
    /// PLMN identifier.
    pub plmn: PlmnId,
    /// Network identifier value as six raw octets.
    pub nid: [u8; 6],
}

impl NasSnpnList {
    /// Return entries.
    pub fn entries(&self) -> Vec<SnpnListEntry> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 9 <= data.len() {
            let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                Some(p) => p,
                None => break,
            };
            pos += 3;
            let mut nid = [0u8; 6];
            nid.copy_from_slice(&data[pos..pos + 6]);
            pos += 6;
            out.push(SnpnListEntry { plmn, nid });
        }
        out
    }

    /// Construct a value from entries.
    pub fn from_entries(entries: &[SnpnListEntry]) -> Self {
        let mut value = Vec::with_capacity(entries.len() * 9);
        for e in entries {
            value.extend_from_slice(&e.plmn.to_tbcd());
            value.extend_from_slice(&e.nid);
        }
        Self::new(value)
    }
}

// ── 9.11.3.89 Relay key request parameters ──────────────────────────────────

/// Decoded view of [`NasRelayKeyRequestParameters`] per TS 24.501 §9.11.3.89.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelayKeyRequestParameters {
    /// Relay service code (3 bytes, big-endian).
    pub relay_service_code: u32,
    /// Nonce 1 (16 bytes).
    pub nonce_1: [u8; 16],
    /// UIT — UE identity type bit (bit 1, mask 0x01).
    pub uit: bool,
    /// UE identity bytes (variable length).
    pub ue_id: Vec<u8>,
}

impl NasRelayKeyRequestParameters {
    /// Parse the typed contents.
    pub fn parse(&self) -> Option<RelayKeyRequestParameters> {
        let data = &self.value;
        if data.len() < 20 {
            return None;
        }
        let relay_service_code =
            ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let mut nonce_1 = [0u8; 16];
        nonce_1.copy_from_slice(&data[3..19]);
        let uit = data[19] & 0x01 != 0;
        let ue_id = data[20..].to_vec();
        Some(RelayKeyRequestParameters {
            relay_service_code,
            nonce_1,
            uit,
            ue_id,
        })
    }

    /// Construct a value from parsed.
    pub fn from_parsed(p: &RelayKeyRequestParameters) -> Self {
        let mut value = Vec::with_capacity(20 + p.ue_id.len());
        value.push(((p.relay_service_code >> 16) & 0xFF) as u8);
        value.push(((p.relay_service_code >> 8) & 0xFF) as u8);
        value.push((p.relay_service_code & 0xFF) as u8);
        value.extend_from_slice(&p.nonce_1);
        value.push(if p.uit { 0x01 } else { 0x00 });
        value.extend_from_slice(&p.ue_id);
        Self::new(value)
    }
}

// ── 9.11.3.90 Relay key response parameters ─────────────────────────────────

/// Decoded view of [`NasRelayKeyResponseParameters`] per TS 24.501 §9.11.3.90.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RelayKeyResponseParameters {
    /// K_NR_PROSE (32 bytes).
    pub key_knr_prose: [u8; 32],
    /// Nonce 2 (16 bytes).
    pub nonce_2: [u8; 16],
    /// CP-PRUK ID bytes (variable length).
    pub cp_pruk_id: Vec<u8>,
}

impl NasRelayKeyResponseParameters {
    /// Parse the typed contents.
    pub fn parse(&self) -> Option<RelayKeyResponseParameters> {
        let data = &self.value;
        if data.len() < 49 {
            return None;
        }
        let mut key_knr_prose = [0u8; 32];
        key_knr_prose.copy_from_slice(&data[..32]);
        let mut nonce_2 = [0u8; 16];
        nonce_2.copy_from_slice(&data[32..48]);
        let cp_pruk_id = data[48..].to_vec();
        Some(RelayKeyResponseParameters {
            key_knr_prose,
            nonce_2,
            cp_pruk_id,
        })
    }

    /// Construct a value from parsed.
    pub fn from_parsed(p: &RelayKeyResponseParameters) -> Self {
        let mut value = Vec::with_capacity(48 + p.cp_pruk_id.len());
        value.extend_from_slice(&p.key_knr_prose);
        value.extend_from_slice(&p.nonce_2);
        value.extend_from_slice(&p.cp_pruk_id);
        Self::new(value)
    }
}

// ── 9.11.4.40 ECN marking for L4S indication ────────────────────────────────

impl NasEcnMarkingL4sIndication {
    /// Per-flow QRI bytes — one octet per QoS flow per TS 24.501 §9.11.4.40.
    pub fn qri_values(&self) -> &[u8] {
        &self.value
    }

    /// Construct a value from qri values.
    pub fn from_qri_values(qris: &[u8]) -> Self {
        Self::new(qris.to_vec())
    }

    /// Return try from qri values.
    pub fn try_from_qri_values(qris: &[u8]) -> Result<Self> {
        if qris.contains(&0) {
            return Err(NasError::EncodingError(
                "ECN marking for L4S indication QRI values must be in 1..=255".into(),
            ));
        }
        Ok(Self::new(qris.to_vec()))
    }
}

// ============================================================================
// Tests
// ============================================================================

// Raw value access for IEs whose counterpart in the other protocol has it.
crate::common::nas_opaque_ie!(NasAuthenticationFailureParameter, "24.501", "9.11.3.14");
crate::common::nas_opaque_ie!(NasAuthenticationResponseParameter, "24.501", "9.11.3.17");
crate::common::nas_opaque_ie!(NasRegistrationWaitRange, "24.501", "9.11.3.84");
crate::common::nas_opaque_ie!(NasAdditionalInformation, "24.501", "9.11.2.1");

#[cfg(test)]
mod tests {
    use crate::common::Encode;

    #[test]
    fn bit_setters_keep_declared_length_in_sync() {
        let mut capability = NasFGmmCapability::new(vec![0]);
        capability.set_racs(true);
        assert_eq!(capability.length as usize, capability.value.len());
        let mut wire = bytes::BytesMut::new();
        capability.encode(&mut wire).unwrap();
        assert_eq!(wire[1] as usize, capability.value.len());
    }

    #[test]
    fn value_setters_keep_declared_length_in_sync() {
        fn encodes<T: Encode>(ie: &T) {
            ie.encode(&mut bytes::BytesMut::new()).unwrap();
        }
        let mut support = NasFGsNetworkFeatureSupport::new(vec![]);
        support.set_emc(1);
        encodes(&support);
        let mut support = NasFGsNetworkFeatureSupport::new(vec![]);
        support.set_emf(1);
        encodes(&support);
        let mut support = NasFGsNetworkFeatureSupport::new(vec![0]);
        support.set_restrict_ec(1);
        encodes(&support);
        let mut ambr = NasSessionAmbr::new(vec![]);
        ambr.set_downlink(6, 100);
        encodes(&ambr);
        let mut ambr = NasSessionAmbr::new(vec![]);
        ambr.set_uplink(6, 100);
        encodes(&ambr);
        let mut capability = NasFGsmCapability::new(vec![]);
        capability.set_atsss_st(0x3);
        encodes(&capability);
        let mut capability = NasFGsmCapability::new(vec![0]);
        capability.set_atsss_ll(0x1);
        encodes(&capability);
        let mut container = NasAtsssContainer::new(vec![]);
        container.set_container_data(vec![1, 2, 3]);
        encodes(&container);
        encodes(&NasAtsssContainer::new(vec![]).with_container_data(vec![1]));
        let mut container = NasPortManagementInformationContainer::new(vec![]);
        container.set_container_data(vec![1, 2, 3]);
        encodes(&container);
        encodes(&NasPortManagementInformationContainer::new(vec![]).with_container_data(vec![1]));
        let mut restriction = NasPagingRestriction::new(vec![]);
        restriction
            .set_restriction_type(PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions);
        encodes(&restriction);
        restriction.set_unrestricted_psi_list(&[1, 5]);
        encodes(&restriction);
        restriction.set_restriction_type(PagingRestrictionType::AllRestricted);
        encodes(&restriction);
        let mut requested = NasAdditionalInformationRequested::new(vec![]);
        requested.set_cipher_key_data_requested(true);
        encodes(&requested);
        let mut nid = NasNid::new(vec![]);
        nid.set_assignment_mode_raw(1);
        encodes(&nid);
        let mut truncated = NasTruncatedFGSTmsiConfiguration::new(vec![]);
        truncated.set_set_id_length(4);
        encodes(&truncated);
        let mut truncated = NasTruncatedFGSTmsiConfiguration::new(vec![]);
        truncated.set_pointer_length(2);
        encodes(&truncated);
        encodes(&NasTruncatedFGSTmsiConfiguration::new(vec![]).with_set_id_length(4));
        encodes(&NasTruncatedFGSTmsiConfiguration::new(vec![]).with_pointer_length(2));
        let mut tnan = NasTnanInformation::new(vec![]);
        tnan.set_tngf_id(Some(&[1, 2]));
        encodes(&tnan);
        tnan.set_ssid(Some(b"ssid"));
        encodes(&tnan);
        encodes(
            &NasFGsRegistrationResult::new(vec![])
                .with_result_value(RegistrationResult::ThreeGppAccess),
        );
        encodes(&NasFGsUpdateType::new(vec![]).with_sms_requested(true));
    }

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
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            },
            amf_region_id: 0x02,
            amf_set_id: 0x40,  // 10 bits
            amf_pointer: 0x00, // 6 bits
            tmsi: 0xC00002DF,
        };
        let identity = NasFGsMobileIdentity::from_guti(&guti);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Guti));
        let parsed = identity.as_guti().unwrap();
        assert_eq!(parsed.plmn, guti.plmn);
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
    fn test_security_algorithms_reserved_codes_roundtrip() {
        let sa = NasSecurityAlgorithms::from_algorithms(
            CipheringAlgorithm::NEA7,
            IntegrityAlgorithm::NIA6,
        );
        assert_eq!(sa.ciphering(), Some(CipheringAlgorithm::NEA7));
        assert_eq!(sa.integrity(), Some(IntegrityAlgorithm::NIA6));
    }

    #[test]
    fn test_registration_type() {
        let rt = NasFGsRegistrationType::default()
            .with_registration_type(RegistrationType::InitialRegistration)
            .with_follow_on_request(true)
            .with_ngksi(0x07)
            .with_tsc(false);
        assert_eq!(rt.value, 0x79); // 0111_1001
        assert_eq!(
            rt.registration_type(),
            Some(RegistrationType::InitialRegistration)
        );
        assert!(rt.follow_on_request());
        assert_eq!(rt.ngksi(), 0x07);
        assert!(!rt.tsc());

        let standalone =
            NasFGsRegistrationType::from_registration_type(RegistrationType::EmergencyRegistration);
        assert_eq!(standalone.value, 0x04);
        assert_eq!(
            standalone.registration_type(),
            Some(RegistrationType::EmergencyRegistration)
        );
        assert_eq!(standalone.ngksi(), 0);
        assert!(!standalone.tsc());
    }

    #[test]
    fn test_nas_ksi() {
        let ksi = NasKeySetIdentifier::default().with_ngksi(3).with_tsc(false);
        assert_eq!(ksi.value, 0x03);
        assert_eq!(ksi.ngksi(), 3);
        assert!(!ksi.tsc());
        assert!(!ksi.no_key_available());

        let no_key = NasKeySetIdentifier::default().with_ngksi(NAS_KSI_NO_KEY_AVAILABLE);
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
        assert_eq!(
            GsmCause::from_u8_for_ue(0x01),
            GsmCause::RequestRejectedUnspecified
        );
        assert_eq!(
            GsmCause::from_u8_for_network(0x01),
            GsmCause::ProtocolErrorUnspecified
        );
        assert_eq!(GsmCause::from_u8_strict(0x01), None);
    }

    #[test]
    fn mapped_eps_bearer_parameters_use_the_eps_grammars() {
        use crate::nas_eps::{ApnAmbrValue, EpsBitRate, TftOperation};
        // Parity review F13: TS 24.501 §9.11.4.8 codes the parameter contents
        // as the EPS QoS, TFT, and APN-AMBR values of TS 24.301.
        let qos = MappedEpsBearerParam {
            param_id: 0x01,
            contents: vec![0x01, 0x40, 0x40, 0x40, 0x40],
        };
        assert_eq!(qos.eps_qos().unwrap().mbr_ul(), Some(EpsBitRate::Kbps(64)));
        assert_eq!(qos.apn_ambr(), None);
        let ambr = MappedEpsBearerParam {
            param_id: 0x04,
            contents: vec![0xfe, 0x01, 0x10, 0x00],
        };
        assert_eq!(
            ambr.apn_ambr().and_then(|ambr| Some(ApnAmbrValue {
                dl_kbps: ambr.downlink_kbps()?,
                ul_kbps: ambr.uplink_kbps()?,
            })),
            Some(ApnAmbrValue {
                dl_kbps: 10_200,
                ul_kbps: 1
            })
        );
        let tft = MappedEpsBearerParam {
            param_id: 0x03,
            contents: vec![0x21, 0x21, 0x01, 0x02, 0x30, 0x11],
        };
        assert_eq!(tft.tft().unwrap().operation, TftOperation::Create);
        assert!(
            MappedEpsBearerParam {
                param_id: 0x05,
                contents: vec![3, 0, 1, 3, 0, 1],
            }
            .extended_apn_ambr()
            .is_some()
        );
        assert_eq!(
            MappedEpsBearerParam {
                param_id: 0x02,
                contents: vec![0; 10],
            }
            .extended_eps_qos()
            .map(|qos| qos.mbr_unit),
            Some(0)
        );
    }

    #[test]
    fn unknown_causes_stay_visible_like_eps() {
        // Parity review F4: the receiver fallback is explicit, as in EPS.
        let gmm = NasFGmmCause::new(0x01);
        assert_eq!(gmm.cause(), None);
        assert_eq!(gmm.cause_raw(), 0x01);
        assert_eq!(gmm.cause_received(), GmmCause::ProtocolErrorUnspecified);
        assert_eq!(gmm.description(), "Unknown 5GMM cause 0x01");
        let gsm = NasFGsmCause::new(0x01);
        assert_eq!(gsm.cause(), None);
        assert_eq!(gsm.cause_for_ue(), GsmCause::RequestRejectedUnspecified);
        assert_eq!(gsm.cause_for_network(), GsmCause::ProtocolErrorUnspecified);
        assert_eq!(gsm.description(), "Unknown 5GSM cause 0x01");
        assert_eq!(GmmCause::from_u8_received(0x03), GmmCause::IllegalUe);
    }

    #[test]
    fn test_gprs_timer3() {
        // 5 minutes = unit=OneMinute(5), value=5
        let timer = NasGprsTimer3::new(vec![(5 << 5) | 5]);
        assert_eq!(timer.unit(), Some(GprsTimer3Unit::OneMinute));
        assert_eq!(timer.timer_value(), Some(5));
        assert_eq!(timer.to_seconds(), Some(300));
    }

    #[test]
    fn gprs_timers_share_the_ts_24008_grammar() {
        // A zero value is a zero duration; procedures decide what it means.
        assert_eq!(NasGprsTimer::new(0x20).to_seconds(), Some(0));
        assert_eq!(NasGprsTimer2::new(vec![0x20]).to_seconds(), Some(0));
        assert_eq!(NasGprsTimer3::new(vec![0xa0]).to_seconds(), Some(0));
        // The 320-hour unit is defined only for T3512 among the 5GS timers.
        let t3512 = NasGprsTimer3::new(vec![0xc2]);
        assert_eq!(t3512.to_seconds(), None);
        assert_eq!(
            t3512.t3512_value_for_ue(true),
            Some(GprsTimerValue::Seconds(2 * 1_152_000))
        );
        assert_eq!(
            t3512.t3512_value_for_ue(false),
            Some(GprsTimerValue::Seconds(2 * 3_600))
        );
        assert_eq!(
            NasGprsTimer3::new(vec![0xa0]).t3512_value_for_ue(true),
            Some(GprsTimerValue::Deactivated)
        );
        assert!(!t3512.is_well_formed());
        assert_eq!(
            NasGprsTimer::from_unit_value(GprsTimerUnit::Deactivated, 5).value,
            0xe0
        );
        // 60 s is 30 steps of 2 s; 3600 s is 6 steps of 10 minutes.
        assert_eq!(NasGprsTimer2::from_seconds(60).unwrap().value, vec![0x1e]);
        assert_eq!(
            NasGprsTimer3::from_seconds(3_600).unwrap().value,
            vec![0x06]
        );
        assert!(NasGprsTimer2::from_seconds(90).is_none());
        assert!(
            NasRegistrationWaitRange::new(vec![0x20, 0x21])
                .min_timer()
                .is_some_and(|timer| timer.to_seconds() == Some(0))
        );
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
        let dnn = NasDnn::from_string("internet").unwrap();
        assert_eq!(dnn.as_string(), Some("internet".to_string()));

        let dnn2 = NasDnn::from_string("ims.mnc093.mcc208.3gppnetwork.org").unwrap();
        assert_eq!(
            dnn2.as_string(),
            Some("ims.mnc093.mcc208.3gppnetwork.org".to_string())
        );

        // Over-long label is refused (no silent truncation).
        assert!(NasDnn::from_string(&"a".repeat(64)).is_none());
        // Empty label is refused.
        assert!(NasDnn::from_string("a..b").is_none());
    }

    #[test]
    fn test_bcd_imei_decode() {
        // IMEI 123456789012345: type 3 (IMEI) with the odd flag set.
        let wire = [0x1b, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54];
        let imei = NasFGsMobileIdentity::new(wire.to_vec());
        assert_eq!(imei.as_imei().as_deref(), Some("123456789012345"));
        // Parity review F10: a non-decimal digit or a wrong odd/even flag is
        // not an IMEI, as in EPS.
        let mut digit = wire;
        digit[3] = 0x7a;
        assert_eq!(NasFGsMobileIdentity::new(digit.to_vec()).as_imei(), None);
        let mut even = wire;
        even[0] = 0x13;
        assert_eq!(NasFGsMobileIdentity::new(even.to_vec()).as_imei(), None);
        // TS 24.008 codes IMEI as type 010 where TS 24.501 uses 011.
        let mut eps = wire;
        eps[0] = 0x1a;
        assert_eq!(
            crate::nas_eps::NasMobileIdentity::new(eps.to_vec()).as_imei(),
            imei.as_imei()
        );
    }

    #[test]
    fn test_deregistration_type() {
        // switch_off=1, access_type=1 (3GPP) = 0b1001
        let dt = NasDeRegistrationType::new(0x09);
        assert!(dt.switch_off());
        assert!(!dt.re_registration_required());
        assert_eq!(dt.access_type(), Some(AccessTypeValue::ThreeGpp));
        assert_eq!(
            dt.deregistration_access_type(),
            Some(DeregistrationAccessType::ThreeGpp)
        );

        // access_type=1, no switch-off = 0b0001
        let dt2 = NasDeRegistrationType::new(0x01);
        assert!(!dt2.switch_off());
        assert!(!dt2.re_registration_required());
        assert_eq!(dt2.access_type(), Some(AccessTypeValue::ThreeGpp));

        // Test fluent builder with ngKSI
        let dt3 = NasDeRegistrationType::default()
            .with_switch_off(true)
            .with_access_type(AccessTypeValue::ThreeGpp)
            .with_ngksi(3)
            .with_tsc(false);
        assert!(dt3.switch_off());
        assert_eq!(dt3.access_type(), Some(AccessTypeValue::ThreeGpp));
        assert_eq!(dt3.ngksi(), 3);
        assert!(!dt3.tsc());
        // Upper nibble: ngKSI=3, TSC=0 → 0b0011, lower nibble: switch_off+3GPP = 0b1001
        assert_eq!(dt3.value, 0x39);

        let mut dt4 = NasDeRegistrationType::new(0x01);
        dt4.set_re_registration_required(true);
        assert!(dt4.re_registration_required());
        assert_eq!(dt4.value, 0x05);

        let dt5 = NasDeRegistrationType::default()
            .with_deregistration_access_type(DeregistrationAccessType::ThreeGppAndNon3Gpp);
        assert_eq!(
            dt5.deregistration_access_type(),
            Some(DeregistrationAccessType::ThreeGppAndNon3Gpp)
        );
        assert_eq!(dt5.access_type(), None);
    }

    #[test]
    fn test_registration_result() {
        let result = NasFGsRegistrationResult::new(vec![0x09]); // 3GPP access + SMS allowed
        assert_eq!(
            result.result_value(),
            Some(RegistrationResult::ThreeGppAccess)
        );
        assert!(result.sms_allowed());
    }

    #[test]
    fn test_payload_container_type() {
        let pct = NasPayloadContainerType::new(0x01);
        assert!(pct.is_n1_sm());
        assert_eq!(pct.kind(), Some(PayloadContainerKind::N1SmInformation));
    }

    #[test]
    fn test_nssai_parse_all() {
        // Two S-NSSAIs: SST=1 (1 byte) + SST=2,SD=0x010203 (4 bytes)
        let nssai = NasNssai::new(vec![
            0x01, 0x01, // entry 1: len=1, SST=1
            0x04, 0x02, 0x01, 0x02, 0x03, // entry 2: len=4, SST=2, SD=010203
        ]);
        let entries = nssai.parse_all();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sst, 1);
        assert_eq!(entries[0].sd, None);
        assert_eq!(entries[1].sst, 2);
        assert_eq!(entries[1].sd, Some([0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_nssai_from_snssais_roundtrip() {
        let snssais = vec![
            NasSNssai::from_sst_sd(1, None),
            NasSNssai::from_sst_sd(2, Some([0x00, 0x00, 0x01])),
        ];
        let nssai = NasNssai::from_snssais(&snssais);
        let parsed = nssai.parse_all();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sst, 1);
        assert_eq!(parsed[0].sd, None);
        assert_eq!(parsed[1].sst, 2);
        assert_eq!(parsed[1].sd, Some([0x00, 0x00, 0x01]));
    }

    #[test]
    fn test_tracking_area_identity() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let tai = NasFGsTrackingAreaIdentity::from_plmn_tac(&plmn, [0x00, 0x00, 0x01]);
        let parsed = tai.parse().unwrap();
        assert_eq!(parsed.plmn.mcc_string(), "208");
        assert_eq!(parsed.plmn.mnc_string(), "93");
        assert_eq!(parsed.tac, [0x00, 0x00, 0x01]);

        let abnormal = NasFGsTrackingAreaIdentity::new(hex::decode("ab0000000001").unwrap());
        assert_eq!(
            abnormal.receiver_value(),
            Some(ReceivedTrackingAreaIdentity::Deleted {
                raw_plmn: [0xab, 0x00, 0x00],
                tac: [0x00, 0x00, 0x01],
            })
        );
        assert!(abnormal.is_deleted());
        assert!(abnormal.parse().is_none());

        let deleted = NasFGsTrackingAreaIdentity::from_deleted(&plmn).unwrap();
        assert!(deleted.is_deleted());
        assert_eq!(deleted.value, hex::decode("02f839fffffe").unwrap());
        assert!(NasFGsTrackingAreaIdentity::try_from_plmn_tac(&plmn, [0, 0, 0]).is_none());
    }

    #[test]
    fn test_tai_list_type00() {
        // Type 00: 1 PLMN + 2 TACs
        // header: type=00, count=1 (meaning 2 elements) → 0b000_00001 = 0x01
        let plmn_tbcd = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        }
        .to_tbcd();
        let mut data = vec![0x01]; // type=00, num=2
        data.extend_from_slice(&plmn_tbcd);
        data.extend_from_slice(&[0x00, 0x00, 0x01]); // TAC 1
        data.extend_from_slice(&[0x00, 0x00, 0x02]); // TAC 2
        let tai_list = NasFGsTrackingAreaIdentityList::new(data);
        let entries = tai_list.parse();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            TaiListEntry::OnePlmnNonConsecutive { plmn, tacs } => {
                assert_eq!(plmn.mcc_string(), "208");
                assert_eq!(tacs.len(), 2);
                assert_eq!(tacs[0], [0x00, 0x00, 0x01]);
                assert_eq!(tacs[1], [0x00, 0x00, 0x02]);
            }
            other => panic!("unexpected entry: {other:?}"),
        }
    }

    #[test]
    fn test_allowed_pdu_session_status() {
        let status = NasAllowedPduSessionStatus::from_sessions(&[1, 3, 8]);
        assert!(status.is_allowed(1));
        assert!(!status.is_allowed(2));
        assert!(status.is_allowed(3));
        assert!(status.is_allowed(8));
        assert_eq!(status.allowed_sessions(), vec![1, 3, 8]);
    }

    #[test]
    fn test_session_ambr() {
        // DL: unit=0x06 (1Mbps), value=100 → 100 Mbps = 100_000 kbps
        // UL: unit=0x06 (1Mbps), value=50  → 50 Mbps  = 50_000 kbps
        let ambr = NasSessionAmbr::new(vec![0x06, 0x00, 0x64, 0x06, 0x00, 0x32]);
        let parsed = ambr.parse().unwrap();
        assert_eq!(ambr.downlink_unit(), Some(SessionAmbrUnit::Mbps1));
        assert_eq!(ambr.downlink_value(), 100);
        assert_eq!(ambr.uplink_unit(), Some(SessionAmbrUnit::Mbps1));
        assert_eq!(ambr.uplink_value(), 50);
        assert_eq!(parsed.dl_kbps, 100_000);
        assert_eq!(parsed.ul_kbps, 50_000);
        assert_eq!(
            NasSessionAmbr::try_from_kbps(100_000, 50_000).and_then(|encoded| encoded.parse()),
            Some(parsed)
        );
        assert!(NasSessionAmbr::try_from_kbps(u64::MAX, 1).is_none());
        assert!(QosFlowBitRate::try_from_kbps(u64::MAX).is_none());
    }

    #[test]
    fn test_session_ambr_pbps_units() {
        let ambr = NasSessionAmbr::from_raw_fields(0x16, 0x0002, 0x19, 0x0001);
        assert_eq!(ambr.downlink_unit(), Some(SessionAmbrUnit::Pbps4));
        assert_eq!(ambr.downlink_kbps(), Some(8_000_000_000_000));
        assert_eq!(ambr.uplink_unit(), Some(SessionAmbrUnit::Pbps256));
        assert_eq!(ambr.uplink_kbps(), Some(256_000_000_000_000));
    }

    #[test]
    fn test_eps_security_algorithms() {
        use crate::nas_eps::{CipheringAlgorithm as Eea, IntegrityAlgorithm as Eia};
        let sa = NasEpsNasSecurityAlgorithms::from_algorithms(Eea::EEA2, Eia::EIA2);
        assert_eq!(sa.ciphering(), Some(Eea::EEA2));
        assert_eq!(sa.integrity(), Some(Eia::EIA2));
        assert_eq!(sa.value, 0x22);
        // Spare bits 8 and 4 are ignored on receipt and reported to senders.
        let spare = NasSecurityAlgorithms::new(0xaa);
        assert_eq!(spare.ciphering(), Some(CipheringAlgorithm::NEA2));
        assert_eq!(spare.integrity(), Some(IntegrityAlgorithm::NIA2));
        assert!(!spare.is_well_formed());
        assert_eq!(
            NasSecurityAlgorithms::new(0x11)
                .with_ciphering(CipheringAlgorithm::NEA2)
                .value,
            0x21
        );
    }

    #[test]
    fn test_gprs_timer() {
        // Unit=0b001 (1 min), value=10 → 600 seconds
        let timer = NasGprsTimer::new((0b001 << 5) | 10);
        assert_eq!(timer.unit(), Some(GprsTimerUnit::OneMinute));
        assert_eq!(timer.timer_value(), 10);
        assert_eq!(timer.to_seconds(), Some(600));

        // Deactivated
        let deactivated = NasGprsTimer::new(0b111 << 5);
        assert_eq!(deactivated.to_seconds(), None);
    }

    #[test]
    fn test_network_feature_support() {
        // Octet 1: IMS VoPS(1) + non-3GPP VoPS(0) + EMC=01(bits 3-4) + EMF=00 + IWK_N26(0) + MPSI(0)
        // = 0b0000_0101 = 0x05
        let nfs = NasFGsNetworkFeatureSupport::new(vec![0x05]);
        assert!(nfs.ims_vops_3gpp());
        assert!(!nfs.ims_vops_n3gpp());
        assert_eq!(nfs.emc(), 0x01);
        assert_eq!(nfs.emf(), 0x00);
        assert!(!nfs.iwk_n26());
        assert!(!nfs.mpsi());
    }

    #[test]
    fn test_network_feature_support_octet_2_to_4_accessors() {
        let nfs = NasFGsNetworkFeatureSupport::new(vec![0x00, 0x03, 0xC3, 0x3F]);
        assert!(nfs.emcn3());
        assert!(nfs.mcsi());
        assert_eq!(
            nfs.restrict_ec_value(),
            Some(RestrictionOnEnhancedCoverage::NotRestricted)
        );
        assert!(!nfs.cp_ciot());
        assert!(nfs.n3_data());
        assert!(!nfs.n3_data_not_supported());
        assert!(!nfs.iphc_cp_ciot());
        assert!(!nfs.up_ciot());
        assert!(nfs.lcs_5g());
        assert!(nfs.ats_ind());
        assert!(!nfs.ehc_cp_ciot());
        assert!(!nfs.ncr());
        assert!(!nfs.piv());
        assert!(!nfs.rpr());
        assert!(nfs.pr());
        assert!(nfs.un_per());
        assert!(nfs.naps());
        assert!(nfs.lcs_upp());
        assert!(nfs.supl());
        assert!(nfs.rslp());
        assert!(nfs.mlcsup());
        assert!(nfs.ef5l());
    }

    #[test]
    fn test_authn_parameter_autn() {
        let autn_bytes = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // SQN⊕AK
            0x80, 0x00, // AMF
            0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, // MAC-A
        ];
        let autn =
            NasAuthenticationParameterAutn::from_autn(autn_bytes.clone().try_into().unwrap());
        assert_eq!(autn.autn(), &autn_bytes);
        assert_eq!(
            autn.sqn_xor_ak().unwrap(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        );
        assert_eq!(autn.amf_field().unwrap(), [0x80, 0x00]);
        assert_eq!(
            autn.mac_a().unwrap(),
            &[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8]
        );
    }

    #[test]
    fn test_auth_failure_parameter() {
        let auts_bytes: [u8; 14] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // SQN⊕AK*
            0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, // MAC-S
        ];
        let auts = NasAuthenticationFailureParameter::from_auts(auts_bytes);
        assert_eq!(
            auts.sqn_xor_aks().unwrap(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
        );
        assert_eq!(
            auts.mac_s().unwrap(),
            &[0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8]
        );
    }

    #[test]
    fn test_eap_message() {
        // EAP Success: code=3, id=1, length=4
        let eap = NasEapMessage::from_eap_data(vec![0x03, 0x01, 0x00, 0x04]);
        assert_eq!(eap.eap_code(), Some(EapCode::Success));
        assert_eq!(eap.eap_identifier(), Some(1));
        assert_eq!(eap.eap_data(), &[0x03, 0x01, 0x00, 0x04]);
    }

    #[test]
    fn test_registration_wait_range() {
        let rwr = NasRegistrationWaitRange::from_range(10, 60).unwrap();
        assert!(rwr.is_well_formed());
        assert!(NasRegistrationWaitRange::from_range(61, 62).is_none());
        assert_eq!(rwr.value.len(), 2);
        assert_eq!(rwr.min_timer().unwrap().to_seconds(), Some(10));
        assert_eq!(rwr.max_timer().unwrap().to_seconds(), Some(60));
        assert_eq!(rwr.min_seconds(), Some(10));
        assert_eq!(rwr.max_seconds(), Some(60));
    }

    #[test]
    fn test_paging_restriction_reserved_and_bitmap_width() {
        let reserved = NasPagingRestriction::from_restriction_type(PagingRestrictionType::Reserved);
        assert_eq!(
            reserved.restriction_type(),
            Some(PagingRestrictionType::Reserved)
        );
        assert!(reserved.restricted_psi_list().is_empty());

        let ie = NasPagingRestriction::new(vec![
            PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions as u8,
            0x01,
            0x80,
            0xFF,
        ]);
        assert_eq!(ie.unrestricted_psi_bitmap(), Some([0x00, 0x80]));
        assert_eq!(ie.unrestricted_psi_list(), vec![15]);
    }

    #[test]
    fn eps_parity_sender_checks_cover_shared_and_corresponding_ies() {
        assert!(NasReAttemptIndicator::from_flags(true, false).is_well_formed());
        assert!(!NasReAttemptIndicator::new(vec![0x80]).is_well_formed());
        let mut retry = NasReAttemptIndicator::new(vec![]);
        retry.set_ratc_not_allowed(true);
        assert!(retry.ratc_not_allowed());
        assert!(retry.with_eplmnc_not_allowed(true).eplmnc_not_allowed());

        assert!(NasControlPlaneOnlyIndication::control_plane_only().is_well_formed());
        assert!(NasControlPlaneOnlyIndication::try_from_cpoi(false).is_none());
        assert!(
            NasControlPlaneOnlyIndication::try_from_cpoi(true)
                .unwrap()
                .is_control_plane_only()
        );

        assert!(
            NasAdditionalInformationRequested::from_cipher_key_data_requested(true)
                .is_well_formed()
        );
        assert!(!NasAdditionalInformationRequested::new(vec![0x80]).is_well_formed());

        assert!(
            !NasPagingRestriction::from_restriction_type(PagingRestrictionType::Reserved)
                .is_well_formed()
        );
        assert!(
            NasPagingRestriction::from_restriction_type(PagingRestrictionType::AllRestricted)
                .is_well_formed()
        );
        assert!(
            NasPagingRestriction::from_restriction_type_with_unrestricted_psis(
                PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions,
                &[1, 15]
            )
            .is_well_formed()
        );
        assert!(!NasPagingRestriction::new(vec![0x03, 0x01, 0x00]).is_well_formed());
    }

    #[test]
    fn test_sor_ack_includes_mac_iue() {
        let sor_mac_iue = [0xAB; 16];
        let ie = NasSorTransparentContainer::from_ack(true, false, true, sor_mac_iue);
        assert!(ie.sor_data_type_ack());
        assert!(ie.mssi());
        assert!(!ie.mssnpnsi());
        assert!(ie.msssnpnsils());
        assert_eq!(ie.sor_mac_iue(), Some(sor_mac_iue));
        let plmn_list = [0x02, 0xf8, 0x39, 0x00, 0x01];
        let information = NasSorTransparentContainer::from_information(
            true,
            SorListType::PlmnAccessTechnologyList,
            true,
            false,
            [0xCD; 16],
            0x1234,
            &plmn_list,
        )
        .unwrap();
        assert_eq!(information.sor_header(), Some(0x0e));
        assert_eq!(information.sor_mac_iausf(), Some([0xCD; 16]));
        assert_eq!(information.counter_sor(), Some(0x1234));
        assert_eq!(information.plmn_list_payload(), Some(plmn_list.as_slice()));
        assert!(information.is_well_formed_for(SorTransparentContainerDirection::NetworkToUe));
        assert!(matches!(
            information.parse(),
            Some(SorTransparentContainerContents::Information {
                list_indication: true,
                list_type: SorListType::PlmnAccessTechnologyList,
                acknowledgement_requested: true,
                additional_parameters: false,
                ..
            })
        ));
    }

    #[test]
    fn test_ds_tt_mac_address() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let ie = NasDsTtEthernetPortMacAddress::from_mac_address(mac);
        assert_eq!(ie.mac_address().unwrap(), mac);
    }

    #[test]
    fn test_pdu_session_pair_id() {
        let ie = NasPduSessionPairId::from_pair_id(5);
        assert_eq!(ie.pair_id(), Some(5));
    }

    #[test]
    fn test_truncated_tmsi_config() {
        // TS 24.501 §9.11.3.70: set ID length in upper nibble, pointer length in lower.
        let ie = NasTruncatedFGSTmsiConfiguration::new(vec![(6 << 4) | 4]);
        assert_eq!(ie.truncated_amf_set_id_length(), Some(6));
        assert_eq!(ie.truncated_amf_pointer_length(), Some(4));
        assert!(ie.is_well_formed());
        assert_eq!(
            NasTruncatedFGSTmsiConfiguration::try_from_lengths(6, 4),
            Some(ie)
        );
        assert!(NasTruncatedFGSTmsiConfiguration::try_from_lengths(4, 3).is_none());
    }

    #[test]
    fn test_nid_raw_helpers() {
        let nid = NasNid::from_nid_value("1a32547698ba").unwrap();
        assert_eq!(nid.assignment_mode_raw(), 0x01);
        assert_eq!(nid.nid_value(), "1a32547698ba");

        let nid = nid.with_assignment_mode_raw(0x02);
        assert_eq!(nid.assignment_mode_raw(), 0x02);
        assert_eq!(nid.data()[0], 0xA2);
    }

    #[test]
    fn test_ue_request_type_ignores_spare_bits() {
        let ie = NasUeRequestType::from_data(vec![0x12]);
        assert_eq!(ie.request_type_raw(), Some(0x02));
        assert_eq!(ie.request_type(), Some(UeRequestType::RejectionOfPaging));
        assert!(!ie.is_well_formed());
        let ie = NasUeRequestType::from_request_type(UeRequestType::NasSignallingConnectionRelease);
        assert_eq!(ie.data(), &[0x01]);
    }

    #[test]
    fn test_audited_tv1_setters_clear_spare_bits() {
        let access = NasAccessType::new(0x0F).with_access_type(AccessTypeValue::Non3Gpp);
        assert_eq!(access.value, 0x02);

        let pdu = NasPduSessionType::new(0x0F).with_session_type(PduSessionTypeValue::Ethernet);
        assert_eq!(pdu.value, 0x05);

        let ssc = NasSscMode::new(0x0F).with_mode(SscModeValue::Ssc3);
        assert_eq!(ssc.value, 0x03);

        let mut request = NasRequestType::new(0x0F);
        assert_eq!(request.request_type_raw(), 0x07);
        assert_eq!(request.request_type(), None);
        request.set_request_type(RequestTypeValue::ExistingPduSession);
        assert_eq!(request.value, 0x02);
    }

    #[test]
    fn test_request_type_reserved_code_is_raw_only() {
        assert_eq!(
            RequestTypeValue::from_u8(0x00),
            Some(RequestTypeValue::InitialRequest)
        );
        assert_eq!(RequestTypeValue::from_u8(0x07), None);
        assert_eq!(RequestTypeValue::from_u8_strict(0x07), None);

        let reserved = NasRequestType::new(0x07);
        assert_eq!(reserved.request_type(), None);
        assert_eq!(reserved.request_type_raw(), 0x07);
    }

    #[test]
    fn test_strict_spare_bit_validators_and_fallible_builders() {
        let packet_filters = NasMaximumNumberOfSupportedPacketFilters::from_max_filters(1024);
        assert_eq!(packet_filters.max_filters(), 1024);
        assert!(packet_filters.spare_bits_are_zero());
        assert!(packet_filters.validate_strict().is_ok());
        assert!(NasMaximumNumberOfSupportedPacketFilters::try_from_max_filters(16).is_none());
        assert!(NasMaximumNumberOfSupportedPacketFilters::try_from_max_filters(1025).is_none());
        assert!(
            NasMaximumNumberOfSupportedPacketFilters::new(vec![0x00, 0x01])
                .validate_strict()
                .is_err()
        );

        let subgroup = NasLpWuspsAssistanceInformation::try_from_paging_subgroup_id(30).unwrap();
        assert_eq!(subgroup.paging_subgroup_id(), Some(30));
        assert!(NasLpWuspsAssistanceInformation::try_from_paging_subgroup_id(31).is_err());

        let probability =
            NasLpWuspsAssistanceInformation::try_from_ue_paging_probability_information(20)
                .unwrap();
        assert_eq!(probability.ue_paging_probability_information(), Some(20));
        assert!(
            NasLpWuspsAssistanceInformation::try_from_ue_paging_probability_information(21)
                .is_err()
        );

        let status = NasLpWusStatus::from_disabled(true);
        assert!(status.lp_wus_disabled());
        assert!(status.spare_bits_are_zero());
        assert!(status.validate_strict().is_ok());
        assert!(NasLpWusStatus::new(0x02).validate_strict().is_err());
    }

    #[test]
    fn test_ip_header_compression_configuration_from_data() {
        let ie = NasIpHeaderCompressionConfiguration::from_data(vec![0x01, 0x00, 0x02]);
        assert!(ie.profiles().p0002);
        assert_eq!(ie.max_cid(), 2);
    }

    #[test]
    fn test_timezone_roundtrip() {
        // +32 quarter-hours (UTC+8)
        let tz = NasTimeZone::from_quarter_hours(32).unwrap();
        assert_eq!(tz.quarter_hours(), 32);

        // -32 quarter-hours (UTC-8)
        let tz = NasTimeZone::from_quarter_hours(-32).unwrap();
        assert_eq!(tz.quarter_hours(), -32);

        // +8 quarter-hours (UTC+2) — this was broken before (units digit=8)
        let tz = NasTimeZone::from_quarter_hours(8).unwrap();
        assert_eq!(tz.quarter_hours(), 8);

        // +48 quarter-hours (UTC+12) — units digit=8
        let tz = NasTimeZone::from_quarter_hours(48).unwrap();
        assert_eq!(tz.quarter_hours(), 48);

        // -48 quarter-hours (UTC-12)
        let tz = NasTimeZone::from_quarter_hours(-48).unwrap();
        assert_eq!(tz.quarter_hours(), -48);

        // 0 quarter-hours (UTC)
        let tz = NasTimeZone::from_quarter_hours(0).unwrap();
        assert_eq!(tz.quarter_hours(), 0);

        // +9 quarter-hours — units digit=9
        let tz = NasTimeZone::from_quarter_hours(9).unwrap();
        assert_eq!(tz.quarter_hours(), 9);
        assert!(NasTimeZone::from_quarter_hours(80).is_none());
        assert!(NasTimeZone::from_quarter_hours(-128).is_none());
    }

    #[test]
    fn test_timezone_and_time_roundtrip() {
        let tzt = NasTimeZoneAndTime::default()
            .with_year(26)
            .with_month(4)
            .with_day(6)
            .with_hour(14)
            .with_minute(30)
            .with_second(0)
            .with_timezone_quarter_hours(32)
            .unwrap();
        assert_eq!(tzt.year(), 26);
        assert_eq!(tzt.month(), 4);
        assert_eq!(tzt.day(), 6);
        assert_eq!(tzt.hour(), 14);
        assert_eq!(tzt.minute(), 30);
        assert_eq!(tzt.second(), 0);
        assert_eq!(tzt.timezone_quarter_hours(), 32);

        // Negative timezone
        let tzt = NasTimeZoneAndTime::default()
            .with_year(26)
            .with_month(1)
            .with_day(1)
            .with_timezone_quarter_hours(-20)
            .unwrap();
        assert_eq!(tzt.timezone_quarter_hours(), -20);
        assert!(
            NasTimeZoneAndTime::default()
                .with_timezone_quarter_hours(80)
                .is_none()
        );
    }

    #[test]
    fn test_imei_roundtrip() {
        let identity = NasFGsMobileIdentity::from_imei("123456789012345");
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Imei));
        let decoded = identity.as_imei().unwrap();
        assert_eq!(decoded, "123456789012345");
        assert!(NasFGsMobileIdentity::try_from_imei("123456789012345").is_some());
        assert!(NasFGsMobileIdentity::try_from_imei("12345678901234").is_none());
        assert!(NasFGsMobileIdentity::try_from_imei("12345678901234x").is_none());
        assert_eq!(
            NasFGsMobileIdentity::from_imei_tac_snr("12345678901234")
                .unwrap()
                .as_imei()
                .as_deref(),
            Some("123456789012340")
        );
        assert!(NasFGsMobileIdentity::from_imei_tac_snr("1234567890123").is_none());
    }

    #[test]
    fn test_imeisv_roundtrip() {
        let identity = NasFGsMobileIdentity::from_imeisv("1234567890123456");
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Imeisv));
        let decoded = identity.as_imeisv().unwrap();
        assert_eq!(decoded, "1234567890123456");
        assert!(NasFGsMobileIdentity::try_from_imeisv("1234567890123456").is_some());
        assert!(NasFGsMobileIdentity::try_from_imeisv("123456789012345").is_none());
        assert!(NasFGsMobileIdentity::try_from_imeisv("123456789012345x").is_none());
    }

    #[test]
    fn test_suci_roundtrip() {
        let suci = Suci::Imsi(ImsiSuci {
            plmn_id: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            },
            routing_indicator: vec![0xF0, 0xFF],
            protection_scheme: ProtectionScheme::Null,
            home_nw_public_key_id: 0,
            scheme_output: vec![0x00, 0x00, 0x00, 0x00, 0x50],
        });
        let identity = NasFGsMobileIdentity::from_suci(&suci);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));
        let parsed = identity.as_suci().unwrap();
        match parsed {
            Suci::Imsi(parsed) => {
                assert_eq!(parsed.plmn_id.mcc_string(), "208");
                assert_eq!(parsed.plmn_id.mnc_string(), "93");
                assert_eq!(parsed.protection_scheme, ProtectionScheme::Null);
                assert_eq!(
                    parsed.scheme_output,
                    match &suci {
                        Suci::Imsi(suci) => suci.scheme_output.clone(),
                        Suci::Utf8 { .. } => unreachable!(),
                    }
                );
            }
            Suci::Utf8 { .. } => panic!("expected IMSI-form SUCI"),
        }
    }

    #[test]
    fn test_suci_nai_roundtrip() {
        let nai = "type1.rid678.schid0.useriduser17@example.com";
        let identity =
            NasFGsMobileIdentity::from_suci_nai(SupiFormat::NetworkSpecific, nai).unwrap();
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));
        match identity.as_suci().unwrap() {
            Suci::Utf8 { supi_format, nai } => {
                assert_eq!(supi_format, SupiFormat::NetworkSpecific);
                assert_eq!(nai, "type1.rid678.schid0.useriduser17@example.com");
            }
            Suci::Imsi(_) => panic!("expected UTF-8 SUCI"),
        }
        match identity.suci_nai() {
            Some((SupiFormat::NetworkSpecific, parsed)) => assert_eq!(parsed, nai),
            other => panic!("unexpected SUCI NAI payload: {other:?}"),
        }
        assert_eq!(identity.plmn(), None);
    }

    #[test]
    fn test_suci_supi_format_unused_values_fall_back_to_imsi() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let tbcd = plmn.to_tbcd();
        let mut value = vec![0x41]; // SUPI format=4, type=SUCI.
        value.extend_from_slice(&tbcd);
        value.extend_from_slice(&[0xF0, 0xFF]);
        value.push(ProtectionScheme::Null.to_u8());
        value.push(0x00);
        value.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x50]);

        let identity = NasFGsMobileIdentity::new(value);
        assert_eq!(SupiFormat::from_u8_strict(4), None);
        assert_eq!(identity.supi_format(), Some(SupiFormat::Imsi));
        match identity.as_suci().unwrap() {
            Suci::Imsi(parsed) => assert_eq!(parsed.plmn_id.mcc_string(), "208"),
            Suci::Utf8 { .. } => panic!("unused SUPI format values shall be interpreted as IMSI"),
        }
    }

    #[test]
    fn test_mac_address_mobile_identity_mauri() {
        let mac = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];
        let mut identity = NasFGsMobileIdentity::from_mac_address_with_mauri(mac, true);
        assert_eq!(identity.as_mac_address(), Some(mac));
        assert_eq!(identity.mauri(), Some(true));
        identity.set_mauri(false);
        assert_eq!(identity.mauri(), Some(false));
    }

    #[test]
    fn test_no_identity() {
        let identity = NasFGsMobileIdentity::from_no_identity();
        assert_eq!(
            identity.identity_type(),
            Some(MobileIdentityType::NoIdentity)
        );
    }

    #[test]
    fn test_suci_nai_string() {
        let suci = Suci::Imsi(ImsiSuci {
            plmn_id: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            },
            routing_indicator: vec![0xF0, 0xFF],
            protection_scheme: ProtectionScheme::Null,
            home_nw_public_key_id: 0,
            scheme_output: vec![0x00, 0x00, 0x00, 0x00, 0x50],
        });
        let nai = suci.to_nai_string();
        assert!(nai.starts_with("suci-0-208-93-"));
    }

    #[test]
    fn test_service_type() {
        // Verify 4-bit masking works for all defined values
        assert_eq!(ServiceType::from_u8(0x00), Some(ServiceType::Signalling));
        assert_eq!(
            ServiceType::from_u8(0x04),
            Some(ServiceType::EmergencyServicesFallback)
        );
        assert_eq!(
            ServiceType::from_u8(0x06),
            Some(ServiceType::ElevatedSignalling)
        );
        assert_eq!(ServiceType::from_u8(0x07), Some(ServiceType::Signalling));
        assert_eq!(ServiceType::from_u8(0x08), Some(ServiceType::Signalling));
        assert_eq!(ServiceType::from_u8(0x09), Some(ServiceType::Data));
        assert_eq!(ServiceType::from_u8(0x0A), Some(ServiceType::Data));
        assert_eq!(ServiceType::from_u8(0x0B), Some(ServiceType::Data));
        assert_eq!(ServiceType::from_u8_strict(0x07), None);
        assert_eq!(ServiceType::from_u8_strict(0x08), None);
        assert_eq!(ServiceType::from_u8_strict(0x0B), None);
        assert_eq!(ServiceType::from_u8(0x0F), None); // undefined
    }

    #[test]
    fn test_pdu_address_builders() {
        let addr = NasPduAddress::from_ipv4([10, 0, 0, 1]);
        assert_eq!(addr.session_type(), Some(PduSessionTypeValue::IPv4));
        assert_eq!(addr.ipv4(), Some([10, 0, 0, 1]));

        let addr6 = NasPduAddress::from_ipv6_iid([0; 8]);
        assert_eq!(addr6.session_type(), Some(PduSessionTypeValue::IPv6));
        assert!(addr6.ipv6_interface_id().is_some());

        let addr46 = NasPduAddress::from_ipv4v6([1; 8], [192, 168, 1, 1]);
        assert_eq!(addr46.session_type(), Some(PduSessionTypeValue::IPv4v6));
        assert_eq!(addr46.ipv4(), Some([192, 168, 1, 1]));
        assert!(addr46.is_well_formed());
        assert!(addr46.receiver_syntax_is_valid());
        let short_ipv6 = NasPduAddress::new(vec![0x02, 0, 0, 0, 0]);
        assert!(!short_ipv6.receiver_syntax_is_valid());
        let mut extended = NasPduAddress::from_ipv6_iid([0; 8]);
        extended.value.push(0xAA);
        assert!(extended.receiver_syntax_is_valid());
        assert!(!extended.is_well_formed());
        let ipv4_with_lla =
            NasPduAddress::from_ipv4_with_smf_ipv6_link_local_address([192, 0, 2, 1], [0xFE; 16]);
        assert!(ipv4_with_lla.receiver_syntax_is_valid());
        assert!(ipv4_with_lla.is_well_formed());
        assert_eq!(ipv4_with_lla.ipv4(), Some([192, 0, 2, 1]));
        assert_eq!(
            ipv4_with_lla.smf_ipv6_link_local_address(),
            Some([0xFE; 16])
        );
        assert!(addr46.ipv6_interface_id().is_some());
    }

    #[test]
    fn test_drx_value_enum() {
        assert_eq!(DrxValue::from_u8(0x00), Some(DrxValue::NotSpecified));
        assert_eq!(DrxValue::from_u8(0x04), Some(DrxValue::Cycle256));
        assert_eq!(DrxValue::from_u8(0x05), Some(DrxValue::NotSpecified));
        assert_eq!(DrxValue::from_u8_strict(0x05), None);
    }

    #[test]
    fn test_gprs_timer_reserved_unit() {
        // Unit=3 is reserved per TS 24.008 §10.5.7.3:
        // "All other values shall be interpreted as multiples of 1 minute"
        let timer = NasGprsTimer::new(0b011 << 5 | 5);
        assert_eq!(timer.unit(), Some(GprsTimerUnit::OneMinute));
        assert_eq!(timer.to_seconds(), Some(300)); // 5 minutes
    }

    #[test]
    fn test_fgmm_capability_builder() {
        let cap =
            NasFGmmCapability::from_flags(true, false, false, false, false, false, false, true);
        assert!(cap.sgc());
        assert!(!cap.iphc_cp_ciot());
        assert!(cap.s1_mode());
    }

    #[test]
    fn test_network_feature_support_full() {
        let nfs =
            NasFGsNetworkFeatureSupport::from_features(true, false, 0, 0, false, false, true, true);
        assert!(nfs.ims_vops_3gpp());
        assert!(nfs.mcsi());
        assert!(nfs.emcn3());
    }

    #[test]
    fn test_mobile_identity_receiver_prefix_and_checked_builders() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let guti = Guti {
            plmn,
            amf_region_id: 1,
            amf_set_id: 0x03ff,
            amf_pointer: 0x3f,
            tmsi: 1,
        };
        let mut raw = NasFGsMobileIdentity::try_from_guti(&guti).unwrap().value;
        raw.push(0xaa);
        assert_eq!(NasFGsMobileIdentity::new(raw).as_guti(), Some(guti));

        assert!(
            NasFGsMobileIdentity::try_from_guti(&Guti {
                amf_set_id: 0x0400,
                ..guti
            })
            .is_none()
        );
        assert!(
            NasFGsMobileIdentity::try_from_guti(&Guti {
                amf_pointer: 0x40,
                ..guti
            })
            .is_none()
        );

        let s_tmsi = STmsi {
            amf_set_id: 0x03ff,
            amf_pointer: 0x3f,
            tmsi: 2,
        };
        let mut raw = NasFGsMobileIdentity::try_from_s_tmsi(&s_tmsi)
            .unwrap()
            .value;
        raw.push(0xaa);
        assert_eq!(NasFGsMobileIdentity::new(raw).as_s_tmsi(), Some(s_tmsi));
        assert!(
            NasFGsMobileIdentity::try_from_s_tmsi(&STmsi {
                amf_set_id: 0x0400,
                ..s_tmsi
            })
            .is_none()
        );

        let mut mac = NasFGsMobileIdentity::from_mac_address([1, 2, 3, 4, 5, 6]).value;
        mac.push(0xaa);
        assert_eq!(
            NasFGsMobileIdentity::new(mac).as_mac_address(),
            Some([1, 2, 3, 4, 5, 6])
        );

        let mut eui = NasFGsMobileIdentity::from_eui64([1, 2, 3, 4, 5, 6, 7, 8]).value;
        eui.push(0xaa);
        assert_eq!(
            NasFGsMobileIdentity::new(eui).as_eui64(),
            Some([1, 2, 3, 4, 5, 6, 7, 8])
        );
    }

    #[test]
    fn test_suci_and_plmn_checked_construction() {
        assert_eq!(ProtectionScheme::Reserved(0x12).try_to_u8(), None);
        assert_eq!(ProtectionScheme::HplmnDefined(1).try_to_u8(), None);
        assert_eq!(ProtectionScheme::Reserved(3).try_to_u8(), Some(3));
        assert_eq!(ProtectionScheme::HplmnDefined(0x0c).try_to_u8(), Some(0x0c));

        let invalid_plmn = PlmnId {
            mcc: [16, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        assert_eq!(invalid_plmn.try_to_tbcd(), None);

        let base = ImsiSuci {
            plmn_id: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            routing_indicator: vec![0xf0, 0xff],
            protection_scheme: ProtectionScheme::Null,
            home_nw_public_key_id: 0,
            scheme_output: vec![0x21],
        };
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(base.clone())).is_some());
        let mut invalid = base.clone();
        invalid.routing_indicator.push(0xff);
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        let mut invalid = base.clone();
        invalid.home_nw_public_key_id = 1;
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());

        let mut invalid = base.clone();
        invalid.routing_indicator = vec![0xff, 0xff];
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        assert!(
            !NasFGsMobileIdentity::new(hex::decode("0102f839ffff000021").unwrap()).is_well_formed()
        );

        let mut invalid = base.clone();
        invalid.protection_scheme = ProtectionScheme::ProfileA;
        invalid.home_nw_public_key_id = 0xff;
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        assert!(
            !NasFGsMobileIdentity::new(hex::decode("0102f839000001ff21").unwrap()).is_well_formed()
        );

        let mut invalid = base.clone();
        invalid.protection_scheme = ProtectionScheme::ProfileA;
        invalid.home_nw_public_key_id = 0;
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        assert!(
            !NasFGsMobileIdentity::new(hex::decode("0102f8390000010021").unwrap()).is_well_formed()
        );

        let mut invalid = base.clone();
        invalid.protection_scheme = ProtectionScheme::Reserved(3);
        invalid.home_nw_public_key_id = 1;
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        let mut invalid = base;
        invalid.scheme_output = vec![0xaa];
        assert!(NasFGsMobileIdentity::try_from_suci(&Suci::Imsi(invalid)).is_none());
        assert!(
            NasFGsMobileIdentity::from_suci_nai(SupiFormat::NetworkSpecific, "bad@@realm",)
                .is_none()
        );
    }

    #[test]
    fn test_nssai_and_qos_flow_checked_parsers() {
        assert!(NasNssai::new(vec![0]).try_parse_all().is_none());
        assert!(NasNssai::try_from_snssais(&[]).is_none());
        assert!(NasNssai::try_from_snssais(&[NasSNssai::new(Vec::new())]).is_none());

        let malformed = NasQosFlowDescriptions::new(hex::decode("01204101020900").unwrap());
        assert!(malformed.try_descriptions().is_none());

        let invalid_five_qi = [QosFlowDescription {
            qfi: 1,
            op_code: QosFlowOpCode::Create,
            e_flag: true,
            params: vec![QosFlowParameter::FiveQi(0)],
        }];
        assert!(NasQosFlowDescriptions::try_from_descriptions(&invalid_five_qi).is_none());

        let invalid_ebi = [QosFlowDescription {
            qfi: 1,
            op_code: QosFlowOpCode::Create,
            e_flag: true,
            params: vec![QosFlowParameter::EpsBearerId(0)],
        }];
        assert!(NasQosFlowDescriptions::try_from_descriptions(&invalid_ebi).is_none());
    }

    #[test]
    fn test_requested_mbs_typed_wire_values() {
        let wire = hex::decode("06c0000201ef010203").unwrap();
        let ie = NasRequestedMbsContainer::new(wire.clone());
        assert_eq!(
            ie.try_sessions(),
            Some(vec![RequestedMbsSession {
                operation: RequestedMbsOperation::Join,
                session_id: RequestedMbsSessionId::Ipv4 {
                    source: [192, 0, 2, 1],
                    destination: [239, 1, 2, 3],
                },
            }])
        );
        assert_eq!(
            NasRequestedMbsContainer::try_from_sessions(&ie.sessions())
                .unwrap()
                .value,
            wire
        );

        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let records = vec![
            RequestedMbsSession {
                operation: RequestedMbsOperation::Leave,
                session_id: RequestedMbsSessionId::Tmgi(MbsTmgi {
                    service_id: [1, 2, 3],
                    plmn: Some(plmn),
                }),
            },
            RequestedMbsSession {
                operation: RequestedMbsOperation::Join,
                session_id: RequestedMbsSessionId::Ipv6 {
                    source: [0x11; 16],
                    destination: [0x22; 16],
                },
            },
        ];
        let encoded = NasRequestedMbsContainer::try_from_sessions(&records).unwrap();
        assert_eq!(encoded.try_sessions(), Some(records));
        assert!(encoded.is_well_formed());
    }

    #[test]
    fn test_received_mbs_typed_roundtrip_and_fallbacks() {
        let simple = NasReceivedMbsContainer::new(vec![0x02, 0x00, 0x03, 1, 2, 3]);
        assert_eq!(
            simple.try_sessions(),
            Some(vec![ReceivedMbsSession {
                decision: MbsDecision::JoinAccepted,
                rejection_cause: None,
                tmgi: MbsTmgi {
                    service_id: [1, 2, 3],
                    plmn: None,
                },
                ipv4: None,
                ipv6: None,
                service_area: None,
                timer: None,
                security_keys: Vec::new(),
            }])
        );

        let fallback = NasReceivedMbsContainer::new(vec![0xe7, 0xe6, 0x03, 1, 2, 3]);
        let record = &fallback.try_sessions().unwrap()[0];
        assert_eq!(record.decision, MbsDecision::NoIndication);
        assert_eq!(record.rejection_cause, None);
        assert_eq!(record.timer, None);
        assert!(!fallback.is_well_formed());

        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let records = vec![ReceivedMbsSession {
            decision: MbsDecision::JoinAccepted,
            rejection_cause: None,
            tmgi: MbsTmgi {
                service_id: [4, 5, 6],
                plmn: Some(plmn),
            },
            ipv4: Some(([192, 0, 2, 1], [239, 1, 2, 3])),
            ipv6: None,
            service_area: Some(MbsServiceArea::TaiAndNrCgi {
                tais: vec![TaiListEntry::OnePlmnNonConsecutive {
                    plmn,
                    tacs: vec![[0, 0, 1]],
                }],
                nr_cgis: vec![MbsNrCgi {
                    nr_cell_id: 0x0a_bcde_f012,
                    plmn,
                }],
            }),
            timer: Some(MbsTimer::StartTime([1, 2, 3, 4, 5, 6])),
            security_keys: vec![MbsSecurityKeySet {
                key_domain_id: [1, 2, 3],
                msk_id: [4, 5, 6, 7],
                msk: [8; 16],
                mtk_id: Some([9, 10]),
                encrypted_mtk: Some([11; 16]),
            }],
        }];
        let encoded = NasReceivedMbsContainer::try_from_sessions(&records).unwrap();
        assert_eq!(encoded.try_sessions(), Some(records));
        assert!(encoded.is_well_formed());
    }

    #[test]
    fn test_ue_ds_tt_residence_time_typed_overflow() {
        let ie = NasUeDsTtResidenceTime::new(hex::decode("ffffffffffffff7f").unwrap());
        assert!(ie.is_overflow());
        assert_eq!(ie.correction_field(), Some(DsTtCorrectionField::OVERFLOW));
        assert_eq!(NasUeDsTtResidenceTime::overflow().value, ie.value);

        let field = DsTtCorrectionField::from_wire_bytes([1, 2, 3, 4, 5, 6, 7, 8]);
        let ie = NasUeDsTtResidenceTime::from_correction_field(field);
        assert_eq!(ie.correction_field(), Some(field));
        assert!(ie.is_well_formed());

        let mut excess = ie.value.clone();
        excess.push(9);
        assert_eq!(
            NasUeDsTtResidenceTime::new(excess).correction_field(),
            Some(field)
        );
    }

    #[test]
    fn test_uplink_data_status_skips_spare_psi_zero() {
        let status = NasUplinkDataStatus::from_sessions(&[0, 1, 15]);
        assert!(!status.has_data(0));
        assert!(status.has_data(1));
        assert!(status.has_data(15));
        assert_eq!(status.sessions_with_data(), vec![1, 15]);
        assert_eq!(status.value[0] & 0x01, 0);

        let received = NasUplinkDataStatus::new(vec![0x01, 0x00]);
        assert!(!received.has_data(0));
    }

    #[test]
    fn test_pdu_session_reactivation_result_skips_psi_zero() {
        let result = NasPduSessionReactivationResult::from_failed_sessions(&[0, 8, 15]);
        assert!(!result.reactivation_failed(0));
        assert!(result.reactivation_failed(8));
        assert!(result.reactivation_failed(15));
        assert_eq!(result.failed_sessions(), vec![8, 15]);
    }

    #[test]
    fn test_snssai_mapped_sst_roundtrip() {
        // SST + mapped SST (2 bytes, no SD)
        let contents = SNssaiContents {
            sst: 1,
            sd: None,
            mapped_sst: Some(2),
            mapped_sd: None,
        };
        let snssai = contents.to_snssai().unwrap();
        let parsed = snssai.parse().unwrap();
        assert_eq!(parsed.sst, 1);
        assert_eq!(parsed.sd, None);
        assert_eq!(parsed.mapped_sst, Some(2));
    }

    #[test]
    fn test_snssai_full_roundtrip() {
        // SST + SD + mapped SST + mapped SD (8 bytes)
        let contents = SNssaiContents {
            sst: 1,
            sd: Some([0x00, 0x00, 0x01]),
            mapped_sst: Some(2),
            mapped_sd: Some([0x00, 0x00, 0x02]),
        };
        let snssai = contents.to_snssai().unwrap();
        let parsed = snssai.parse().unwrap();
        assert_eq!(parsed.sst, 1);
        assert_eq!(parsed.sd, Some([0x00, 0x00, 0x01]));
        assert_eq!(parsed.mapped_sst, Some(2));
        assert_eq!(parsed.mapped_sd, Some([0x00, 0x00, 0x02]));
    }

    #[test]
    fn test_snssai_sst_sd_mapped_sst_roundtrip() {
        // SST + SD + mapped SST (5 bytes)
        let contents = SNssaiContents {
            sst: 3,
            sd: Some([0xAA, 0xBB, 0xCC]),
            mapped_sst: Some(4),
            mapped_sd: None,
        };
        let snssai = contents.to_snssai().unwrap();
        let parsed = snssai.parse().unwrap();
        assert_eq!(parsed.sst, 3);
        assert_eq!(parsed.sd, Some([0xAA, 0xBB, 0xCC]));
        assert_eq!(parsed.mapped_sst, Some(4));
        assert_eq!(parsed.mapped_sd, None);
    }

    #[test]
    fn test_tai_list_type01() {
        // Build a type 10 TAI list with 2 individual TAIs from different PLMNs.
        let tais = vec![
            TrackingAreaIdentity {
                plmn: PlmnId {
                    mcc: [2, 0, 8],
                    mnc: [9, 3, 0x0F],
                },
                tac: [0x00, 0x00, 0x01],
            },
            TrackingAreaIdentity {
                plmn: PlmnId {
                    mcc: [3, 1, 0],
                    mnc: [2, 6, 0],
                },
                tac: [0x00, 0x00, 0x02],
            },
        ];
        let tai_list = NasFGsTrackingAreaIdentityList::from_tai_list(&tais);
        let entries = tai_list.parse();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            TaiListEntry::DifferentPlmns(parsed) => assert_eq!(parsed, &tais),
            other => panic!("unexpected entry: {other:?}"),
        }
    }

    #[test]
    fn test_tai_list_consecutive_entry() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let tai_list =
            NasFGsTrackingAreaIdentityList::from_consecutive_tacs(&plmn, [0x00, 0x00, 0x01], 2);
        let entries = tai_list.parse();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            TaiListEntry::OnePlmnConsecutive {
                plmn: parsed_plmn,
                first_tac,
                count,
            } => {
                assert_eq!(parsed_plmn, &plmn);
                assert_eq!(*first_tac, [0x00, 0x00, 0x01]);
                assert_eq!(*count, 2);
                assert_eq!(
                    entries[0].tracking_area_identities(),
                    vec![
                        TrackingAreaIdentity {
                            plmn,
                            tac: [0x00, 0x00, 0x01],
                        },
                        TrackingAreaIdentity {
                            plmn,
                            tac: [0x00, 0x00, 0x02],
                        },
                    ]
                );
            }
            other => panic!("unexpected entry: {other:?}"),
        }
    }

    #[test]
    fn test_tai_list_builder_rejects_more_than_sixteen_entries() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        assert!(
            NasFGsTrackingAreaIdentityList::try_from_consecutive_tacs(
                &plmn,
                [0x00, 0x00, 0x01],
                20,
            )
            .is_none()
        );
        assert!(NasFGsTrackingAreaIdentityList::try_from_consecutive_tacs(
            &plmn,
            [0xff, 0xff, 0xff],
            2,
        )
        .is_none());
    }

    #[test]
    fn test_tai_list_from_entries() {
        let entries = vec![TaiListEntry::OnePlmnNonConsecutive {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            },
            tacs: vec![[0x00, 0x00, 0x01], [0x00, 0x00, 0x02]],
        }];
        let tai_list = NasFGsTrackingAreaIdentityList::from_entries(&entries);
        let parsed = tai_list.parse();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].tacs().len(), 2);
    }

    #[test]
    fn tai_list_distinguishes_receiver_prefix_from_sender_canonical_form() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let one = NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[[0x00, 0x00, 0x01]]);
        assert!(one.receiver_syntax_is_valid());
        assert!(one.is_well_formed());

        let mut truncated = one.value.clone();
        truncated[0] = 0x01;
        assert!(!NasFGsTrackingAreaIdentityList::new(truncated).receiver_syntax_is_valid());

        let sixteen = [[0x00, 0x00, 0x01]; 16];
        let mut tolerant = NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &sixteen).value;
        tolerant[0] = 0x1F;
        tolerant.push(0xAA);
        let tolerant = NasFGsTrackingAreaIdentityList::new(tolerant);
        assert!(tolerant.receiver_syntax_is_valid());
        assert!(!tolerant.is_well_formed());
    }

    #[test]
    fn test_suci_profile_a_roundtrip() {
        let suci = Suci::Imsi(ImsiSuci {
            plmn_id: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            },
            routing_indicator: vec![0xF0, 0xFF],
            protection_scheme: ProtectionScheme::ProfileA,
            home_nw_public_key_id: 1,
            scheme_output: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
        });
        let identity = NasFGsMobileIdentity::from_suci(&suci);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));
        let parsed = identity.as_suci().unwrap();
        match parsed {
            Suci::Imsi(parsed) => {
                assert_eq!(parsed.plmn_id.mcc_string(), "208");
                assert_eq!(parsed.protection_scheme, ProtectionScheme::ProfileA);
                assert_eq!(parsed.home_nw_public_key_id, 1);
                assert_eq!(
                    parsed.scheme_output,
                    match &suci {
                        Suci::Imsi(suci) => suci.scheme_output.clone(),
                        Suci::Utf8 { .. } => unreachable!(),
                    }
                );
            }
            Suci::Utf8 { .. } => panic!("expected IMSI-form SUCI"),
        }
    }

    #[test]
    fn test_suci_protection_scheme_reserved_and_hplmn_defined_ranges() {
        // Build a SUCI-like identity with protection scheme = 0x03 (reserved).
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let tbcd = plmn.to_tbcd();
        let mut value = vec![0x01]; // type=SUCI
        value.extend_from_slice(&tbcd);
        value.extend_from_slice(&[0xF0, 0xFF]); // routing indicator
        value.push(0x03); // reserved protection scheme
        value.push(0x01); // key id
        value.extend_from_slice(&[0xAA, 0xBB]); // scheme output
        let identity = NasFGsMobileIdentity::new(value);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));
        assert!(identity.as_suci().is_none());
        assert_eq!(identity.value[6] & 0x0f, 0x03);
        assert_eq!(
            ProtectionScheme::from_u8(identity.value[6]),
            Some(ProtectionScheme::Reserved(0x03))
        );

        let mut value = vec![0x01]; // type=SUCI
        value.extend_from_slice(&tbcd);
        value.extend_from_slice(&[0xF0, 0xFF]); // routing indicator
        value.push(0x0C); // first HPLMN-defined protection scheme
        value.push(0x01); // key id
        value.extend_from_slice(&[0xAA, 0xBB]); // scheme output
        let identity = NasFGsMobileIdentity::new(value);
        let parsed = identity.as_suci().unwrap();
        match parsed {
            Suci::Imsi(parsed) => {
                assert_eq!(
                    parsed.protection_scheme,
                    ProtectionScheme::HplmnDefined(0x0C)
                );
            }
            Suci::Utf8 { .. } => panic!("expected IMSI-form SUCI"),
        }
    }

    #[test]
    fn test_upu_data_sets_enforce_24501_structure() {
        let wire = hex::decode("00000000000000000000000000000000000001010003aabbcc").unwrap();
        let container = NasUeParametersUpdateTransparentContainer::new(wire.clone());
        let parsed = container.parse().unwrap();
        let UeParametersUpdateTransparentContainerContents::UpdateList(update) = &parsed else {
            panic!("expected update list");
        };
        assert_eq!(
            update.data_sets,
            [UeParametersUpdateDataSet::RoutingIndicatorUpdateData(vec![
                0xaa, 0xbb, 0xcc,
            ])]
        );
        assert_eq!(
            NasUeParametersUpdateTransparentContainer::from_parsed(&parsed)
                .unwrap()
                .value,
            wire
        );

        let base = UeParametersUpdateListContents {
            acknowledgement_requested: false,
            re_registration_requested: false,
            upu_mac_iausf: [0; 16],
            counter_upu: 1,
            data_sets: Vec::new(),
        };
        let rejected = [
            UeParametersUpdateDataSet::Unknown {
                data_set_type: 6,
                contents: vec![0xaa],
            },
            UeParametersUpdateDataSet::DefaultConfiguredNssaiUpdateData(NasNssai::new(vec![0])),
            UeParametersUpdateDataSet::MeRoutingIndicatorUpdateData([0xff, 0xff]),
            UeParametersUpdateDataSet::ProtectedUeParametersUpdateHeaderInformation(
                UeParametersUpdateProtectedHeaderInformation {
                    acknowledgement_requested: false,
                    re_registration_requested: false,
                    data_type: UeParametersUpdateDataType::Acknowledgement,
                },
            ),
        ];
        for data_set in rejected {
            let contents = UeParametersUpdateTransparentContainerContents::UpdateList(
                UeParametersUpdateListContents {
                    data_sets: vec![data_set],
                    ..base.clone()
                },
            );
            assert!(NasUeParametersUpdateTransparentContainer::from_parsed(&contents).is_none());
        }
        let oversized = UeParametersUpdateTransparentContainerContents::UpdateList(
            UeParametersUpdateListContents {
                data_sets: vec![UeParametersUpdateDataSet::RoutingIndicatorUpdateData(vec![
                    0;
                    u16::MAX as usize
                ])],
                ..base
            },
        );
        assert!(NasUeParametersUpdateTransparentContainer::from_parsed(&oversized).is_none());
    }

    #[test]
    fn test_plmn_invalid_digits_returns_none() {
        // Byte with nibble > 9 (0xAB has nibbles 0xB and 0xA, both > 9)
        assert!(PlmnId::from_tbcd(&[0xAB, 0x00, 0x00]).is_none());
        // Valid PLMN should still work
        assert!(PlmnId::from_tbcd(&[0x02, 0xF8, 0x39]).is_some());
    }

    #[test]
    fn test_eap_length() {
        // EAP Success: code=3, id=1, length=4
        let eap = NasEapMessage::from_eap_data(vec![0x03, 0x01, 0x00, 0x04]);
        assert_eq!(eap.eap_length(), Some(4));
        // Too short
        let eap_short = NasEapMessage::from_eap_data(vec![0x03]);
        assert_eq!(eap_short.eap_length(), None);
    }

    #[test]
    fn test_gprs_timer3_deactivated_clears_value() {
        let timer = NasGprsTimer3::from_unit_value(GprsTimer3Unit::Deactivated, 15);
        assert_eq!(timer.timer_value(), Some(0)); // value forced to 0
        assert_eq!(timer.to_seconds(), None);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Rel-17/18 structured parsers
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_n3iwf_identifier_ipv4_roundtrip() {
        let id = NasN3iwfIdentifier::from_address(&N3iwfAddress::Ipv4([10, 0, 0, 1]));
        assert_eq!(id.id_type(), Some(N3iwfIdentifierType::Ipv4));
        match id.address() {
            Some(N3iwfAddress::Ipv4(ip)) => assert_eq!(ip, [10, 0, 0, 1]),
            other => panic!("expected Ipv4, got {:?}", other),
        }
    }

    #[test]
    fn test_n3iwf_identifier_ipv4v6_roundtrip() {
        let ipv4 = [192, 168, 1, 1];
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let id = NasN3iwfIdentifier::from_address(&N3iwfAddress::Ipv4v6 { ipv4, ipv6 });
        match id.address() {
            Some(N3iwfAddress::Ipv4v6 { ipv4: a, ipv6: b }) => {
                assert_eq!(a, ipv4);
                assert_eq!(b, ipv6);
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_n3iwf_identifier_fqdn() {
        let bytes = b"\x07example\x03com\x00".to_vec();
        let id = NasN3iwfIdentifier::from_address(&N3iwfAddress::Fqdn(bytes.clone()));
        assert_eq!(id.id_type(), Some(N3iwfIdentifierType::Fqdn));
        match id.address() {
            Some(N3iwfAddress::Fqdn(b)) => assert_eq!(b, bytes),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_tnan_information_both_fields() {
        let tngf = b"tngf-id-bytes";
        let ssid = b"SSID";
        let ie = NasTnanInformation::from_tngf_id(tngf).with_ssid(Some(ssid));
        assert!(ie.tngf_id_indicator());
        assert!(ie.ssid_indicator());
        assert_eq!(ie.tngf_id().unwrap(), tngf);
        assert_eq!(ie.ssid().unwrap(), ssid);
    }

    #[test]
    fn test_tnan_information_ssid_only() {
        let ie = NasTnanInformation::from_ssid(b"WLAN-AP");
        assert!(!ie.tngf_id_indicator());
        assert!(ie.ssid_indicator());
        assert_eq!(ie.tngf_id(), None);
        assert_eq!(ie.ssid().unwrap(), b"WLAN-AP");
    }

    #[test]
    fn test_extended_rejected_nssai_uses_typed_backoff_timer() {
        let timer = NasGprsTimer3::from_unit_value(GprsTimer3Unit::TenMinutes, 7);
        let ie =
            NasExtendedRejectedNssai::from_partial_lists(&[ExtendedRejectedNssaiPartialList {
                type_of_list: 1,
                back_off_timer: Some(timer.clone()),
                rejected: vec![ExtendedRejectedSNssai {
                    cause: 3,
                    s_nssai: vec![0x01, 0x02, 0x03, 0x04],
                }],
            }]);

        let parsed = ie.partial_lists();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].back_off_timer.as_ref(), Some(&timer));
        assert_eq!(parsed[0].rejected[0].cause, 3);
    }

    #[test]
    fn test_operator_access_category_rejects_reserved_criterion() {
        let reserved = NasOperatorDefinedAccessCategoryDefinitions::from_data(vec![
            0x04, 0x01, 0x03, 0x01, 0x07,
        ]);
        assert!(reserved.try_definitions().is_none());

        let dnn = crate::common::encode_labels("internet", 100).unwrap();
        let definition = OperatorAccessCategoryDefinition {
            precedence: 1,
            psac: true,
            category_number_raw: 3,
            criteria: vec![OperatorAccessCategoryCriterion::Dnns(vec![dnn])],
            standardised_category: Some(7),
        };
        let encoded = NasOperatorDefinedAccessCategoryDefinitions::try_from_definitions(
            std::slice::from_ref(&definition),
        )
        .unwrap();
        assert_eq!(encoded.definitions(), [definition]);
        assert!(
            NasOperatorDefinedAccessCategoryDefinitions::try_from_definitions(&[
                OperatorAccessCategoryDefinition {
                    precedence: 1,
                    psac: false,
                    category_number_raw: 3,
                    criteria: vec![OperatorAccessCategoryCriterion::OsApps(vec![(
                        vec![0; 15],
                        vec![],
                    )])],
                    standardised_category: None,
                },
            ])
            .is_none()
        );
    }

    #[test]
    fn test_ran_timing_sync() {
        let ie = NasRanTimingSynchronization::from_recreation_request(true);
        assert!(ie.recreation_request());
        let ie = NasRanTimingSynchronization::from_recreation_request(false);
        assert!(!ie.recreation_request());
    }

    #[test]
    fn test_non_3gpp_path_switching_information() {
        let ie = NasNon3GppAccessPathSwitchingIndication::from_naps(true);
        assert!(ie.naps());

        let ie = NasNon3GppPathSwitchingInformation::from_nsonr(true);
        assert!(ie.nsonr());
    }

    #[test]
    fn test_aun3_indication() {
        let ie = NasAun3Indication::from_aun3reg(true);
        assert!(ie.aun3reg());
    }

    #[test]
    fn test_feature_authorization_indication() {
        let ie = NasFeatureAuthorizationIndication::from_flags(
            true,
            FeatureAuthMbsraiValue::AuthorizedAsMbsr,
        );
        assert!(ie.hpase());
        assert_eq!(ie.mbsrai(), Some(FeatureAuthMbsraiValue::AuthorizedAsMbsr));
        assert_eq!(ie.mbsrai_raw(), 2);
    }

    #[test]
    fn test_aun3_device_security_key_roundtrip() {
        let key = vec![0xDE; 32];
        let ie = NasAun3DeviceSecurityKey::from_typed(Aun3DeviceSecurityKeyType::KWagfKey, &key);
        assert_eq!(ie.askt(), Some(Aun3DeviceSecurityKeyType::KWagfKey));
        assert_eq!(ie.key_length(), Some(32));
        assert_eq!(ie.key().unwrap(), key.as_slice());
        assert_eq!(
            Aun3DeviceSecurityKeyType::from_u8(2),
            Some(Aun3DeviceSecurityKeyType::MasterSessionKey)
        );
        assert_eq!(Aun3DeviceSecurityKeyType::from_u8_strict(2), None);
        assert!(
            NasAun3DeviceSecurityKey::try_from_typed(
                Aun3DeviceSecurityKeyType::MasterSessionKey,
                &[0u8; 31],
            )
            .is_err()
        );
        assert!(
            NasAun3DeviceSecurityKey::try_from_typed(
                Aun3DeviceSecurityKeyType::MasterSessionKey,
                &[0u8; 254],
            )
            .is_err()
        );
    }

    #[test]
    fn test_on_demand_nssai_roundtrip() {
        let entries = vec![
            OnDemandNssaiEntry {
                s_nssai: vec![0x01],
                slice_dereg_inactivity_timer: Some([0x00, 0x01, 0x2C]),
            },
            OnDemandNssaiEntry {
                s_nssai: vec![0x02, 0x00, 0x00, 0x01],
                slice_dereg_inactivity_timer: None,
            },
        ];
        assert!(NasOnDemandNssai::try_from_entries(&entries).is_ok());
        let ie = NasOnDemandNssai::from_entries(&entries);
        let parsed = ie.entries();
        assert_eq!(parsed, entries);
        assert!(
            NasOnDemandNssai::try_from_entries(&vec![
                OnDemandNssaiEntry {
                    s_nssai: vec![0x01],
                    slice_dereg_inactivity_timer: None,
                };
                17
            ])
            .is_err()
        );
        assert!(
            NasOnDemandNssai::try_from_entries(&[OnDemandNssaiEntry {
                s_nssai: vec![0x01, 0x02, 0x03],
                slice_dereg_inactivity_timer: None,
            }])
            .is_err()
        );
        assert!(
            NasOnDemandNssai::new(vec![0x03, 0x01, 0x01, 0xAA])
                .entries()
                .is_empty()
        );
    }

    #[test]
    fn test_extended_5gmm_cause() {
        let ie = NasExtendedFGmmCause::from_satellite_nr_allowed(true);
        assert!(ie.satellite_nr_allowed());
        assert!(ie.spare_bits_are_zero());
        assert!(ie.validate_strict().is_ok());
        assert!(
            NasExtendedFGmmCause::from_data(vec![0x02])
                .validate_strict()
                .is_err()
        );
        assert!(
            NasExtendedFGmmCause::from_data(vec![0x00, 0x00])
                .validate_strict()
                .is_err()
        );
    }

    #[test]
    fn test_partial_nssai_roundtrip() {
        let entries = vec![
            PartialNssaiEntry {
                s_nssai: vec![0x01],
                tai_list: vec![0x00, 0x02, 0xF8, 0x39, 0x00, 0x00, 0x01],
            },
            PartialNssaiEntry {
                s_nssai: vec![0x02, 0xAA, 0xBB, 0xCC],
                tai_list: vec![],
            },
        ];
        assert!(NasPartialNssai::try_from_entries(&entries).is_ok());
        let ie = NasPartialNssai::from_entries(&entries);
        assert_eq!(ie.entries(), entries);

        let plmn = PlmnId::from_tbcd(&[0x02, 0xF8, 0x39]).unwrap();
        let tai_list =
            NasFGsTrackingAreaIdentityList::from_consecutive_tacs(&plmn, [0x00, 0x00, 0x01], 16);
        assert!(
            NasPartialNssai::try_from_entries(&[PartialNssaiEntry {
                s_nssai: vec![0x01],
                tai_list: tai_list.value.clone(),
            }])
            .is_err()
        );
        assert!(
            NasPartialNssai::try_from_entries(&[PartialNssaiEntry {
                s_nssai: vec![0x01],
                tai_list: vec![0x00],
            }])
            .is_err()
        );
    }

    #[test]
    fn test_service_area_list_roundtrip_preserves_wire_forms() {
        let allowed = ServiceAreaListAllowedType::Allowed;
        let non_allowed = ServiceAreaListAllowedType::NonAllowed;
        let plmn = PlmnId::from_tbcd(&[0x02, 0xF8, 0x39]).unwrap();
        let tais = vec![
            TrackingAreaIdentity {
                plmn,
                tac: [0x00, 0x00, 0x01],
            },
            TrackingAreaIdentity {
                plmn: PlmnId::from_tbcd(&[0x13, 0x00, 0x62]).unwrap(),
                tac: [0x00, 0x00, 0x02],
            },
        ];
        let entries = vec![
            ServiceAreaListEntry::OnePlmnNonConsecutive {
                allowed,
                plmn,
                tacs: vec![[0x00, 0x00, 0x01], [0x00, 0x00, 0x03]],
            },
            ServiceAreaListEntry::OnePlmnConsecutive {
                allowed,
                plmn,
                first_tac: [0x00, 0x10, 0x00],
                count: 3,
            },
            ServiceAreaListEntry::DifferentPlmns {
                allowed,
                tais: tais.clone(),
            },
            ServiceAreaListEntry::PlmnOnly { allowed, plmn },
        ];

        let ie = NasServiceAreaList::from_entries(&entries);
        let mut expected = entries.clone();
        if let ServiceAreaListEntry::PlmnOnly { allowed, .. } = &mut expected[3] {
            *allowed = ServiceAreaListAllowedType::Allowed;
        }
        assert_eq!(ie.entries(), expected);
        assert!(ie.receiver_syntax_is_valid());
        assert!(ie.is_well_formed());
        let allowed_one = NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0x00, 0x00, 0x01]]);
        let non_allowed_one =
            NasServiceAreaList::from_plmn_tacs(non_allowed, &plmn, &[[0x00, 0x00, 0x02]]);
        let mixed = NasServiceAreaList::new([allowed_one.value, non_allowed_one.value].concat());
        assert!(!mixed.receiver_syntax_is_valid());
        assert!(!mixed.is_well_formed());
        let mut truncated =
            NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0x00, 0x00, 0x01]]);
        truncated.value[0] = 0x01;
        assert!(!truncated.receiver_syntax_is_valid());
        let fallback = NasServiceAreaList::new([vec![0xE0], plmn.to_tbcd().to_vec()].concat());
        assert!(fallback.receiver_syntax_is_valid());
        assert!(!fallback.is_well_formed());
        assert_eq!(
            NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0x00, 0x00, 0x01]]).entries(),
            vec![ServiceAreaListEntry::OnePlmnNonConsecutive {
                allowed,
                plmn,
                tacs: vec![[0x00, 0x00, 0x01]],
            }]
        );
        assert_eq!(
            NasServiceAreaList::from_consecutive_tacs(allowed, &plmn, [0x00, 0x10, 0x00], 2)
                .entries(),
            vec![ServiceAreaListEntry::OnePlmnConsecutive {
                allowed,
                plmn,
                first_tac: [0x00, 0x10, 0x00],
                count: 2,
            }]
        );
        assert_eq!(
            NasServiceAreaList::from_different_plmns(allowed, &tais).entries(),
            vec![ServiceAreaListEntry::DifferentPlmns { allowed, tais }]
        );
    }

    #[test]
    fn test_alternative_nssai_roundtrip() {
        let entries = vec![AlternativeNssaiEntry {
            replaced: vec![0x01],
            alternative: vec![0x02, 0x00, 0x00, 0x42],
        }];
        assert!(NasAlternativeNssai::try_from_entries(&entries).is_ok());
        let ie = NasAlternativeNssai::from_entries(&entries);
        assert_eq!(ie.entries(), entries);
        assert!(
            NasAlternativeNssai::try_from_entries(&vec![
                AlternativeNssaiEntry {
                    replaced: vec![0x01],
                    alternative: vec![0x02],
                };
                9
            ])
            .is_err()
        );
        assert!(
            NasAlternativeNssai::try_from_entries(&[AlternativeNssaiEntry {
                replaced: vec![0x01, 0x02, 0x03],
                alternative: vec![0x02],
            }])
            .is_err()
        );
    }

    #[test]
    fn test_snpn_list_roundtrip() {
        let plmn = PlmnId::from_tbcd(&[0x02, 0xF8, 0x39]).unwrap();
        let entry = SnpnListEntry {
            plmn,
            nid: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB],
        };
        let ie = NasSnpnList::from_entries(std::slice::from_ref(&entry));
        let parsed = ie.entries();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], entry);
    }

    #[test]
    fn test_peips_assistance_information_roundtrip() {
        let entries = vec![PeipsAssistanceInformationEntry::PagingSubgroupId(0x05)];
        let ie = NasPeipsAssistanceInformation::from_entries(&entries);
        assert_eq!(ie.entries(), entries);
        assert_eq!(ie.data(), &[0x05]);
        assert_eq!(
            NasPeipsAssistanceInformation::from_data(vec![0x1F]).entry(),
            Some(PeipsAssistanceInformationEntry::PagingSubgroupId(0))
        );
        assert_eq!(
            NasPeipsAssistanceInformation::from_data(vec![0x3F]).entry(),
            Some(PeipsAssistanceInformationEntry::UePagingProbabilityInformation(20))
        );
    }

    #[test]
    fn test_deregistration_request_from_ue_packed_ksi_helpers() {
        let msg = crate::nas_5gs::messages::NasDeregistrationRequestFromUe::new(
            NasDeRegistrationType::new(0x09),
            NasFGsMobileIdentity::from_no_identity(),
        )
        .with_ngksi(3)
        .with_tsc(true);

        assert_eq!(msg.ngksi(), 3);
        assert!(msg.tsc());
        assert_eq!(msg.nas_key_set_identifier().ngksi(), 3);
        assert!(msg.nas_key_set_identifier().tsc());
        assert_eq!(msg.de_registration_type.value, 0xB9);
    }

    #[test]
    fn test_relay_key_request_parameters_roundtrip() {
        let p = RelayKeyRequestParameters {
            relay_service_code: 0x123456,
            nonce_1: [0xAA; 16],
            uit: true,
            ue_id: vec![0x01, 0x02, 0x03, 0x04],
        };
        let ie = NasRelayKeyRequestParameters::from_parsed(&p);
        assert_eq!(ie.parse(), Some(p));
    }

    #[test]
    fn test_relay_key_response_parameters_roundtrip() {
        let p = RelayKeyResponseParameters {
            key_knr_prose: [0x55; 32],
            nonce_2: [0x77; 16],
            cp_pruk_id: vec![0x10, 0x20, 0x30],
        };
        let ie = NasRelayKeyResponseParameters::from_parsed(&p);
        assert_eq!(ie.parse(), Some(p));
    }

    #[test]
    fn test_ecn_marking_l4s_indication() {
        let qris = [0x05u8, 0x07, 0x09];
        let ie = NasEcnMarkingL4sIndication::from_qri_values(&qris);
        assert_eq!(ie.qri_values(), &qris);
        let ie = NasEcnMarkingL4sIndication::try_from_qri_values(&qris).unwrap();
        assert_eq!(ie.qri_values(), &qris);
        assert!(NasEcnMarkingL4sIndication::try_from_qri_values(&[0]).is_err());
    }

    #[test]
    fn test_qos_flow_descriptions_typed_roundtrip() {
        let descriptions = vec![QosFlowDescription {
            qfi: 9,
            op_code: QosFlowOpCode::Create,
            e_flag: true,
            params: vec![
                QosFlowParameter::FiveQi(7),
                QosFlowParameter::GfbrUl(QosFlowBitRate {
                    unit: SessionAmbrUnit::Mbps1 as u8,
                    value: 10,
                }),
                QosFlowParameter::AveragingWindow(32),
                QosFlowParameter::EpsBearerId(5),
            ],
        }];

        let ie = NasQosFlowDescriptions::from_descriptions(&descriptions);
        assert_eq!(ie.descriptions(), descriptions);
    }

    #[test]
    fn test_qos_rules_typed_roundtrip() {
        let rules = vec![QosRule {
            rule_id: 3,
            op_code: QosRuleOpCode::Create,
            dqr: true,
            packet_filters: vec![QosPacketFilter::Match {
                direction: QosPacketFilterDirection::Bidirectional,
                identifier: 4,
                components: vec![
                    QosPacketFilterComponent::Ipv4RemoteAddress {
                        address: [10, 0, 0, 1],
                        mask: [255, 255, 255, 255],
                    },
                    QosPacketFilterComponent::SingleLocalPort(8080),
                    QosPacketFilterComponent::CTagPcpDei {
                        pcp_present: true,
                        dei_present: true,
                        pcp: 5,
                        dei: true,
                    },
                ],
            }],
            precedence: Some(11),
            qfi: Some(7),
            segregation: Some(true),
        }];

        let ie = NasQosRules::from_rules(&rules);
        assert_eq!(ie.rules(), rules);
        assert!(ie.validate_strict().is_ok());
    }

    #[test]
    fn test_qos_rules_strict_semantic_validation() {
        let match_all_with_extra = vec![QosRule {
            rule_id: 1,
            op_code: QosRuleOpCode::Create,
            dqr: false,
            packet_filters: vec![QosPacketFilter::Match {
                direction: QosPacketFilterDirection::Bidirectional,
                identifier: 1,
                components: vec![
                    QosPacketFilterComponent::MatchAll,
                    QosPacketFilterComponent::SingleRemotePort(2152),
                ],
            }],
            precedence: Some(1),
            qfi: Some(1),
            segregation: Some(false),
        }];
        assert!(NasQosRules::try_from_rules(&match_all_with_extra).is_none());

        let duplicate_ids = vec![QosRule {
            rule_id: 2,
            op_code: QosRuleOpCode::Create,
            dqr: false,
            packet_filters: vec![
                QosPacketFilter::Match {
                    direction: QosPacketFilterDirection::Bidirectional,
                    identifier: 1,
                    components: vec![QosPacketFilterComponent::SingleRemotePort(2152)],
                },
                QosPacketFilter::Match {
                    direction: QosPacketFilterDirection::Bidirectional,
                    identifier: 1,
                    components: vec![QosPacketFilterComponent::SingleLocalPort(2152)],
                },
            ],
            precedence: Some(1),
            qfi: Some(1),
            segregation: Some(false),
        }];
        assert!(NasQosRules::try_from_rules(&duplicate_ids).is_none());

        let mixed_ip_families = vec![QosRule {
            rule_id: 3,
            op_code: QosRuleOpCode::Create,
            dqr: false,
            packet_filters: vec![QosPacketFilter::Match {
                direction: QosPacketFilterDirection::Bidirectional,
                identifier: 1,
                components: vec![
                    QosPacketFilterComponent::Ipv4RemoteAddress {
                        address: [192, 0, 2, 1],
                        mask: [255, 255, 255, 255],
                    },
                    QosPacketFilterComponent::Ipv6LocalAddressPrefix {
                        address: [0; 16],
                        prefix_length: 64,
                    },
                ],
            }],
            precedence: Some(1),
            qfi: Some(1),
            segregation: Some(false),
        }];
        assert!(NasQosRules::try_from_rules(&mixed_ip_families).is_none());
    }

    #[test]
    fn test_service_level_aa_container_roundtrip() {
        let parameters = vec![
            ServiceLevelAaParameter::DeviceId("sensor-1".into()),
            ServiceLevelAaParameter::ServerAddress(ServiceLevelAaServerAddress::Ipv4([1, 2, 3, 4])),
            ServiceLevelAaParameter::Response(ServiceLevelAaResponse {
                c2ar: ServiceLevelAaResponseC2AuthorizationResult::Successful,
                slar: ServiceLevelAaResponseResult::NotSuccessfulOrRevoked,
            }),
            ServiceLevelAaParameter::PayloadType(ServiceLevelAaPayloadType::Uuaa),
            ServiceLevelAaParameter::Payload(vec![0xAA, 0xBB, 0xCC]),
            ServiceLevelAaParameter::PendingIndication(true),
            ServiceLevelAaParameter::ServiceStatusIndication(false),
        ];

        let ie = NasServiceLevelAaContainer::from_parameters(&parameters).unwrap();
        assert!(ie.validate_strict().is_ok());
        assert_eq!(ie.parameters().unwrap(), parameters);
    }

    #[test]
    fn test_service_level_aa_server_address_variants() {
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let parameters = vec![
            ServiceLevelAaParameter::ServerAddress(ServiceLevelAaServerAddress::Ipv6(ipv6)),
            ServiceLevelAaParameter::ServerAddress(ServiceLevelAaServerAddress::Ipv4v6 {
                ipv4: [192, 0, 2, 1],
                ipv6,
            }),
            ServiceLevelAaParameter::ServerAddress(ServiceLevelAaServerAddress::Fqdn(
                "sl-aa.example".into(),
            )),
        ];

        let ie = NasServiceLevelAaContainer::from_parameters(&parameters).unwrap();
        assert!(ie.validate_strict().is_ok());
        assert_eq!(ie.parameters().unwrap(), parameters);
    }

    #[test]
    fn test_service_level_aa_container_strict_validation() {
        let missing_payload =
            NasServiceLevelAaContainer::from_container_data(vec![0x40, 0x01, 0x01]);
        assert!(missing_payload.parameters().is_ok());
        assert!(missing_payload.validate_strict().is_err());

        let pending_spare = NasServiceLevelAaContainer::from_container_data(vec![0xA2]);
        assert_eq!(
            pending_spare.parameters().unwrap(),
            vec![ServiceLevelAaParameter::PendingIndication(false)]
        );
        assert!(pending_spare.validate_strict().is_err());

        let status_spare = NasServiceLevelAaContainer::from_container_data(vec![0x50, 0x01, 0x02]);
        assert_eq!(
            status_spare.parameters().unwrap(),
            vec![ServiceLevelAaParameter::ServiceStatusIndication(false)]
        );
        assert!(status_spare.validate_strict().is_err());
    }

    #[test]
    fn test_service_level_aa_container_rejects_truncated_payload() {
        let ie = NasServiceLevelAaContainer::from_container_data(vec![0x70, 0x00, 0x02, 0xAA]);
        assert!(ie.parameters().is_err());
    }

    #[test]
    fn test_service_level_aa_container_ignores_unknown_parameter_iei() {
        let ie = NasServiceLevelAaContainer::from_container_data(vec![
            0x10, 0x08, b's', b'e', b'n', b's', b'o', b'r', b'-', b'1', 0x60, 0x03, 0x00, 0x03,
            0x84, 0x50, 0x01, 0x00,
        ]);

        assert_eq!(
            ie.parameters().unwrap(),
            vec![
                ServiceLevelAaParameter::DeviceId("sensor-1".into()),
                ServiceLevelAaParameter::ServiceStatusIndication(false),
            ]
        );
    }

    #[test]
    fn test_common_transparent_container_helpers() {
        let ksi = NasKeySetIdentifier::new(0x09);
        let intra = NasIntraN1ModeNasTransparentContainer::from_fields(
            0x11223344,
            NasSecurityAlgorithms::from_algorithms(
                CipheringAlgorithm::NEA2,
                IntegrityAlgorithm::NIA2,
            ),
            true,
            ksi.clone(),
            0x5A,
        );
        assert_eq!(intra.message_authentication_code(), Some(0x11223344));
        assert_eq!(
            intra.security_algorithms().unwrap().ciphering(),
            Some(CipheringAlgorithm::NEA2)
        );
        assert_eq!(
            intra.security_algorithms().unwrap().integrity(),
            Some(IntegrityAlgorithm::NIA2)
        );
        assert_eq!(intra.k_amf_change_flag(), Some(true));
        assert_eq!(intra.key_set_identifier(), Some(ksi.clone()));
        assert_eq!(intra.sequence_number(), Some(0x5A));

        let s1_to_n1 = NasS1ModeToN1ModeNasTransparentContainer::from_fields(
            0x55667788,
            NasSecurityAlgorithms::from_algorithms(
                CipheringAlgorithm::NEA1,
                IntegrityAlgorithm::NIA1,
            ),
            5,
            ksi.clone(),
        );
        assert_eq!(s1_to_n1.message_authentication_code(), Some(0x55667788));
        assert_eq!(s1_to_n1.ncc(), Some(5));
        assert_eq!(s1_to_n1.key_set_identifier(), Some(ksi));
        assert!(s1_to_n1.spare_octets_are_zero());

        let n1_to_s1 = NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x9C);
        assert_eq!(n1_to_s1.sequence_number(), 0x9C);
    }

    #[test]
    fn test_late_release_raw_pass_through_helpers() {
        macro_rules! assert_raw_roundtrip {
            ($ty:ty) => {{
                let data = vec![0xAA, 0xBB, 0xCC];
                let ie = <$ty>::from_data(data.clone());
                assert_eq!(ie.data(), data.as_slice(), stringify!($ty));
            }};
        }

        assert_raw_roundtrip!(NasAccessTechnologyUtilizationControl);
        assert_raw_roundtrip!(NasUeParametersUpdateTransparentContainer);
        assert_raw_roundtrip!(NasRelayKeyRequestParameters);
        assert_raw_roundtrip!(NasRelayKeyResponseParameters);
        let mut relay = NasRelayKeyResponseParameters::from_data(vec![0; 49]);
        relay.set_data(vec![1; 50]);
        assert_eq!(relay.length, 50);
        assert_eq!(relay.with_data(vec![2; 51]).length, 51);
        assert_raw_roundtrip!(NasSnpnList);
        assert_raw_roundtrip!(NasN3iwfIdentifier);
        assert_raw_roundtrip!(NasTnanInformation);
        assert_raw_roundtrip!(NasRanTimingSynchronization);
        assert_raw_roundtrip!(NasExtendedLadnInformation);
        assert_raw_roundtrip!(NasAlternativeNssai);
        assert_raw_roundtrip!(NasType6IeContainer);
        assert_raw_roundtrip!(NasNon3GppAccessPathSwitchingIndication);
        assert_raw_roundtrip!(NasSNssaiLocationValidityInformation);
        assert_raw_roundtrip!(NasSNssaiTimeValidityInformation);
        assert_raw_roundtrip!(NasNon3GppPathSwitchingInformation);
        assert_raw_roundtrip!(NasPartialNssai);
        assert_raw_roundtrip!(NasAun3Indication);
        assert_raw_roundtrip!(NasFeatureAuthorizationIndication);
        assert_raw_roundtrip!(NasAun3DeviceSecurityKey);
        assert_raw_roundtrip!(NasOnDemandNssai);
        assert_raw_roundtrip!(NasEcsAddress);
        assert_raw_roundtrip!(NasN3Qai);
        assert_raw_roundtrip!(NasNon3GppDelayBudget);
        assert_raw_roundtrip!(NasUrspRuleEnforcementReports);
        assert_raw_roundtrip!(NasRemoteUeContextList);
        assert_raw_roundtrip!(NasProtocolDescription);
        assert_raw_roundtrip!(NasNon3GppDeviceInformation);

        let requested = NasRequestedMbsContainer::from_container_data(vec![0x01, 0x02]);
        assert_eq!(requested.container_data(), &[0x01, 0x02]);
        let received = NasReceivedMbsContainer::from_container_data(vec![0x03, 0x04]);
        assert_eq!(received.container_data(), &[0x03, 0x04]);

        let ecs = NasEcsAddress::from_address_data(vec![0x02, 0x03, b'a', b'p', b'p']);
        assert_eq!(ecs.address_type(), Some(EcsAddressType::Fqdn));
        assert_eq!(
            ecs.spatial_validity_type(),
            Some(EcsSpatialValidityType::None)
        );
        assert_eq!(ecs.ecs_address_bytes(), Some(b"app".as_slice()));

        let payload_info = NasPayloadContainerInformation::from_pru(true);
        assert!(payload_info.pru());
    }

    #[test]
    fn test_time_duration_helpers() {
        let ie = NasTimeDuration::from_seconds(3600).unwrap();
        assert_eq!(ie.seconds(), Some(3600));
    }

    #[test]
    fn test_ciot_small_data_container_roundtrip() {
        let control_plane = CiotSmallDataContainerContents::ControlPlaneUserData {
            downlink_data_expected:
                CiotSmallDataDownlinkDataExpected::SingleDownlinkNoFurtherUplink,
            pdu_session_id: 3,
            data: vec![0xAA, 0xBB],
        };
        let ie = NasCiotSmallDataContainer::from_parsed(&control_plane).unwrap();
        assert_eq!(ie.parse(), Some(control_plane));

        let lcs = CiotSmallDataContainerContents::LocationServicesMessageContainer {
            downlink_data_expected: CiotSmallDataDownlinkDataExpected::NoFurtherUplinkOrDownlink,
            additional_information: vec![0x10, 0x20],
            data: vec![0x33, 0x44],
        };
        let ie = NasCiotSmallDataContainer::from_parsed(&lcs).unwrap();
        assert_eq!(ie.parse(), Some(lcs));
        assert!(ie.validate_strict().is_ok());

        let reserved_dde = NasCiotSmallDataContainer::from_data(vec![0x18]);
        assert!(reserved_dde.validate_strict().is_err());

        let lcs_bad_spare = NasCiotSmallDataContainer::from_data(vec![0x41, 0x00]);
        assert!(lcs_bad_spare.validate_strict().is_err());

        let lcs_bad_length = NasCiotSmallDataContainer::from_data(vec![0x40, 0x02, 0xAA]);
        assert!(lcs_bad_length.validate_strict().is_err());
    }

    #[test]
    fn test_extended_ladn_information_roundtrip() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let entry = ExtendedLadnInformationEntry {
            dnn: NasDnn::from_string("internet").unwrap(),
            s_nssai: NasSNssai::from_sst_sd(1, Some([0x00, 0x00, 0x01])),
            tai_list: NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[[0x00, 0x00, 0x01]]),
        };

        let ie = NasExtendedLadnInformation::from_entries(std::slice::from_ref(&entry)).unwrap();
        let parsed = ie.entries();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].dnn.as_string(), Some("internet".to_string()));
        assert_eq!(parsed[0].s_nssai.parse(), entry.s_nssai.parse());
        assert_eq!(parsed[0].tai_list.parse(), entry.tai_list.parse());
    }

    #[test]
    fn test_type_6_ie_container_roundtrip() {
        let ladn = NasExtendedLadnInformation::from_entries(&[ExtendedLadnInformationEntry {
            dnn: NasDnn::from_string("ims").unwrap(),
            s_nssai: NasSNssai::from_sst_sd(1, None),
            tai_list: NasFGsTrackingAreaIdentityList::from_plmn_tacs(
                &PlmnId {
                    mcc: [2, 0, 8],
                    mnc: [9, 3, 0x0F],
                },
                &[[0x00, 0x00, 0x01]],
            ),
        }])
        .unwrap();

        let location_validity =
            NasSNssaiLocationValidityInformation::from_entries(&[SNssaiLocationValidityEntry {
                s_nssai: NasSNssai::from_sst_sd(1, None),
                nr_cgis: vec![SNssaiLocationValidityNrCgi {
                    nr_cell_id: [0x01, 0x02, 0x03, 0x04, 0x50],
                    plmn: PlmnId {
                        mcc: [2, 0, 8],
                        mnc: [9, 3, 0x0F],
                    },
                }],
            }])
            .unwrap();

        let entries = vec![
            Type6IeContainerEntry::ExtendedLadnInformation(ladn.clone()),
            Type6IeContainerEntry::SNssaiLocationValidityInformation(location_validity.clone()),
        ];
        let ie = NasType6IeContainer::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);
    }

    #[test]
    fn test_type_6_ie_container_ignores_unknown_and_duplicate_entries() {
        let ie = NasType6IeContainer::new(vec![
            0x01, 0x00, 0x00, // known entry with empty contents
            0x10, 0x00, 0x01, 0xFF, // unknown entry ignored
            0x01, 0x00, 0x00, // duplicate ignored
        ]);

        assert_eq!(
            ie.entries(),
            vec![Type6IeContainerEntry::ExtendedLadnInformation(
                NasExtendedLadnInformation::new(vec![])
            )]
        );
    }

    #[test]
    fn test_snssai_location_validity_information_roundtrip() {
        let entries = vec![SNssaiLocationValidityEntry {
            s_nssai: NasSNssai::from_sst_sd(1, Some([0xAA, 0xBB, 0xCC])),
            nr_cgis: vec![
                SNssaiLocationValidityNrCgi {
                    nr_cell_id: [1, 2, 3, 4, 0],
                    plmn: PlmnId {
                        mcc: [2, 0, 8],
                        mnc: [9, 3, 0x0F],
                    },
                },
                SNssaiLocationValidityNrCgi {
                    nr_cell_id: [6, 7, 8, 9, 0],
                    plmn: PlmnId {
                        mcc: [3, 1, 0],
                        mnc: [2, 6, 0],
                    },
                },
            ],
        }];

        let ie = NasSNssaiLocationValidityInformation::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);
    }

    #[test]
    fn test_snssai_time_validity_information_roundtrip() {
        let entries = vec![SNssaiTimeValidityEntry {
            s_nssai: NasSNssai::from_sst_sd(1, None),
            time_windows: vec![SNssaiTimeWindow {
                start_time: [0x01; 8],
                stop_time: [0x02; 8],
                recurrence_pattern: Some(SNssaiTimeWindowRecurrencePattern::EveryWeek),
                recurrence_end_time: Some([0x03; 8]),
            }],
        }];

        let ie = NasSNssaiTimeValidityInformation::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);
    }

    #[test]
    fn test_prose_relay_transaction_identity_helpers() {
        let assigned = NasProseRelayTransactionIdentity::from_identity(
            ProseRelayTransactionIdentityValue::Assigned(42),
        );
        assert_eq!(
            assigned.identity(),
            Some(ProseRelayTransactionIdentityValue::Assigned(42))
        );

        let reserved = NasProseRelayTransactionIdentity::from_identity(
            ProseRelayTransactionIdentityValue::Reserved,
        );
        assert_eq!(
            reserved.identity(),
            Some(ProseRelayTransactionIdentityValue::Reserved)
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // 5GMM/5GSM capability accessor regression
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_fgmm_capability_octet_3_bit_layout() {
        // SGC at bit 7 (0x80), S1 mode at bit 0 (0x01) per TS 24.501 §9.11.3.1.
        let cap = NasFGmmCapability::new(vec![0x80]);
        assert!(cap.sgc());
        assert!(!cap.s1_mode());

        let cap = NasFGmmCapability::new(vec![0x01]);
        assert!(!cap.sgc());
        assert!(cap.s1_mode());
    }

    #[test]
    fn test_fgmm_capability_octet_8_bits() {
        // Octet 8 (Rust value[5]): SBTS=bit7, NSR=bit6, ..., RcMap=bit0.
        let mut cap = NasFGmmCapability::new(vec![0u8; 6]);
        cap.set_sbts(true);
        cap.set_rcmap(true);
        assert!(cap.sbts());
        assert!(cap.rcmap());
        assert!(!cap.nsr());
        assert_eq!(cap.octet(6), 0x81);
    }

    #[test]
    fn test_fgmm_capability_accepts_rel19_max_length() {
        let mut octets = vec![0u8; 13];
        octets[0] = 0x80;
        octets[9] = 0x01;

        let cap = NasFGmmCapability::from_octets(octets.clone());
        assert_eq!(cap.octets(), octets.as_slice());
        assert_eq!(cap.octet(13), 0x00);
        assert!(cap.spare_octets_are_zero());
        assert!(cap.validate_strict().is_ok());
        assert!(NasFGmmCapability::try_from_octets(octets).is_some());
    }

    #[test]
    fn test_fgmm_capability_rejects_nonzero_spare_extension_octets() {
        let mut octets = vec![0u8; 13];
        octets[10] = 0x01;

        assert!(NasFGmmCapability::try_from_octets(octets.clone()).is_none());

        let cap = NasFGmmCapability::new(octets);
        assert!(!cap.spare_octets_are_zero());
        assert!(cap.validate_strict().is_err());
    }

    #[test]
    fn test_fgsm_capability_octet_3_bits_correct() {
        // TPMIC=0x80, RQoS=0x01 per TS 24.501 §9.11.4.1.
        let cap = NasFGsmCapability::from_flags(true, 0, false, false, true);
        assert!(cap.tpmic());
        assert!(cap.rqos());
        assert!(!cap.ept_s1());
    }

    #[test]
    fn test_fgsm_capability_typed_atsss_values() {
        let cap = NasFGsmCapability::default()
            .with_tpmic(true)
            .with_atsss_st_value(AtsssSteeringFunctionality::MptcpAnyAndLowLayerAny)
            .with_atsss_ll_value(AtsssLowLayerFunctionality::AnySteering);
        assert!(cap.tpmic());
        assert_eq!(
            cap.atsss_st_value(),
            Some(AtsssSteeringFunctionality::MptcpAnyAndLowLayerAny)
        );
        assert_eq!(
            cap.atsss_ll_value(),
            Some(AtsssLowLayerFunctionality::AnySteering)
        );
    }

    #[test]
    fn test_fgsm_capability_octet_4_bits() {
        let mut cap = NasFGsmCapability::new(vec![0, 0]);
        cap.set_mpquic_ip(true);
        cap.set_mptcp(true);
        cap.set_atsss_ll(2);
        assert!(cap.mpquic_ip());
        assert!(cap.mptcp());
        assert_eq!(cap.atsss_ll(), 2);
    }

    // ────────────────────────────────────────────────────────────────────────
    // New 5GMM message types
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_control_plane_service_request_roundtrip() {
        use crate::nas_5gs::messages::*;
        let standalone = NasControlPlaneServiceType::from_service_type(
            ControlPlaneServiceTypeValue::EmergencyServices,
        );
        assert_eq!(standalone.value, 0x02);
        assert_eq!(standalone.ngksi(), 0);
        assert!(!standalone.tsc());

        let msg = NasControlPlaneServiceRequest::new(
            NasControlPlaneServiceType::default()
                .with_service_type(ControlPlaneServiceTypeValue::MobileTerminatingRequest)
                .with_ngksi(3)
                .with_tsc(true),
        );
        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = NasControlPlaneServiceRequest::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.control_plane_service_type.value,
            msg.control_plane_service_type.value
        );
        assert_eq!(
            decoded.control_plane_service_type.service_type(),
            Some(ControlPlaneServiceTypeValue::MobileTerminatingRequest)
        );
        assert_eq!(decoded.ngksi(), 3);
        assert!(decoded.tsc());
        assert!(decoded.ciot_small_data_container_is_exclusive());
    }

    #[test]
    fn test_control_plane_service_request_ciot_exclusivity_helper() {
        use crate::nas_5gs::messages::*;
        let ciot = NasCiotSmallDataContainer::from_parsed(&CiotSmallDataContainerContents::Sms {
            data: vec![0xAA, 0xBB],
        })
        .unwrap();
        let msg = NasControlPlaneServiceRequest::new(NasControlPlaneServiceType::default())
            .set_ciot_small_data_container(ciot)
            .set_release_assistance_indication(NasReleaseAssistanceIndication::from_ddx(
                DownlinkDataExpected::NoFurtherData,
            ));
        assert!(!msg.ciot_small_data_container_is_exclusive());
    }

    #[test]
    fn test_relay_key_request_message_roundtrip() {
        use crate::nas_5gs::messages::*;
        let params = RelayKeyRequestParameters {
            relay_service_code: 0xABCDEF,
            nonce_1: [0x11; 16],
            uit: false,
            ue_id: vec![0x01, 0x02],
        };
        let msg = NasRelayKeyRequest::new(
            NasProseRelayTransactionIdentity::from_identity(
                ProseRelayTransactionIdentityValue::Assigned(0x42),
            ),
            NasRelayKeyRequestParameters::from_parsed(&params),
        );
        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf[0], 0x42);
        let mut bytes = buf.freeze();
        let decoded = NasRelayKeyRequest::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.prose_relay_transaction_identity.identity(),
            Some(ProseRelayTransactionIdentityValue::Assigned(0x42))
        );
        assert_eq!(
            decoded.relay_key_request_parameters.parse().unwrap(),
            params
        );
    }

    #[test]
    fn test_registration_accept_unavailability_configuration_roundtrip() {
        use crate::nas_5gs::messages::*;
        let msg = NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![0x01]))
            .set_unavailability_configuration(NasUnavailabilityConfiguration::new(vec![
                0x01, 0x02, 0x03,
            ]));

        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = NasRegistrationAccept::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.unavailability_configuration.unwrap().value,
            vec![0x01, 0x02, 0x03]
        );
    }

    #[test]
    fn test_configuration_update_command_snssai_location_validity_roundtrip() {
        use crate::nas_5gs::messages::*;
        let location_validity =
            NasSNssaiLocationValidityInformation::from_entries(&[SNssaiLocationValidityEntry {
                s_nssai: NasSNssai::from_sst_sd(1, None),
                nr_cgis: vec![SNssaiLocationValidityNrCgi {
                    nr_cell_id: [1, 2, 3, 4, 0x50],
                    plmn: PlmnId {
                        mcc: [2, 0, 8],
                        mnc: [9, 3, 0x0F],
                    },
                }],
            }])
            .unwrap();

        let msg = NasConfigurationUpdateCommand::new()
            .set_s_nssai_location_validity_information(location_validity.clone());
        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = NasConfigurationUpdateCommand::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded
                .s_nssai_location_validity_information
                .unwrap()
                .entries(),
            location_validity.entries()
        );
    }

    #[test]
    fn test_remote_ue_report_roundtrip() {
        use crate::nas_5gs::messages::*;
        let mut msg = NasRemoteUeReport::new();
        msg = msg.set_connected_remote_ue_context_list(NasRemoteUeContextList::from_data(vec![
            0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]));
        let mut buf = bytes::BytesMut::new();
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let decoded = NasRemoteUeReport::decode(&mut bytes).unwrap();
        assert_eq!(
            decoded.connected_remote_ue_context_list.unwrap().data(),
            &[0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_n3qai_roundtrip() {
        let entries = vec![N3QaiEntry {
            qfis: vec![5, 7],
            parameters: vec![
                N3QaiParameter {
                    identifier: N3QaiParameterIdentifier::FiveQi,
                    contents: vec![9],
                },
                N3QaiParameter {
                    identifier: N3QaiParameterIdentifier::Arp,
                    contents: vec![3],
                },
            ],
        }];
        let ie = NasN3Qai::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);
        assert!(ie.is_well_formed());

        let mut receiver_value = ie.value.clone();
        receiver_value[3] += 1;
        receiver_value.extend_from_slice(&[0x99, 0x01, 0xaa]);
        let receiver_ie = NasN3Qai::new(receiver_value);
        assert_eq!(receiver_ie.entries()[0].parameters.len(), 3);
        let spec_entries = receiver_ie.entries_spec();
        assert_eq!(spec_entries.len(), 1);
        assert_eq!(spec_entries[0].parameters.len(), 2);
        assert!(!receiver_ie.is_well_formed());
        assert!(spec_entries[0].parameters.iter().all(|parameter| !matches!(
            parameter.identifier,
            N3QaiParameterIdentifier::Unknown(_)
        )));
    }

    #[test]
    fn test_n3qai_typed_parameter_wire_values() {
        let values = [
            N3QaiParameterValue::FiveQi(9),
            N3QaiParameterValue::GfbrUplink(QosFlowBitRate { unit: 1, value: 64 }),
            N3QaiParameterValue::AveragingWindow(4000),
            N3QaiParameterValue::ResourceType(N3QaiResourceType::DelayedCriticalGbr),
            N3QaiParameterValue::PriorityLevel(127),
            N3QaiParameterValue::PacketDelayBudget(1023),
            N3QaiParameterValue::PacketErrorRate {
                scalar: 9,
                exponent: 9,
            },
            N3QaiParameterValue::MaximumDataBurstVolume(4095),
            N3QaiParameterValue::MaximumPacketLossRateDownlink(1000),
            N3QaiParameterValue::Arp(15),
            N3QaiParameterValue::Periodicity(vec![0x00, 0x0f, 0x42, 0x40]),
        ];
        for value in values {
            let parameter = N3QaiParameter::from_value(value.clone()).unwrap();
            assert_eq!(parameter.value(), Some(value));
        }
        assert!(N3QaiParameter::from_value(N3QaiParameterValue::FiveQi(0)).is_none());
        assert!(N3QaiParameter::from_value(N3QaiParameterValue::PriorityLevel(128)).is_none());
        assert!(N3QaiParameter::from_value(N3QaiParameterValue::PacketDelayBudget(1024)).is_none());
        assert!(
            N3QaiParameter::from_value(N3QaiParameterValue::PacketErrorRate {
                scalar: 10,
                exponent: 1,
            })
            .is_none()
        );
        assert!(
            N3QaiParameter {
                identifier: N3QaiParameterIdentifier::FiveQi,
                contents: vec![9, 10],
            }
            .value()
            .is_none()
        );
    }

    #[test]
    fn test_non_3gpp_delay_budget_roundtrip() {
        let entries = vec![Non3GppDelayBudgetEntry {
            delay_budget: 80,
            qfis: vec![9],
            packet_filters: vec![QosPacketFilter::Match {
                direction: QosPacketFilterDirection::Bidirectional,
                identifier: 1,
                components: vec![QosPacketFilterComponent::MatchAll],
            }],
        }];
        let ie = NasNon3GppDelayBudget::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);
    }

    #[test]
    fn test_ursp_rule_enforcement_reports_roundtrip() {
        let reports = vec![
            UrspRuleEnforcementReport {
                connection_capability_identifiers: vec![1, 2],
            },
            UrspRuleEnforcementReport {
                connection_capability_identifiers: vec![7],
            },
        ];
        let ie = NasUrspRuleEnforcementReports::from_reports(&reports).unwrap();
        assert_eq!(ie.reports(), reports);
    }

    #[test]
    fn test_protocol_description_roundtrip() {
        let entries = vec![
            ProtocolDescriptionEntry::Delete { qri: 3 },
            ProtocolDescriptionEntry::Description {
                qri: 5,
                transport_protocol: ProtocolDescriptionTransportProtocol::Rtp,
                rtp_header_extension: Some((
                    ProtocolDescriptionRtpHeaderExtensionType::PduSetMarking,
                    9,
                )),
                rtp_payload_information_list: vec![
                    ProtocolDescriptionRtpPayloadInformation {
                        payload_format: ProtocolDescriptionRtpPayloadFormat::H264Avc,
                        payload_types: vec![96, 97],
                    },
                    ProtocolDescriptionRtpPayloadInformation {
                        payload_format: ProtocolDescriptionRtpPayloadFormat::H265Hevc,
                        payload_types: vec![98],
                    },
                ],
            },
        ];
        let ie = NasProtocolDescription::from_entries(&entries).unwrap();
        assert_eq!(ie.entries(), entries);

        let valid =
            NasProtocolDescription::from_entries(&[ProtocolDescriptionEntry::Delete { qri: 9 }])
                .unwrap();
        let mut raw = vec![0x00, 0x02, 0x01, 0x0F]; // spare transport protocol entry
        raw.extend_from_slice(valid.data());
        let ie = NasProtocolDescription::from_data(raw);
        assert_eq!(
            ie.entries(),
            vec![ProtocolDescriptionEntry::Delete { qri: 9 }]
        );
    }

    #[test]
    fn test_non_3gpp_device_information_roundtrip() {
        let suspended =
            Non3GppDeviceInformationEntry::without_connection_information(b"camera-02".to_vec());
        assert!(!suspended.has_connection_information());
        assert!(suspended.is_qos_differentiation_suspended());

        let entries = vec![
            Non3GppDeviceInformationEntry {
                device_identifier: b"printer-01".to_vec(),
                connection_information: Some(Non3GppDeviceConnectionInformation::Ipv4 {
                    ipv4_address: Some([192, 0, 2, 10]),
                    ipv4_port_ranges: vec![PortRange {
                        low: 4000,
                        high: 4010,
                    }],
                }),
            },
            suspended,
        ];
        let ie =
            NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::IPv4, &entries).unwrap();
        assert_eq!(ie.pdu_session_type(), Some(PduSessionTypeValue::IPv4));
        assert_eq!(ie.entries(), entries);
        assert!(ie.validate_strict().is_ok());

        let dirty_pdu_type_spare =
            NasNon3GppDeviceInformation::from_device_information_data(vec![0x81]);
        assert!(dirty_pdu_type_spare.validate_strict().is_err());

        let dirty_header_spare =
            NasNon3GppDeviceInformation::from_device_information_data(vec![0x01, 0x01, 0xC0]);
        assert!(dirty_header_spare.validate_strict().is_err());

        let dirty_connection_spare =
            NasNon3GppDeviceInformation::from_device_information_data(vec![
                0x01, 0x04, 0x01, b'a', 0x80,
            ]);
        assert!(dirty_connection_spare.validate_strict().is_err());
    }

    #[test]
    fn test_remote_ue_context_list_roundtrip() {
        let contexts = vec![RemoteUeContext {
            remote_ue_identifier: RemoteUeIdentifier::UpPrukId {
                format: RemoteUeIdFormat::BitString64,
                value: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
            protocol_information: RemoteUeProtocolInformation::Ipv4 {
                address: [10, 0, 0, 42],
                udp_port_range: Some(PortRange {
                    low: 5000,
                    high: 5005,
                }),
                tcp_port_range: Some(PortRange {
                    low: 6000,
                    high: 6008,
                }),
            },
            hplmn_id: Some(PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0F],
            }),
        }];
        let ie = NasRemoteUeContextList::from_contexts(&contexts).unwrap();
        assert_eq!(ie.contexts(), contexts);
    }

    #[test]
    fn release_19_remaining_scalar_ie_wire_values() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };

        let drx = NasFGsDrxParameters::from_drx_value(DrxValue::Cycle128);
        assert_eq!(drx.value, [0x03]);
        assert_eq!(drx.drx_value(), Some(DrxValue::Cycle128));

        let identity = NasFGsIdentityType::new(0x00);
        assert_eq!(identity.identity_type_strict(), None);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));

        let security = NasAdditional5gSecurityInformation::from_flags(true, true);
        assert_eq!(security.value, [0x03]);
        assert!(security.rinmr() && security.hdp());

        let rand = NasAuthenticationParameterRand::from_rand([0x5a; 16]);
        assert_eq!(rand.rand_array(), Some([0x5a; 16]));
        let res = NasAuthenticationResponseParameter::from_res_star([0xa5; 16]);
        assert_eq!(res.res_star_array(), Some([0xa5; 16]));

        let update = NasConfigurationUpdateIndication::from_flags(true, true);
        assert_eq!(update.value, 0x03);
        assert!(update.ack() && update.red());
        let daylight =
            NasDaylightSavingTime::from_adjustment(DaylightSavingAdjustment::PlusOneHour);
        assert_eq!(daylight.value, [0x01]);
        assert_eq!(
            daylight.adjustment(),
            Some(DaylightSavingAdjustment::PlusOneHour)
        );

        let mico = NasMicoIndication::from_flags(true, true);
        assert_eq!(mico.value, 0x03);
        assert!(mico.raai() && mico.sprti());
        let ma =
            NasMaPduSessionInformation::from_info(MaPduSessionInfoValue::NetworkUpgradeAllowed);
        assert_eq!(ma.value, 0x01);
        assert_eq!(
            ma.info(),
            Some(MaPduSessionInfoValue::NetworkUpgradeAllowed)
        );
        let slicing = NasNetworkSlicingIndication::from_flags(true, true);
        assert_eq!(slicing.value, 0x03);
        let mode = NasNssaiInclusionMode::from_mode(NssaiInclusionModeValue::D);
        assert_eq!(mode.value, 0x03);
        assert_eq!(mode.mode(), NssaiInclusionModeValue::D);

        let plmn_list = NasPlmnList::from_plmns(&[plmn]).unwrap();
        assert_eq!(plmn_list.value, [0x02, 0xf8, 0x39]);
        assert_eq!(plmn_list.plmns(), [plmn]);
        let disaster = NasListOfPlmnsToBeUsedInDisasterCondition::from_plmns(&[plmn]).unwrap();
        assert_eq!(disaster.value, [0x02, 0xf8, 0x39]);
        assert_eq!(disaster.plmns(), [plmn]);

        assert_eq!(ServiceType::from_u8(0x0a), Some(ServiceType::Data));
        let sms = NasSmsIndication::from_sai(true);
        assert_eq!(sms.value, 0x01);
        assert!(sms.sai());
        let usage = NasUeUsageSetting::from_data_centric(true);
        assert_eq!(usage.value, [0x01]);
        assert!(usage.data_centric());
        let status = NasUeStatus::from_status(true, false);
        assert_eq!(status.value, [0x02]);
        assert!(status.n1_mode_reg() && !status.s1_mode_reg());
        let n5gc = NasN5gcIndication::from_n5gc(true);
        assert_eq!(n5gc.value, 0x01);
        assert!(n5gc.n5gc());
        let nb_drx = NasNbN1ModeDrxParameters::from_drx_value(NbN1DrxValue::T1024);
        assert_eq!(nb_drx.value, [0x07]);
        assert_eq!(nb_drx.drx_value(), Some(NbN1DrxValue::T1024));
        let config = NasAdditionalConfigurationIndication::from_scmr(true);
        assert_eq!(config.value, 0x01);
        assert!(config.scmr());
        let request = NasFGsAdditionalRequestResult::from_prd(
            PagingRestrictionDecision::PagingRestrictionAccepted,
        );
        assert_eq!(request.value, [0x01]);
        assert_eq!(
            request.prd(),
            Some(PagingRestrictionDecision::PagingRestrictionAccepted)
        );
        let priority = NasPriorityIndicator::from_flags(true, true);
        assert_eq!(priority.value, 0x03);
        assert!(priority.access_identity_1_valid() && priority.access_identity_2_valid());

        let always_indication = NasAlwaysOnPduSessionIndication::from_apsi(true);
        assert_eq!(always_indication.value, 0x01);
        assert!(always_indication.apsi());
        let always_requested = NasAlwaysOnPduSessionRequested::from_apsr(true);
        assert_eq!(always_requested.value, 0x01);
        assert!(always_requested.apsr());
        let ssc = NasAllowedSscMode::from_modes(true, false, true);
        assert_eq!(ssc.value, 0x05);
        assert!(ssc.ssc1() && !ssc.ssc2() && ssc.ssc3());

        let dn = NasSmPduDnRequestContainer::from_str("sensor-1@example.net");
        assert_eq!(dn.as_utf8_str(), Some("sensor-1@example.net"));
        let feature = NasFGsmNetworkFeatureSupport::from_flags(true, true);
        assert_eq!(feature.value, [0x03]);
        assert!(feature.ept_s1() && feature.naps());
        let congestion = NasFGsmCongestionReAttemptIndicator::from_flags(true, true);
        assert_eq!(congestion.value, [0x03]);
        assert!(congestion.abo() && congestion.catbo());
        let ethernet = NasEthernetHeaderCompressionConfiguration::from_cid_length(
            EthHdrCompCidLen::FifteenBits,
        );
        assert_eq!(ethernet.value, [0x02]);
        assert_eq!(ethernet.cid_length(), Some(EthHdrCompCidLen::FifteenBits));
        let rsn = NasRsn::from_rsn(RsnValue::V2);
        assert_eq!(rsn.value, [0x01]);
        assert_eq!(rsn.rsn(), Some(RsnValue::V2));
    }

    #[test]
    fn release_19_remaining_structured_ie_wire_values() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let dnn = NasDnn::from_string("internet").unwrap().value;

        let cag_entry = CagInformationEntry {
            plmn,
            cag_only: true,
            caili: false,
            lci: false,
            cag_ids: vec![0x1122_3344],
            cag_ids_with_info: vec![],
        };
        let cag = NasCagInformationList::from_entries(std::slice::from_ref(&cag_entry)).unwrap();
        assert_eq!(
            cag.value,
            [0x08, 0x02, 0xf8, 0x39, 0x01, 0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(cag.entries().as_slice(), std::slice::from_ref(&cag_entry));

        let extended_entry = CagInformationEntry {
            lci: true,
            ..cag_entry.clone()
        };
        let extended =
            NasExtendedCagInformationList::from_entries(std::slice::from_ref(&extended_entry))
                .unwrap();
        assert_eq!(
            extended.value,
            [
                0x00, 0x0a, 0x02, 0xf8, 0x39, 0x05, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44
            ]
        );
        assert_eq!(extended.entries(), [extended_entry]);

        let cipher_set = CipheringDataSet {
            set_id: 0x0102,
            ciphering_key: [0x11; 16],
            c0: vec![],
            eutra_pos_sib_types: vec![0x80, 0x00],
            nr_pos_sib_types: vec![],
            validity_start_time: [0x62, 0x90, 0x62, 0x21, 0x00],
            validity_duration: 1440,
            tai_list: vec![],
        };
        let cipher =
            NasCipheringKeyData::from_data_sets(std::slice::from_ref(&cipher_set)).unwrap();
        assert_eq!(cipher.value.len(), 31);
        assert_eq!(cipher.value[0..2], [0x01, 0x02]);
        assert_eq!(cipher.value[18..23], [0x00, 0x02, 0x80, 0x00, 0x00]);
        assert_eq!(cipher.data_sets(), [cipher_set]);

        let ladn_indication =
            NasLadnIndication::from_dnn_values(std::slice::from_ref(&dnn)).unwrap();
        let mut expected_ladn_indication = vec![dnn.len() as u8];
        expected_ladn_indication.extend_from_slice(&dnn);
        assert_eq!(ladn_indication.value, expected_ladn_indication);
        assert_eq!(
            ladn_indication.dnn_values().as_slice(),
            std::slice::from_ref(&dnn)
        );

        let tai_list = vec![0x00, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x01];
        let ladn_entry = LadnInfoEntry {
            dnn: dnn.clone(),
            tai_list: tai_list.clone(),
        };
        let ladn = NasLadnInformation::from_entries(std::slice::from_ref(&ladn_entry)).unwrap();
        assert_eq!(ladn.value[0], dnn.len() as u8);
        assert_eq!(ladn.value[1 + dnn.len()], tai_list.len() as u8);
        assert_eq!(ladn.entries(), [ladn_entry]);

        let mapped_slice = NasSNssai::from_sst_sd(1, Some([0x11, 0x22, 0x33]));
        let mapped = NasMappedNssai::from_snssais(std::slice::from_ref(&mapped_slice)).unwrap();
        assert_eq!(mapped.value, [0x04, 0x01, 0x11, 0x22, 0x33]);
        assert_eq!(mapped.parse_all().len(), 1);
        let rejected = NasRejectedNssai::from_entries(&[(
            RejectedNssaiCause::AuthenticationOrAuthorizationFailedOrRevoked,
            &mapped_slice,
        )])
        .unwrap();
        assert_eq!(rejected.value, [0x42, 0x01, 0x11, 0x22, 0x33]);
        assert_eq!(rejected.entries().len(), 1);

        let inner = NasMessageContainer::new(vec![0x7e, 0x00, 0x43]);
        assert!(inner.decode_plain_inner().is_ok());

        let error_causes = NasPduSessionReactivationResultErrorCause::from_entries(&[(
            7,
            GmmCause::InsufficientResourcesForSliceDnn,
        )])
        .unwrap();
        assert_eq!(error_causes.value, [0x07, 0x43]);
        assert_eq!(
            error_causes.entries(),
            [(7, GmmCause::InsufficientResourcesForSliceDnn)]
        );

        let nssrg_entry = NssrgInfoEntry {
            s_nssai: vec![0x01],
            nssrg_values: vec![0xaa, 0xbb],
        };
        let nssrg = NasNssrgInformation::from_entries(std::slice::from_ref(&nssrg_entry)).unwrap();
        assert_eq!(nssrg.value, [0x04, 0x01, 0x01, 0xaa, 0xbb]);
        assert_eq!(nssrg.entries(), [nssrg_entry]);

        let nsag_entry = NsagInfoEntry {
            nsag_id: 7,
            s_nssai: vec![0x01, 0x01],
            priority: 9,
            tai_list: vec![],
        };
        let nsag = NasNsagInformation::from_entries(std::slice::from_ref(&nsag_entry)).unwrap();
        assert_eq!(nsag.value, [0x05, 0x07, 0x02, 0x01, 0x01, 0x09]);
        assert_eq!(nsag.entries(), [nsag_entry]);

        let mapped_context = MappedEpsBearerContext {
            eps_bearer_id: 5,
            op_code: MappedEpsBearerOpCode::Create as u8,
            e_flag: true,
            params: vec![MappedEpsBearerParam {
                param_id: MappedEpsBearerParamId::ApnAmbr as u8,
                contents: vec![0xfe, 0x01, 0x10, 0x00],
            }],
        };
        let contexts =
            NasMappedEpsBearerContexts::from_contexts(std::slice::from_ref(&mapped_context))
                .unwrap();
        assert_eq!(
            contexts.value,
            [0x50, 0x00, 0x07, 0x51, 0x04, 0x04, 0xfe, 0x01, 0x10, 0x00]
        );
        assert_eq!(contexts.contexts(), [mapped_context]);

        assert!(NasMappedNssai::from_snssais(&[]).is_none());
        assert!(NasRejectedNssai::from_entries_raw(&[(3, &mapped_slice)]).is_none());
        assert!(
            NasPduSessionReactivationResultErrorCause::from_entries(&[(
                0,
                GmmCause::InsufficientResourcesForSliceDnn,
            )])
            .is_none()
        );
        assert!(
            NasMappedEpsBearerContexts::new(vec![0x50, 0x00, 0x02, 0x51])
                .try_contexts()
                .is_none()
        );
    }
}
