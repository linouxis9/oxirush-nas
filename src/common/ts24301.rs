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

//! Value grammars defined in TS 24.301 and carried by both NAS protocols.
//!
//! TS 24.501 delegates several IEs to TS 24.301 chapter 9. The macros here
//! add one implementation of each grammar to the EPS type and to its 5GS
//! counterpart. Typed getters follow the receiver rules of TS 24.007
//! §11.1.4 and §11.4.2: spare bits and octets beyond those defined are
//! ignored. Sender-side rules are checked by `is_well_formed()`.

/// NAS key set identifier value 111: no key is available (TS 24.301
/// §9.9.3.21, TS 24.501 §9.11.3.32).
pub const NAS_KSI_NO_KEY_AVAILABLE: u8 = 0x07;

/// NAS key set identifier (TS 24.301 Table 9.9.3.21.1, TS 24.501 §9.11.3.32).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeySetIdentifier {
    /// Native security context KSI (0 to 6).
    Native(u8),
    /// Mapped security context KSI (0 to 6).
    Mapped(u8),
    /// No key is available (value 7).
    NoKey,
}

impl KeySetIdentifier {
    /// Decode bits 4-1 (TSC and KSI).
    pub fn from_u8(value: u8) -> Self {
        let id = value & 0x07;
        if id == 7 {
            Self::NoKey
        } else if value & 0x08 != 0 {
            Self::Mapped(id)
        } else {
            Self::Native(id)
        }
    }

    /// Encode to bits 4-1; `Err` for a KSI above 6.
    pub fn as_u8(self) -> crate::common::Result<u8> {
        match self {
            Self::Native(id) if id <= 6 => Ok(id),
            Self::Mapped(id) if id <= 6 => Ok(0x08 | id),
            Self::NoKey => Ok(7),
            _ => Err(crate::common::NasError::EncodingError(
                "EPS NAS key set identifier must be 0..=6".into(),
            )),
        }
    }
}

/// NAS key set identifier (TS 24.301 §9.9.3.21, TS 24.501 §9.11.3.32) in
/// bits 4-1 of the value; setters preserve bits 8-5, which 5GS uses for the
/// half octet that shares the octet. The `builders` form adds typed
/// constructors.
macro_rules! key_set_identifier_ie {
    ($name:ident, builders) => {
        crate::common::ts24301::key_set_identifier_ie!($name);

        impl $name {
            /// Build from a typed key set identifier.
            pub fn from_key_set_identifier(
                value: crate::common::ts24301::KeySetIdentifier,
            ) -> crate::common::Result<Self> {
                Ok(Self::new(value.as_u8()?))
            }

            /// Replace the key set identifier and TSC.
            pub fn set_key_set_identifier(
                &mut self,
                value: crate::common::ts24301::KeySetIdentifier,
            ) -> crate::common::Result<()> {
                self.value = (self.value & 0xf0) | value.as_u8()?;
                Ok(())
            }

            /// Builder form of [`Self::set_key_set_identifier`].
            pub fn with_key_set_identifier(
                mut self,
                value: crate::common::ts24301::KeySetIdentifier,
            ) -> crate::common::Result<Self> {
                self.set_key_set_identifier(value)?;
                Ok(self)
            }
        }
    };
    ($name:ident) => {
        impl $name {
            /// Key set identifier (bits 3-1).
            pub fn ksi(&self) -> u8 {
                self.value & 0x07
            }

            /// Set the key set identifier, preserving the other bits.
            pub fn set_ksi(&mut self, ksi: u8) {
                self.value = (self.value & 0xf8) | (ksi & 0x07);
            }

            /// Builder form of [`Self::set_ksi`].
            pub fn with_ksi(mut self, ksi: u8) -> Self {
                self.set_ksi(ksi);
                self
            }

            /// Type of security context (bit 4): `true` for a mapped context.
            /// The flag does not apply when no key is available.
            pub fn tsc(&self) -> bool {
                self.value & 0x08 != 0
            }

            /// Set the type of security context, preserving the other bits.
            pub fn set_tsc(&mut self, mapped: bool) {
                self.value = (self.value & !0x08) | (u8::from(mapped) << 3);
            }

            /// Builder form of [`Self::set_tsc`].
            pub fn with_tsc(mut self, mapped: bool) -> Self {
                self.set_tsc(mapped);
                self
            }

            /// Whether the identifier is 111: no key available from the UE,
            /// reserved from the network.
            pub fn no_key_available(&self) -> bool {
                self.ksi() == crate::common::ts24301::NAS_KSI_NO_KEY_AVAILABLE
            }

            /// Typed key set identifier.
            pub fn key_set_identifier(&self) -> crate::common::ts24301::KeySetIdentifier {
                crate::common::ts24301::KeySetIdentifier::from_u8(self.value)
            }
        }
    };
}

// ── NAS security algorithms (TS 24.301 §9.9.3.23, TS 33.401 §5.1) ─────────

/// EPS NAS ciphering algorithm identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CipheringAlgorithm {
    /// Null ciphering.
    EEA0 = 0,
    /// SNOW 3G ciphering.
    EEA1 = 1,
    /// AES CTR ciphering.
    EEA2 = 2,
    /// ZUC ciphering.
    EEA3 = 3,
    /// Reserved for future ciphering use.
    EEA4 = 4,
    /// Reserved for future ciphering use.
    EEA5 = 5,
    /// Reserved for future ciphering use.
    EEA6 = 6,
    /// Reserved for future ciphering use.
    EEA7 = 7,
}

impl CipheringAlgorithm {
    /// Decode bits 7-5; reserved values return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EEA0),
            1 => Some(Self::EEA1),
            2 => Some(Self::EEA2),
            3 => Some(Self::EEA3),
            4 => Some(Self::EEA4),
            5 => Some(Self::EEA5),
            6 => Some(Self::EEA6),
            7 => Some(Self::EEA7),
            _ => None,
        }
    }
}

/// EPS NAS integrity algorithm identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IntegrityAlgorithm {
    /// Null integrity, used for unauthenticated emergency calls.
    EIA0 = 0,
    /// SNOW 3G integrity.
    EIA1 = 1,
    /// AES CMAC integrity.
    EIA2 = 2,
    /// ZUC integrity.
    EIA3 = 3,
    /// Reserved for future integrity use.
    EIA4 = 4,
    /// Reserved for future integrity use.
    EIA5 = 5,
    /// Reserved for future integrity use.
    EIA6 = 6,
    /// Reserved for future integrity use.
    EIA7 = 7,
}

impl IntegrityAlgorithm {
    /// Decode bits 3-1; reserved values return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EIA0),
            1 => Some(Self::EIA1),
            2 => Some(Self::EIA2),
            3 => Some(Self::EIA3),
            4 => Some(Self::EIA4),
            5 => Some(Self::EIA5),
            6 => Some(Self::EIA6),
            7 => Some(Self::EIA7),
            _ => None,
        }
    }
}

/// NAS security algorithms octet (TS 24.301 §9.9.3.23, TS 24.501
/// §9.11.3.34): bits 7-5 carry the ciphering algorithm and bits 3-1 the
/// integrity algorithm; bits 8 and 4 are spare.
macro_rules! nas_security_algorithms_ie {
    ($name:ident, $ciphering:ty, $integrity:ty) => {
        impl $name {
            /// Type of ciphering algorithm (bits 7-5); spare bit 8 is ignored.
            pub fn ciphering(&self) -> Option<$ciphering> {
                <$ciphering>::from_u8(self.ciphering_raw())
            }

            /// Type of integrity protection algorithm (bits 3-1); spare bit 4
            /// is ignored.
            pub fn integrity(&self) -> Option<$integrity> {
                <$integrity>::from_u8(self.integrity_raw())
            }

            /// Raw ciphering algorithm identifier.
            pub fn ciphering_raw(&self) -> u8 {
                (self.value >> 4) & 0x07
            }

            /// Raw integrity algorithm identifier.
            pub fn integrity_raw(&self) -> u8 {
                self.value & 0x07
            }

            /// Build the IE with the spare bits clear.
            pub fn from_algorithms(ciphering: $ciphering, integrity: $integrity) -> Self {
                Self::new((ciphering as u8 & 0x07) << 4 | (integrity as u8 & 0x07))
            }

            /// Replace the ciphering algorithm.
            pub fn set_ciphering(&mut self, ciphering: $ciphering) {
                self.value = (self.value & 0x07) | ((ciphering as u8 & 0x07) << 4);
            }

            /// Builder form of [`Self::set_ciphering`].
            pub fn with_ciphering(mut self, ciphering: $ciphering) -> Self {
                self.set_ciphering(ciphering);
                self
            }

            /// Replace the integrity algorithm.
            pub fn set_integrity(&mut self, integrity: $integrity) {
                self.value = (self.value & 0x70) | (integrity as u8 & 0x07);
            }

            /// Builder form of [`Self::set_integrity`].
            pub fn with_integrity(mut self, integrity: $integrity) -> Self {
                self.set_integrity(integrity);
                self
            }

            /// Sender check: spare bits 8 and 4 are clear.
            pub fn is_well_formed(&self) -> bool {
                self.value & 0x88 == 0
            }
        }
    };
}

/// UE network capability (TS 24.301 §9.9.3.34).
///
/// Value octet 1 carries EEA0 to EEA7 and octet 2 carries EIA0 to EIA6 and
/// EPS-UPIP. Octets 3 to 13 are optional; an absent octet reads as "not
/// supported". Octet 10 bit 1 (NonSATLSP) is new in V19.8.0, and the
/// remaining bits of octets 10 to 13 are spare.
macro_rules! ue_network_capability_ie {
    ($name:ident) => {
        crate::common::ts24301::eps_algorithm_octets_ie!($name);

        crate::common::nas_ie_flags!($name {
            /// EPS user plane integrity protection supported (octet 4, bit 1).
            eps_upip: 1, 1;
            /// UCS2 support (octet 6, bit 8): `true` means no preference for
            /// the default alphabet over UCS2.
            ucs2: 3, 8;
            /// ProSe direct discovery (octet 7, bit 8).
            prose_dd: 4, 8;
            /// ProSe (octet 7, bit 7).
            prose: 4, 7;
            /// H.245 after SRVCC handover (octet 7, bit 6).
            h245_ash: 4, 6;
            /// Access class control for CSFB (octet 7, bit 5).
            acc_csfb: 4, 5;
            /// LTE Positioning Protocol (octet 7, bit 4).
            lpp: 4, 4;
            /// Location services notification mechanisms (octet 7, bit 3).
            lcs: 4, 3;
            /// SRVCC from E-UTRAN to cdma2000 1xCS (octet 7, bit 2).
            srvcc_1x: 4, 2;
            /// Notification procedure (octet 7, bit 1).
            nf: 4, 1;
            /// Extended protocol configuration options (octet 8, bit 8).
            epco: 5, 8;
            /// Header compression for control plane CIoT EPS optimization (octet 8, bit 7).
            hc_cp_ciot: 5, 7;
            /// EMM-REGISTERED without PDN connection (octet 8, bit 6).
            erw_opdn: 5, 6;
            /// S1-U data transfer bit as sent (octet 8, bit 5); see
            /// [`Self::s1u_data_supported`] for the receiver interpretation.
            s1u_data: 5, 5;
            /// User plane CIoT EPS optimization (octet 8, bit 4).
            up_ciot: 5, 4;
            /// Control plane CIoT EPS optimization (octet 8, bit 3).
            cp_ciot: 5, 3;
            /// ProSe UE-to-network relay (octet 8, bit 2).
            prose_relay: 5, 2;
            /// ProSe direct communication (octet 8, bit 1).
            prose_dc: 5, 1;
            /// Signalling for a maximum of 15 EPS bearer contexts (octet 9, bit 8).
            fifteen_bearers: 6, 8;
            /// Service gap control (octet 9, bit 7).
            sgc: 6, 7;
            /// N1 mode for 3GPP access (octet 9, bit 6).
            n1_mode: 6, 6;
            /// Dual connectivity with NR (octet 9, bit 5).
            dcnr: 6, 5;
            /// Control plane data back-off (octet 9, bit 4).
            cp_backoff: 6, 4;
            /// Restriction on use of enhanced coverage (octet 9, bit 3).
            restrict_ec: 6, 3;
            /// V2X communication over E-UTRA PC5 (octet 9, bit 2).
            v2x_pc5: 6, 2;
            /// Multiple user plane radio bearers in NB-S1 mode (octet 9, bit 1).
            multiple_drb: 6, 1;
            /// Reject paging request (octet 10, bit 8).
            rpr: 7, 8;
            /// Paging indication for voice services (octet 10, bit 7).
            piv: 7, 7;
            /// NAS signalling connection release (octet 10, bit 6).
            ncr: 7, 6;
            /// V2X communication over NR PC5 (octet 10, bit 5).
            v2x_nr_pc5: 7, 5;
            /// User plane mobile terminated early data transmission (octet 10, bit 4).
            up_mt_edt: 7, 4;
            /// Control plane mobile terminated early data transmission (octet 10, bit 3).
            cp_mt_edt: 7, 3;
            /// Wake-up signal assistance (octet 10, bit 2).
            wusa: 7, 2;
            /// Radio capability signalling optimisation (octet 10, bit 1).
            racs: 7, 1;
            /// Minimization of service interruption (octet 11, bit 8).
            mint_eps: 8, 8;
            /// Overhead reduction bit as sent (octet 11, bit 7); see
            /// [`Self::ohr_cp_ciot_supported`] for the receiver interpretation.
            ohr_cp_ciot: 8, 7;
            /// S&F satellite operation (octet 11, bit 6).
            sfso: 8, 6;
            /// Access technology utilization control (octet 11, bit 5).
            atuc: 8, 5;
            /// Coarse location reporting via NAS (octet 11, bit 4).
            rclin: 8, 4;
            /// Enhanced discontinuous coverage (octet 11, bit 3).
            edc: 8, 3;
            /// Paging timing collision control (octet 11, bit 2).
            ptcc: 8, 2;
            /// Paging restriction (octet 11, bit 1).
            pr: 8, 1;
            /// Non-satellite lower PLMN selection (octet 12, bit 1).
            non_sat_lsp: 9, 1;
        });

        impl $name {
            /// UMTS encryption algorithms octet (UEA0 to UEA7), if present.
            pub fn uea_byte(&self) -> Option<u8> {
                self.value.get(2).copied()
            }

            /// UMTS integrity algorithms UIA1 to UIA7 (octet 6 without UCS2), if present.
            pub fn uia_byte(&self) -> Option<u8> {
                self.value.get(3).map(|octet| octet & 0x7f)
            }

            /// Whether UEA`algo` (0 to 7) is supported.
            pub fn supports_uea(&self, algo: u8) -> bool {
                algo <= 7 && self.uea_byte().is_some_and(|octet| octet & (0x80 >> algo) != 0)
            }

            /// Whether UIA`algo` (1 to 7) is supported.
            pub fn supports_uia(&self, algo: u8) -> bool {
                (1..=7).contains(&algo)
                    && self.uia_byte().is_some_and(|octet| octet & (0x80 >> algo) != 0)
            }

            /// S1-U data transfer as interpreted by the receiver: supported
            /// when control plane CIoT EPS optimization is not indicated.
            pub fn s1u_data_supported(&self) -> bool {
                !self.cp_ciot() || self.s1u_data()
            }

            /// Overhead reduction as interpreted by the receiver: ignored when
            /// control plane CIoT EPS optimization is not indicated.
            pub fn ohr_cp_ciot_supported(&self) -> bool {
                self.cp_ciot() && self.ohr_cp_ciot()
            }

            /// Whether the spare bits of octets 12 to 15 are zero.
            pub fn spare_bits_are_zero(&self) -> bool {
                self.value.get(9).is_none_or(|octet| octet & 0xfe == 0)
                    && self.value.get(10..).is_none_or(|spare| spare.iter().all(|&octet| octet == 0))
            }

            /// Sender check: 2 to 13 value octets with zero spare bits.
            pub fn is_well_formed(&self) -> bool {
                (2..=13).contains(&self.value.len()) && self.spare_bits_are_zero()
            }
        }
    };
}

/// UE security capability (TS 24.301 §9.9.3.36).
///
/// Octets 1 and 2 carry the EPS algorithms, octets 3 and 4 the UMTS
/// algorithms, and octet 5 the GPRS algorithms. The second argument names
/// the UE network capability type of the same protocol, whose values the
/// replayed capability must match.
macro_rules! ue_security_capability_ie {
    ($name:ident, $network_capability:ident) => {
        crate::common::ts24301::eps_algorithm_octets_ie!($name);

        crate::common::nas_ie_flags!($name {
            /// EPS user plane integrity protection supported (octet 4, bit 1).
            eps_upip: 1, 1;
        });

        impl $name {
            /// UMTS encryption algorithms octet (UEA0 to UEA7), if present.
            pub fn uea_byte(&self) -> Option<u8> {
                self.value.get(2).copied()
            }

            /// UMTS integrity algorithms UIA1 to UIA7, if present; bit 8 is spare.
            pub fn uia_byte(&self) -> Option<u8> {
                self.value.get(3).map(|octet| octet & 0x7f)
            }

            /// GPRS encryption algorithms GEA1 to GEA7, if present; bit 8 is spare.
            pub fn gea_byte(&self) -> Option<u8> {
                self.value.get(4).map(|octet| octet & 0x7f)
            }

            /// Whether UEA`algo` (0 to 7) is supported.
            pub fn supports_uea(&self, algo: u8) -> bool {
                algo <= 7 && self.uea_byte().is_some_and(|octet| octet & (0x80 >> algo) != 0)
            }

            /// Whether UIA`algo` (1 to 7) is supported.
            pub fn supports_uia(&self, algo: u8) -> bool {
                (1..=7).contains(&algo)
                    && self.uia_byte().is_some_and(|octet| octet & (0x80 >> algo) != 0)
            }

            /// Whether GEA`algo` (1 to 7) is supported.
            pub fn supports_gea(&self, algo: u8) -> bool {
                (1..=7).contains(&algo)
                    && self.gea_byte().is_some_and(|octet| octet & (0x80 >> algo) != 0)
            }

            /// Build the IE with the octet inclusion rules of §9.9.3.36.
            ///
            /// `uea_uia` holds the UEA octet and UIA1-UIA7 octet; `gea` holds
            /// GEA1-GEA7. Octet 5 is included only when a GEA algorithm is
            /// supported, and then octets 3 and 4 are zero when no UMTS
            /// algorithm is given. Spare bits are cleared.
            pub fn from_algorithms(eea: u8, eia: u8, uea_uia: Option<(u8, u8)>, gea: Option<u8>) -> Self {
                let mut value = vec![eea, eia];
                let gea = gea.map(|octet| octet & 0x7f).filter(|&octet| octet != 0);
                let uea_uia = uea_uia.filter(|&(uea, uia)| uea != 0 || uia & 0x7f != 0);
                if uea_uia.is_some() || gea.is_some() {
                    let (uea, uia) = uea_uia.unwrap_or((0, 0));
                    value.extend_from_slice(&[uea, uia & 0x7f]);
                }
                if let Some(gea) = gea {
                    value.push(gea);
                }
                Self::new(value)
            }

            /// Whether this replayed capability equals the UE network
            /// capability it was derived from (TS 24.301 §5.4.3.3): the EPS
            /// octets, and the UMTS octets when the UE sent them.
            pub fn matches_ue_network_capability(&self, capability: &$network_capability) -> bool {
                self.eea_byte() == capability.eea_byte()
                    && self.eia_byte() == capability.eia_byte()
                    && match (capability.uea_byte(), capability.uia_byte()) {
                        (Some(uea), Some(uia)) if uea != 0 || uia != 0 => {
                            self.uea_byte() == Some(uea) && self.uia_byte() == Some(uia)
                        }
                        _ => self.uea_byte().unwrap_or(0) == 0 && self.uia_byte().unwrap_or(0) == 0,
                    }
            }

            /// Sender check: 2, 4, or 5 octets, zero spare bits, octet 5
            /// only with a GEA algorithm, and octets 3-4 only with a UMTS or
            /// GPRS algorithm.
            pub fn is_well_formed(&self) -> bool {
                let spare_clear = self.value.get(3).is_none_or(|octet| octet & 0x80 == 0)
                    && self.value.get(4).is_none_or(|octet| octet & 0x80 == 0);
                spare_clear
                    && match self.value.len() {
                        2 => true,
                        4 => self.value[2] != 0 || self.value[3] != 0,
                        5 => self.value[4] != 0,
                        _ => false,
                    }
            }
        }
    };
}

/// EPS encryption and integrity algorithm octets shared by the UE network
/// capability and UE security capability IEs.
macro_rules! eps_algorithm_octets_ie {
    ($name:ident) => {
        impl $name {
            /// The raw capability octets.
            pub fn capability_bytes(&self) -> &[u8] {
                &self.value
            }

            /// Build from raw capability octets.
            pub fn from_capability_bytes(bytes: Vec<u8>) -> Self {
                Self::new(bytes)
            }

            /// Build the two-octet form from the EEA and EIA octets.
            pub fn from_eea_eia(eea: u8, eia: u8) -> Self {
                Self::new(vec![eea, eia])
            }

            /// EPS encryption algorithms octet (EEA0 to EEA7).
            pub fn eea_byte(&self) -> u8 {
                self.value.first().copied().unwrap_or(0)
            }

            /// EPS integrity algorithms octet, including EPS-UPIP in bit 1.
            pub fn eia_byte(&self) -> u8 {
                self.value.get(1).copied().unwrap_or(0)
            }

            /// Whether EEA`algo` (0 to 7) is supported.
            pub fn supports_eea(&self, algo: u8) -> bool {
                algo <= 7 && self.eea_byte() & (0x80 >> algo) != 0
            }

            /// Whether EIA`algo` (0 to 6) is supported. Bit 1 of the octet is
            /// EPS-UPIP, so EIA7 is never reported.
            pub fn supports_eia(&self, algo: u8) -> bool {
                algo <= 6 && self.eia_byte() & (0x80 >> algo) != 0
            }

            /// Set EEA`algo` (0 to 7), extending the value to two octets.
            pub fn set_eea(&mut self, algo: u8, supported: bool) {
                if algo <= 7 {
                    self.set_algorithm_bit(0, algo, supported);
                }
            }

            /// Set EIA`algo` (0 to 6), extending the value to two octets.
            pub fn set_eia(&mut self, algo: u8, supported: bool) {
                if algo <= 6 {
                    self.set_algorithm_bit(1, algo, supported);
                }
            }

            fn set_algorithm_bit(&mut self, octet: usize, algo: u8, supported: bool) {
                if self.value.len() < 2 {
                    self.value.resize(2, 0);
                }
                let mask = 0x80 >> algo;
                if supported {
                    self.value[octet] |= mask;
                } else {
                    self.value[octet] &= !mask;
                }
                self.length = self.value.len() as _;
            }
        }
    };
}

// ── EPS bit rates (Tables 9.9.4.2.1, 9.9.4.3.1, 9.9.4.29.1, 9.9.4.30.1) ─────

/// Decode an 8-bit EPS bit rate (octets 3/4 of APN-AMBR, octets 4-7 of EPS
/// QoS). The value 0 (reserved, or "subscribed" from the UE) returns `None`;
/// 255 means 0 kbps.
pub(crate) fn eps_bit_rate_kbps(octet: u8) -> Option<u64> {
    let octet = u64::from(octet);
    match octet {
        0 => None,
        1..=63 => Some(octet),
        64..=127 => Some(64 + (octet - 64) * 8),
        128..=254 => Some(576 + (octet - 128) * 64),
        _ => Some(0),
    }
}

/// Decode an extended EPS bit rate octet. The value 0 returns `None` (use
/// the 8-bit value); undefined values are interpreted as 256 Mbps.
pub(crate) fn eps_extended_bit_rate_kbps(octet: u8) -> Option<u64> {
    let octet = u64::from(octet);
    match octet {
        0 => None,
        1..=0x4a => Some(8_600 + octet * 100),
        0x4b..=0xba => Some(16_000 + (octet - 0x4a) * 1_000),
        0xbb..=0xfa => Some(128_000 + (octet - 0xba) * 2_000),
        _ => Some(256_000),
    }
}

/// Decode an EPS QoS extended-2 bit rate octet. The value 0 returns `None`
/// (use the previous octets); undefined values map to the 10 Gbps maximum.
pub(crate) fn eps_qos_extended2_bit_rate_kbps(octet: u8) -> Option<u64> {
    let octet = u64::from(octet);
    match octet {
        0 => None,
        1..=0x3d => Some(256_000 + octet * 4_000),
        0x3e..=0xa1 => Some(500_000 + (octet - 0x3d) * 10_000),
        0xa2..=0xf6 => Some(1_500_000 + (octet - 0xa1) * 100_000),
        _ => Some(10_000_000),
    }
}

/// Encode a rate up to 8640 kbps as the 8-bit EPS bit rate octet.
pub(crate) fn eps_bit_rate_octet(kbps: u64) -> Option<u8> {
    match kbps {
        0 => Some(0xff),
        1..=63 => Some(kbps as u8),
        64..=568 if (kbps - 64).is_multiple_of(8) => Some((64 + (kbps - 64) / 8) as u8),
        576..=8_640 if (kbps - 576).is_multiple_of(64) => Some((128 + (kbps - 576) / 64) as u8),
        _ => None,
    }
}

/// Encode a rate from 8700 kbps to 256 Mbps as the extended octet.
pub(crate) fn eps_extended_bit_rate_octet(kbps: u64) -> Option<u8> {
    match kbps {
        8_700..=16_000 if (kbps - 8_600).is_multiple_of(100) => Some(((kbps - 8_600) / 100) as u8),
        17_000..=128_000 if kbps.is_multiple_of(1_000) => {
            Some((0x4a + (kbps - 16_000) / 1_000) as u8)
        }
        130_000..=256_000 if kbps.is_multiple_of(2_000) => {
            Some((0xba + (kbps - 128_000) / 2_000) as u8)
        }
        _ => None,
    }
}

/// Encode a rate from 260 Mbps to 10 Gbps as the EPS QoS extended-2 octet.
pub(crate) fn eps_qos_extended2_bit_rate_octet(kbps: u64) -> Option<u8> {
    match kbps {
        260_000..=500_000 if kbps.is_multiple_of(4_000) => Some(((kbps - 256_000) / 4_000) as u8),
        510_000..=1_500_000 if kbps.is_multiple_of(10_000) => {
            Some((0x3d + (kbps - 500_000) / 10_000) as u8)
        }
        1_600_000..=10_000_000 if kbps.is_multiple_of(100_000) => {
            Some((0xa1 + (kbps - 1_500_000) / 100_000) as u8)
        }
        _ => None,
    }
}

/// Encode a rate up to 256 Mbps as the (8-bit, extended) octet pair of
/// APN-AMBR or EPS QoS; the extended octet is 0 when unused.
pub(crate) fn eps_bit_rate_octets(kbps: u64) -> Option<(u8, u8)> {
    if let Some(octet) = eps_bit_rate_octet(kbps) {
        return Some((octet, 0));
    }
    Some((0xfe, eps_extended_bit_rate_octet(kbps)?))
}

/// Multiplier in kbps of a unit from 4 Mbps (code 3) to 256 Pbps (code
/// 0x15); larger codes are interpreted as 256 Pbps.
fn eps_extended_unit_step_kbps(unit: u8) -> u64 {
    match unit {
        0..=6 => 1_000 * 4u64.pow(u32::from(unit.max(3)) - 2),
        7..=0x0b => 1_000_000 * 4u64.pow(u32::from(unit) - 7),
        0x0c..=0x10 => 1_000_000_000 * 4u64.pow(u32::from(unit) - 0x0c),
        0x11..=0x15 => 1_000_000_000_000 * 4u64.pow(u32::from(unit) - 0x11),
        _ => 256_000_000_000_000,
    }
}

/// Multiplier in kbps of an extended APN-AMBR unit (Table 9.9.4.29.1).
/// The unused codes 0 to 2 are interpreted as 4 Mbps.
pub(crate) fn extended_apn_ambr_unit_kbps(unit: u8) -> u64 {
    eps_extended_unit_step_kbps(unit)
}

/// Multiplier in kbps of an extended QoS unit (Table 9.9.4.30.1). The
/// unused code 0 is interpreted as 200 kbps.
pub(crate) fn extended_qos_unit_kbps(unit: u8) -> u64 {
    match unit {
        0 | 1 => 200,
        2 => 1_000,
        _ => eps_extended_unit_step_kbps(unit),
    }
}

/// Encode a rate as the smallest exact (unit, value) pair from `units`.
pub(crate) fn eps_extended_unit_value(
    kbps: u64,
    units: std::ops::RangeInclusive<u8>,
    unit_kbps: fn(u8) -> u64,
) -> Option<(u8, u16)> {
    units.into_iter().find_map(|unit| {
        let multiplier = unit_kbps(unit);
        (kbps.is_multiple_of(multiplier) && kbps / multiplier <= u64::from(u16::MAX))
            .then(|| (unit, (kbps / multiplier) as u16))
    })
}

/// Authentication response parameter (TS 24.301 §9.9.3.4): RES of 4 to 16
/// octets for EPS AKA, or the 16-octet RES* that TS 24.501 §9.11.3.17 carries.
macro_rules! authentication_response_parameter_ie {
    ($name:ident) => {
        impl $name {
            /// The RES octets.
            pub fn res(&self) -> &[u8] {
                &self.value
            }

            /// Build from RES octets; `None` unless 4 to 16 octets.
            pub fn from_res(res: &[u8]) -> Option<Self> {
                (4..=16)
                    .contains(&res.len())
                    .then(|| Self::new(res.to_vec()))
            }

            /// The RES* octets (5G AKA).
            pub fn res_star(&self) -> &[u8] {
                &self.value
            }

            /// Build from RES* octets; `None` unless 4 to 16 octets.
            pub fn from_res_star_bytes(res_star: &[u8]) -> Option<Self> {
                Self::from_res(res_star)
            }

            /// Build from a 16-octet RES*.
            pub fn from_res_star(res_star: [u8; 16]) -> Self {
                Self::new(res_star.to_vec())
            }

            /// The 16-octet RES*, or `None` for another length.
            pub fn res_star_array(&self) -> Option<[u8; 16]> {
                self.value.as_slice().try_into().ok()
            }
        }
    };
}

/// EPS bearer context status (TS 24.301 §9.9.2.1, TS 24.501 §9.11.3.23A).
///
/// Value octet 1 bits 2 to 8 carry EBI(1) to EBI(7) and octet 2 carries
/// EBI(8) to EBI(15). EBI(0) is spare.
macro_rules! eps_bearer_context_status_ie {
    ($name:ident) => {
        impl $name {
            /// Whether EBI 1 to 15 is marked active. Missing octets read as
            /// inactive; other EBIs are never active.
            pub fn is_active(&self, ebi: u8) -> bool {
                (1..=15).contains(&ebi)
                    && self
                        .value
                        .get(usize::from(ebi / 8))
                        .is_some_and(|octet| octet >> (ebi % 8) & 1 != 0)
            }

            /// Active EBIs in ascending order. The spare EBI(0) bit and
            /// octets after the second are ignored.
            pub fn active_bearers(&self) -> Vec<u8> {
                (1..=15).filter(|&ebi| self.is_active(ebi)).collect()
            }

            /// Build from EBIs 1 to 15; `None` for any other value.
            pub fn from_bearers(ebis: &[u8]) -> Option<Self> {
                let mut status = Self::new(vec![0, 0]);
                for &ebi in ebis {
                    status.set_active(ebi, true)?;
                }
                Some(status)
            }

            /// Mark EBI 1 to 15 active or inactive; `None` for any other value.
            pub fn set_active(&mut self, ebi: u8, active: bool) -> Option<&mut Self> {
                if !(1..=15).contains(&ebi) {
                    return None;
                }
                if self.value.len() < 2 {
                    self.value.resize(2, 0);
                    self.length = self.value.len() as _;
                }
                let octet = &mut self.value[usize::from(ebi / 8)];
                let mask = 1 << (ebi % 8);
                if active {
                    *octet |= mask;
                } else {
                    *octet &= !mask;
                }
                Some(self)
            }

            /// Sender check: two octets with the spare EBI(0) bit clear.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() == 2 && self.value[0] & 0x01 == 0
            }
        }
    };
}

/// Serving PLMN rate control (TS 24.301 §9.9.4.28, TS 24.501 §9.11.4.20).
///
/// A 16-bit count of uplink messages per 6 minutes, at least 10. The value
/// `0xFFFF` means no restriction.
macro_rules! serving_plmn_rate_control_ie {
    ($name:ident) => {
        impl $name {
            /// Rate from the first two octets; `None` below 10 or if truncated.
            pub fn rate(&self) -> Option<u16> {
                let rate = u16::from_be_bytes([*self.value.first()?, *self.value.get(1)?]);
                (rate >= 10).then_some(rate)
            }

            /// Raw rate value, or 0 if truncated.
            pub fn rate_raw(&self) -> u16 {
                match self.value.as_slice() {
                    [high, low, ..] => u16::from_be_bytes([*high, *low]),
                    _ => 0,
                }
            }

            /// Build from a rate of at least 10; `0xFFFF` means unrestricted.
            pub fn from_rate(rate: u16) -> Option<Self> {
                (rate >= 10).then(|| Self::new(rate.to_be_bytes().to_vec()))
            }

            /// Whether the rate imposes no restriction.
            pub fn is_unrestricted(&self) -> bool {
                self.rate() == Some(u16::MAX)
            }

            /// Sender check: exactly two octets with a rate of at least 10.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() == 2 && self.rate().is_some()
            }
        }
    };
}

/// Downlink data expected (TS 24.301 §9.9.4.25, TS 24.501 §9.11.3.46A).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DownlinkDataExpected {
    /// No information available.
    NoInfo = 0,
    /// No further uplink or downlink data expected.
    NoFurtherData = 1,
    /// One downlink data transmission, then no further data expected.
    SingleDlThenNone = 2,
}

impl DownlinkDataExpected {
    /// Decode bits 2-1, rejecting the reserved value 3.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoInfo),
            1 => Some(Self::NoFurtherData),
            2 => Some(Self::SingleDlThenNone),
            _ => None,
        }
    }
}

/// Release assistance indication (TS 24.301 §9.9.4.25, TS 24.501
/// §9.11.3.46A), a type 1 IE.
macro_rules! release_assistance_indication_ie {
    ($name:ident) => {
        impl $name {
            /// Downlink data expected (bits 2-1); `None` for the reserved value.
            pub fn ddx(&self) -> Option<DownlinkDataExpected> {
                DownlinkDataExpected::from_u8(self.value)
            }

            /// Raw downlink data expected value (bits 2-1).
            pub fn ddx_raw(&self) -> u8 {
                self.value & 0x03
            }

            /// Build with the spare bits clear.
            pub fn from_ddx(ddx: DownlinkDataExpected) -> Self {
                Self::new(ddx as u8)
            }

            /// Set the downlink data expected value and clear the spare bits.
            pub fn set_ddx(&mut self, ddx: DownlinkDataExpected) -> &mut Self {
                self.value = ddx as u8;
                self
            }

            /// Builder form of [`Self::set_ddx`].
            pub fn with_ddx(mut self, ddx: DownlinkDataExpected) -> Self {
                self.set_ddx(ddx);
                self
            }
        }
    };
}

/// ROHC profiles of the header compression configuration (TS 24.301
/// §9.9.4.22, TS 24.501 §9.11.4.24), octet 3 bits 1 to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpHdrCompProfiles {
    /// Profile 0x0002 (UDP/IP).
    pub p0002: bool,
    /// Profile 0x0003 (ESP/IP).
    pub p0003: bool,
    /// Profile 0x0004 (IP).
    pub p0004: bool,
    /// Profile 0x0006 (TCP/IP).
    pub p0006: bool,
    /// Profile 0x0102 (UDP/IP).
    pub p0102: bool,
    /// Profile 0x0103 (ESP/IP).
    pub p0103: bool,
    /// Profile 0x0104 (IP).
    pub p0104: bool,
}

impl IpHdrCompProfiles {
    /// Decode bits 1 to 7; the spare bit 8 is ignored.
    pub fn from_u8(octet: u8) -> Self {
        Self {
            p0002: octet & 0x01 != 0,
            p0003: octet & 0x02 != 0,
            p0004: octet & 0x04 != 0,
            p0006: octet & 0x08 != 0,
            p0102: octet & 0x10 != 0,
            p0103: octet & 0x20 != 0,
            p0104: octet & 0x40 != 0,
        }
    }

    /// Encode with the spare bit clear.
    pub fn as_u8(self) -> u8 {
        [
            self.p0002, self.p0003, self.p0004, self.p0006, self.p0102, self.p0103, self.p0104,
        ]
        .iter()
        .enumerate()
        .fold(0, |octet, (bit, &set)| octet | u8::from(set) << bit)
    }
}

/// Additional header compression context setup parameters type (TS 24.301
/// Table 9.9.4.22.1). Codes 0x09 to 0xFF are spare.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IpHdrCompAdditionalSetupType {
    /// Profile 0x0000 (no compression).
    NoCompression = 0x00,
    /// Profile 0x0002 (UDP/IP).
    RohcUdpIp = 0x01,
    /// Profile 0x0003 (ESP/IP).
    RohcEspIp = 0x02,
    /// Profile 0x0004 (IP).
    RohcIp = 0x03,
    /// Profile 0x0006 (TCP/IP).
    RohcTcpIp = 0x04,
    /// Profile 0x0102 (UDP/IP).
    RohcV2UdpIp = 0x05,
    /// Profile 0x0103 (ESP/IP).
    RohcV2EspIp = 0x06,
    /// Profile 0x0104 (IP).
    RohcV2Ip = 0x07,
    /// Other profile.
    Other = 0x08,
}

impl IpHdrCompAdditionalSetupType {
    /// Decode a defined code; spare codes return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::NoCompression),
            0x01 => Some(Self::RohcUdpIp),
            0x02 => Some(Self::RohcEspIp),
            0x03 => Some(Self::RohcIp),
            0x04 => Some(Self::RohcTcpIp),
            0x05 => Some(Self::RohcV2UdpIp),
            0x06 => Some(Self::RohcV2EspIp),
            0x07 => Some(Self::RohcV2Ip),
            0x08 => Some(Self::Other),
            _ => None,
        }
    }
}

/// Header compression configuration (TS 24.301 §9.9.4.22, TS 24.501
/// §9.11.4.24): profiles, MAX_CID, and optional additional context setup
/// parameters (type and container of at most 251 octets). Raw access
/// comes from `nas_opaque_ie!`.
macro_rules! header_compression_configuration_ie {
    ($name:ident) => {
        impl $name {
            /// ROHC profiles; all clear if the value is empty.
            pub fn profiles(&self) -> IpHdrCompProfiles {
                IpHdrCompProfiles::from_u8(self.value.first().copied().unwrap_or(0))
            }

            /// MAX_CID (octets 4-5), or 0 if truncated.
            pub fn max_cid(&self) -> u16 {
                match self.value.as_slice() {
                    [_, high, low, ..] => u16::from_be_bytes([*high, *low]),
                    _ => 0,
                }
            }

            /// Whether the spare bit is clear, MAX_CID is 1 to 16383, and the
            /// value fits in 255 octets.
            pub fn header_constraints_are_valid(&self) -> bool {
                self.value.first().is_some_and(|octet| octet & 0x80 == 0)
                    && (1..=16383).contains(&self.max_cid())
                    && self.value.len() <= 255
            }

            /// Sender check: [`Self::header_constraints_are_valid`] and at
            /// least three value octets.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() >= 3
                    && self.header_constraints_are_valid()
                    && self
                        .value
                        .get(3)
                        .is_none_or(|value| IpHdrCompAdditionalSetupType::from_u8(*value).is_some())
            }

            /// Raw additional setup parameters type (octet 6).
            pub fn additional_setup_type(&self) -> Option<u8> {
                self.value.get(3).copied()
            }

            /// Typed additional setup parameters type; `None` if absent or spare.
            pub fn additional_setup_type_value(&self) -> Option<IpHdrCompAdditionalSetupType> {
                self.additional_setup_type()
                    .and_then(IpHdrCompAdditionalSetupType::from_u8)
            }

            /// Additional setup parameters container (octets 7 onwards).
            pub fn additional_setup_container(&self) -> Option<&[u8]> {
                self.value
                    .get(4..)
                    .filter(|container| !container.is_empty())
            }

            /// Build from profiles and a MAX_CID of 1 to 16383.
            pub fn from_profiles(profiles: IpHdrCompProfiles, max_cid: u16) -> Option<Self> {
                (1..=16383).contains(&max_cid).then(|| {
                    let [high, low] = max_cid.to_be_bytes();
                    Self::new(vec![profiles.as_u8(), high, low])
                })
            }

            /// Build with additional setup parameters; the container holds at
            /// most 251 octets.
            pub fn from_profiles_with_additional_setup(
                profiles: IpHdrCompProfiles,
                max_cid: u16,
                additional_setup_type: IpHdrCompAdditionalSetupType,
                additional_setup_container: &[u8],
            ) -> Option<Self> {
                if additional_setup_container.len() > 251 {
                    return None;
                }
                let mut value = Self::from_profiles(profiles, max_cid)?.value;
                value.push(additional_setup_type as u8);
                value.extend_from_slice(additional_setup_container);
                Some(Self::new(value))
            }
        }
    };
}

/// One entry of the extended emergency number list (TS 24.301 §9.9.3.37A).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedEmergencyNumber {
    /// Number digits: `0`-`9`, `*`, `#`, `a`, `b`, and `c`.
    pub digits: String,
    /// Sub-services of the emergency service URN, such as "police.municipal";
    /// empty for "urn:service:sos".
    pub sub_services: String,
}

/// Extended emergency number list (TS 24.301 §9.9.3.37A, TS 24.501
/// §9.11.3.26): the validity flag, then numbers with GSM 7-bit coded
/// sub-services.
macro_rules! extended_emergency_number_list_ie {
    ($name:ident) => {
        impl $name {
            /// Validity (EENLV): `true` when the list is valid only in the
            /// PLMN it came from, `false` for the whole country.
            pub fn valid_only_in_plmn(&self) -> Option<bool> {
                self.value.first().map(|octet| octet & 0x01 != 0)
            }

            /// Emergency numbers in wire order; `None` if an entry overruns
            /// the value.
            pub fn numbers(&self) -> Option<Vec<ExtendedEmergencyNumber>> {
                let mut numbers = Vec::new();
                let mut remaining = self.value.get(1..)?;
                while let Some((&length, rest)) = remaining.split_first() {
                    let digits = rest.get(..usize::from(length))?;
                    let (&sub_length, rest) = rest[digits.len()..].split_first()?;
                    let sub_services = rest.get(..usize::from(sub_length))?;
                    numbers.push(ExtendedEmergencyNumber {
                        digits: crate::common::ts24008::decode_number_digits(digits),
                        sub_services: crate::common::gsm7::decode_septets(
                            &crate::common::gsm7::unpack_padded_septets(sub_services),
                        ),
                    });
                    remaining = &rest[sub_services.len()..];
                }
                Some(numbers)
            }

            /// Build from emergency numbers; `None` for an empty list,
            /// invalid digits, or sub-services outside the GSM 7-bit default
            /// alphabet.
            pub fn from_numbers(
                valid_only_in_plmn: bool,
                numbers: &[ExtendedEmergencyNumber],
            ) -> Option<Self> {
                if numbers.is_empty() {
                    return None;
                }
                let mut value = vec![u8::from(valid_only_in_plmn)];
                for number in numbers {
                    let digits = crate::common::ts24008::encode_number_digits(&number.digits)?;
                    let septets = crate::common::gsm7::encode_septets(&number.sub_services)?;
                    let sub_services = crate::common::gsm7::pack_padded_septets(&septets);
                    value.push(u8::try_from(digits.len()).ok()?);
                    value.extend(digits);
                    value.push(u8::try_from(sub_services.len()).ok()?);
                    value.extend(sub_services);
                }
                (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
            }

            /// Sender check: spare bits clear, at least one number, complete
            /// entries, and canonical digits.
            pub fn is_well_formed(&self) -> bool {
                let Some((&validity, mut remaining)) = self.value.split_first() else {
                    return false;
                };
                if validity & 0xfe != 0 || remaining.is_empty() {
                    return false;
                }
                while let Some((&length, rest)) = remaining.split_first() {
                    let Some(digits) = rest.get(..usize::from(length)) else {
                        return false;
                    };
                    if digits.is_empty()
                        || !crate::common::ts24008::number_digits_are_well_formed(digits)
                    {
                        return false;
                    }
                    let Some((&sub_length, rest)) = rest[digits.len()..].split_first() else {
                        return false;
                    };
                    let Some(sub_services) = rest.get(..usize::from(sub_length)) else {
                        return false;
                    };
                    remaining = &rest[sub_services.len()..];
                }
                true
            }
        }
    };
}

/// UE paging probability of the WUS assistance information (TS 24.301
/// Table 9.9.3.62.1): `P00` is 0 %, and each step adds up to 5 %.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum UePagingProbability {
    /// Paging probability 0 %.
    P00 = 0,
    /// Paging probability above 0 % up to 5 %.
    P05 = 1,
    /// Paging probability above 5 % up to 10 %.
    P10 = 2,
    /// Paging probability above 10 % up to 15 %.
    P15 = 3,
    /// Paging probability above 15 % up to 20 %.
    P20 = 4,
    /// Paging probability above 20 % up to 25 %.
    P25 = 5,
    /// Paging probability above 25 % up to 30 %.
    P30 = 6,
    /// Paging probability above 30 % up to 35 %.
    P35 = 7,
    /// Paging probability above 35 % up to 40 %.
    P40 = 8,
    /// Paging probability above 40 % up to 45 %.
    P45 = 9,
    /// Paging probability above 45 % up to 50 %.
    P50 = 10,
    /// Paging probability above 50 % up to 55 %.
    P55 = 11,
    /// Paging probability above 55 % up to 60 %.
    P60 = 12,
    /// Paging probability above 60 % up to 65 %.
    P65 = 13,
    /// Paging probability above 65 % up to 70 %.
    P70 = 14,
    /// Paging probability above 70 % up to 75 %.
    P75 = 15,
    /// Paging probability above 75 % up to 80 %.
    P80 = 16,
    /// Paging probability above 80 % up to 85 %.
    P85 = 17,
    /// Paging probability above 85 % up to 90 %.
    P90 = 18,
    /// Paging probability above 90 % up to 95 %.
    P95 = 19,
    /// Paging probability above 95 % up to 100 %.
    P100 = 20,
}

impl UePagingProbability {
    const ALL: [Self; 21] = [
        Self::P00,
        Self::P05,
        Self::P10,
        Self::P15,
        Self::P20,
        Self::P25,
        Self::P30,
        Self::P35,
        Self::P40,
        Self::P45,
        Self::P50,
        Self::P55,
        Self::P60,
        Self::P65,
        Self::P70,
        Self::P75,
        Self::P80,
        Self::P85,
        Self::P90,
        Self::P95,
        Self::P100,
    ];

    /// Decode bits 5-1; other values are interpreted as `P100`.
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::P100)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        Self::ALL.get(usize::from(value & 0x1f)).copied()
    }

    /// Upper bound of the probability range in percent.
    pub fn percent(self) -> u8 {
        self as u8 * 5
    }
}

/// WUS assistance information (TS 24.301 §9.9.3.62, TS 24.501 §9.11.3.71):
/// the type of information and the UE paging probability.
macro_rules! wus_assistance_information_ie {
    ($name:ident) => {
        impl $name {
            /// Type of information (bits 8-6); only 0 is defined.
            pub fn information_type(&self) -> Option<u8> {
                self.value.first().map(|octet| octet >> 5)
            }

            /// UE paging probability with the receive fallback, when the
            /// type of information is "UE paging probability information".
            pub fn paging_probability(&self) -> Option<UePagingProbability> {
                let octet = *self.value.first()?;
                (octet >> 5 == 0).then(|| UePagingProbability::from_u8(octet))
            }

            /// Raw UE paging probability (bits 5-1).
            pub fn paging_probability_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x1f)
            }

            /// Build from a UE paging probability.
            pub fn from_paging_probability(probability: UePagingProbability) -> Self {
                Self::new(vec![probability as u8])
            }

            /// Sender check: one octet with type 0 and a defined probability.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [octet] if *octet <= 20)
            }
        }
    };
}

/// MUSIM request type (TS 24.301 Table 9.9.3.65.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum UeRequestType {
    /// Release the NAS signalling connection.
    NasSignallingConnectionRelease = 1,
    /// Reject paging.
    RejectionOfPaging = 2,
}

impl UeRequestType {
    /// Decode bits 4-1; reserved values return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0f {
            1 => Some(Self::NasSignallingConnectionRelease),
            2 => Some(Self::RejectionOfPaging),
            _ => None,
        }
    }
}

/// UE request type (TS 24.301 §9.9.3.65, TS 24.501 §9.11.3.76).
macro_rules! ue_request_type_ie {
    ($name:ident) => {
        impl $name {
            /// Typed request type; reserved values return `None`.
            pub fn request_type(&self) -> Option<UeRequestType> {
                UeRequestType::from_u8(*self.value.first()?)
            }

            /// Raw request type (bits 4-1).
            pub fn request_type_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x0f)
            }

            /// Build with the spare bits clear.
            pub fn from_request_type(request_type: UeRequestType) -> Self {
                Self::new(vec![request_type as u8])
            }

            /// Sender check: one octet with a defined value and spare bits clear.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [1 | 2])
            }
        }
    };
}

/// Read a three-octet time duration in seconds (TS 24.301 §9.9.3.68).
pub(crate) fn read_time_duration(octets: &[u8]) -> Option<u32> {
    let [a, b, c] = *octets.first_chunk::<3>()?;
    Some(u32::from_be_bytes([0, a, b, c]))
}

/// Unavailability information (TS 24.301 §9.9.3.69, TS 24.501 §9.11.2.20),
/// sent by the UE.
macro_rules! unavailability_information_ie {
    ($name:ident) => {
        impl $name {
            /// Whether the unavailability is due to discontinuous coverage;
            /// spare type values are read as "due to UE reasons".
            pub fn due_to_discontinuous_coverage(&self) -> Option<bool> {
                self.value.first().map(|octet| octet & 0x07 == 1)
            }

            /// Raw unavailability type (bits 3-1).
            pub fn unavailability_type_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x07)
            }

            /// Unavailability period duration in seconds, when indicated.
            pub fn period_duration(&self) -> Option<u32> {
                let header = *self.value.first()?;
                if header & 0x08 == 0 {
                    return None;
                }
                crate::common::ts24301::read_time_duration(self.value.get(1..)?)
            }

            /// Time until the start of the unavailability period in seconds,
            /// when indicated.
            pub fn start_of_period(&self) -> Option<u32> {
                let header = *self.value.first()?;
                if header & 0x10 == 0 {
                    return None;
                }
                let offset = 1 + if header & 0x08 != 0 { 3 } else { 0 };
                crate::common::ts24301::read_time_duration(self.value.get(offset..)?)
            }

            /// Build from the fields; durations are at most 0xFFFFFF seconds.
            pub fn from_fields(
                discontinuous_coverage: bool,
                period_duration: Option<u32>,
                start_of_period: Option<u32>,
            ) -> Option<Self> {
                let mut value = vec![
                    u8::from(discontinuous_coverage)
                        | u8::from(period_duration.is_some()) << 3
                        | u8::from(start_of_period.is_some()) << 4,
                ];
                for seconds in [period_duration, start_of_period].into_iter().flatten() {
                    if seconds > 0x00ff_ffff {
                        return None;
                    }
                    value.extend_from_slice(&seconds.to_be_bytes()[1..]);
                }
                Some(Self::new(value))
            }

            /// Sender check: spare bits clear, a defined type, and exactly
            /// the indicated durations.
            pub fn is_well_formed(&self) -> bool {
                self.value.first().is_some_and(|header| {
                    header & 0xe6 == 0
                        && self.value.len()
                            == 1 + 3
                                * (usize::from(header & 0x08 != 0)
                                    + usize::from(header & 0x10 != 0))
                })
            }
        }
    };
}

/// Unavailability configuration (TS 24.301 §9.9.3.70, TS 24.501
/// §9.11.2.21), sent by the network.
macro_rules! unavailability_configuration_ie {
    ($name:ident) => {
        impl $name {
            /// Whether the UE must report the end of the unavailability
            /// period (EUPR bit clear).
            pub fn end_of_period_report_needed(&self) -> Option<bool> {
                self.value.first().map(|octet| octet & 0x01 == 0)
            }

            /// Unavailability period duration in seconds, when indicated.
            pub fn period_duration(&self) -> Option<u32> {
                let header = *self.value.first()?;
                if header & 0x02 == 0 {
                    return None;
                }
                crate::common::ts24301::read_time_duration(self.value.get(1..)?)
            }

            /// Time until the start of the unavailability period in seconds,
            /// when indicated.
            pub fn start_of_period(&self) -> Option<u32> {
                let header = *self.value.first()?;
                if header & 0x04 == 0 {
                    return None;
                }
                let offset = 1 + if header & 0x02 != 0 { 3 } else { 0 };
                crate::common::ts24301::read_time_duration(self.value.get(offset..)?)
            }

            /// Build from the fields; durations are at most 0xFFFFFF seconds.
            pub fn from_fields(
                end_of_period_report_needed: bool,
                period_duration: Option<u32>,
                start_of_period: Option<u32>,
            ) -> Option<Self> {
                let mut value = vec![
                    u8::from(!end_of_period_report_needed)
                        | u8::from(period_duration.is_some()) << 1
                        | u8::from(start_of_period.is_some()) << 2,
                ];
                for seconds in [period_duration, start_of_period].into_iter().flatten() {
                    if seconds > 0x00ff_ffff {
                        return None;
                    }
                    value.extend_from_slice(&seconds.to_be_bytes()[1..]);
                }
                Some(Self::new(value))
            }

            /// Sender check: spare bits clear and exactly the indicated durations.
            pub fn is_well_formed(&self) -> bool {
                self.value.first().is_some_and(|header| {
                    header & 0xf8 == 0
                        && self.value.len()
                            == 1 + 3
                                * (usize::from(header & 0x02 != 0)
                                    + usize::from(header & 0x04 != 0))
                })
            }
        }
    };
}

/// Access technology utilization control (TS 24.301 §9.9.3.3A, TS 24.501
/// §9.11.3.110). An empty value asks the UE to remove the stored
/// information.
macro_rules! access_technology_utilization_control_ie {
    ($name:ident) => {
        impl $name {
            /// Whether the value removes the stored restriction information.
            pub fn is_removal(&self) -> bool {
                self.value.is_empty()
            }

            /// Whether the restrictions also apply to equivalent PLMNs; the
            /// unused values 2 and 3 are read as "current PLMN". `None` when
            /// octet 4 is missing, since the receiver then ignores the IE.
            pub fn applies_to_equivalent_plmns(&self) -> Option<bool> {
                self.value.get(1)?;
                Some(self.value[0] & 0x03 == 1)
            }

            /// Restricted access technology bitmap (octet 4); `None` when the
            /// receiver ignores the IE.
            pub fn restricted_bitmap(&self) -> Option<u8> {
                self.value.get(1).map(|octet| octet & 0x3f)
            }
        }

        crate::common::nas_ie_flags!($name {
            /// GERAN is restricted (octet 4, bit 1).
            geran_restricted: 1, 1;
            /// UTRAN is restricted (octet 4, bit 2).
            utran_restricted: 1, 2;
            /// E-UTRAN is restricted (octet 4, bit 3).
            eutran_restricted: 1, 3;
            /// NG-RAN is restricted (octet 4, bit 4).
            ng_ran_restricted: 1, 4;
            /// Satellite E-UTRAN is restricted (octet 4, bit 5).
            sat_eutran_restricted: 1, 5;
            /// Satellite NG-RAN is restricted (octet 4, bit 6).
            sat_ng_ran_restricted: 1, 6;
        });

        impl $name {
            /// Build a restriction list with octets 3 and 4.
            pub fn from_restrictions(equivalent_plmns: bool, restricted_bitmap: u8) -> Option<Self> {
                (restricted_bitmap <= 0x3f)
                    .then(|| Self::new(vec![u8::from(equivalent_plmns), restricted_bitmap]))
            }

            /// Sender check: empty, or octets 3 and 4 (and an all-zero octet
            /// 5) with the spare bits clear and a defined type.
            pub fn is_well_formed(&self) -> bool {
                match self.value.as_slice() {
                    [] => true,
                    [kind, bitmap, rest @ ..] => {
                        kind & 0xfe == 0 && bitmap & 0xc0 == 0 && matches!(rest, [] | [0])
                    }
                    _ => false,
                }
            }
        }
    };
}

pub(crate) use {
    access_technology_utilization_control_ie, authentication_response_parameter_ie,
    eps_algorithm_octets_ie, eps_bearer_context_status_ie, extended_emergency_number_list_ie,
    header_compression_configuration_ie, key_set_identifier_ie, nas_security_algorithms_ie,
    release_assistance_indication_ie, serving_plmn_rate_control_ie, ue_network_capability_ie,
    ue_request_type_ie, ue_security_capability_ie, unavailability_configuration_ie,
    unavailability_information_ie, wus_assistance_information_ie,
};

#[cfg(test)]
mod tests {
    use crate::nas_5gs::{NasS1UeNetworkCapability, NasS1UeSecurityCapability};
    use crate::nas_eps::{NasReplayedUeSecurityCapabilities, NasUeNetworkCapability};

    #[test]
    fn ue_network_capability_flags_follow_v19_8_layout() {
        // Capture packet 33 of the EPS fixtures: EEA0-2, EIA0-2, UEA/UIA octets zero.
        let capture = NasUeNetworkCapability::new(vec![0xe0, 0xe0, 0x00, 0x00, 0x00]);
        assert!((0..=2).all(|algo| capture.supports_eea(algo) && capture.supports_eia(algo)));
        assert!(!capture.supports_eea(3) && !capture.eps_upip());
        assert_eq!((capture.uea_byte(), capture.uia_byte()), (Some(0), Some(0)));
        assert!(capture.is_well_formed());

        // EIA7 no longer exists: octet 2 bit 1 is EPS-UPIP.
        let upip = NasUeNetworkCapability::new(vec![0x00, 0x01]);
        assert!(upip.eps_upip());
        assert!(!upip.supports_eia(7));

        // NonSATLSP (octet 12 bit 1) is valid; other octet 12-15 bits are spare.
        let mut value = vec![0; 10];
        value[9] = 0x01;
        let non_sat_lsp = NasUeNetworkCapability::new(value.clone());
        assert!(non_sat_lsp.non_sat_lsp() && non_sat_lsp.is_well_formed());
        value[9] = 0x03;
        let spare = NasUeNetworkCapability::new(value);
        assert!(spare.non_sat_lsp() && !spare.is_well_formed());

        // The receiver assumes S1-U data transfer without CP CIoT, and ignores
        // OHR-CP CIoT without it.
        let receiver = NasUeNetworkCapability::new(vec![0, 0, 0, 0, 0, 0x00, 0, 0, 0x40]);
        assert!(receiver.s1u_data_supported());
        assert!(receiver.ohr_cp_ciot() && !receiver.ohr_cp_ciot_supported());
        let cp_ciot = NasUeNetworkCapability::new(vec![0, 0, 0, 0, 0, 0x04, 0, 0, 0x40]);
        assert!(!cp_ciot.s1u_data_supported() && cp_ciot.ohr_cp_ciot_supported());
    }

    #[test]
    fn capability_setters_keep_declared_length_in_sync() {
        let mut capability = NasUeNetworkCapability::new(Vec::new())
            .with_racs(true)
            .with_non_sat_lsp(true);
        capability.set_eea(2, true);
        capability.set_eia(7, true);
        assert_eq!(capability.value.len(), 10);
        assert_eq!(capability.length as usize, capability.value.len());
        assert_eq!(capability.value[0], 0x20);
        assert_eq!(capability.value[1], 0x00);
        assert!(capability.racs() && capability.non_sat_lsp());
        let mut wire = bytes::BytesMut::new();
        crate::common::Encode::encode(&capability, &mut wire).unwrap();
        assert_eq!(wire[0] as usize, capability.value.len());
    }

    #[test]
    fn replayed_security_capability_inclusion_rules_and_match() {
        // Capture packet 37: the MME replays two octets because the UE
        // indicated no UMTS or GPRS algorithms.
        let ue = NasUeNetworkCapability::new(vec![0xe0, 0xe0, 0x00, 0x00, 0x00]);
        let replayed =
            NasReplayedUeSecurityCapabilities::from_algorithms(0xe0, 0xe0, Some((0, 0)), None);
        assert_eq!(replayed.value, [0xe0, 0xe0]);
        assert!(replayed.is_well_formed());
        assert!(replayed.matches_ue_network_capability(&ue));

        // Gb support without Iu support: octets 5 and 6 are zero-filled.
        let gb_only =
            NasReplayedUeSecurityCapabilities::from_algorithms(0x80, 0x80, None, Some(0x40));
        assert_eq!(gb_only.value, [0x80, 0x80, 0, 0, 0x40]);
        assert!(gb_only.is_well_formed() && gb_only.supports_gea(1));

        // UCS2 is not part of the replayed value; UIA spare bits are ignored.
        let iu_ue = NasUeNetworkCapability::new(vec![0xe0, 0xe0, 0xc0, 0xc0]);
        let iu = NasReplayedUeSecurityCapabilities::new(vec![0xe0, 0xe0, 0xc0, 0x40]);
        assert!(iu_ue.ucs2() && iu.matches_ue_network_capability(&iu_ue));
        assert!(!replayed.matches_ue_network_capability(&iu_ue));
        for invalid in [
            vec![0xe0],
            vec![0xe0, 0xe0, 0, 0],
            vec![0, 0, 1, 0x80],
            vec![0, 0, 0, 0, 0],
        ] {
            assert!(!NasReplayedUeSecurityCapabilities::new(invalid).is_well_formed());
        }
    }

    #[test]
    fn five_gs_s1_capabilities_share_the_eps_grammar() {
        let capability = NasS1UeNetworkCapability::new(vec![0xf0, 0x71, 0x00, 0x00, 0x00, 0x04]);
        assert!(capability.supports_eea(3) && capability.eps_upip() && !capability.supports_eia(7));
        assert!(capability.cp_ciot() && !capability.s1u_data_supported());
        let replayed = NasS1UeSecurityCapability::from_eea_eia(0xf0, 0x71);
        assert!(replayed.matches_ue_network_capability(&capability));
    }

    #[test]
    fn shared_esm_grammars_behave_identically_in_both_protocols() {
        use super::{DownlinkDataExpected, IpHdrCompAdditionalSetupType, IpHdrCompProfiles};
        use crate::nas_5gs::{self, NasIpHeaderCompressionConfiguration};
        use crate::nas_eps::{self, NasHeaderCompressionConfiguration};

        // §9.9.4.28: a rate below 10 is invalid in both protocols.
        assert!(nas_5gs::NasServingPlmnRateControl::from_rate(9).is_none());
        assert_eq!(
            nas_5gs::NasServingPlmnRateControl::new(vec![0, 9]).rate(),
            None
        );
        let rate = nas_eps::NasServingPlmnRateControl::from_rate(u16::MAX).unwrap();
        assert!(rate.is_unrestricted() && rate.is_well_formed());
        assert_eq!(
            nas_eps::NasServingPlmnRateControl::new(vec![0, 10, 0]).rate(),
            Some(10)
        );

        // §9.9.2.1: EBIs 1 to 4 are valid bitmap positions in 5GS too.
        let status = nas_5gs::NasEpsBearerContextStatus::from_bearers(&[1, 15]).unwrap();
        assert_eq!(status.value, [0x02, 0x80]);
        assert_eq!(status.active_bearers(), [1, 15]);

        let mut release = nas_eps::NasReleaseAssistanceIndication::new(0x0f);
        assert_eq!((release.ddx(), release.ddx_raw()), (None, 3));
        release.set_ddx(DownlinkDataExpected::NoFurtherData);
        assert_eq!(release.value, 1);
        let release = nas_5gs::NasReleaseAssistanceIndication::new(0x0e);
        assert_eq!(release.ddx(), Some(DownlinkDataExpected::SingleDlThenNone));

        let profiles = IpHdrCompProfiles {
            p0002: true,
            p0104: true,
            ..Default::default()
        };
        let eps = NasHeaderCompressionConfiguration::from_profiles_with_additional_setup(
            profiles,
            16383,
            IpHdrCompAdditionalSetupType::RohcIp,
            &[0xaa],
        )
        .unwrap();
        assert_eq!(eps.value, [0x41, 0x3f, 0xff, 0x03, 0xaa]);
        assert!(eps.is_well_formed());
        let fgs = NasIpHeaderCompressionConfiguration::from_data(eps.value.clone());
        assert_eq!(fgs.profiles(), profiles);
        assert_eq!(fgs.additional_setup_container(), Some([0xaa].as_slice()));
        assert!(NasIpHeaderCompressionConfiguration::from_profiles(profiles, 0).is_none());
        let received = NasHeaderCompressionConfiguration::new(vec![0xc1, 0x00, 0x01, 0x09]);
        assert!(received.profiles().p0002 && !received.is_well_formed());
        assert_eq!(received.additional_setup_type_value(), None);
        let reserved_setup = NasHeaderCompressionConfiguration::new(vec![0x00, 0x00, 0x01, 0x09]);
        assert!(!reserved_setup.is_well_formed());
    }

    #[test]
    fn shared_mobility_grammars_behave_identically_in_both_protocols() {
        use super::{UePagingProbability, UeRequestType};
        use crate::nas_5gs::{self, NasWusAssistanceInformation};
        use crate::nas_eps::{self, NasRequestedWusAssistanceInformation};

        // Table 9.9.3.62.1: undefined probabilities are read as p100.
        let wus = NasRequestedWusAssistanceInformation::new(vec![0x1f]);
        assert_eq!(wus.paging_probability(), Some(UePagingProbability::P100));
        assert!(!wus.is_well_formed());
        let wus = NasWusAssistanceInformation::from_paging_probability(UePagingProbability::P45);
        assert_eq!(
            (wus.value.as_slice(), UePagingProbability::P45.percent()),
            ([9].as_slice(), 45)
        );
        assert_eq!(
            NasWusAssistanceInformation::new(vec![0x21]).paging_probability(),
            None
        );

        let request =
            nas_eps::NasUeRequestType::from_request_type(UeRequestType::RejectionOfPaging);
        assert!(request.is_well_formed());
        assert_eq!(
            nas_5gs::NasUeRequestType::new(vec![0x31]).request_type(),
            Some(UeRequestType::NasSignallingConnectionRelease)
        );

        let info =
            nas_5gs::NasUnavailabilityInformation::from_fields(true, None, Some(3_600)).unwrap();
        assert_eq!(info.value, [0x11, 0x00, 0x0e, 0x10]);
        assert!(info.is_well_formed());
        assert_eq!(
            (info.period_duration(), info.start_of_period()),
            (None, Some(3_600))
        );
        // Spare unavailability types read as "due to UE reasons".
        assert_eq!(
            nas_eps::NasUnavailabilityInformation::new(vec![0x07]).due_to_discontinuous_coverage(),
            Some(false)
        );
        let config =
            nas_eps::NasUnavailabilityConfiguration::from_fields(false, Some(60), Some(120))
                .unwrap();
        assert_eq!(config.value, [0x07, 0, 0, 60, 0, 0, 120]);
        assert_eq!(config.end_of_period_report_needed(), Some(false));
        assert_eq!(config.start_of_period(), Some(120));

        let atuc =
            nas_eps::NasAccessTechnologyUtilizationControl::from_restrictions(true, 0x24).unwrap();
        assert!(atuc.is_well_formed() && atuc.eutran_restricted() && atuc.sat_ng_ran_restricted());
        assert_eq!(atuc.applies_to_equivalent_plmns(), Some(true));
        // Type 11 is read as "current PLMN"; octet 3 without octet 4 is ignored.
        let unused = nas_5gs::NasAccessTechnologyUtilizationControl::new(vec![0x03, 0x01]);
        assert_eq!(unused.applies_to_equivalent_plmns(), Some(false));
        assert!(!unused.is_well_formed());
        assert_eq!(
            nas_5gs::NasAccessTechnologyUtilizationControl::new(vec![0x01]).restricted_bitmap(),
            None
        );
        assert!(nas_eps::NasAccessTechnologyUtilizationControl::new(vec![]).is_removal());
    }

    #[test]
    fn key_set_identifier_is_one_grammar_for_both_protocols() {
        use super::KeySetIdentifier;
        use crate::{nas_5gs, nas_eps};
        // Setters preserve bits 8-5 on both sides.
        assert_eq!(
            nas_5gs::NasKeySetIdentifier::new(0xf8).with_ksi(2).value,
            0xfa
        );
        assert_eq!(
            nas_eps::NasKeySetIdentifier::new(0xf8).with_ksi(2).value,
            0xfa
        );
        assert_eq!(
            nas_5gs::NasKeySetIdentifier::new(0xf8).with_ngksi(2).value,
            0xfa
        );
        let mapped = nas_5gs::NasKeySetIdentifier::new(0x0b);
        assert_eq!(mapped.key_set_identifier(), KeySetIdentifier::Mapped(3));
        assert_eq!(mapped.ngksi(), 3);
        assert!(mapped.tsc());
        assert!(nas_eps::NasKeySetIdentifier::new(0x07).no_key_available());
        assert_eq!(
            nas_5gs::NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(6))
                .unwrap()
                .value,
            6
        );
        assert!(
            nas_eps::NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Mapped(7))
                .is_err()
        );
        let mut octet = nas_5gs::NasKeySetIdentifier::new(0x10);
        octet
            .set_key_set_identifier(KeySetIdentifier::Mapped(1))
            .unwrap();
        assert_eq!(octet.value, 0x19);
    }
}
