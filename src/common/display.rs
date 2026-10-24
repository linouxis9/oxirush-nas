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

//! The forms that the `Display` of the messages and of the IEs of both
//! systems share: one formatter for each kind of value, which the IE types
//! of 5GS and of EPS that have its grammar call.
//!
//! - a cause by its number and its name in the table of the specification:
//!   `#22 (Congestion)`;
//! - a timer with its unit: `10 min`, `54 min`, `2 h`, `deactivated`;
//! - octets that travel in clear, RAND, AUTN and AUTS, whole and in lower
//!   case; a key, RES or RES\*, never;
//! - an identity as oxirush-utils prints it, `5g-guti-...`, `suci-...`,
//!   `imsi-...`, and a TAI as `208-93-000001`;
//! - a list whole up to four entries, then its first three and how many
//!   more;
//! - other octets whole up to sixteen, then their count.

use crate::common::ts24008::GprsTimerValue;
use crate::common::types::*;
use core::fmt::{self, Display as _};

/// The items of a message after its name: ` (label=value, word)`, and
/// nothing when it shows none.
pub(crate) struct Items<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
    open: bool,
}

impl<'a, 'b> Items<'a, 'b> {
    /// The items that follow what `f` has.
    pub(crate) fn new(f: &'a mut fmt::Formatter<'b>) -> Self {
        Self { f, open: false }
    }

    fn separate(&mut self) -> fmt::Result {
        let separator = if self.open { ", " } else { " (" };
        self.open = true;
        self.f.write_str(separator)
    }

    /// `label=value`.
    pub(crate) fn item(&mut self, label: &str, value: impl fmt::Display) -> fmt::Result {
        self.separate()?;
        write!(self.f, "{label}={value}")
    }

    /// `label=value`, for an IE that the message has.
    pub(crate) fn some(&mut self, label: &str, value: Option<impl fmt::Display>) -> fmt::Result {
        match value {
            Some(value) => self.item(label, value),
            None => Ok(()),
        }
    }

    /// A word that says that a bit is set, or that an IE has no value to
    /// show.
    pub(crate) fn flag(&mut self, word: &str, set: bool) -> fmt::Result {
        if !set {
            return Ok(());
        }
        self.separate()?;
        self.f.write_str(word)
    }

    /// The closing parenthesis, when there was an item.
    pub(crate) fn end(self) -> fmt::Result {
        match self.open {
            true => self.f.write_str(")"),
            false => Ok(()),
        }
    }
}

/// Octets in hexadecimal, whole and in lower case.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|octet| write!(f, "{octet:02x}"))
    }
}

/// Octets that have no other form: whole up to sixteen, otherwise their
/// count.
pub(crate) struct Octets<'a>(pub &'a [u8]);

impl fmt::Display for Octets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.len() {
            0 => f.write_str("empty"),
            1..=16 => Hex(self.0).fmt(f),
            length => write!(f, "{length} octets"),
        }
    }
}

/// A list: whole up to four entries, otherwise its first three and how
/// many more.
pub(crate) struct List<'a, T>(pub &'a [T]);

impl<T: fmt::Display> fmt::Display for List<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shown = if self.0.len() > 4 { 3 } else { self.0.len() };
        f.write_str("[")?;
        for (index, entry) in self.0[..shown].iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            entry.fmt(f)?;
        }
        if shown < self.0.len() {
            write!(f, ", {} more", self.0.len() - shown)?;
        }
        f.write_str("]")
    }
}

/// A cause: `#22 (Congestion)`, by the name of the table of the
/// specification, and `#4` for a value that the table does not have.
pub(crate) fn cause(f: &mut fmt::Formatter<'_>, value: u8, name: Option<&str>) -> fmt::Result {
    match name {
        Some(name) => write!(f, "#{value} ({name})"),
        None => write!(f, "#{value}"),
    }
}

/// A duration in its largest unit that divides it: `10 min`, `2 h`,
/// `90 s`.
pub(crate) struct Duration(pub u64);

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0 s"),
            seconds if seconds % 3_600 == 0 => write!(f, "{} h", seconds / 3_600),
            seconds if seconds % 60 == 0 => write!(f, "{} min", seconds / 60),
            seconds => write!(f, "{seconds} s"),
        }
    }
}

/// A timer: its duration, or `deactivated`.
impl fmt::Display for GprsTimerValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deactivated => f.write_str("deactivated"),
            Self::Seconds(seconds) => Duration(*seconds).fmt(f),
        }
    }
}

/// A timer IE: its value, or its octets when it has none, as a value
/// octet with a unit that the timer does not define.
pub(crate) fn timer(
    f: &mut fmt::Formatter<'_>,
    value: Option<GprsTimerValue>,
    octets: &[u8],
) -> fmt::Result {
    match value {
        Some(value) => value.fmt(f),
        None if octets.is_empty() => f.write_str("empty"),
        None => write!(f, "undefined ({})", Hex(octets)),
    }
}

/// A bit rate in its largest unit that divides it: `64 kbps`,
/// `100 Mbps`, `1 Gbps`.
pub(crate) struct Rate(pub u64);

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("0 kbps"),
            kbps if kbps % 1_000_000_000 == 0 => write!(f, "{} Tbps", kbps / 1_000_000_000),
            kbps if kbps % 1_000_000 == 0 => write!(f, "{} Gbps", kbps / 1_000_000),
            kbps if kbps % 1_000 == 0 => write!(f, "{} Mbps", kbps / 1_000),
            kbps => write!(f, "{kbps} kbps"),
        }
    }
}

/// An aggregate maximum bit rate: `DL 100 Mbps UL 50 Mbps`.
pub(crate) fn rates(
    f: &mut fmt::Formatter<'_>,
    downlink: Option<u64>,
    uplink: Option<u64>,
    octets: &[u8],
) -> fmt::Result {
    match (downlink, uplink) {
        (Some(downlink), Some(uplink)) => {
            write!(f, "DL {} UL {}", Rate(downlink), Rate(uplink))
        }
        _ => Octets(octets).fmt(f),
    }
}

/// The address of a PDU session or of a PDN connection: `IPv4 10.45.0.2`,
/// `IPv6 ::0:0:0:1`, the interface identifier as the last four groups of an
/// address, or `IPv4v6 ::0:0:0:1 10.45.0.2`.
pub(crate) fn address(
    f: &mut fmt::Formatter<'_>,
    ipv4: Option<[u8; 4]>,
    interface_identifier: Option<[u8; 8]>,
) -> fmt::Result {
    let interface = |f: &mut fmt::Formatter<'_>, identifier: [u8; 8]| {
        f.write_str(":")?;
        identifier
            .chunks(2)
            .try_for_each(|pair| write!(f, ":{:x}", u16::from_be_bytes([pair[0], pair[1]])))
    };
    match (ipv4, interface_identifier) {
        (Some(ipv4), None) => write!(f, "IPv4 {}", core::net::Ipv4Addr::from(ipv4)),
        (None, Some(identifier)) => {
            f.write_str("IPv6 ")?;
            interface(f, identifier)
        }
        (Some(ipv4), Some(identifier)) => {
            f.write_str("IPv4v6 ")?;
            interface(f, identifier)?;
            write!(f, " {}", core::net::Ipv4Addr::from(ipv4))
        }
        (None, None) => f.write_str("none"),
    }
}

/// The algorithms of a capability: `EA0 EA1 EA2 / IA1 IA2`, and `none`
/// for a side that has none.
pub(crate) fn algorithms(
    f: &mut fmt::Formatter<'_>,
    (ciphering, integrity): (&str, &str),
    supports_ciphering: impl Fn(u8) -> bool,
    supports_integrity: impl Fn(u8) -> bool,
) -> fmt::Result {
    let names = |f: &mut fmt::Formatter<'_>, name: &str, supports: &dyn Fn(u8) -> bool| {
        let mut separator = "";
        for number in (0..8).filter(|&number| supports(number)) {
            write!(f, "{separator}{name}{number}")?;
            separator = " ";
        }
        match separator {
            "" => f.write_str("none"),
            _ => Ok(()),
        }
    };
    names(f, ciphering, &supports_ciphering)?;
    f.write_str(" / ")?;
    names(f, integrity, &supports_integrity)
}

/// An identity as the service based interfaces write it, in the place of
/// one that oxirush-utils has no type for: a MAC address, `mac-` and its
/// six octets with `-untrusted` when it is not usable as an equipment
/// identifier, and an EUI-64, `eui-` and its eight octets (TS 29.571
/// table 5.3.2-1, Pei).
pub(crate) fn hyphenated(
    f: &mut fmt::Formatter<'_>,
    prefix: &str,
    octets: &[u8],
    suffix: &str,
) -> fmt::Result {
    f.write_str(prefix)?;
    octets
        .iter()
        .try_for_each(|octet| write!(f, "-{octet:02x}"))?;
    f.write_str(suffix)
}

/// An identity of a type that is not read, or one whose octets are not
/// those of its type: what it is, and its octets.
pub(crate) fn unread_identity(
    f: &mut fmt::Formatter<'_>,
    kind: &str,
    octets: &[u8],
) -> fmt::Result {
    write!(f, "{kind} ({})", Hex(octets))
}

/// A value that is not printed, a key such as RES and RES\*: its length
/// alone, `hidden (16 octets)`.
pub(crate) struct Hidden(pub usize);

impl fmt::Display for Hidden {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hidden ({} octets)", self.0)
    }
}

/// The `Debug` of an IE whose octets hold a key: its name and their length,
/// `NasCipheringKeyData { value: hidden (40 octets) }`.
pub(crate) fn hidden_octets(f: &mut fmt::Formatter<'_>, name: &str, octets: &[u8]) -> fmt::Result {
    f.debug_struct(name)
        .field("value", &format_args!("{}", Hidden(octets.len())))
        .finish()
}

// ── The IEs of TS 24.008 that both systems have, one type for both ──

/// RAND, whole: it travels in clear.
impl fmt::Display for NasAuthenticationParameterRand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.value).fmt(f)
    }
}

/// AUTN, whole: it travels in clear.
impl fmt::Display for NasAuthenticationParameterAutn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.value).fmt(f)
    }
}

/// AUTS, the authentication failure parameter, whole: it travels in clear.
impl fmt::Display for NasAuthenticationFailureParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.value).fmt(f)
    }
}

/// A GPRS timer: `6 min`, `deactivated`.
impl fmt::Display for NasGprsTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}

/// A GPRS timer 2: `10 min`, `deactivated`.
impl fmt::Display for NasGprsTimer2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        timer(f, self.value(), &self.value)
    }
}

/// A GPRS timer 3: `1 h`, `deactivated`.
impl fmt::Display for NasGprsTimer3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        timer(f, self.value(), &self.value)
    }
}

/// A network name in quotes: `"Open5GS"`.
impl fmt::Display for NasNetworkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name:?}"),
            None => Octets(&self.value).fmt(f),
        }
    }
}

/// A time zone as its offset from UTC: `+02:00`, `-03:30`.
impl fmt::Display for NasTimeZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let quarters = self.quarter_hours();
        let sign = if quarters < 0 { '-' } else { '+' };
        let minutes = u32::from(quarters.unsigned_abs()) * 15;
        write!(f, "{sign}{:02}:{:02}", minutes / 60, minutes % 60)
    }
}

/// The EPS bearers that an EPS bearer context status has active: `[5, 6]`.
impl fmt::Display for NasEpsBearerContextStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        List(&self.active_bearers()).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    struct Shown<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(F);

    impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Display for Shown<F> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0(f)
        }
    }

    #[test]
    fn each_kind_of_value_has_its_form() {
        let shown = |f: &dyn Fn(&mut fmt::Formatter<'_>) -> fmt::Result| Shown(f).to_string();
        assert_eq!(
            shown(&|f| cause(f, 22, Some("Congestion"))),
            "#22 (Congestion)"
        );
        assert_eq!(shown(&|f| cause(f, 4, None)), "#4");
        assert_eq!(Duration(600).to_string(), "10 min");
        assert_eq!(Duration(7_200).to_string(), "2 h");
        assert_eq!(Duration(90).to_string(), "90 s");
        assert_eq!(Duration(0).to_string(), "0 s");
        assert_eq!(GprsTimerValue::Deactivated.to_string(), "deactivated");
        assert_eq!(Rate(100_000).to_string(), "100 Mbps");
        assert_eq!(Rate(64).to_string(), "64 kbps");
        assert_eq!(Octets(&[0xab; 16]).to_string(), "ab".repeat(16));
        assert_eq!(Octets(&[0xab; 17]).to_string(), "17 octets");
        assert_eq!(Octets(&[]).to_string(), "empty");
        assert_eq!(List(&[1, 2, 3, 4]).to_string(), "[1, 2, 3, 4]");
        assert_eq!(List(&[1, 2, 3, 4, 5]).to_string(), "[1, 2, 3, 2 more]");
        assert_eq!(
            shown(&|f| address(f, Some([10, 45, 0, 2]), Some([0, 0, 0, 0, 0, 0, 0, 1]))),
            "IPv4v6 ::0:0:0:1 10.45.0.2"
        );
        assert_eq!(
            shown(&|f| algorithms(f, ("EA", "IA"), |n| n != 1, |n| n == 2)),
            "EA0 EA2 EA3 EA4 EA5 EA6 EA7 / IA2"
        );
        assert_eq!(
            shown(&|f| hyphenated(f, "mac", &[1, 2, 3, 4, 5, 6], "-untrusted")),
            "mac-01-02-03-04-05-06-untrusted"
        );
    }
}
