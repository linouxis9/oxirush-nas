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

//! The names of the specifications, as an error, a view and a path print
//! them.

use crate::prelude::*;

/// A name as it prints: lower case, its words joined by hyphens, and the
/// `fg` of an identifier of the codec as the `5g` it stands for.
pub(crate) fn printed(name: &str) -> String {
    // The words of most names fit here, and those of a longer one are
    // allocated.
    let mut short = [0_u8; 128];
    let long: Vec<u8>;
    let words = match 2 * name.len() <= short.len() {
        true => {
            let length = hyphenated(name.as_bytes(), |at, octet| short[at] = octet);
            &short[..length]
        }
        false => {
            let mut words = Vec::with_capacity(2 * name.len());
            hyphenated(name.as_bytes(), |_, octet| words.push(octet));
            long = words;
            &long
        }
    };
    // Only letters of ASCII were changed, and hyphens of ASCII added.
    let words = String::from_utf8_lossy(words);
    let mut printed = String::with_capacity(words.len());
    let mut words = words.split('-').peekable();
    while let Some(word) = words.next() {
        if !printed.is_empty() {
            printed.push('-');
        }
        // The digits that an identifier of Rust spells out or keeps apart.
        let joined = match (word, words.peek().copied()) {
            ("fg" | "fgs" | "fgmm" | "fgsm", _) => {
                printed.extend(["5", &word[1..]]);
                continue;
            }
            ("f" | "five", Some(next @ ("g" | "gs" | "gmm" | "gsm" | "gcn" | "qi"))) => ["5", next],
            ("three", Some("gpp")) => ["3", "gpp"],
            ("non3", Some("gpp")) => ["non-3", "gpp"],
            _ => {
                printed.push_str(word);
                continue;
            }
        };
        printed.extend(joined);
        words.next();
    }
    printed
}

/// Give `write` the octets of `name` in lower case, with a hyphen for each
/// separator and before each capital that starts a word, each with its
/// place, and return how many there are: at most twice those of `name`.
fn hyphenated(name: &[u8], mut write: impl FnMut(usize, u8)) -> usize {
    let lower = |at: usize| name.get(at).is_some_and(u8::is_ascii_lowercase);
    let mut length = 0;
    let mut push = |octet: u8| {
        write(length, octet);
        length += 1;
    };
    for (index, &c) in name.iter().enumerate() {
        if matches!(c, b'_' | b' ' | b'-') {
            push(b'-');
            continue;
        }
        // A number of a technology starts a word after a small letter: the
        // `1x` of `Or1xCsFallback`.
        if c.is_ascii_digit() && index > 0 && lower(index - 1) {
            let end = (index..name.len())
                .find(|&at| !name[at].is_ascii_digit())
                .unwrap_or(name.len());
            if name.get(end) == Some(&b'x') && name.get(end + 1).is_some_and(u8::is_ascii_uppercase)
            {
                push(b'-');
            }
        }
        // A capital starts a word after a small letter, before a small
        // letter after a digit, and before two after a capital.
        if c.is_ascii_uppercase()
            && index > 0
            && (lower(index - 1)
                || (lower(index + 1)
                    && (name[index - 1].is_ascii_digit()
                        || (name[index - 1].is_ascii_uppercase() && lower(index + 2)))))
        {
            push(b'-');
        }
        push(c.to_ascii_lowercase());
    }
    length
}

/// How a name of the source of the crate prints, and its letters and digits
/// alone: the name of a field, of a variant or of a flag, which a view
/// prints each time it shows a message.
#[cfg(all(feature = "serde", feature = "std"))]
#[derive(Clone, Copy)]
pub(crate) struct Printed {
    /// The name as [`printed`] gives it.
    pub(crate) name: &'static str,
    /// Its letters and its digits.
    pub(crate) letters: &'static str,
}

/// [`printed`] for a name of the source of the crate, which is printed
/// once: what it prints as is kept for as long as the program runs, and
/// there are as many such names as the crate has fields and variants.
#[cfg(all(feature = "serde", feature = "std"))]
pub(crate) fn printed_static(name: &'static str) -> Printed {
    let known = known();
    if let Some(found) = (known.read().ok()).and_then(|known| known.of.get(name).copied()) {
        return found;
    }
    let printed_name = printed(name);
    let letters: String = (printed_name.chars())
        .filter(char::is_ascii_alphanumeric)
        .collect();
    // A name that prints as itself, as nearly all do, has its own letters.
    let prints_as_itself = printed(&printed_name) == printed_name;
    let new = Printed {
        name: Box::leak(printed_name.into_boxed_str()),
        letters: Box::leak(letters.into_boxed_str()),
    };
    match known.write() {
        Ok(mut known) => {
            let kept = *known.of.entry(name).or_insert(new);
            if prints_as_itself {
                known.letters.entry(kept.name).or_insert(kept.letters);
            }
            kept
        }
        Err(_) => new,
    }
}

/// The letters and the digits of `name` as it prints, if it is how a name
/// of the source of the crate prints: what a view writes.
#[cfg(all(feature = "serde", feature = "std"))]
pub(crate) fn letters_of_printed(name: &str) -> Option<&'static str> {
    known().read().ok()?.letters.get(name).copied()
}

/// The names of the source of the crate that were printed.
#[cfg(all(feature = "serde", feature = "std"))]
#[derive(Default)]
struct Known {
    /// What a name prints as.
    of: std::collections::HashMap<&'static str, Printed>,
    /// The letters of what a name prints as, for one that prints as itself.
    letters: std::collections::HashMap<&'static str, &'static str>,
}

#[cfg(all(feature = "serde", feature = "std"))]
fn known() -> &'static std::sync::RwLock<Known> {
    static KNOWN: std::sync::OnceLock<std::sync::RwLock<Known>> = std::sync::OnceLock::new();
    KNOWN.get_or_init(Default::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`printed`] as it was written first: one character at a time, into
    /// a string of the words.
    fn printed_by_characters(name: &str) -> String {
        let chars: Vec<char> = name.chars().collect();
        let lower = |at: usize| chars.get(at).is_some_and(char::is_ascii_lowercase);
        let mut words = String::with_capacity(name.len() + 4);
        for (index, &c) in chars.iter().enumerate() {
            if matches!(c, '_' | ' ' | '-') {
                words.push('-');
                continue;
            }
            if c.is_ascii_digit() && index > 0 && lower(index - 1) {
                let end = (index..chars.len())
                    .find(|&at| !chars[at].is_ascii_digit())
                    .unwrap_or(chars.len());
                if chars.get(end) == Some(&'x')
                    && chars.get(end + 1).is_some_and(char::is_ascii_uppercase)
                {
                    words.push('-');
                }
            }
            if c.is_ascii_uppercase()
                && index > 0
                && (lower(index - 1)
                    || (lower(index + 1)
                        && (chars[index - 1].is_ascii_digit()
                            || (chars[index - 1].is_ascii_uppercase() && lower(index + 2)))))
            {
                words.push('-');
            }
            words.push(c.to_ascii_lowercase());
        }
        let mut printed = String::with_capacity(words.len());
        let mut words = words.split('-').peekable();
        while let Some(word) = words.next() {
            if !printed.is_empty() {
                printed.push('-');
            }
            let joined = match (word, words.peek().copied()) {
                ("fg" | "fgs" | "fgmm" | "fgsm", _) => {
                    printed.extend(["5", &word[1..]]);
                    continue;
                }
                ("f" | "five", Some(next @ ("g" | "gs" | "gmm" | "gsm" | "gcn" | "qi"))) => {
                    ["5", next]
                }
                ("three", Some("gpp")) => ["3", "gpp"],
                ("non3", Some("gpp")) => ["non-3", "gpp"],
                _ => {
                    printed.push_str(word);
                    continue;
                }
            };
            printed.extend(joined);
            words.next();
        }
        printed
    }

    #[test]
    fn a_name_prints_as_it_did_one_character_at_a_time() {
        // Names of the crate, and names made of what a name is made of.
        let mut names: Vec<String> = [
            "fgs_mobile_identity",
            "FiveGmmStatus",
            "PlainNasMessage",
            "PlainFiveGsNasMessageNotSecurityProtected",
            "RedirectionToFiveGcnRequired",
            "MobileOriginatingCsFallbackOr1xCsFallback",
            "Ipv4v6",
            "Non3GppAccess",
            "ThreeGppAccess",
            "five_qi",
            "f_gs",
            "T3512Value",
            "PDUSessionID",
            "NasEPSBearer",
            "__a__b_",
            "",
            "é_Été",
            "ÉA",
            "aÉb",
            "A",
            "AB",
            "ABc",
        ]
        .map(String::from)
        .into();
        let parts = [
            "F", "g", "Gs", "5", "_", "-", " ", "three", "Gpp", "non3", "A", "b", "é",
        ];
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..20_000 {
            let mut name = String::new();
            for _ in 0..1 + seed % 9 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                name.push_str(parts[(seed % parts.len() as u64) as usize]);
            }
            names.push(name);
        }
        // A name whose words do not fit where short ones are kept.
        names.push("FgsMobileIdentity".repeat(9));
        for name in names {
            assert_eq!(printed(&name), printed_by_characters(&name), "{name:?}");
        }
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn a_name_of_the_crate_is_printed_once() {
        let first = printed_static("fgs_mobile_identity");
        assert_eq!(first.name, "5gs-mobile-identity");
        assert_eq!(first.letters, "5gsmobileidentity");
        let again = printed_static("fgs_mobile_identity");
        assert!(core::ptr::eq(first.name, again.name));
        assert_eq!(
            letters_of_printed("5gs-mobile-identity"),
            Some("5gsmobileidentity")
        );
        assert_eq!(letters_of_printed("fgs_mobile_identity"), None);
    }
}
