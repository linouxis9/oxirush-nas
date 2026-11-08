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
    let mut words = vec![0; 2 * name.len()];
    let mut octets = vec![0; 2 * name.len()];
    let length = print(name.as_bytes(), &mut words, &mut octets);
    octets.truncate(length);
    // Only letters of ASCII were changed, and hyphens of ASCII added.
    String::from_utf8(octets).unwrap_or_default()
}

/// A name of the source of the crate as it prints, made when the crate is
/// compiled: `name!(stringify!(fgs_mobile_identity))` is
/// `"5gs-mobile-identity"`.
macro_rules! name {
    ($name:expr) => {{
        const SOURCE: &str = $name;
        const ROOM: usize = 2 * SOURCE.len();
        const PRINTED: ([u8; ROOM], usize) = $crate::common::names::printed_into(SOURCE);
        const LENGTH: usize = PRINTED.1;
        const OCTETS: [u8; LENGTH] = $crate::common::names::first(&PRINTED.0);
        const NAME: &str = match core::str::from_utf8(&OCTETS) {
            Ok(name) => name,
            Err(_) => panic!("a name prints as UTF-8"),
        };
        NAME
    }};
}

pub(crate) use name;

/// The octets that `name` prints as, in `N` octets, twice those of `name`, and how
/// many of them there are.
pub(crate) const fn printed_into<const N: usize>(name: &str) -> ([u8; N], usize) {
    let (mut words, mut octets) = ([0; N], [0; N]);
    let length = print(name.as_bytes(), &mut words, &mut octets);
    (octets, length)
}

/// The first `M` of `octets`.
pub(crate) const fn first<const N: usize, const M: usize>(octets: &[u8; N]) -> [u8; M] {
    let mut first = [0; M];
    let mut at = 0;
    while at < M {
        first[at] = octets[at];
        at += 1;
    }
    first
}

/// Write in `printed` the octets that `name` prints as, its words first in
/// `words`, and return how many there are. Each holds twice the octets of
/// `name`, without the `r#` of a raw identifier.
const fn print(name: &[u8], words: &mut [u8], printed: &mut [u8]) -> usize {
    let name = match name {
        [b'r', b'#', rest @ ..] => rest,
        _ => name,
    };
    let length = hyphenated(name, words);
    let mut out = 0;
    let mut start = 0;
    loop {
        let word = (start, word_end(words, start, length));
        if out > 0 {
            printed[out] = b'-';
            out += 1;
        }
        // The digits that an identifier of Rust spells out or keeps apart. After
        // the last word, the next is empty, and is none of those below.
        let next = (word.1 + 1, word_end(words, word.1 + 1, length));
        let mut taken = word.1;
        if is(words, word, b"fg")
            || is(words, word, b"fgs")
            || is(words, word, b"fgmm")
            || is(words, word, b"fgsm")
        {
            out = put(printed, out, b"5");
            out = put_word(printed, out, words, (word.0 + 1, word.1));
        } else if (is(words, word, b"f") || is(words, word, b"five"))
            && (is(words, next, b"g")
                || is(words, next, b"gs")
                || is(words, next, b"gmm")
                || is(words, next, b"gsm")
                || is(words, next, b"gcn")
                || is(words, next, b"qi"))
        {
            out = put(printed, out, b"5");
            out = put_word(printed, out, words, next);
            taken = next.1;
        } else if is(words, word, b"three") && is(words, next, b"gpp") {
            out = put(printed, out, b"3gpp");
            taken = next.1;
        } else if is(words, word, b"non3") && is(words, next, b"gpp") {
            out = put(printed, out, b"non-3gpp");
            taken = next.1;
        } else {
            out = put_word(printed, out, words, word);
        }
        if taken >= length {
            return out;
        }
        start = taken + 1;
    }
}

/// Where the word of `words` that starts at `start` ends: at a hyphen, or at
/// `length`.
const fn word_end(words: &[u8], start: usize, length: usize) -> usize {
    let mut end = start;
    while end < length && words[end] != b'-' {
        end += 1;
    }
    end
}

/// Whether the word of `words` between `word.0` and `word.1` is `text`.
const fn is(words: &[u8], word: (usize, usize), text: &[u8]) -> bool {
    if word.1 - word.0 != text.len() {
        return false;
    }
    let mut at = 0;
    while at < text.len() {
        if words[word.0 + at] != text[at] {
            return false;
        }
        at += 1;
    }
    true
}

/// Put `text` in `printed` at `out`, and return where it ends.
const fn put(printed: &mut [u8], out: usize, text: &[u8]) -> usize {
    let mut at = 0;
    while at < text.len() {
        printed[out + at] = text[at];
        at += 1;
    }
    out + text.len()
}

/// Put the word of `words` between `word.0` and `word.1` in `printed` at
/// `out`, and return where it ends.
const fn put_word(printed: &mut [u8], out: usize, words: &[u8], word: (usize, usize)) -> usize {
    let mut at = word.0;
    while at < word.1 {
        printed[out + at - word.0] = words[at];
        at += 1;
    }
    out + word.1 - word.0
}

/// Write in `words` the octets of `name` in lower case, with a hyphen for
/// each separator and before each capital that starts a word, and return
/// how many there are: at most twice those of `name`.
const fn hyphenated(name: &[u8], words: &mut [u8]) -> usize {
    let mut length = 0;
    let mut index = 0;
    while index < name.len() {
        let c = name[index];
        if matches!(c, b'_' | b' ' | b'-') {
            words[length] = b'-';
            length += 1;
            index += 1;
            continue;
        }
        // A number of a technology starts a word after a small letter: the
        // `1x` of `Or1xCsFallback`.
        if c.is_ascii_digit() && index > 0 && lower(name, index - 1) {
            let mut end = index;
            while end < name.len() && name[end].is_ascii_digit() {
                end += 1;
            }
            if end + 1 < name.len() && name[end] == b'x' && name[end + 1].is_ascii_uppercase() {
                words[length] = b'-';
                length += 1;
            }
        }
        // A capital starts a word after a small letter, before a small
        // letter after a digit, and before two after a capital; the T of
        // IoT ends its word, as the `CIoT` of `ciot`.
        let iot = c == b'T' && index > 1 && name[index - 2] == b'I' && name[index - 1] == b'o';
        if c.is_ascii_uppercase()
            && index > 0
            && !iot
            && (lower(name, index - 1)
                || (lower(name, index + 1)
                    && (name[index - 1].is_ascii_digit()
                        || (name[index - 1].is_ascii_uppercase() && lower(name, index + 2)))))
        {
            words[length] = b'-';
            length += 1;
        }
        words[length] = c.to_ascii_lowercase();
        length += 1;
        index += 1;
    }
    length
}

/// Whether the octet of `name` at `at` is a small letter.
const fn lower(name: &[u8], at: usize) -> bool {
    at < name.len() && name[at].is_ascii_lowercase()
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

    /// A name of the source prints when the crate is compiled as it prints
    /// when the program runs, without the `r#` of a raw identifier.
    #[test]
    fn a_name_of_the_source_prints_as_the_program_prints_it() {
        assert_eq!(
            name!(stringify!(fgs_mobile_identity)),
            "5gs-mobile-identity"
        );
        assert_eq!(name!(stringify!(r#type)), "type");
        assert_eq!(name!("Non3GppAccess"), printed("Non3GppAccess"));
        assert_eq!(name!("__a__b_"), printed("__a__b_"));
        assert_eq!(name!(""), "");
    }

    /// A digit starts a word after a small letter, where an `x` and a capital follow the
    /// number; and a name whose words would not fit where short ones are kept prints
    /// whole.
    #[test]
    fn a_number_of_a_technology_starts_a_word() {
        assert_eq!(printed("TaxBase"), "tax-base");
        assert_eq!(printed("ab12xCd"), "ab-12x-cd");
        assert_eq!(printed("Or1xCsFallback"), "or-1x-cs-fallback");
        assert_eq!(printed(&"aB".repeat(45)), "a-b".repeat(45));
    }
}
