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

/// A name as it prints: lower case, its words joined by hyphens, and the
/// `fg` of an identifier of the codec as the `5g` it stands for.
pub(crate) fn printed(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let lower = |at: usize| chars.get(at).is_some_and(char::is_ascii_lowercase);
    let mut words = String::with_capacity(name.len() + 4);
    for (index, &c) in chars.iter().enumerate() {
        if matches!(c, '_' | ' ' | '-') {
            words.push('-');
            continue;
        }
        // A capital starts a word after a small letter, before a small
        // letter after a digit, and before two after a capital.
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
        // The digits that an identifier of Rust spells out or keeps apart.
        let joined = match (word, words.peek().copied()) {
            ("fg" | "fgs" | "fgmm" | "fgsm", _) => {
                printed.extend(["5", &word[1..]]);
                continue;
            }
            ("f" | "five", Some(next @ ("g" | "gs" | "gmm" | "gsm" | "qi"))) => ["5", next],
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
