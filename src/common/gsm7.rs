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

//! GSM 7-bit default alphabet and septet packing (TS 23.038 §6.1.2.1,
//! §6.2.1), used by network names and emergency sub-services.

const ESCAPE: u8 = 0x1b;

/// Default alphabet; index 0x1B is the escape to the extension table.
const DEFAULT_ALPHABET: [char; 128] = [
    '@', '£', '$', '¥', 'è', 'é', 'ù', 'ì', 'ò', 'Ç', '\n', 'Ø', 'ø', '\r', 'Å', 'å', //
    'Δ', '_', 'Φ', 'Γ', 'Λ', 'Ω', 'Π', 'Ψ', 'Σ', 'Θ', 'Ξ', '\u{1b}', 'Æ', 'æ', 'ß', 'É', //
    ' ', '!', '"', '#', '¤', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', //
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', //
    '¡', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', //
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'Ä', 'Ö', 'Ñ', 'Ü', '§', //
    '¿', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', //
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'ä', 'ö', 'ñ', 'ü', 'à', //
];

/// Extension table entries of the default alphabet (TS 23.038 §6.2.1.1).
const EXTENSION: [(u8, char); 10] = [
    (0x0a, '\u{0c}'),
    (0x14, '^'),
    (0x28, '{'),
    (0x29, '}'),
    (0x2f, '\\'),
    (0x3c, '['),
    (0x3d, '~'),
    (0x3e, ']'),
    (0x40, '|'),
    (0x65, '€'),
];

/// Decode septets as text. An escape followed by a code missing from the
/// extension table is read as the main table character, and an escape
/// followed by another escape as a space (TS 23.038 §6.2.1.1); a trailing
/// escape is dropped.
pub(crate) fn decode_septets(septets: &[u8]) -> String {
    let mut text = String::with_capacity(septets.len());
    let mut escaped = false;
    for &septet in septets {
        let septet = septet & 0x7f;
        if escaped {
            escaped = false;
            let character = match EXTENSION.iter().find(|(code, _)| *code == septet) {
                Some((_, character)) => *character,
                None if septet == ESCAPE => ' ',
                None => DEFAULT_ALPHABET[usize::from(septet)],
            };
            text.push(character);
        } else if septet == ESCAPE {
            escaped = true;
        } else {
            text.push(DEFAULT_ALPHABET[usize::from(septet)]);
        }
    }
    text
}

/// Encode text as septets; `None` if a character is not in the default
/// alphabet or its extension table.
pub(crate) fn encode_septets(text: &str) -> Option<Vec<u8>> {
    let mut septets = Vec::with_capacity(text.len());
    for character in text.chars() {
        if character == '\u{1b}' {
            return None;
        }
        if let Some(code) = DEFAULT_ALPHABET.iter().position(|&c| c == character) {
            septets.push(code as u8);
        } else {
            let (code, _) = EXTENSION.iter().find(|(_, c)| *c == character)?;
            septets.extend([ESCAPE, *code]);
        }
    }
    Some(septets)
}

/// Pack septets least significant bit first (TS 23.038 §6.1.2.1.1).
pub(crate) fn pack_septets(septets: &[u8]) -> Vec<u8> {
    let mut octets = vec![0u8; (septets.len() * 7).div_ceil(8)];
    for (index, &septet) in septets.iter().enumerate() {
        let bit = index * 7;
        let value = u16::from(septet & 0x7f) << (bit % 8);
        octets[bit / 8] |= value as u8;
        if let Some(next) = octets.get_mut(bit / 8 + 1) {
            *next |= (value >> 8) as u8;
        }
    }
    octets
}

/// Unpack `count` septets; `None` if the octets hold fewer.
pub(crate) fn unpack_septets(octets: &[u8], count: usize) -> Option<Vec<u8>> {
    if count * 7 > octets.len() * 8 {
        return None;
    }
    Some(
        (0..count)
            .map(|index| {
                let bit = index * 7;
                let low = u16::from(octets[bit / 8]);
                let high = u16::from(octets.get(bit / 8 + 1).copied().unwrap_or(0));
                (((high << 8 | low) >> (bit % 8)) & 0x7f) as u8
            })
            .collect(),
    )
}

/// Unpack octets that carry a whole number of characters with the padding
/// of TS 23.038 §6.1.2.3.1: when seven fill bits remain, the last septet is
/// a carriage return that is not part of the text.
pub(crate) fn unpack_padded_septets(octets: &[u8]) -> Vec<u8> {
    let count = octets.len() * 8 / 7;
    let mut septets = unpack_septets(octets, count).unwrap_or_default();
    if (octets.len() * 8).is_multiple_of(7) && septets.last() == Some(&0x0d) {
        septets.pop();
    }
    septets
}

/// Pack septets with the padding of TS 23.038 §6.1.2.3.1.
pub(crate) fn pack_padded_septets(septets: &[u8]) -> Vec<u8> {
    if septets.len() % 8 == 7 {
        let mut padded = septets.to_vec();
        padded.push(0x0d);
        return pack_septets(&padded);
    }
    pack_septets(septets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn septets_follow_ts_23038_packing() {
        // TS 23.038 §6.1.2.1.1 example: "hellohello" packs to E8329BFD4697D9EC37.
        let septets = encode_septets("hellohello").unwrap();
        assert_eq!(
            pack_septets(&septets),
            [0xe8, 0x32, 0x9b, 0xfd, 0x46, 0x97, 0xd9, 0xec, 0x37]
        );
        assert_eq!(
            decode_septets(&unpack_septets(&pack_septets(&septets), 10).unwrap()),
            "hellohello"
        );
        assert_eq!(decode_septets(&encode_septets("[€]").unwrap()), "[€]");
        assert!(encode_septets("日本").is_none());
        // Seven characters leave seven fill bits, so a carriage return pads.
        let packed = pack_padded_septets(&encode_septets("police1").unwrap());
        assert_eq!(packed.len(), 7);
        assert_eq!(decode_septets(&unpack_padded_septets(&packed)), "police1");
        // Codec review C-8: undefined extension codes show the main table
        // character; escape, escape shows a space.
        assert_eq!(decode_septets(&[0x1b, 0x7f]), "à");
        assert_eq!(decode_septets(&[0x1b, 0x41]), "A");
        assert_eq!(decode_septets(&[0x1b, 0x1b]), " ");
    }
}
