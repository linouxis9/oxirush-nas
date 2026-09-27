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

//! Shared equipment identity digit handling for 5GS and EPS NAS.

/// Append the transmitted zero spare digit to a 14-digit TAC and serial number.
pub(crate) fn imei_with_spare(tac_snr: &str) -> Option<String> {
    if tac_snr.len() != 14 || !tac_snr.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    Some(format!("{tac_snr}0"))
}

/// Decode the digits of an IMSI, IMEI, or IMEISV mobile identity of type
/// `kind` (TS 24.008 §10.5.1.4, TS 24.501 §9.11.3.4): BCD digits with a
/// filler 1111 only in the last high nibble, and an odd/even indicator that
/// matches the digit count. `None` otherwise.
pub(crate) fn decode_identity_digits(value: &[u8], kind: u8, max_digits: usize) -> Option<String> {
    if value.len() < 2 || value[0] & 0x07 != kind {
        return None;
    }
    let first = value[0] >> 4;
    if first > 9 {
        return None;
    }
    let mut digits = String::from(char::from(b'0' + first));
    for (index, byte) in value[1..].iter().enumerate() {
        let low = byte & 0x0f;
        let high = byte >> 4;
        if low > 9 {
            return None;
        }
        digits.push(char::from(b'0' + low));
        if high == 0x0f && index + 2 == value.len() {
            continue;
        }
        if high > 9 {
            return None;
        }
        digits.push(char::from(b'0' + high));
    }
    if (digits.len() % 2 == 1) != (value[0] & 0x08 != 0) {
        return None;
    }
    (digits.len() >= 2 && digits.len() <= max_digits).then_some(digits)
}

/// Encode `digits` as a mobile identity of type `kind`; `None` unless there
/// are 2 to `max_digits` decimal digits.
pub(crate) fn encode_identity_digits(digits: &str, kind: u8, max_digits: usize) -> Option<Vec<u8>> {
    if digits.len() < 2
        || digits.len() > max_digits
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let raw = digits.as_bytes();
    let mut value = vec![(raw[0] - b'0') << 4 | (digits.len() as u8 & 1) << 3 | kind];
    for pair in raw[1..].chunks(2) {
        let high = pair.get(1).map_or(0x0f, |digit| digit - b'0');
        value.push((high << 4) | (pair[0] - b'0'));
    }
    Some(value)
}
