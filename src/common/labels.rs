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

//! Length-prefixed network name labels used by 5GS DNN and EPS APN IEs.

fn valid_label(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.first().is_some_and(u8::is_ascii_alphanumeric)
        && label.last().is_some_and(u8::is_ascii_alphanumeric)
        && label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// Decode length-prefixed labels as a dot-separated name.
pub(crate) fn decode_labels(value: &[u8]) -> Option<String> {
    decode_labels_with_maximum(value, 100)
}

/// Decode length-prefixed labels with a caller-supplied encoded-length limit.
pub(crate) fn decode_labels_with_maximum(value: &[u8], maximum_length: usize) -> Option<String> {
    if value.is_empty() || value.len() > maximum_length {
        return None;
    }
    let mut result = String::new();
    let mut pos = 0;
    while pos < value.len() {
        let label_len = value[pos] as usize;
        if label_len == 0 || label_len > 63 {
            return None;
        }
        pos += 1;
        if pos + label_len > value.len() {
            return None;
        }
        if !valid_label(&value[pos..pos + label_len]) {
            return None;
        }
        if !result.is_empty() {
            result.push('.');
        }
        result.push_str(std::str::from_utf8(&value[pos..pos + label_len]).ok()?);
        pos += label_len;
    }
    Some(result)
}

/// Whether `value` is length-prefixed labels of 1 to 63 octets that fill it
/// exactly, within `maximum_length` octets. The TS 23.003 §9.1 character
/// rules, which bind a sender, are not checked: a receiver takes the labels as
/// framed.
pub(crate) fn labels_are_framed(value: &[u8], maximum_length: usize) -> bool {
    if value.is_empty() || value.len() > maximum_length {
        return false;
    }
    let mut remaining = value;
    while let Some((&length, rest)) = remaining.split_first() {
        let length = usize::from(length);
        if !(1..=63).contains(&length) || length > rest.len() {
            return false;
        }
        remaining = &rest[length..];
    }
    true
}

/// Encode a dot-separated name into labels of at most 63 octets each.
pub(crate) fn encode_labels(name: &str, maximum_length: usize) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if !valid_label(bytes) {
            return None;
        }
        if value.len() + 1 + bytes.len() > maximum_length {
            return None;
        }
        value.push(bytes.len() as u8);
        value.extend_from_slice(bytes);
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_apn_and_dnn_name_syntax() {
        let value = encode_labels("ims.mnc093.mcc208.3gppnetwork.org", 100).unwrap();
        assert_eq!(
            decode_labels(&value).as_deref(),
            Some("ims.mnc093.mcc208.3gppnetwork.org")
        );
        for name in ["a_b", "-ims", "ims-", "été", "a..b"] {
            assert!(encode_labels(name, 100).is_none(), "{name}");
        }
        assert!(decode_labels(&[3, b'a', b'_', b'b']).is_none());
    }
}
