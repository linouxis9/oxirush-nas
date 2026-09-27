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
