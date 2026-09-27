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

//! Shared NAS validation findings and trait.

use std::fmt;

/// A single validation finding against a NAS message or composed IE check.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Whether this is a hard error or a warning.
    pub severity: Severity,
    /// The field or IE name that triggered the finding.
    pub field: &'static str,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Severity level for validation findings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Message will be rejected by a compliant peer.
    Error,
    /// Message is technically valid but may cause interoperability issues.
    Warning,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}: {}", self.severity, self.field, self.message)
    }
}

/// Trait for validating NAS messages against the implemented NAS checks.
///
/// Returns an empty `Vec` if the message is valid.
pub trait Validate {
    /// Check structural correctness and return any findings.
    fn validate(&self) -> Vec<ValidationError>;
}
