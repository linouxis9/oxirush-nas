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
    /// The sender encoding is nonconforming, or a compliant receiver must
    /// reject or diagnose the condition.
    Error,
    /// A receiver-tolerated or procedure-dependent condition worth reporting.
    Warning,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}: {}", self.severity, self.field, self.message)
    }
}

/// Append findings for unknown IEs encoded as "comprehension required" and
/// the optional IE order findings of the message.
pub(crate) fn with_optional_ie_checks(
    mut errors: Vec<ValidationError>,
    unknown_ies: &[crate::common::UnknownIe],
    order_findings: Vec<ValidationError>,
) -> Vec<ValidationError> {
    errors.extend(order_findings);
    errors.extend(
        unknown_ies
            .iter()
            .filter(|ie| ie.is_comprehension_required())
            .map(|ie| ValidationError {
                severity: Severity::Error,
                field: "unknown_ies",
                message: format!(
                    "Unknown IEI 0x{:02X} is encoded as comprehension required",
                    ie.iei
                ),
            }),
    );
    errors
}

/// Implemented by IE types whose `is_well_formed()` sender check a
/// message's `sender_check_findings()` runs.
pub(crate) trait SenderCheck {
    /// Whether the IE meets its sender rules.
    fn sender_check(&self) -> bool;
}

/// Implemented by variable-length IE types with table-derived wire bounds.
pub(crate) trait IeLengthCheck {
    /// Receiver minimum-length check; excess type-4/type-6 octets are allowed.
    fn receiver_length_ok(&self) -> bool;

    /// Exact sender range check.
    fn sender_length_ok(&self) -> bool;
}

/// Probe that calls [`IeLengthCheck`] when implemented.
pub(crate) struct IeLengthCheckProbe<'a, T>(pub &'a T);

pub(crate) trait ViaIeLengthCheck {
    fn receiver_length_result(&self) -> Option<bool>;
    fn sender_length_result(&self) -> Option<bool>;
}

impl<T: IeLengthCheck> ViaIeLengthCheck for IeLengthCheckProbe<'_, T> {
    fn receiver_length_result(&self) -> Option<bool> {
        Some(self.0.receiver_length_ok())
    }

    fn sender_length_result(&self) -> Option<bool> {
        Some(self.0.sender_length_ok())
    }
}

pub(crate) trait ViaNoIeLengthCheck {
    fn receiver_length_result(&self) -> Option<bool>;
    fn sender_length_result(&self) -> Option<bool>;
}

impl<T> ViaNoIeLengthCheck for &IeLengthCheckProbe<'_, T> {
    fn receiver_length_result(&self) -> Option<bool> {
        None
    }

    fn sender_length_result(&self) -> Option<bool> {
        None
    }
}

/// Implemented by IE types for which the decoder can distinguish a
/// syntactically valid value from a framed but syntactically incorrect value.
///
/// This is deliberately separate from [`SenderCheck`]. TS 24.007 §11.4.2
/// permits a receiver to accept encodings that a sender must not produce
/// (including a type 4 or type 6 IE longer than the specified value).
pub(crate) trait ReceiverSyntaxCheck {
    /// Whether the decoded value is syntactically valid for a receiver.
    fn receiver_syntax_ok(&self) -> bool;

    /// Apply receive rules that depend on the message field carrying the IE.
    fn receiver_syntax_ok_for_field(&self, _field: &str) -> bool {
        self.receiver_syntax_ok()
    }
}

/// Probe that calls [`ReceiverSyntaxCheck`] when it is implemented and leaves
/// types without a receiver-specific grammar check unchanged.
pub(crate) struct ReceiverSyntaxCheckProbe<'a, T>(pub &'a T);

/// Selected for a field type that implements [`ReceiverSyntaxCheck`].
pub(crate) trait ViaReceiverSyntaxCheck {
    fn receiver_syntax_result(&self, field: &str) -> Option<bool>;
}

impl<T: ReceiverSyntaxCheck> ViaReceiverSyntaxCheck for ReceiverSyntaxCheckProbe<'_, T> {
    fn receiver_syntax_result(&self, field: &str) -> Option<bool> {
        Some(self.0.receiver_syntax_ok_for_field(field))
    }
}

/// Fallback for a field type without a receiver-specific syntax check.
pub(crate) trait ViaNoReceiverSyntaxCheck {
    fn receiver_syntax_result(&self, field: &str) -> Option<bool>;
}

impl<T> ViaNoReceiverSyntaxCheck for &ReceiverSyntaxCheckProbe<'_, T> {
    fn receiver_syntax_result(&self, _field: &str) -> Option<bool> {
        None
    }
}

/// Probe that calls [`SenderCheck`] when a field type implements it and
/// yields `None` otherwise (autoref specialization over concrete types).
pub(crate) struct SenderCheckProbe<'a, T>(pub &'a T);

/// Selected for a field type that implements [`SenderCheck`].
pub(crate) trait ViaSenderCheck {
    fn sender_check_result(&self) -> Option<bool>;
}

impl<T: SenderCheck> ViaSenderCheck for SenderCheckProbe<'_, T> {
    fn sender_check_result(&self) -> Option<bool> {
        Some(self.0.sender_check())
    }
}

/// Fallback for a field type without a sender check.
pub(crate) trait ViaNoSenderCheck {
    fn sender_check_result(&self) -> Option<bool>;
}

impl<T> ViaNoSenderCheck for &SenderCheckProbe<'_, T> {
    fn sender_check_result(&self) -> Option<bool> {
        None
    }
}

/// Trait for validating NAS messages against the implemented NAS checks.
///
/// Returns an empty `Vec` if the message is valid.
pub trait Validate {
    /// Check structural correctness and return any findings.
    fn validate(&self) -> Vec<ValidationError>;
}
