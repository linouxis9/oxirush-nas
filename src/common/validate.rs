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

//! Shared NAS validation findings and trait.

use crate::prelude::*;
use core::fmt;

/// A single validation finding against a NAS message or composed IE check.
#[non_exhaustive]
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

/// The findings of one kind about the IEs that a message has no place for.
/// A message can be made to have tens of thousands of such IEs: the first
/// [`Bounded::LISTED`] findings are listed, and one more says how many
/// others there were.
pub(crate) struct Bounded {
    findings: Vec<ValidationError>,
    more: usize,
    field: &'static str,
}

impl Bounded {
    /// How many findings of one kind `validate()` lists for one message.
    pub(crate) const LISTED: usize = 32;

    /// No finding yet.
    pub(crate) fn new() -> Self {
        Self {
            findings: Vec::new(),
            more: 0,
            field: "",
        }
    }

    /// One more error, whose text is written if it is listed.
    pub(crate) fn error(&mut self, field: &'static str, message: impl FnOnce() -> String) {
        if self.findings.len() < Self::LISTED {
            self.findings.push(ValidationError {
                severity: Severity::Error,
                field,
                message: message(),
            });
        } else {
            // The finding that counts those that are not listed has the
            // field of the first of them.
            if self.more == 0 {
                self.field = field;
            }
            self.more += 1;
        }
    }

    /// The findings that are listed, and the one that counts the others.
    pub(crate) fn into_findings(mut self) -> Vec<ValidationError> {
        if self.more > 0 {
            self.findings.push(ValidationError {
                severity: Severity::Error,
                field: self.field,
                message: format!("{} more findings of this kind are not listed", self.more),
            });
        }
        self.findings
    }
}

/// Append findings for unknown IEs encoded as "comprehension required" and
/// the optional IE order findings of the message.
pub(crate) fn with_optional_ie_checks(
    mut errors: Vec<ValidationError>,
    unknown_ies: &crate::common::UnknownIes,
    order_findings: Vec<ValidationError>,
) -> Vec<ValidationError> {
    errors.extend(order_findings);
    // The usual message has no such IE.
    if unknown_ies.is_empty() {
        return errors;
    }
    let mut required = Bounded::new();
    for ie in unknown_ies
        .iter()
        .filter(|ie| ie.is_comprehension_required())
    {
        required.error("unknown_ies", || {
            format!(
                "Unknown IEI 0x{:02X} is encoded as comprehension required",
                ie.iei
            )
        });
    }
    errors.extend(required.into_findings());
    errors
}

/// Implemented by IE types with sender rules, which a message's
/// `sender_check_findings()` runs for its fields of that type.
pub(crate) trait SenderCheck {
    /// Whether the IE meets its sender rules.
    fn sender_check(&self) -> bool;

    /// The sender rules, as a finding of `validate()` says them.
    fn sender_rule(&self) -> &'static str;
}

/// Implement [`IeLengthCheck`] for IE types by the value lengths of their clauses.
macro_rules! ie_length_checked {
    ($($name:ident => $min:expr, $max:expr),* $(,)?) => {
        $(
            impl $crate::common::IeLengthCheck for $name {
                fn receiver_length_ok(&self) -> bool {
                    self.value.len().checked_sub($min).is_some()
                }

                fn sender_length_ok(&self) -> bool {
                    ($min..=$max).contains(&self.value.len())
                }

                fn sender_lengths(&self) -> (usize, usize) {
                    ($min, $max)
                }
            }
        )*
    };
}

/// Implement [`SenderCheck`] for IE types: by `is_well_formed()`, or for
/// `Name => pattern` by the values a sender may set.
macro_rules! sender_checked {
    ($($name:ident $(=> $values:pat)?),* $(,)?) => {
        $(
            impl $crate::common::SenderCheck for $name {
                fn sender_check(&self) -> bool {
                    $crate::common::sender_checked!(@check self $(, $values)?)
                }

                fn sender_rule(&self) -> &'static str {
                    $crate::common::sender_checked!(@rule $name $(, $values)?)
                }
            }
        )*
    };
    (@check $ie:ident) => {
        $ie.is_well_formed()
    };
    (@check $ie:ident, $values:pat) => {
        matches!($ie.value, $values)
    };
    (@rule $name:ident) => {
        <$name>::SENDER_RULE
    };
    (@rule $name:ident, $values:pat) => {
        concat!("a value that a sender sets: ", stringify!($values))
    };
}

pub(crate) use {ie_length_checked, sender_checked};

/// Implemented by variable-length IE types with table-derived wire bounds.
pub(crate) trait IeLengthCheck {
    /// Receiver minimum-length check; excess type-4/type-6 octets are allowed.
    fn receiver_length_ok(&self) -> bool;

    /// Exact sender range check.
    fn sender_length_ok(&self) -> bool;

    /// The least and the most octets that a sender writes.
    fn sender_lengths(&self) -> (usize, usize);
}

/// Probe that calls [`IeLengthCheck`] when implemented.
pub(crate) struct IeLengthCheckProbe<'a, T>(pub &'a T);

pub(crate) trait ViaIeLengthCheck {
    fn receiver_length_result(&self) -> Option<bool>;
    /// The sender rule of its length that the IE breaks, if it breaks one.
    fn sender_length_fault(&self) -> Option<String>;
}

impl<T: IeLengthCheck> ViaIeLengthCheck for IeLengthCheckProbe<'_, T> {
    fn receiver_length_result(&self) -> Option<bool> {
        Some(self.0.receiver_length_ok())
    }

    fn sender_length_fault(&self) -> Option<String> {
        let (least, most) = self.0.sender_lengths();
        (!self.0.sender_length_ok()).then(|| format!("a value of {least} to {most} octets"))
    }
}

pub(crate) trait ViaNoIeLengthCheck {
    fn receiver_length_result(&self) -> Option<bool>;
    fn sender_length_fault(&self) -> Option<String>;
}

impl<T> ViaNoIeLengthCheck for &IeLengthCheckProbe<'_, T> {
    fn receiver_length_result(&self) -> Option<bool> {
        None
    }

    fn sender_length_fault(&self) -> Option<String> {
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
    #[cfg(feature = "serde")]
    fn sender_check_result(&self) -> Option<bool>;
    /// The sender rule that the IE breaks, if it breaks one.
    fn sender_fault(&self) -> Option<&'static str>;
}

impl<T: SenderCheck> ViaSenderCheck for SenderCheckProbe<'_, T> {
    #[cfg(feature = "serde")]
    fn sender_check_result(&self) -> Option<bool> {
        Some(self.0.sender_check())
    }

    fn sender_fault(&self) -> Option<&'static str> {
        (!self.0.sender_check()).then(|| self.0.sender_rule())
    }
}

/// Fallback for a field type without a sender check.
pub(crate) trait ViaNoSenderCheck {
    #[cfg(feature = "serde")]
    fn sender_check_result(&self) -> Option<bool>;
    fn sender_fault(&self) -> Option<&'static str>;
}

impl<T> ViaNoSenderCheck for &SenderCheckProbe<'_, T> {
    #[cfg(feature = "serde")]
    fn sender_check_result(&self) -> Option<bool> {
        None
    }

    fn sender_fault(&self) -> Option<&'static str> {
        None
    }
}

/// Trait for validating NAS messages against the implemented NAS checks.
///
/// Returns an empty `Vec` if the message is valid.
///
/// ```
/// use oxirush_nas::nas_5gs::{Nas5gsMessage, Validate};
///
/// // A REGISTRATION REJECT whose T3346 value is there twice
/// let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a5f012a").unwrap()).unwrap();
/// let findings = reject.validate();
/// assert_eq!(findings[0].to_string(), "[Error] unknown_ies: IEI 0x5F was ignored as repeated");
/// ```
pub trait Validate {
    /// Check structural correctness and return any findings.
    fn validate(&self) -> Vec<ValidationError>;
}
