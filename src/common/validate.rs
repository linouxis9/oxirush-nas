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

/// Append findings for unknown IEs encoded as "comprehension required" or
/// whose octets are not one IE of the format of their IEI, and the optional
/// IE order findings of the message. `tlve_start` is the first IEI of the
/// TLV-E IEs of the system, as the decoder takes it.
pub(crate) fn with_optional_ie_checks(
    mut errors: Vec<ValidationError>,
    unknown_ies: &crate::common::UnknownIes,
    order_findings: Vec<ValidationError>,
    tlve_start: u8,
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
                "Unknown IEI 0x{:02x} is encoded as comprehension required",
                ie.iei
            )
        });
    }
    errors.extend(required.into_findings());
    // A receiver reads the octets of an unknown IE by the format of its IEI
    // (TS 24.007 §11.2.4): octets of another length are other IEs to it.
    let mut framed = Bounded::new();
    let mut octets = Vec::new();
    for ie in unknown_ies.iter() {
        octets.clear();
        octets.push(ie.iei);
        octets.extend_from_slice(ie.data);
        let length = super::unknown_ie::generic_ie_length(&octets, tlve_start);
        if length != Ok(octets.len()) {
            framed.error("unknown_ies", || {
                format!(
                    "Unknown IEI 0x{:02x} has {} octets, which are not one IE of the format \
                     of its IEI (TS 24.007 §11.2.4)",
                    ie.iei,
                    octets.len()
                )
            });
        }
    }
    errors.extend(framed.into_findings());
    errors
}

/// The rules of an IE type that `validate()` and a receiver check: the
/// lengths of its value that its clause gives, the values that a sender sets,
/// and the grammar that a receiver takes. Each IE type of a message has it,
/// from the table of its module ([`ie_rules!`]); a rule that a type has not
/// says nothing (`None`).
pub(crate) trait IeRules {
    /// Whether a receiver takes the length of the value: at least the least
    /// of the clause, and longer (TS 24.007 §11.4.2).
    fn receiver_length_ok(&self) -> Option<bool> {
        None
    }

    /// The rule of the clause on the length of the value that a sender
    /// breaks, if it breaks it.
    fn sender_length_fault(&self) -> Option<String> {
        None
    }

    /// Whether the IE is one that a sender writes.
    #[cfg(feature = "tree")]
    fn sender_ok(&self) -> Option<bool> {
        None
    }

    /// The rule of a sender that the IE breaks, if it breaks one.
    fn sender_fault(&self) -> Option<&'static str> {
        None
    }

    /// Whether a receiver takes the value in the message field `field`.
    fn receiver_ok(&self, _field: &str) -> Option<bool> {
        None
    }

    /// Why a receiver does not take the value, when it says it.
    fn receiver_fault(&self) -> Option<String> {
        None
    }
}

/// [`IeRules`] for IE types, one per row, with the rules that each has:
///
/// - `lengths(least, most)`: the octets of the value that its clause gives;
/// - `sender`: what `is_well_formed()` checks, which `SENDER_RULE` says;
///   `sender(pattern)`: the values that a sender sets; `sender_own`: the
///   type's own `sender_check()` and `sender_rule()`;
/// - `receiver`: the grammar of its [`ReceiverSyntaxCheck`].
macro_rules! ie_rules {
    ($($name:ident $(: $($rule:ident $(($($argument:tt)*))?),+)?;)*) => {$(
        impl $crate::common::IeRules for $name {
            $($($crate::common::ie_rules!(@$rule $(($($argument)*))?);)+)?
        }
    )*};
    (@lengths ($least:expr, $most:expr)) => {
        fn receiver_length_ok(&self) -> Option<bool> {
            Some(self.value.len().checked_sub($least).is_some())
        }

        fn sender_length_fault(&self) -> Option<String> {
            let within = ($least..=$most).contains(&self.value.len());
            (!within).then(|| format!("a value of {} to {} octets", $least, $most))
        }
    };
    (@sender) => {
        #[cfg(feature = "tree")]
        fn sender_ok(&self) -> Option<bool> {
            Some(self.is_well_formed())
        }

        fn sender_fault(&self) -> Option<&'static str> {
            (!self.is_well_formed()).then_some(Self::SENDER_RULE)
        }
    };
    (@sender ($values:pat)) => {
        #[cfg(feature = "tree")]
        fn sender_ok(&self) -> Option<bool> {
            Some(matches!(self.value, $values))
        }

        fn sender_fault(&self) -> Option<&'static str> {
            let rule = concat!("a value that a sender sets: ", stringify!($values));
            (!matches!(self.value, $values)).then_some(rule)
        }
    };
    (@sender_own) => {
        #[cfg(feature = "tree")]
        fn sender_ok(&self) -> Option<bool> {
            Some(self.sender_check())
        }

        fn sender_fault(&self) -> Option<&'static str> {
            (!self.sender_check()).then(|| self.sender_rule())
        }
    };
    (@receiver) => {
        fn receiver_ok(&self, field: &str) -> Option<bool> {
            Some($crate::common::ReceiverSyntaxCheck::receiver_syntax_ok_for_field(self, field))
        }

        fn receiver_fault(&self) -> Option<String> {
            $crate::common::ReceiverSyntaxCheck::receiver_syntax_fault(self)
        }
    };
}

pub(crate) use ie_rules;

/// The grammar of a value that a receiver takes, for an IE type whose value
/// may be framed and still not be one: the `receiver` rule of [`ie_rules!`].
///
/// It is apart from the rules of a sender: TS 24.007 §11.4.2 lets a receiver
/// take what a sender must not write, as a type 4 or type 6 IE longer than
/// its value.
pub(crate) trait ReceiverSyntaxCheck {
    /// Whether the decoded value is syntactically valid for a receiver.
    fn receiver_syntax_ok(&self) -> bool;

    /// Apply receive rules that depend on the message field carrying the IE.
    fn receiver_syntax_ok_for_field(&self, _field: &str) -> bool {
        self.receiver_syntax_ok()
    }

    /// Why the value is not syntactically valid, when it says it.
    fn receiver_syntax_fault(&self) -> Option<String> {
        None
    }
}

/// Trait for validating NAS messages against the implemented NAS checks.
///
/// Returns an empty `Vec` if the message is valid.
///
/// ```
/// use oxirush_nas::Validate;
/// use oxirush_nas::nas_5gs::Message;
///
/// // A REGISTRATION REJECT whose T3346 value is there twice
/// let reject = Message::decode(&hex::decode("7e0044165f012a5f012a").unwrap()).unwrap();
/// let findings = reject.validate();
/// assert_eq!(findings[0].to_string(), "[Error] unknown_ies: IEI 0x5f was ignored as repeated");
/// ```
pub trait Validate {
    /// Check structural correctness and return any findings.
    fn validate(&self) -> Vec<ValidationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The findings past those listed are counted in one, under the field of the first
    /// of them.
    #[test]
    fn the_findings_past_those_listed_are_counted_under_the_first() {
        let mut findings = Bounded::new();
        for _ in 0..Bounded::LISTED {
            findings.error("listed", String::new);
        }
        findings.error("first", String::new);
        findings.error("second", String::new);
        let findings = findings.into_findings();
        assert_eq!(findings.len(), Bounded::LISTED + 1);
        let last = findings.last().unwrap();
        assert_eq!(last.field, "first");
        assert_eq!(last.message, "2 more findings of this kind are not listed");
    }
}
