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

//! Why a typed value cannot be built from what its constructor was given.

use core::fmt;

/// Why a constructor or a setter of a typed value refuses what it was
/// given: the member, by the name that the specification and a view give
/// it, what it was given, and the limit that this breaks.
///
/// ```
/// use oxirush_nas::nas_5gs::{NasTimeZone, ValueFault};
///
/// // A time zone is at most 79 quarters of an hour from UTC
/// let error = NasTimeZone::from_quarter_hours(80).unwrap_err();
/// assert_eq!(error.member, "time-zone");
/// assert_eq!(error.fault, ValueFault::Range { given: 80, min: -79, max: 79 });
/// assert_eq!(error.to_string(), "`time-zone` is 80, and is -79 to 79");
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueError {
    /// The member that is refused, by the name that a view gives it.
    pub member: &'static str,
    /// The entry of a list that the member is in, counted from zero as a
    /// path counts it.
    pub entry: Option<usize>,
    /// What is wrong with the member.
    pub fault: ValueFault,
}

/// What is wrong with the member of a [`ValueError`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueFault {
    /// A number outside its range.
    Range {
        /// The number that was given.
        given: i128,
        /// The least that the member is.
        min: i128,
        /// The most that the member is.
        max: i128,
    },
    /// Octets, digits or characters whose number is outside its limits.
    Length {
        /// How many were given.
        given: usize,
        /// The fewest that the member has.
        min: usize,
        /// The most that the member has: `usize::MAX` where only the IE
        /// that carries it limits them.
        max: usize,
        /// What is counted, in the plural: `"octets"`, `"digits"`,
        /// `"octets in a label"`.
        unit: &'static str,
    },
    /// Entries of a list whose number is outside its limits.
    Count {
        /// How many were given.
        given: usize,
        /// The fewest that the member has.
        min: usize,
        /// The most that the member has: `usize::MAX` where only the IE
        /// that carries them limits them.
        max: usize,
    },
    /// A value that is there twice, where each is there once.
    Repeated {
        /// The value that is there twice.
        given: i128,
    },
    /// A character that the member does not have.
    Character {
        /// The character that was given.
        given: char,
        /// The characters that the member has.
        expected: &'static str,
    },
    /// A number that the member cannot be.
    Value {
        /// The number that was given.
        given: i128,
        /// What the member is, after "is".
        expected: &'static str,
    },
    /// Members that do not go together.
    Combination {
        /// How they go together, after the name of the member.
        rule: &'static str,
    },
    /// An identity that is refused for a fault that the others do not say:
    /// the error of oxirush-utils, which names the same member and says why,
    /// such as a half octet that is no digit.
    Identity(oxirush_utils::identity::Error),
}

impl ValueError {
    /// `member` is `given`, outside `min` to `max`.
    pub(crate) fn range(
        member: &'static str,
        given: impl Into<i128>,
        min: impl Into<i128>,
        max: impl Into<i128>,
    ) -> Self {
        let (given, min, max) = (given.into(), min.into(), max.into());
        Self::of(member, ValueFault::Range { given, min, max })
    }

    /// `member` has `given` of `unit`, outside `min` to `max`.
    pub(crate) fn length(
        member: &'static str,
        unit: &'static str,
        given: usize,
        min: usize,
        max: usize,
    ) -> Self {
        let fault = ValueFault::Length {
            given,
            min,
            max,
            unit,
        };
        Self::of(member, fault)
    }

    /// `member` has `given` entries, outside `min` to `max`.
    pub(crate) fn count(member: &'static str, given: usize, min: usize, max: usize) -> Self {
        Self::of(member, ValueFault::Count { given, min, max })
    }

    /// `member` has `given` twice.
    pub(crate) fn repeated(member: &'static str, given: impl Into<i128>) -> Self {
        let given = given.into();
        Self::of(member, ValueFault::Repeated { given })
    }

    /// `member` has the character `given`, which is none of `expected`.
    pub(crate) fn character(member: &'static str, given: char, expected: &'static str) -> Self {
        Self::of(member, ValueFault::Character { given, expected })
    }

    /// `member` is `given`, and is `expected`.
    pub(crate) fn value(
        member: &'static str,
        given: impl Into<i128>,
        expected: &'static str,
    ) -> Self {
        let given = given.into();
        Self::of(member, ValueFault::Value { given, expected })
    }

    /// `member` does not go with the others: `rule` says how they go.
    pub(crate) fn combination(member: &'static str, rule: &'static str) -> Self {
        Self::of(member, ValueFault::Combination { rule })
    }

    fn of(member: &'static str, fault: ValueFault) -> Self {
        Self {
            member,
            entry: None,
            fault,
        }
    }

    /// The error of a member of the entry `entry` of a list. An error that
    /// has its entry keeps it: it is that of the innermost list.
    pub(crate) fn at(mut self, entry: usize) -> Self {
        self.entry.get_or_insert(entry);
        self
    }

    /// The error under the name `member`, for a constructor that calls
    /// another with a member of its own.
    pub(crate) fn of_member(mut self, member: &'static str) -> Self {
        self.member = member;
        self
    }
}

/// The refusal of an identity of oxirush-utils with the fault of this crate
/// that says the same, where it has one: a length, a range, a number or a
/// character. Another, such as a half octet that is no digit, is kept whole.
impl From<oxirush_utils::identity::Error> for ValueError {
    fn from(error: oxirush_utils::identity::Error) -> Self {
        use oxirush_utils::identity::Fault;
        let fault = match error.fault {
            Fault::Length {
                given,
                min,
                max,
                unit,
            } => ValueFault::Length {
                given,
                min,
                max,
                unit,
            },
            Fault::Range { given, max } => ValueFault::Range {
                given: given.into(),
                min: 0,
                max: max.into(),
            },
            Fault::Value { given, expected } => ValueFault::Value {
                given: given.into(),
                expected,
            },
            Fault::Character { given, expected } => ValueFault::Character { given, expected },
            _ => ValueFault::Identity(error),
        };
        Self::of(error.member, fault)
    }
}

/// `given` if it is `min` to `max`, as the member `member`.
pub(crate) fn within<T: Into<i128> + Copy + PartialOrd>(
    member: &'static str,
    given: T,
    min: T,
    max: T,
) -> Result<T, ValueError> {
    match min <= given && given <= max {
        true => Ok(given),
        false => Err(ValueError::range(member, given, min, max)),
    }
}

/// `given` if it is `min` to `max`, as the member `member`: a number that
/// is a `usize`, as that of the elements a list is said to have.
pub(crate) fn within_usize(
    member: &'static str,
    given: usize,
    min: usize,
    max: usize,
) -> Result<usize, ValueError> {
    within(member, given as u64, min as u64, max as u64).map(|_| given)
}

/// Whether `given` of `unit` are `min` to `max`, as the member `member`.
pub(crate) fn sized(
    member: &'static str,
    unit: &'static str,
    given: usize,
    min: usize,
    max: usize,
) -> Result<(), ValueError> {
    match min <= given && given <= max {
        true => Ok(()),
        false => Err(ValueError::length(member, unit, given, min, max)),
    }
}

/// Whether `given` entries are `min` to `max`, as the member `member`.
pub(crate) fn counted(
    member: &'static str,
    given: usize,
    min: usize,
    max: usize,
) -> Result<(), ValueError> {
    match min <= given && given <= max {
        true => Ok(()),
        false => Err(ValueError::count(member, given, min, max)),
    }
}

/// The limits `min` to `max`, as a refusal ends.
fn limits<T: fmt::Display + PartialEq>(
    f: &mut fmt::Formatter<'_>,
    verb: &str,
    min: T,
    max: T,
    unbounded: bool,
) -> fmt::Result {
    match (min == max, unbounded) {
        (true, _) => write!(f, ", and {verb} {min}"),
        (_, true) => write!(f, ", and {verb} at least {min}"),
        _ => write!(f, ", and {verb} {min} to {max}"),
    }
}

/// `given` of what `unit` names in the plural: "1 octet", "2 octets in a
/// label", "1 entry".
fn number_of(f: &mut fmt::Formatter<'_>, given: usize, unit: &str) -> fmt::Result {
    let (word, rest) = unit.split_at(unit.find(' ').unwrap_or(unit.len()));
    match (given, word.strip_suffix("ies"), word.strip_suffix('s')) {
        (1, Some(stem), _) => write!(f, "1 {stem}y{rest}"),
        (1, None, Some(stem)) => write!(f, "1 {stem}{rest}"),
        _ => write!(f, "{given} {unit}"),
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let member = self.member;
        if let Some(entry) = self.entry {
            write!(f, "entry {entry}: ")?;
        }
        match self.fault {
            ValueFault::Range { given, min, max } => {
                write!(f, "`{member}` is {given}")?;
                limits(f, "is", min, max, false)
            }
            ValueFault::Length {
                given,
                min,
                max,
                unit,
            } => {
                write!(f, "`{member}` has ")?;
                number_of(f, given, unit)?;
                limits(f, "has", min, max, max == usize::MAX)
            }
            ValueFault::Count { given, min, max } => {
                write!(f, "`{member}` has ")?;
                number_of(f, given, "entries")?;
                limits(f, "has", min, max, max == usize::MAX)
            }
            ValueFault::Repeated { given } => write!(f, "`{member}` has {given} twice"),
            ValueFault::Character { given, expected } => {
                write!(
                    f,
                    "`{member}` has the character `{given}`, and has {expected}"
                )
            }
            ValueFault::Value { given, expected } => {
                write!(f, "`{member}` is {given}, and is {expected}")
            }
            ValueFault::Combination { rule } => write!(f, "`{member}` {rule}"),
            ValueFault::Identity(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for ValueError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn a_refusal_says_the_member_what_it_was_given_and_the_limit() {
        let text = |error: ValueError| error.to_string();
        assert_eq!(
            text(ValueError::range("pdu-session-identity", 16, 1, 15)),
            "`pdu-session-identity` is 16, and is 1 to 15"
        );
        assert_eq!(
            text(ValueError::length("mcc", "digits", 2, 3, 3)),
            "`mcc` has 2 digits, and has 3"
        );
        assert_eq!(
            text(ValueError::length("res", "octets", 2, 4, usize::MAX)),
            "`res` has 2 octets, and has at least 4"
        );
        // One of them is in the singular
        assert_eq!(
            text(ValueError::length("mnc", "digits", 1, 2, 3)),
            "`mnc` has 1 digit, and has 2 to 3"
        );
        assert_eq!(
            text(ValueError::length("dnn", "octets in a label", 1, 2, 63)),
            "`dnn` has 1 octet in a label, and has 2 to 63"
        );
        assert_eq!(
            text(ValueError::count("plmns", 1, 2, 15)),
            "`plmns` has 1 entry, and has 2 to 15"
        );
        assert_eq!(
            text(ValueError::count("numbers", 0, 1, 15).at(2)),
            "entry 2: `numbers` has 0 entries, and has 1 to 15"
        );
        assert_eq!(
            text(ValueError::repeated("pdu-session-identity", 5)),
            "`pdu-session-identity` has 5 twice"
        );
        assert_eq!(
            text(ValueError::character("digits", 'x', "decimal digits")),
            "`digits` has the character `x`, and has decimal digits"
        );
        assert_eq!(
            text(ValueError::value("rate", 5, "10 or more")),
            "`rate` is 5, and is 10 or more"
        );
        assert_eq!(
            text(ValueError::combination(
                "presentation",
                "is written with `screening`"
            )),
            "`presentation` is written with `screening`"
        );
        // The entry of the innermost list is kept
        assert_eq!(
            ValueError::count("tacs", 0, 1, 16).at(1).at(4).entry,
            Some(1)
        );
        assert_eq!(within("ebi", 5_u8, 1, 15), Ok(5));
        assert!(sized("res", "octets", 3, 4, 16).is_err());
        assert!(counted("plmns", 16, 1, 15).is_err());
    }
}
