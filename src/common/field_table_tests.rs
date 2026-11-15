//! The tree that a table of fields writes is the one that the hand-written
//! IE macros write: the same members, the same values shown, the same IE
//! written from a tree. Each table here is written by hand from the figure
//! of its clause.

use super::field_table::{Form, Row, Table};
use super::message_tree::{Code, Decoded, Scope};
use super::readable::{self, Readable};
use crate::common::Octets;
use crate::nas_5gs;
use crate::prelude::*;
use alloc::{format, vec};
use oxirush_utils::tree::Value;

/// A row of a field: a flag of one bit, or a value of `$kind`.
macro_rules! row {
    ($field:ident, $octet:literal, $low:literal, 1) => {
        Row {
            member: crate::common::names::name!(stringify!($field)),
            octet: $octet,
            low: $low,
            width: 1,
            next: None,
            form: Form::Flag,
        }
    };
    ($field:ident, $octet:literal, $low:literal, $width:literal, $kind:ty) => {
        Row {
            member: crate::common::names::name!(stringify!($field)),
            octet: $octet,
            low: $low,
            width: $width,
            next: None,
            form: Form::Named {
                show: |raw| {
                    let raw = raw as u8;
                    readable::to_value(&Code::of(<$kind>::named(raw), raw)).unwrap()
                },
                read: |value| {
                    Ok(match readable::from_value::<Code<$kind>>(value)? {
                        Code::Name(name) => u8::from(name).into(),
                        Code::Number(number) => number.into(),
                    })
                },
                takes: <Code<$kind> as Readable>::TAKES,
            },
        }
    };
}

/// The octets of the value of an IE type, which is one octet or several.
trait Held: Sized {
    fn octets(&self) -> Vec<u8>;
    fn of(octets: &[u8]) -> Option<Self>;
}

impl Held for u8 {
    fn octets(&self) -> Vec<u8> {
        vec![*self]
    }
    fn of(octets: &[u8]) -> Option<Self> {
        match octets {
            [octet] => Some(*octet),
            _ => None,
        }
    }
}

impl Held for Octets {
    fn octets(&self) -> Vec<u8> {
        self.to_vec()
    }
    fn of(octets: &[u8]) -> Option<Self> {
        Some(octets.into())
    }
}

/// Whether the hand-written IE macro of a type `T` decides `values` as the
/// table does. `shown_only` for a type whose value is absent where it is not
/// shown (`built_ie!`). Returns the differences.
fn compare<T, H>(
    table: &Table,
    values: &[Vec<u8>],
    get: fn(&T) -> &H,
    make: fn(H) -> T,
    shown_only: bool,
) -> Vec<String>
where
    T: Decoded,
    H: Held,
{
    let name = core::any::type_name::<T>();
    let mut differences = Vec::new();
    let mut kept_shorter = Vec::new();
    let ies: Vec<(Vec<u8>, T)> = (values.iter())
        .filter_map(|octets| Some((octets.clone(), make(H::of(octets)?))))
        .collect();
    let mut shown = Vec::new();
    for (octets, ie) in &ies {
        let tree = match shown_only {
            true => table.shown(octets),
            false => Some(table.tree(octets)),
        };
        if ie.decoded(Scope::NONE) != tree {
            differences.push(format!(
                "{name} {octets:02x?}: decoded {:?}, table {tree:?}",
                ie.decoded(Scope::NONE)
            ));
        }
        let mine = table.shown(octets);
        if ie.shown_value(Scope::NONE) != mine {
            differences.push(format!(
                "{name} {octets:02x?}: shown {:?}, table {mine:?}",
                ie.shown_value(Scope::NONE)
            ));
        }
        shown.extend(mine);
    }
    let blank = make(H::of(&T::unwritten_octets()).unwrap());
    let mut onto: Vec<(Vec<u8>, &T)> = ies
        .iter()
        .step_by(17)
        .map(|(o, ie)| (o.clone(), ie))
        .collect();
    onto.push((T::unwritten_octets(), &blank));
    for tree in &shown {
        for (octets, ie) in &onto {
            let theirs = ie
                .with_decoded(tree, Scope::NONE)
                .map(|ie| get(&ie).octets());
            let mut written = Octets::from(octets.as_slice());
            let mine = table.write(&mut written, tree).map(|()| written.to_vec());
            // The table keeps the spare bits that an edit does not write,
            // where a hand-written setter may clear them.
            let kept = match (&theirs, &mine) {
                (Ok(theirs), Ok(mine)) if theirs.len() == mine.len() => (0..mine.len()).all(|at| {
                    let mask = table.mask(at);
                    (theirs[at] ^ mine[at]) & mask == 0
                        && mine[at] & !mask == octets.get(at).copied().unwrap_or(0) & !mask
                }),
                _ => false,
            };
            // A value written from a tree has the shortest length of its table, where a
            // hand-written sender rule that the value breaks kept octets of zeros.
            let shorter = match (&theirs, &mine) {
                (Ok(theirs), Ok(mine)) if octets.is_empty() && theirs.len() > mine.len() => {
                    theirs.starts_with(mine) && theirs[mine.len()..].iter().all(|octet| *octet == 0)
                }
                _ => false,
            };
            if shorter {
                kept_shorter.push(format!("{name} {tree}: {theirs:02x?} -> {mine:02x?}"));
            }
            if !kept
                && !shorter
                && (theirs.is_ok() != mine.is_ok() || theirs.as_ref().ok() != mine.as_ref().ok())
            {
                differences.push(format!(
                    "{name} {octets:02x?} with {tree}: {theirs:02x?}, table {mine:02x?}"
                ));
            }
        }
    }
    if let Some(first) = kept_shorter.first() {
        std::println!("{} written shorter: {first}", kept_shorter.len());
    }
    differences
}

/// The octets of an IE that is not written yet.
trait Unwritten {
    fn unwritten_octets() -> Vec<u8>;
}

impl<T: Decoded> Unwritten for T {
    fn unwritten_octets() -> Vec<u8> {
        let value = readable::to_value(&T::unwritten()).unwrap();
        match &value["value"] {
            Value::Number(octet) => vec![octet.as_u64().unwrap() as u8],
            Value::String(octets) => (0..octets.len() / 2)
                .map(|at| u8::from_str_radix(&octets[2 * at..2 * at + 2], 16).unwrap())
                .collect(),
            Value::Array(octets) if octets.is_empty() => vec![],
            other => panic!("{other}"),
        }
    }
}

fn one_octet() -> Vec<Vec<u8>> {
    (0..=255).map(|octet| vec![octet]).collect()
}

#[test]
fn a_table_writes_the_tree_of_the_fields_of_security_algorithms() {
    const TABLE: Table = Table {
        rows: &[
            row!(ciphering, 0, 5, 4, nas_5gs::CipheringAlgorithm),
            row!(integrity, 0, 1, 4, nas_5gs::IntegrityAlgorithm),
        ],
        least: 1,
        most: 1,
        receives: 1,
        trailing: false,
    };
    let differences = compare(
        &TABLE,
        &one_octet(),
        |ie: &nas_5gs::SecurityAlgorithms| &ie.value,
        nas_5gs::SecurityAlgorithms::new,
        false,
    );
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn a_table_writes_the_tree_of_the_flags_of_mico_indication() {
    const TABLE: Table = Table {
        rows: &[row!(raai, 0, 1, 1), row!(sprti, 0, 2, 1)],
        least: 1,
        most: 1,
        receives: 1,
        trailing: false,
    };
    let values: Vec<Vec<u8>> = (0..=15).map(|octet| vec![octet]).collect();
    let differences = compare(
        &TABLE,
        &values,
        |ie: &nas_5gs::MicoIndication| &ie.value,
        nas_5gs::MicoIndication::new,
        false,
    );
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn a_table_writes_the_tree_of_the_flags_of_allowed_ssc_mode() {
    const TABLE: Table = Table {
        rows: &[
            row!(ssc1, 0, 1, 1),
            row!(ssc2, 0, 2, 1),
            row!(ssc3, 0, 3, 1),
        ],
        least: 1,
        most: 1,
        receives: 1,
        trailing: false,
    };
    let values: Vec<Vec<u8>> = (0..=15).map(|octet| vec![octet]).collect();
    let differences = compare(
        &TABLE,
        &values,
        |ie: &nas_5gs::AllowedSscMode| &ie.value,
        nas_5gs::AllowedSscMode::new,
        false,
    );
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

/// Each value that the table of a type shows writes the IE back, from an IE
/// without octets: what a tree shows is written as it is.
fn writes_back<T: Decoded>(make: impl Fn(u8) -> T) {
    let name = core::any::type_name::<T>();
    for octet in 0..=u8::MAX {
        let ie = make(octet);
        if let Some(value) = ie.shown_value(Scope::NONE) {
            let written = T::unwritten().with_decoded(&value, Scope::NONE);
            let written = written.unwrap_or_else(|error| panic!("{name} {octet:#04x}: {error}"));
            assert!(
                written.meant(Scope::NONE) == ie.meant(Scope::NONE),
                "{name} {octet:#04x}: {value}"
            );
        }
    }
}

#[test]
fn each_value_that_a_table_shows_writes_its_ie_back() {
    writes_back(nas_5gs::RegistrationType::new);
    let octets = |octet| crate::common::Octets::from([octet]);
    let two = |octet| crate::common::Octets::from([octet, 0x81]);
    writes_back(|octet| nas_5gs::GmmCapability::new(octets(octet)));
    writes_back(|octet| nas_5gs::GmmCapability::new(two(octet)));
    writes_back(|octet| crate::common::types::UeStatus::new(octets(octet)));
    writes_back(|octet| nas_5gs::ReAttemptIndicator::new(octets(octet)));
    writes_back(|octet| crate::nas_eps::ReAttemptIndicator::new(octets(octet)));
    writes_back(crate::common::types::Non3GppNwProvidedPolicies::new);
    writes_back(|octet| crate::common::types::MobileStationClassmark2::new([octet, octet, octet]));
    writes_back(|octet| crate::common::types::AccessTechnologyUtilizationControl::new(two(octet)));
    writes_back(|octet| crate::nas_eps::MsNetworkCapability::new(two(octet)));
    writes_back(crate::nas_eps::DeviceProperties::new);
    writes_back(crate::nas_eps::WlanOffloadAcceptability::new);
    writes_back(crate::nas_eps::NetworkPolicy::new);
    writes_back(crate::nas_eps::MsNetworkFeatureSupport::new);
    writes_back(crate::nas_eps::AdditionalInformationRequested::new);
    writes_back(|octet| nas_5gs::GsmCapability::new(two(octet)));
    writes_back(|octet| crate::nas_eps::EpsNetworkFeatureSupport::new(two(octet)));
    writes_back(|octet| crate::nas_eps::N1UeNetworkCapability::new(octets(octet)));
    writes_back(nas_5gs::DeRegistrationType::new);
    writes_back(|octet| nas_5gs::RegistrationResult::new(octets(octet)));
    writes_back(|octet| nas_5gs::UpdateType::new(octets(octet)));
    writes_back(nas_5gs::ControlPlaneServiceType::new);
    writes_back(crate::nas_eps::EpsUpdateType::new);
    writes_back(crate::nas_eps::ControlPlaneServiceType::new);
    writes_back(crate::nas_eps::DetachType::new);
}
