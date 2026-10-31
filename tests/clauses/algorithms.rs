//! The NAS security algorithms (TS 24.301 §9.9.3.23, TS 24.501 §9.11.3.34): each of
//! the eight values of a field of three bits names an algorithm, EEA0 to EEA7 and
//! EIA0 to EIA7, or 5G-EA0 to 5G-EA7 and 5G-IA0 to 5G-IA7; no other value does.

use oxirush_nas::nas_5gs::{CipheringAlgorithm as Nea, IntegrityAlgorithm as Nia};
use oxirush_nas::nas_eps::{CipheringAlgorithm as Eea, IntegrityAlgorithm as Eia};

#[test]
fn each_value_of_three_bits_is_the_algorithm_of_its_number() {
    let eea = [
        Eea::EEA0,
        Eea::EEA1,
        Eea::EEA2,
        Eea::EEA3,
        Eea::EEA4,
        Eea::EEA5,
        Eea::EEA6,
        Eea::EEA7,
    ];
    let eia = [
        Eia::EIA0,
        Eia::EIA1,
        Eia::EIA2,
        Eia::EIA3,
        Eia::EIA4,
        Eia::EIA5,
        Eia::EIA6,
        Eia::EIA7,
    ];
    let nea = [
        Nea::NEA0,
        Nea::NEA1,
        Nea::NEA2,
        Nea::NEA3,
        Nea::NEA4,
        Nea::NEA5,
        Nea::NEA6,
        Nea::NEA7,
    ];
    let nia = [
        Nia::NIA0,
        Nia::NIA1,
        Nia::NIA2,
        Nia::NIA3,
        Nia::NIA4,
        Nia::NIA5,
        Nia::NIA6,
        Nia::NIA7,
    ];
    for value in 0..=u8::MAX {
        let number = usize::from(value);
        assert_eq!(Eea::from_u8(value), eea.get(number).copied(), "{value}");
        assert_eq!(Eia::from_u8(value), eia.get(number).copied(), "{value}");
        assert_eq!(Nea::from_u8(value), nea.get(number).copied(), "{value}");
        assert_eq!(Nia::from_u8(value), nia.get(number).copied(), "{value}");
    }
    for (number, algorithm) in eea.into_iter().enumerate() {
        assert_eq!(algorithm as usize, number);
        assert_eq!(eia[number] as usize, number);
        assert_eq!(nea[number] as usize, number);
        assert_eq!(nia[number] as usize, number);
    }
}
