//! The NAS security algorithms (TS 24.301 §9.9.3.23, TS 24.501 §9.11.3.34): each value of
//! a field of three bits is the algorithm of its number, EEA0 to EEA3 and EIA0 to EIA3, or
//! 5G-EA0 to 5G-EA3 and 5G-IA0 to 5G-IA3; the values 4 to 7 are reserved, and are read as
//! their number.

use oxirush_nas::identity::Algorithm;
use oxirush_nas::{nas_5gs, nas_eps};

#[test]
fn each_value_of_three_bits_is_the_algorithm_of_its_number() {
    let algorithms = [
        Algorithm::Null,
        Algorithm::Snow3g,
        Algorithm::Aes,
        Algorithm::Zuc,
    ];
    for code in 0..8 {
        let expected = algorithms.get(usize::from(code)).copied().ok_or(code);
        let fgs = nas_5gs::SecurityAlgorithms::new(code << 4 | code);
        let eps = nas_eps::SecurityAlgorithms::new(code << 4 | code);
        assert_eq!(
            (fgs.ciphering(), fgs.integrity()),
            (expected, expected),
            "{code}"
        );
        assert_eq!(
            (eps.ciphering(), eps.integrity()),
            (expected, expected),
            "{code}"
        );
    }
    for (code, algorithm) in (0..).zip(algorithms) {
        let fgs = nas_5gs::SecurityAlgorithms::from_algorithms(algorithm, algorithm);
        let eps = nas_eps::SecurityAlgorithms::from_algorithms(algorithm, algorithm);
        assert_eq!((fgs.value, eps.value), (code << 4 | code, code << 4 | code));
    }
}
