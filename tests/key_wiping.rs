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

//! No copy of a key is left in the memory of the process once the security
//! contexts that were made of it are dropped.
//!
//! Each case runs in a process of its own: it makes two contexts from a
//! KAMF or a KASME, protects and verifies with them, drops them, and then
//! reads every writable mapping of the process through `/proc/self/mem` in
//! search of the master key and of the two NAS keys. The NAS keys that it
//! searches for are derived by another process, which gives them masked, so
//! that the process that is searched never has them outside the crate.
//!
//! A key that is found is one that this crate or oxirush-security left:
//! the scan cannot tell which, and the test fails for either.
//!
//! An optimized build is the one that this is about, and the only one that
//! it runs in: the code of a build without optimization copies every value
//! that it moves, and the copy that this was written for was left on the
//! stack by a release build alone. It is no part of `cargo test`
//! (`test = false`): CI runs it with
//!
//! ```sh
//! cargo test --release --features security --test key_wiping
//! ```

/// Elsewhere than on Linux, and in a build without optimization, the
/// program has nothing to say.
#[cfg(not(all(target_os = "linux", not(debug_assertions))))]
fn main() {
    println!("key_wiping: skipped, it runs on Linux in a release build");
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
fn main() {
    scan::main();
}

#[cfg(all(target_os = "linux", not(debug_assertions)))]
mod scan {
    use std::io::{Read, Seek, SeekFrom};
    use std::process::Command;

    /// What a key is combined with wherever this file holds one.
    const MASK: u8 = 0x5a;

    /// The variable that says what a process of this test does.
    const ROLE: &str = "OXIRUSH_NAS_KEY_WIPING";

    /// The KAMF or KASME of the cases, masked.
    fn masked_master() -> [u8; 32] {
        core::array::from_fn(|at| 0xa0u8.wrapping_add(at as u8 * 7) ^ MASK)
    }

    fn masked(octets: &[u8]) -> String {
        octets
            .iter()
            .map(|octet| format!("{:02x}", octet ^ MASK))
            .collect()
    }

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
            .collect()
    }

    /// The algorithms of the security crate that the number `algorithm` is.
    fn algorithms(
        algorithm: u8,
    ) -> (
        oxirush_security::IntegrityAlgorithm,
        oxirush_security::CipheringAlgorithm,
    ) {
        (algorithm.try_into().unwrap(), algorithm.try_into().unwrap())
    }

    /// The NAS keys of a system and an algorithm, masked: what the process
    /// that derives them prints.
    fn derive(system: &str, algorithm: u8) -> String {
        let master: Vec<u8> = masked_master().iter().map(|octet| octet ^ MASK).collect();
        let (integrity, ciphering) = algorithms(algorithm);
        match system {
            "5gs" => {
                use oxirush_security::nas_5gs::{KAmf, derive_knas_enc, derive_knas_int};
                let kamf = KAmf::from_slice(&master).unwrap();
                let knas_int = derive_knas_int(&kamf, integrity);
                let knas_enc = derive_knas_enc(&kamf, ciphering);
                format!(
                    "{} {}",
                    masked(knas_int.as_octets()),
                    masked(knas_enc.as_octets())
                )
            }
            _ => {
                use oxirush_security::nas_eps::{KAsme, derive_knas_enc, derive_knas_int};
                let kasme = KAsme::from_slice(&master).unwrap();
                let knas_int = derive_knas_int(&kasme, integrity);
                let knas_enc = derive_knas_enc(&kasme, ciphering);
                format!(
                    "{} {}",
                    masked(knas_int.as_octets()),
                    masked(knas_enc.as_octets())
                )
            }
        }
    }

    /// What a case does with its contexts, by the letters of `steps`: `p`
    /// protects four ciphered messages, `u` verifies each, `i` protects one
    /// without ciphering, `r` selects the algorithms again, and `k` keeps the
    /// contexts instead of dropping them, which the scan must then find.
    #[inline(never)]
    fn work(system: &str, algorithm: u8, steps: &str) {
        // The master key is unmasked into a buffer that is wiped, and given to
        // the crate as a slice: this file makes no array of it.
        let mut master = oxirush_security::kdf::Zeroizing::new(masked_master());
        master.iter_mut().for_each(|octet| *octet ^= MASK);
        let has = |step: char| steps.contains(step);
        if system == "5gs" {
            use oxirush_nas::nas_5gs::{
                CipheringAlgorithm as C, Direction, IntegrityAlgorithm as I, KAmf, Nas5gsMessage,
                Nas5gsSecurityHeaderType as Header, NasSecurityContext,
            };
            let (nia, nea) = match algorithm {
                1 => (I::NIA1, C::NEA1),
                2 => (I::NIA2, C::NEA2),
                _ => (I::NIA3, C::NEA3),
            };
            let kamf = KAmf::from_slice(&master[..]).unwrap();
            let message = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
            let mut sender = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
            let mut receiver = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
            for _ in 0..if has('p') { 4 } else { 0 } {
                let header = Header::IntegrityProtectedAndCiphered;
                let wire = sender
                    .protect(&message, header, Direction::Downlink)
                    .unwrap();
                if has('u') {
                    receiver.unprotect(&wire, Direction::Downlink).unwrap();
                }
            }
            if has('i') {
                let header = Header::IntegrityProtected;
                sender
                    .protect(&message, header, Direction::Downlink)
                    .unwrap();
            }
            if has('r') {
                sender.reselect_algorithms(&kamf, nia, nea).unwrap();
            }
            if has('k') {
                std::hint::black_box(Box::leak(Box::new((sender, receiver))));
            }
        } else {
            use oxirush_nas::nas_eps::{
                CipheringAlgorithm as C, Direction, IntegrityAlgorithm as I, KAsme, NasEpsMessage,
                NasEpsSecurityHeaderType as Header, NasSecurityContext,
            };
            let (eia, eea) = match algorithm {
                1 => (I::EIA1, C::EEA1),
                2 => (I::EIA2, C::EEA2),
                _ => (I::EIA3, C::EEA3),
            };
            let kasme = KAsme::from_slice(&master[..]).unwrap();
            let message = NasEpsMessage::decode(&[0x07, 0x60, 0x16]).unwrap();
            let mut sender = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
            let mut receiver = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
            for _ in 0..if has('p') { 4 } else { 0 } {
                let header = Header::IntegrityProtectedAndCiphered;
                let wire = sender
                    .protect(&message, header, Direction::Downlink)
                    .unwrap();
                if has('u') {
                    receiver.unprotect(&wire, Direction::Downlink).unwrap();
                }
            }
            if has('i') {
                let header = Header::IntegrityProtected;
                sender
                    .protect(&message, header, Direction::Downlink)
                    .unwrap();
            }
            if has('r') {
                sender.reselect_algorithms(&kasme, eia, eea).unwrap();
            }
            if has('k') {
                std::hint::black_box(Box::leak(Box::new((sender, receiver))));
            }
        }
    }

    /// The work of a case, far down the stack: the calls of the scan that
    /// follows would write over what the case left just below its caller, and
    /// they do not reach this deep.
    #[inline(never)]
    fn below(work: fn(&str, u8, &str), system: &str, algorithm: u8, steps: &str) {
        let padding = [0u8; 1 << 17];
        std::hint::black_box(&padding);
        work(system, algorithm, steps);
        std::hint::black_box(&padding);
    }

    /// Where the scan reads the memory to: one place, which the scan knows and
    /// does not count, and wipes when it is done.
    static BUFFER: std::sync::Mutex<[u8; 1 << 16]> = std::sync::Mutex::new([0; 1 << 16]);

    /// How many times the key that `masked` is, is in the writable memory of
    /// this process. The key itself is never made here: the memory is masked
    /// and compared with `masked`.
    #[inline(never)]
    fn scan(name: &str, masked: &[u8]) -> usize {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
        let mut memory = std::fs::File::open("/proc/self/mem").expect("/proc/self/mem");
        let mut buffer = BUFFER.lock().unwrap();
        let own = buffer.as_ptr() as u64..buffer.as_ptr() as u64 + buffer.len() as u64;
        let (mut hits, mut read) = (0, 0u64);
        for line in maps.lines() {
            let mut fields = line.split_whitespace();
            let (range, permissions) = (fields.next().unwrap(), fields.next().unwrap());
            let what = line.split_whitespace().nth(5).unwrap_or("(anonymous)");
            // The mappings of the kernel are not memory of the program.
            if !permissions.starts_with("rw") || what.starts_with("[v") {
                continue;
            }
            let (start, end) = range.split_once('-').unwrap();
            let start = u64::from_str_radix(start, 16).unwrap();
            let end = u64::from_str_radix(end, 16).unwrap();
            // In pieces that overlap by one octet less than a key has
            let step = (buffer.len() - masked.len() + 1) as u64;
            let mut from = start;
            while from < end {
                let length = (end - from).min(buffer.len() as u64) as usize;
                let piece = &mut buffer[..length];
                if memory.seek(SeekFrom::Start(from)).is_err() || memory.read_exact(piece).is_err()
                {
                    break;
                }
                read += length as u64;
                for (at, window) in piece.windows(masked.len()).enumerate() {
                    let address = from + at as u64;
                    let found = window
                        .iter()
                        .zip(masked)
                        .all(|(octet, masked)| octet ^ MASK == *masked);
                    // What the scan itself read is no copy of the program's.
                    if found && !own.contains(&address) {
                        hits += 1;
                        println!("\n{name} at {address:#x} in {what}");
                    }
                }
                from += step;
            }
        }
        // What was read may hold a key: it is not left behind either.
        buffer.fill(0);
        assert!(read > 0, "no writable mapping of the process could be read");
        hits
    }

    /// One case, in the process that was started for it: it prints where it
    /// finds a key, and that it has looked.
    fn case(
        work: fn(&str, u8, &str),
        system: &str,
        algorithm: u8,
        steps: &str,
        knas_int: &str,
        knas_enc: &str,
    ) -> ! {
        below(work, system, algorithm, steps);
        let master = if system == "5gs" { "KAMF" } else { "KASME" };
        let hits = scan(master, &masked_master())
            + scan("KNASint", &from_hex(knas_int))
            + scan("KNASenc", &from_hex(knas_enc));
        println!("\n{SCANNED} {hits}");
        std::process::exit(0)
    }

    /// What a case prints when its scan is done, before the number of keys
    /// that it found.
    const SCANNED: &str = "scanned, found";

    /// This program in a process of its own, with `role`: what it prints.
    fn process(role: &str) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .env(ROLE, role)
            .output()
            .unwrap();
        assert!(output.status.success(), "{role}: {:?}", output.status);
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The lines of what a case printed that say where a key was found.
    fn found(printed: &str) -> Vec<&str> {
        (printed.lines())
            .filter(|line| line.starts_with('K'))
            .collect()
    }

    pub(crate) fn main() {
        // A process that was started for a role does that, and nothing else.
        if let Ok(role) = std::env::var(ROLE) {
            let fields: Vec<&str> = role.split(' ').collect();
            match fields[..] {
                ["derive", system, algorithm] => {
                    // On a line of its own, after what the test harness printed
                    println!("\nkeys {}", derive(system, algorithm.parse().unwrap()));
                    std::process::exit(0)
                }
                ["case", system, algorithm, steps, knas_int, knas_enc] => {
                    let algorithm = algorithm.parse().unwrap();
                    case(work, system, algorithm, steps, knas_int, knas_enc)
                }
                _ => panic!("no role `{role}`"),
            }
        }

        let (mut left, mut cases) = (Vec::new(), 0);
        for system in ["5gs", "eps"] {
            for algorithm in 1..=3 {
                let printed = process(&format!("derive {system} {algorithm}"));
                let keys = (printed.lines())
                    .find_map(|line| line.strip_prefix("keys "))
                    .expect("the keys of the case")
                    .to_owned();

                // The scan finds a key that is there: contexts that are kept
                // have their two NAS keys, twice.
                let printed = process(&format!("case {system} {algorithm} k {keys}"));
                let kept = found(&printed).len();
                assert!(
                    kept >= 4,
                    "{system} {algorithm}: the scan finds {kept} keys of two contexts that are \
                     kept\n{printed}"
                );

                for steps in ["c", "ci", "cp", "cpu", "cr", "cpur"] {
                    let printed = process(&format!("case {system} {algorithm} {steps} {keys}"));
                    cases += 1;
                    let keys_left = found(&printed);
                    if !printed.contains(SCANNED) || !keys_left.is_empty() {
                        left.push(format!(
                            "{system}, algorithm {algorithm}, steps {steps}: {}",
                            keys_left.join("; ")
                        ));
                    }
                }
            }
        }
        assert!(
            left.is_empty(),
            "keys are left after the contexts are dropped:\n{}",
            left.join("\n")
        );
        println!("key_wiping: {cases} cases, and no key is left after the contexts are dropped");
    }
}
