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

//! oxirush-nas and packet-dissector, as `compare.sh` runs each program:
//!
//! ```text
//! oxirush-nas-compare <oxirush-nas|packet-dissector> check <5gs|eps> <fixtures>
//! oxirush-nas-compare <oxirush-nas|packet-dissector> run <decode|encode> <5gs|eps> <messages> <passes>
//! ```
//!
//! `check` prints, for each message of a file of the fixtures, its name,
//! whether the implementation decodes it (1 or 0), and whether it encodes
//! what it decoded to the same octets (1, 0, or `-` without an encoder).
//! `run` does the operation on each message of the file, `passes` times,
//! and prints the nanoseconds, the allocations and the octets allocated per
//! message, and the peak memory of the program in KiB.

use oxirush_nas::common::Direction;
use oxirush_nas::nas_5gs::Nas5gsMessage;
use oxirush_nas::nas_eps::NasEpsMessage;
use packet_dissector_core::dissector::Dissector;
use packet_dissector_core::packet::DissectBuffer;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// The allocator of the program, which counts the allocations and their
/// octets.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static OCTETS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        OCTETS.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        OCTETS.fetch_add(size as u64, Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The messages of a file: a name and octets in hexadecimal on each line.
fn messages(file: &str) -> Vec<(String, Vec<u8>)> {
    let text = std::fs::read_to_string(file).unwrap_or_else(|error| panic!("{file}: {error}"));
    (text.lines())
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (name, octets) = line.split_once('\t').expect("a name, a tab and octets");
            (name.to_owned(), hex::decode(octets.trim()).expect("octets"))
        })
        .collect()
}

/// The direction of an EPS message of the fixtures, which the decoder needs
/// for DETACH REQUEST alone.
fn direction(name: &str) -> Direction {
    match name.starts_with("DetachRequestUeTerminated") {
        true => Direction::Downlink,
        false => Direction::Uplink,
    }
}

/// The peak memory of the program, in KiB.
fn peak_memory() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    (status.lines())
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|kib| kib.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// What an implementation does to a message.
trait Implementation {
    /// Whether it decodes the message, and whether it encodes what it
    /// decoded to the same octets (`None` without an encoder).
    fn check(&self, name: &str, octets: &[u8]) -> (bool, Option<bool>);
    /// The operation on every message, `passes` times.
    fn run(&self, operation: &str, messages: &[(String, Vec<u8>)], passes: usize);
}

struct OxirushNas {
    eps: bool,
}

impl Implementation for OxirushNas {
    fn check(&self, name: &str, octets: &[u8]) -> (bool, Option<bool>) {
        let encoded = match self.eps {
            false => Nas5gsMessage::decode(octets).map(|message| message.encode()),
            true => NasEpsMessage::decode_with_direction(octets, direction(name))
                .map(|message| message.encode()),
        };
        match encoded {
            Ok(encoded) => (true, Some(encoded.is_ok_and(|encoded| encoded == octets))),
            Err(_) => (false, Some(false)),
        }
    }

    fn run(&self, operation: &str, messages: &[(String, Vec<u8>)], passes: usize) {
        match (operation, self.eps) {
            ("decode", false) => {
                let octets: Vec<_> = messages.iter().map(|(_, octets)| octets).collect();
                timed(messages.len(), passes, || {
                    for octets in &octets {
                        drop(black_box(Nas5gsMessage::decode(black_box(octets))));
                    }
                });
            }
            ("decode", true) => {
                let octets: Vec<_> = (messages.iter())
                    .map(|(name, octets)| (octets, direction(name)))
                    .collect();
                timed(messages.len(), passes, || {
                    for (octets, direction) in &octets {
                        let decoded =
                            NasEpsMessage::decode_with_direction(black_box(octets), *direction);
                        drop(black_box(decoded));
                    }
                });
            }
            ("encode", false) => {
                let decoded: Vec<_> = (messages.iter())
                    .map(|(_, octets)| Nas5gsMessage::decode(octets).unwrap())
                    .collect();
                timed(messages.len(), passes, || {
                    for message in &decoded {
                        drop(black_box(black_box(message).encode()));
                    }
                });
            }
            ("encode", true) => {
                let decoded: Vec<_> = (messages.iter())
                    .map(|(name, octets)| {
                        NasEpsMessage::decode_with_direction(octets, direction(name)).unwrap()
                    })
                    .collect();
                timed(messages.len(), passes, || {
                    for message in &decoded {
                        drop(black_box(black_box(message).encode()));
                    }
                });
            }
            _ => panic!("no operation {operation}"),
        }
    }
}

/// packet-dissector, which dissects into a buffer that it is given again
/// for each message, and has no encoder.
struct PacketDissector {
    eps: bool,
}

impl PacketDissector {
    fn dissector(&self) -> &dyn Dissector {
        match self.eps {
            false => &packet_dissector_nas5g::Nas5gDissector,
            true => &packet_dissector_nas_eps::NasEpsDissector,
        }
    }
}

impl Implementation for PacketDissector {
    fn check(&self, _: &str, octets: &[u8]) -> (bool, Option<bool>) {
        let mut buffer = DissectBuffer::new();
        (
            self.dissector().dissect(octets, &mut buffer, 0).is_ok(),
            None,
        )
    }

    fn run(&self, operation: &str, messages: &[(String, Vec<u8>)], passes: usize) {
        assert_eq!(operation, "decode", "packet-dissector has no encoder");
        let dissector = self.dissector();
        let mut buffer = DissectBuffer::new();
        timed(messages.len(), passes, || {
            for (_, octets) in messages {
                buffer.clear();
                let _ = black_box(dissector.dissect(black_box(octets), &mut buffer, 0));
            }
        });
    }
}

/// Run `pass` `passes` times, and print what one message took.
fn timed(messages: usize, passes: usize, mut pass: impl FnMut()) {
    pass();
    let (allocations, octets) = (ALLOCATIONS.load(Relaxed), OCTETS.load(Relaxed));
    let start = Instant::now();
    for _ in 0..passes {
        pass();
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    let operations = (messages * passes) as f64;
    println!(
        "{:.1} {:.2} {:.0} {}",
        elapsed / operations,
        (ALLOCATIONS.load(Relaxed) - allocations) as f64 / operations,
        (OCTETS.load(Relaxed) - octets) as f64 / operations,
        peak_memory()
    );
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let usage = "oxirush-nas-compare <oxirush-nas|packet-dissector> \
                 (check <5gs|eps> <fixtures> | run <decode|encode> <5gs|eps> <messages> <passes>)";
    let system = |system: &str| match system {
        "5gs" => false,
        "eps" => true,
        _ => panic!("{usage}"),
    };
    let implementation = |name: &str, eps| -> Box<dyn Implementation> {
        match name {
            "oxirush-nas" => Box::new(OxirushNas { eps }),
            "packet-dissector" => Box::new(PacketDissector { eps }),
            _ => panic!("{usage}"),
        }
    };
    match arguments[..] {
        [name, "check", system_name, file] => {
            let implementation = implementation(name, system(system_name));
            for (message, octets) in messages(file) {
                let (decodes, encodes) = implementation.check(&message, &octets);
                let encodes = encodes.map_or("-", |encodes| if encodes { "1" } else { "0" });
                println!("{message}\t{}\t{encodes}", u8::from(decodes));
            }
        }
        [name, "run", operation, system_name, file, passes] => {
            let implementation = implementation(name, system(system_name));
            let passes = passes.parse().expect("a number of passes");
            implementation.run(operation, &messages(file), passes);
        }
        _ => panic!("{usage}"),
    }
}
