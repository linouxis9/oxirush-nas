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

//! Where an operation allocates.
//!
//! ```sh
//! cargo bench --bench heap -- decode/5gs-fixtures
//! cargo bench --bench heap -- with-view/unknown-ies-1000 12   # the 12 first sites
//! ```
//!
//! The program runs the benchmarks that its arguments select, each for a
//! hundred passes over its input under the heap profiler of `dhat`, and
//! prints the sites that allocated the most octets: how many octets and how
//! many allocations in a pass, and the functions of the crate that led
//! there, innermost first. `dhat-heap.json`, in the directory of this
//! package, is the whole profile of the last benchmark, for
//! <https://nnethercote.github.io/dh_view/dh_view.html>.

use oxirush_nas_benches::{filter, inputs, selected};
use serde_json::Value;

#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

/// The passes over an input that one profile is made of.
const PASSES: u64 = 100;

/// The functions of a site that tell where it is: those of this crate and of
/// the library, without the allocator and the runtime under them.
fn frames<'a>(site: &Value, functions: &'a [Value]) -> Vec<&'a str> {
    let named = |index: &Value| functions.get(index.as_u64()? as usize)?.as_str();
    let ours = |frame: &&str| frame.contains("oxirush_nas") || frame.contains("serde_json");
    (site["fs"].as_array().into_iter().flatten())
        .filter_map(named)
        .filter(ours)
        // "0x55d0: path::function (file:line:column)" without its address
        .map(|frame| frame.split_once(": ").map_or(frame, |(_, frame)| frame))
        .take(4)
        .collect()
}

fn main() {
    let mut words = filter();
    let shown = match words.last().and_then(|word| word.parse::<usize>().ok()) {
        Some(shown) => {
            words.pop();
            shown
        }
        None => 8,
    };
    if words.is_empty() {
        eprintln!("which benchmark? for instance: cargo bench --bench heap -- decode/5gs-fixtures");
        return;
    }
    for input in inputs() {
        for operation in input.operations() {
            if !selected(&words, operation.name, input.name) {
                continue;
            }
            // What the calls are given is made before the profile starts.
            let passes: Vec<_> = (0..PASSES).map(|_| operation.calls()).collect();
            let profiler = dhat::Profiler::builder()
                .file_name("dhat-heap.json")
                .build();
            for call in passes.into_iter().flatten() {
                call();
            }
            drop(profiler);
            let profile = std::fs::read_to_string("dhat-heap.json").unwrap();
            let profile: Value = serde_json::from_str(&profile).unwrap();
            let functions = profile["ftbl"].as_array().cloned().unwrap_or_default();
            let mut sites = profile["pps"].as_array().cloned().unwrap_or_default();
            sites.sort_by_key(|site| std::cmp::Reverse(site["tb"].as_u64()));
            let total = |member: &str| -> u64 {
                sites.iter().filter_map(|site| site[member].as_u64()).sum()
            };
            let per_pass = |count: u64| count as f64 / PASSES as f64;
            println!(
                "\n{}/{}: {:.0} octets in {:.1} allocations a pass of {} messages",
                operation.name,
                input.name,
                per_pass(total("tb")),
                per_pass(total("tbk")),
                operation.messages
            );
            println!("{:>10} {:>8}  site", "octets", "allocs");
            for site in sites.iter().take(shown) {
                let (octets, blocks) = (site["tb"].as_u64(), site["tbk"].as_u64());
                let frames = frames(site, &functions);
                println!(
                    "{:>10.0} {:>8.1}  {}",
                    per_pass(octets.unwrap_or_default()),
                    per_pass(blocks.unwrap_or_default()),
                    frames.first().unwrap_or(&"(outside the crate)")
                );
                for frame in frames.iter().skip(1) {
                    println!("{:>19}  < {frame}", "");
                }
            }
        }
    }
}
