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

//! The allocations of each operation.
//!
//! ```bash
//! cargo bench --bench allocations             # every operation on every input
//! cargo bench --bench allocations -- decode   # those whose name has "decode"
//! ```
//!
//! A row is one operation on one input, and gives for one message:
//!
//! - `allocs`: the allocations of one call, after a first call that is not
//!   counted: the JSON forms keep the names that they have printed for the
//!   whole program, and the times of `codec` are those of such later calls
//!   too;
//! - `bytes`: the octets that those allocations asked for;
//! - `peak`: the most octets that were allocated at one time during the call,
//!   beyond what was allocated before it.
//!
//! For an input of several messages, `allocs` and `bytes` are the mean over
//! its messages and `peak` the largest. The numbers are exact, and the same
//! on every run: an allocator that counts stands in for the system allocator
//! in this program, which makes no measure of time.

// The allocator that counts is `unsafe` code, as an allocator has to be. The
// library has none.
#![allow(unsafe_code)]

use oxirush_nas_benches::{filter, inputs, selected};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

// ── An allocator that counts ────────────────────────────────────────────────

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static REQUESTED: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    ALLOCATIONS.fetch_add(1, Relaxed);
    REQUESTED.fetch_add(size, Relaxed);
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocated(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        LIVE.fetch_sub(layout.size(), Relaxed);
        allocated(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The allocations of one call of `operation`: how many, the octets they
/// asked for, and the most that were live beyond what was before the call.
fn allocations(operation: impl FnOnce()) -> [usize; 3] {
    let before = [ALLOCATIONS.load(Relaxed), REQUESTED.load(Relaxed)];
    let live = LIVE.load(Relaxed);
    PEAK.store(live, Relaxed);
    operation();
    [
        ALLOCATIONS.load(Relaxed) - before[0],
        REQUESTED.load(Relaxed) - before[1],
        PEAK.load(Relaxed) - live,
    ]
}

fn main() {
    let filter = filter();
    println!(
        "{:<16} {:<20} {:>9} {:>11} {:>11}",
        "operation", "input", "allocs", "bytes", "peak"
    );
    for input in inputs() {
        for operation in input.operations() {
            if !selected(&filter, operation.name, input.name) {
                continue;
            }
            // The first call on each message, which is not counted.
            operation.calls().into_iter().for_each(|call| call());
            let mut counted = [0; 3];
            for call in operation.calls() {
                let one = allocations(call);
                counted[0] += one[0];
                counted[1] += one[1];
                counted[2] = counted[2].max(one[2]);
            }
            let mean = |total: usize| total as f64 / operation.messages as f64;
            println!(
                "{:<16} {:<20} {:>9.1} {:>11.0} {:>11}",
                operation.name,
                input.name,
                mean(counted[0]),
                mean(counted[1]),
                counted[2]
            );
        }
    }
}
