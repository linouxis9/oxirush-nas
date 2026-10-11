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

//! The time of each operation, and its CPU profile.
//!
//! ```bash
//! cargo bench --bench codec                     # every operation on every input
//! cargo bench --bench codec -- decode/5gs       # those whose name has "decode/5gs"
//! cargo bench --bench codec -- --profile-time 10 decode/5gs-fixtures
//! go tool pprof -top target/criterion/decode/5gs-fixtures/profile/profile.pb
//! ```
//!
//! A benchmark is `operation/input`, and its time is that of one pass over
//! the messages of the input: criterion also gives it per message, as
//! elements per second. What an operation is given, such as the view that
//! `with-view` reads, is made before the pass and is no part of its time. With `--profile-time`, criterion runs the benchmark
//! for that many seconds under pprof, which samples the program a thousand
//! times a second and writes `profile.pb`, a profile that `go tool pprof`
//! reads (`-top`, `-list REGEX`, `-peek REGEX`, `-traces`). With
//! `PROFILE=flamegraph` in the environment it writes `flamegraph.svg`
//! instead.

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_nas_benches::{Run, inputs};
use pprof::criterion::{Output, PProfProfiler};
use std::time::Duration;

fn operations(criterion: &mut Criterion) {
    for input in inputs() {
        for operation in input.operations() {
            let mut group = criterion.benchmark_group(operation.name);
            group.throughput(Throughput::Elements(operation.messages as u64));
            group.bench_function(input.name, |bencher| match &operation.run {
                Run::Direct(call) => bencher.iter(|| (0..operation.messages).for_each(call)),
                Run::Prepared(_) => bencher.iter_batched(
                    || operation.calls(),
                    |calls| calls.into_iter().for_each(|call| call()),
                    BatchSize::SmallInput,
                ),
            });
            group.finish();
        }
    }
}

fn configuration() -> Criterion {
    let output = match std::env::var("PROFILE").as_deref() {
        Ok("flamegraph") => Output::Flamegraph(None),
        _ => Output::Protobuf,
    };
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(50)
        .with_profiler(PProfProfiler::new(1000, output))
}

criterion_group! {
    name = benches;
    config = configuration();
    targets = operations
}
criterion_main!(benches);
