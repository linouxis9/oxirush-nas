# Contributing to oxirush-nas

## Tests

```sh
cargo test --all-features
cargo test --no-default-features --features security
cargo test --release --features security --test key_wiping
```

`key_wiping` searches the memory of its own process for the keys of a
dropped security context, in an optimized build. `examples/` has six
programs, each for 5GS and for EPS, such as
`cargo run --example decode_message_nas_5gs`.

## Fuzzing

```sh
./fuzz/seed.sh
cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512 -dict=fuzz/nas-5gs.dict
```

`fuzz/` has twelve [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets,
six for each system: they decode, edit and build messages, take any path of
their trees, and protect them. `seed.sh` writes their seeds from the
fixtures and the lab captures. CI runs each for a minute at a push, an hour
each day but Tuesday and Sunday, and four hours on Tuesday.

## Benchmarks

[`benches/README.md`](benches/README.md) has the figures and the commands.

## Pull requests

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.
