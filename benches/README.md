# Benchmarks of oxirush-nas

A package of its own, which the published crate does not have. It measures
the codec, the JSON forms and NAS security on the messages of the fixtures,
with criterion; [`src/lib.rs`](src/lib.rs) has the commands of the
profilers. The [README](../README.md#performance) has the figures of the
crate alone, taken on core 2 of an Intel Xeon E5-2680 v4 (Broadwell, 2.4 GHz;
a KVM guest bound to NUMA node 0; Linux 7.0, Rust 1.100.0) at 626037a on
2026-11-15, the median of ten runs of `codec` (with the feature `security`),
and the allocations of `allocations`.

```sh
cargo bench
```

## Against other implementations

The plain messages of the fixtures that each implementation decodes, and
for encoding those that each writes back to the same octets, on core 3 of
the machine of the README (Go 1.27.4, Python 3.14, GCC 15.2), at 626037a on
2026-11-15. Each implementation ran once a round, in turns, ten rounds: a
time is the median of the ten, beside the lowest and the highest. Cycles
and instructions are per message, the median of those of `perf stat` in
user mode, and peak memory is that of the whole program. A ratio is that of
the medians, given where the ten times of the two do not overlap, and
"about the same" where they do; the layout of the code alone moves a time
by 7 to 15 % between two builds. packet-dissector reads a message into
fields and writes none. Open5GS decodes from a packet buffer made for each
message. Python counts no allocations.

| Operation | | ns | Lowest and highest | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Other / this crate |
|---|---|---|---|---|---|---|---|---|---|
| decode, 5GS, 87 messages | oxirush-nas | 224.6 | 220.1 to 232.5 | 635 | 1,119 | 1.2 | 254 | 3.8 MiB |  |
| | free5GC nas v1.2.3 | 864.1 | 856 to 913.5 | 2,449 | 5,862 | 16.36 | 412 | 9.9 MiB | 3.9x |
| | Open5GS v2.8.0 | 3,032 | 3,017 to 3,400 | 8,680 | 25,746 | 0 | 0 | 5.8 MiB | 14x |
| | packet-dissector 0.6.1 | 247.4 | 237.8 to 264.7 | 730 | 1,497 | 0 | 0 | 3.0 MiB | 1.1x |
| | pycrate 0.8.1 | 593,425 | 582,432 to 612,816 | 1,702,105 | 2,737,596 |  |  | 51.9 MiB | 2,600x |
| decode, EPS, 95 messages | oxirush-nas | 196.1 | 193.2 to 200.2 | 563 | 904 | 1.06 | 195 | 3.7 MiB |  |
| | Open5GS v2.8.0 | 1,952 | 1,931 to 2,067 | 5,570 | 16,518 | 0 | 0 | 5.8 MiB | 10.0x |
| | packet-dissector 0.6.1 | 186.2 | 182.8 to 204.7 | 542 | 1,174 | 0 | 0 | 3.0 MiB | about the same |
| | pycrate 0.8.1 | 388,264 | 382,271 to 437,564 | 1,105,962 | 1,812,202 |  |  | 49.6 MiB | 2,000x |
| encode, 5GS, 72 messages | oxirush-nas | 75.5 | 74.6 to 77.9 | 214 | 464 | 1.01 | 66 | 3.9 MiB |  |
| | free5GC nas v1.2.3 | 337.4 | 335.1 to 347.3 | 951 | 2,344 | 7.83 | 120 | 9.9 MiB | 4.5x |
| | Open5GS v2.8.0 | 3,353 | 3,300 to 3,458 | 9,547 | 19,956 | 1 | 32,960 | 5.4 MiB | 44x |
| | pycrate 0.8.1 | 49,388 | 47,893 to 51,445 | 140,657 | 301,440 |  |  | 35.5 MiB | 650x |
| encode, EPS, 82 messages | oxirush-nas | 74.5 | 73.2 to 77.2 | 214 | 466 | 1 | 64 | 3.7 MiB |  |
| | Open5GS v2.8.0 | 3,245 | 3,184 to 3,287 | 9,420 | 19,304 | 1 | 32,960 | 5.4 MiB | 44x |
| | pycrate 0.8.1 | 44,920 | 43,943 to 45,943 | 126,391 | 274,514 |  |  | 35.3 MiB | 600x |

`benches/compare/compare.sh 3` runs every row on core 3, ten rounds
(`ROUNDS` sets them). It fetches each
implementation at the version that it pins, and builds Open5GS's NAS
libraries; perf may need `PERF="sudo -n perf"`.
