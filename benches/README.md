# Benchmarks of oxirush-nas

A package of its own, which the published crate does not have. It measures
the codec, the JSON forms and NAS security on the messages of the fixtures,
with criterion; [`src/lib.rs`](src/lib.rs) has the commands of the
profilers. The [README](../README.md#performance) has the figures of the
crate alone, taken on an AMD Ryzen 7 5700G (16 threads, Linux 7.0, Rust
1.98.1), on a quiet machine on 2026-10-18, at c4fdffc, and the JSON forms at
3a0d08d, the lowest of five runs.

```sh
cargo bench
```

## Against other implementations

The plain messages of the fixtures that each implementation decodes, and
for encoding those that each writes back to the same octets, on core 2 of
the machine of the README (Go 1.27, Python 3.14), at c4fdffc. Times are the
lowest of three runs, and each figure the median of three runs of the script.
Cycles and instructions are per message, from `perf stat`, in user mode,
and peak memory is that of the whole program. A ratio within 10 % is
"about the same": the layout of the code alone moves a time by 7 to 15 %
between two builds. packet-dissector reads a message into fields and
writes none. Open5GS decodes from a packet buffer made for each message.
Python counts no allocations.

| Operation | | ns | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Other / this crate |
|---|---|---|---|---|---|---|---|---|
| decode, 5GS, 76 messages | oxirush-nas | 108.4 | 498 | 1,028 | 1.18 | 225 | 3.7 MiB | |
| | free5GC nas v1.2.3 | 408.9 | 1,835 | 5,782 | 15.95 | 394 | 10.2 MiB | 3.8x |
| | Open5GS v2.8.0 | 1,348.6 | 6,139 | 22,294 | 0 | 0 | 5.5 MiB | 12x |
| | packet-dissector 0.6.1 | 147.5 | 674 | 1,361 | 0 | 0 | 3.2 MiB | 1.4x |
| | pycrate 0.8.1 | 257,963 | 1,187,520 | 2,379,701 | | | 51.7 MiB | 2,400x |
| decode, EPS, 95 messages | oxirush-nas | 98.1 | 446 | 855 | 1.06 | 195 | 3.6 MiB | |
| | Open5GS v2.8.0 | 999.9 | 4,509 | 16,398 | 0 | 0 | 6.1 MiB | 10x |
| | packet-dissector 0.6.1 | 121.6 | 556 | 1,175 | 0 | 0 | 3.2 MiB | 1.2x |
| | pycrate 0.8.1 | 191,042 | 872,478 | 1,799,598 | | | 49.8 MiB | 1,900x |
| encode, 5GS, 61 messages | oxirush-nas | 33.7 | 145 | 412 | 1.00 | 64 | 3.7 MiB | |
| | free5GC nas v1.2.3 | 156.7 | 692 | 2,034 | 7.28 | 118 | 9.7 MiB | 4.6x |
| | Open5GS v2.8.0 | 1,131.0 | 5,057 | 16,372 | 1.00 | 32,960 | 5.2 MiB | 34x |
| | pycrate 0.8.1 | 18,889 | 85,405 | 229,048 | | | 35.2 MiB | 560x |
| encode, EPS, 82 messages | oxirush-nas | 36.5 | 163 | 463 | 1.00 | 64 | 3.7 MiB | |
| | Open5GS v2.8.0 | 1,410.0 | 6,324 | 20,961 | 1.00 | 32,960 | 5.8 MiB | 39x |
| | pycrate 0.8.1 | 22,629 | 101,987 | 274,416 | | | 36.0 MiB | 620x |

`benches/compare/compare.sh 3` runs every row on core 3. It fetches each
implementation at the version that it pins, and builds Open5GS's NAS
libraries; perf may need `PERF="sudo -n perf"`.
