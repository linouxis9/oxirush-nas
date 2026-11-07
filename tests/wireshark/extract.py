#!/usr/bin/env python3
"""Collect NAS messages for the Wireshark differential, one row per message.

Sources, any number of each:
  --pcap PATH      a capture, or a directory searched for *.pcap and *.pcapng:
                   the NAS-PDUs of its NGAP (5GS) and S1AP (EPS) messages, as
                   tshark reads them; the capture is read from standard input
  --tsv SYSTEM PATH[:N]
                   rows of a TSV whose column N, or else its last column of
                   hexadecimal, is a message (comments with #); SYSTEM is 5gs,
                   eps or auto (by the first octet)
  --raw SYSTEM DIR one message per file, its octets as they are

Rows out, separated by tabs: system, class, source, octets. A message
appears once, by its octets and system; `source` is where it was first
seen, and the summary counts every occurrence. The class is that of its
security header: plain, integrity (protected but not ciphered, which
both decoders read) or ciphered (opaque to both without keys).
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path


def system_of(octets):
    if not octets:
        return None
    if octets[0] in (0x7E, 0x2E):
        return "5gs"
    if octets[0] & 0x0F in (0x07, 0x02):
        return "eps"
    return None


def security_class(system, octets):
    """plain, integrity, ciphered or short (the EPS SERVICE REQUEST header)."""
    if system == "5gs":
        if len(octets) < 2 or octets[0] != 0x7E:
            return "plain"
        header = octets[1] & 0x0F
    else:
        if octets[0] & 0x0F != 0x07:
            return "plain"
        header = octets[0] >> 4
        if header >= 12:
            return "short"
    if header == 0:
        return "plain"
    if header in (1, 3):
        return "integrity"
    return "ciphered"


def captures(path):
    if path.is_dir():
        for root, _, files in os.walk(path):
            for name in sorted(files):
                if name.endswith((".pcap", ".pcapng")):
                    yield Path(root) / name
    else:
        yield path


def from_capture(path):
    # tshark reads the capture from standard input: a path may be refused
    # where the file is readable.
    with path.open("rb") as source:
        result = subprocess.run(
            ["tshark", "-n", "-r", "-", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
             "-e", "frame.number", "-e", "ngap.NAS_PDU", "-e", "s1ap.NAS_PDU"],
            stdin=source, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{path}: tshark failed: {result.stderr.strip()}", file=sys.stderr)
        return
    for line in result.stdout.splitlines():
        frame, ngap, s1ap = (line.split("\t") + ["", ""])[:3]
        for system, column in (("5gs", ngap), ("eps", s1ap)):
            for octets in filter(None, column.split("|")):
                yield system, f"{path}#{frame}", bytes.fromhex(octets)


def from_tsv(system, spec):
    path, _, index = spec.partition(":")
    path = Path(path)
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        columns = line.split("\t")
        if index:
            columns = columns[int(index) - 1:int(index)]
        for column in reversed(columns):
            column = column.strip()
            if column and all(c in "0123456789abcdefABCDEF" for c in column) and len(column) % 2 == 0:
                octets = bytes.fromhex(column)
                break
        else:
            continue
        yield (system_of(octets) if system == "auto" else system), f"{path}:{number}", octets


def from_raw(system, path):
    for name in sorted(os.listdir(path)):
        file = path / name
        if file.is_file():
            octets = file.read_bytes()
            yield (system_of(octets) if system == "auto" else system), str(file), octets


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", type=Path, action="append", default=[])
    parser.add_argument("--tsv", nargs=2, action="append", default=[], metavar=("SYSTEM", "PATH"))
    parser.add_argument("--raw", nargs=2, action="append", default=[], metavar=("SYSTEM", "DIR"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    seen = {}
    counts = {}

    def add(system, source, octets):
        if system not in ("5gs", "eps") or not octets:
            counts["unknown system"] = counts.get("unknown system", 0) + 1
            return
        kind = security_class(system, octets)
        key = (system, kind)
        counts[key] = counts.get(key, 0) + 1
        seen.setdefault((system, octets), (kind, source))

    for path in args.pcap:
        for capture in captures(path):
            for row in from_capture(capture):
                add(*row)
    for system, path in args.tsv:
        for row in from_tsv(system, path):
            add(*row)
    for system, path in args.raw:
        for row in from_raw(system, Path(path)):
            add(*row)

    with args.output.open("w") as output:
        output.write("# system\tclass\tsource\toctets\n")
        for (system, octets), (kind, source) in seen.items():
            output.write(f"{system}\t{kind}\t{source}\t{octets.hex()}\n")
        output.flush()
        os.fsync(output.fileno())
    unique = {}
    for (system, _), (kind, _) in seen.items():
        unique[(system, kind)] = unique.get((system, kind), 0) + 1
    for key in sorted(k for k in counts if isinstance(k, tuple)):
        print(f"{key[0]} {key[1]}: {counts[key]} seen, {unique.get(key, 0)} distinct")
    if "unknown system" in counts:
        print(f"unknown system: {counts['unknown system']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
