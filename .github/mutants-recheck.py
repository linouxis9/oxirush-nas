"""The mutants that a file of the repository names, one a line, as a missed.txt of
cargo-mutants has them: each run again at the head. The shard SHARD of SHARDS takes every
SHARDS-th name from the SHARD-th. It fails when a mutant is missed, and when one is not
tried: a name that is no mutant of the head, as one whose line has moved, or a run that
ended early. mutants.out keeps the outcomes, the commit that they are of, in `commit`,
and the names that were not tried, in `not-tried.txt`.

    python3 .github/mutants-recheck.py FILE SHARD SHARDS
"""

import json
import pathlib
import subprocess
import sys

# What cargo-mutants reads as more than itself in a regular expression.
META = set("\\.+*?()|[]{}^$#&-~")


def escaped(name):
    return "".join("\\" + character if character in META else character for character in name)


def main():
    named, shard, shards = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    with open(named) as lines:
        names = sorted({line.strip() for line in lines if line.strip()})[shard::shards]
    out = pathlib.Path("mutants.out")
    code = 0
    if names:
        pattern = "|".join(f"^{escaped(name)}$" for name in names)
        code = subprocess.run(["cargo", "mutants", "-F", pattern, "-j", "2"]).returncode
    out.mkdir(exist_ok=True)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True)
    (out / "commit").write_text(commit)
    outcomes = out / "outcomes.json"
    tried = set()
    if outcomes.exists():
        for outcome in json.loads(outcomes.read_text())["outcomes"]:
            mutant = outcome["scenario"]
            if isinstance(mutant, dict) and "Mutant" in mutant:
                tried.add(mutant["Mutant"]["name"])
    not_tried = [name for name in names if name not in tried]
    (out / "not-tried.txt").write_text("".join(name + "\n" for name in not_tried))
    print(f"{len(names)} named, {len(not_tried)} not tried, cargo-mutants exited with {code}")
    # 2: a mutant was missed; 3: a test ran until its timeout, which sees the mutant
    missed = (out / "missed.txt").exists() and (out / "missed.txt").read_text().strip()
    if not_tried or code not in (0, 2, 3) or missed:
        sys.exit(1)


main()
