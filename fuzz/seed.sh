#!/bin/sh
# Start the corpus of each target from the fixtures of the crate: one file
# for each message of tests/fixtures. Run it from the root of the repository.
set -eu
for system in 5gs eps; do
    mkdir -p "fuzz/corpus/decode_$system" "fuzz/corpus/view_$system"
    grep -v '^#' "tests/fixtures/nas-$system.tsv" | while IFS="$(printf '\t')" read -r name octets; do
        printf '%s' "$octets" | xxd -r -p > "fuzz/corpus/decode_$system/$name"
        cp "fuzz/corpus/decode_$system/$name" "fuzz/corpus/view_$system/$name"
    done
done
