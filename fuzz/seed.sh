#!/bin/sh
# Start the corpus of each target that reads octets from the messages of the
# crate: one file for each message of tests/fixtures and of fuzz/seeds-*.tsv,
# for each lab message of tests/fixtures/captured.tsv on the wire and plain,
# and for each initial NAS message of tests/fixtures/initial-nas.tsv,
# complete and protected. The targets that build their input with
# `arbitrary` pick the messages of the fixtures themselves, and need none.
# Run it from the root of the repository.
set -eu
tab="$(printf '\t')"

# The message of the octets $3, under the name $2, for the targets of the
# system $1.
seed() {
    for target in decode view; do
        mkdir -p "fuzz/corpus/${target}_$1"
        printf '%s' "$3" | xxd -r -p > "fuzz/corpus/${target}_$1/$2"
    done
}

for system in 5gs eps; do
    cat "tests/fixtures/nas-$system.tsv" "fuzz/seeds-$system.tsv" | grep -v '^#' | while IFS="$tab" read -r name octets; do
        seed "$system" "$name" "$octets"
    done
done
grep -v '^#' tests/fixtures/captured.tsv | awk -F "$tab" '{ print $1, NR, $9, $10 }' | while read -r system row wire plain; do
    seed "$system" "captured-$row" "$wire"
    seed "$system" "captured-$row-plain" "$plain"
done
grep -v '^#' tests/fixtures/initial-nas.tsv | while IFS="$tab" read -r name _ _ _ _ complete protected; do
    seed 5gs "initial-$name" "$complete"
    seed 5gs "initial-$name-protected" "$protected"
done
