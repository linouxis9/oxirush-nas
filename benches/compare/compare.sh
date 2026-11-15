#!/bin/sh
# The table of the comparison in benches/README.md: oxirush-nas beside free5GC's nas,
# Open5GS, packet-dissector and pycrate, on the messages of tests/fixtures
# that each of them reads, and for encoding writes back to the same octets.
#
#   benches/compare/compare.sh [core]
#
# The others are fetched at the versions that this directory pins: Cargo
# fetches packet-dissector 0.6.1 (Cargo.toml), go fetches free5gc/nas v1.2.3
# (free5gc/go.mod), git fetches Open5GS v2.8.0 and meson builds its NAS
# libraries, pip installs pycrate 0.8.1 in an environment of its own. They
# are kept in target/compare beside this script, or under CARGO_TARGET_DIR.
#
# Each implementation of a case runs once a round, in turns, ROUNDS rounds
# (10 by default), on one core (3 by default), so that a busy moment of the
# machine falls on all of them. The table has the median time of the rounds
# and their spread, the lowest and the highest; the time against oxirush-nas
# is the ratio of the medians, given only where the two spreads do not
# overlap. Cycles and instructions per message are the median of those of
# perf stat, between a run of N passes over the messages and one of 2N in
# each round, which leaves out the start of each program: PERF="sudo -n
# perf" where the kernel keeps perf from users (kernel.perf_event_paranoid
# above 2). Needs cargo,
# go, git, meson, ninja, a C compiler and the libraries that the meson setup
# of Open5GS asks for, and python3 with venv.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fixtures=$here/../../tests/fixtures
core=${1:-3}
rounds=${ROUNDS:-10}
perf=${PERF:-perf}
target=${CARGO_TARGET_DIR:-$here/target}
out=$target/compare
mkdir -p "$out"

# The programs
cargo build --quiet --release --manifest-path "$here/Cargo.toml"
rust=$target/release/oxirush-nas-compare
(cd "$here/free5gc" && go build -buildvcs=false -o "$out/free5gc-nas" .)
[ -d "$out/open5gs" ] ||
	git clone --quiet --depth 1 --branch v2.8.0 https://github.com/open5gs/open5gs "$out/open5gs"
[ -d "$out/open5gs-build" ] ||
	meson setup --buildtype=release "$out/open5gs-build" "$out/open5gs" > "$out/meson-setup.log"
meson compile -C "$out/open5gs-build" ogsnas-5gs ogsnas-eps > "$out/meson-compile.log"
o=$out/open5gs b=$out/open5gs-build
for system in 5gs eps; do
	libraries="$b/lib/nas/$system:$b/lib/nas/common:$b/lib/proto:$b/lib/core:$b/lib/crypt"
	cc -O2 -std=gnu99 -DOGS_$(echo $system | tr a-z A-Z) -D_FILE_OFFSET_BITS=64 \
		-I"$o/lib" -I"$b/lib" -I"$o/lib/core" -I"$b/lib/core" -I"$o/lib/proto" -I"$b/lib/proto" \
		-I"$o/lib/crypt" -I"$b/lib/crypt" -I"$o/lib/nas/common" -I"$b/lib/nas/common" \
		-I"$o/lib/nas/$system" -I"$b/lib/nas/$system" -o "$out/open5gs-nas-$system" "$here/open5gs/nas.c" \
		-L"$b/lib/nas/$system" -L"$b/lib/nas/common" -L"$b/lib/proto" -L"$b/lib/core" \
		-logsnas-$system -logsnas-common -logsproto -logscore -Wl,-rpath,"$libraries"
done
[ -x "$out/venv/bin/python" ] || python3 -m venv "$out/venv"
"$out/venv/bin/pip" install --quiet pycrate==0.8.1

# The command of an implementation for a system
program() { # implementation system
	case $1 in
	oxirush-nas | packet-dissector) echo "$rust $1" ;;
	free5gc) echo "$out/free5gc-nas" ;;
	open5gs) echo "$out/open5gs-nas-$2" ;;
	pycrate) echo "$out/venv/bin/python -I $here/pycrate_nas.py" ;;
	esac
}
implementations() { # system
	case $1 in
	5gs) echo "oxirush-nas free5gc open5gs packet-dissector pycrate" ;;
	eps) echo "oxirush-nas open5gs packet-dissector pycrate" ;;
	esac
}
name() {
	case $1 in
	oxirush-nas) echo "oxirush-nas" ;;
	free5gc) echo "free5GC nas v1.2.3" ;;
	open5gs) echo "Open5GS v2.8.0" ;;
	packet-dissector) echo "packet-dissector 0.6.1" ;;
	pycrate) echo "pycrate 0.8.1" ;;
	esac
}

# The messages that every implementation decodes, among the plain ones of
# the fixtures, and those that every implementation with an encoder writes
# back to the same octets.
for system in 5gs eps; do
	set --
	for implementation in $(implementations $system); do
		$(program $implementation $system) check $system "$fixtures/nas-$system.tsv" \
			> "$out/check-$implementation-$system.tsv" 2> /dev/null
		set -- "$@" "$out/check-$implementation-$system.tsv"
	done
	awk -F'\t' -v files=$# -v kind=$system '
		FNR == 1 { file++ }
		file <= files { decodes[$1] += $2; encodes[$1] += ($3 == "1"); writers[$1] += ($3 != "-"); next }
		/^#/ { next }
		{
			first = substr($2, 1, 2); second = substr($2, 3, 2)
			plain = kind == "5gs" ? (first == "2e" || (first == "7e" && substr(second, 2, 1) == "0")) \
				: (first ~ /^0[27]$/ || substr(first, 2, 1) == "2")
			if (plain && decodes[$1] == files) print > (out "/decode-" kind ".tsv")
			if (plain && decodes[$1] == files && encodes[$1] == writers[$1]) print > (out "/encode-" kind ".tsv")
		}' out="$out" "$@" "$fixtures/nas-$system.tsv"
done

# Cycles and instructions per message, between a run of N passes and one
# of 2N.
counted() { # command passes messages
	for passes in "$2" $(($2 * 2)); do
		$perf stat -x, -e cycles:u,instructions:u -o "$out/perf" taskset -c "$core" $1 "$passes" > /dev/null 2>&1
		awk -F, '$3 ~ /^(cycles|instructions)/ { printf "%s ", $1 }' "$out/perf"
		echo
	done | awk -v n=$(($2 * $3)) 'NR == 1 { c = $1; i = $2 } NR == 2 { printf "%.0f %.0f", ($1 - c) / n, ($2 - i) / n }'
}

rows=$out/rows
: > "$rows"
echo "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'), core $core, $rounds rounds; load before: $(cut -d' ' -f1-3 /proc/loadavg)"
round=0
while [ "$round" -lt "$rounds" ]; do
	for operation in decode encode; do
		for system in 5gs eps; do
			messages=$out/$operation-$system.tsv
			count=$(wc -l < "$messages")
			for implementation in $(implementations $system); do
				[ $operation = encode ] && [ $implementation = packet-dissector ] && continue
				passes=20000
				[ $implementation = pycrate ] && passes=100
				command="$(program $implementation $system) run $operation $system $messages"
				# ns, allocations, octets allocated, peak KiB, cycles, instructions
				set -- $(taskset -c "$core" $command $passes 2> /dev/null) $(counted "$command" $passes $count 2> /dev/null || echo - -)
				echo "$operation|$system|$implementation|$1|$2|$3|$4|$5|$6" >> "$rows"
			done
		done
	done
	round=$((round + 1))
done

echo
echo "| Operation | | ns | Lowest and highest | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Time against oxirush-nas |"
echo "|---|---|---|---|---|---|---|---|---|---|"
for operation in decode encode; do
	for system in 5gs eps; do
		count=$(wc -l < "$out/$operation-$system.tsv")
		for implementation in $(implementations $system); do
			[ $operation = encode ] && [ $implementation = packet-dissector ] && continue
			row=""
			[ $implementation = oxirush-nas ] && row="$operation, $(echo $system | sed 's/5gs/5GS/; s/eps/EPS/'), $count messages"
			awk -F'|' -v operation="$operation" -v wanted_system="$system" -v implementation="$implementation" -v row="$row" -v name="$(name $implementation)" '
				function median(list, count,    sorted, i, j, t) {
					for (i = 1; i <= count; i++) sorted[i] = list[i]
					for (i = 2; i <= count; i++)
						for (j = i; j > 1 && sorted[j - 1] + 0 > sorted[j] + 0; j--) {
							t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t
						}
					return count % 2 ? sorted[(count + 1) / 2] : (sorted[count / 2] + sorted[count / 2 + 1]) / 2
				}
				$1 != operation || $2 != wanted_system { next }
				$3 == "oxirush-nas" { ours[++o] = $4; if (o == 1 || $4 < ourlow) ourlow = $4; if (o == 1 || $4 > ourhigh) ourhigh = $4 }
				$3 == implementation {
					n++; ns[n] = $4; allocations[n] = $5; octets[n] = $6; peak[n] = $7; cycles[n] = $8; instructions[n] = $9
					if (n == 1 || $4 < low) low = $4
					if (n == 1 || $4 > high) high = $4
				}
				END {
					m = median(ns, n)
					ratio = ""
					if (implementation != "oxirush-nas")
						ratio = (low > ourhigh || high < ourlow) ? sprintf("%.2f", m / median(ours, o)) : "spreads overlap"
					format = m < 1000 ? "%.1f" : "%.0f"
					printf "| %s | %s | " format " | " format " to " format " | %s | %s | %s | %s | %.1f MiB | %s |\n", row, name, m, low, high,
						cycles[1] == "-" ? "-" : sprintf("%.0f", median(cycles, n)),
						instructions[1] == "-" ? "-" : sprintf("%.0f", median(instructions, n)),
						allocations[1] == "-" ? "" : median(allocations, n), octets[1] == "-" ? "" : median(octets, n), median(peak, n) / 1024, ratio
				}' "$rows"
		done
	done
done
echo
echo "load after: $(cut -d' ' -f1-3 /proc/loadavg)"
