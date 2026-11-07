#!/bin/sh
# Write the dictionaries of the fuzz targets that read octets, from the
# tables of the crate: fuzz/nas-5gs.dict and fuzz/nas-eps.dict. Each has the
# header of each message type, and each optional IE of the message tables
# whole: its IEI, the length indicator of its format and the least value
# that its table allows, of zeros, or its IEI and length indicator alone
# where that value is long. The fuzzer inserts them, so that it writes IEs
# that a decoder reads from their first octet. Run it from the root of the
# repository; the continuous integration checks that the files are those it
# writes.
set -eu

# The message types of the `TryFrom<u8>` of `$2` in `$1`, as
# `code name` lines, in hexadecimal.
types() {
    awk -v impl="impl TryFrom<u8> for $2 " '
        index($0, impl) == 1 { inside = 1; next }
        inside && /^}/ { inside = 0 }
        inside && /=> (Ok\()?(Self|[A-Za-z0-9]+)::[A-Za-z0-9]+/ {
            code = $1
            name = $0
            sub(/.*::/, "", name)
            sub(/[^A-Za-z0-9].*/, "", name)
            if (code ~ /^0x/) { code = substr(code, 3) } else { code = sprintf("%02x", code) }
            printf "%s %s\n", tolower(code), name
        }
    ' "$1"
}

# The format of each IE type of the files, as `type format` lines.
formats() {
    awk '
        /^nas_ie_[a-z0-9_]*!\($/ { format = $0; sub(/^nas_ie_/, "", format); sub(/!.*/, "", format); next }
        format != "" && /^ *\/\/\// { next }
        format != "" { name = $1; sub(/[,)].*/, "", name); print name, format; format = "" }
    ' "$@"
}

# The optional IEs of the message tables of `$1`: `iei field type least`.
ies() {
    sed -n 's/^ *\(0x[0-9A-Fa-f][0-9A-Fa-f]\( | 0x[0-9A-Fa-f][0-9A-Fa-f]\)*\) => \([a-z0-9_]*\): \([A-Za-z0-9]*\).*{wire_len \([0-9]*\),.*/\1 \3 \4 \5/p' "$1" |
        awk '{ n = split($0, f, " "); for (i = 1; i < n - 2; i++) if (f[i] ~ /^0x/) print tolower(substr(f[i], 3)), f[n - 2], f[n - 1], f[n] }'
}

# A dictionary: `$1` the system, then the files of its tables.
dictionary() {
    system=$1 messages=$2 types=$3
    echo "# The message types and IEs of the tables of src/nas_$system: written by fuzz/dict.sh."
    case $system in
    5gs)
        types src/nas_5gs/message_types.rs Nas5gmmMessageType | while read -r code name; do
            printf '%s="\\x7e\\x00\\x%s"\n' "$name" "$code"
        done
        types src/nas_5gs/message_types.rs Nas5gsmMessageType | while read -r code name; do
            printf '%s="\\x2e\\x05\\x01\\x%s"\n' "$name" "$code"
        done
        ;;
    eps)
        types src/nas_eps/message_types.rs NasEmmMessageType | while read -r code name; do
            printf '%s="\\x07\\x%s"\n' "$name" "$code"
        done
        types src/nas_eps/message_types.rs NasEsmMessageType | while read -r code name; do
            printf '%s="\\x52\\x01\\x%s"\n' "$name" "$code"
        done
        ;;
    esac
    formats=$(formats "$types" src/common/types.rs)
    ies "$messages" | sort -u -k1,2 | while read -r iei field type least; do
        format=$(printf '%s\n' "$formats" | awk -v type="$type" '$1 == type { print $2; exit }')
        case $format in
        "") case $iei in
            [89a-f]?) format=tv1 ;;
            7?) if [ "$system" = 5gs ]; then format=lve; else format=lv; fi ;;
            *) format=lv ;;
            esac ;;
        esac
        case $format in
        tv1) header=1 indicator="" ;;
        lve) header=3 indicator=$(printf '\\x%02x\\x%02x' $(((least - 3) / 256)) $(((least - 3) % 256))) ;;
        lv) header=2 indicator=$(printf '\\x%02x' $((least - 2))) ;;
        *) header=1 indicator="" ;;
        esac
        value=$((least - header))
        zeros=""
        if [ "$value" -gt 0 ] && [ "$value" -le 16 ]; then
            zeros=$(i=0; while [ "$i" -lt "$value" ]; do printf '\\x00'; i=$((i + 1)); done)
        fi
        printf '%s="\\x%s%s%s"\n' "$field" "$iei" "$indicator" "$zeros"
    done
}

dictionary 5gs src/nas_5gs/messages.rs src/nas_5gs/types.rs > fuzz/nas-5gs.dict
dictionary eps src/nas_eps/messages.rs src/nas_eps/types.rs > fuzz/nas-eps.dict
