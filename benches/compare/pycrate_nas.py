# pycrate's NAS, as compare.sh runs it, with the interpreter of the
# environment that compare.sh makes:
#
#   python3 -I pycrate_nas.py check <5gs|eps> <fixtures>
#   python3 -I pycrate_nas.py run <decode|encode> <5gs|eps> <messages> <passes>
#
# check prints, for each message of a file of the fixtures, its name, whether
# pycrate decodes it (1 or 0), and whether it encodes what it decoded to the
# same octets. run does the operation on each message of the file, passes
# times, and prints the nanoseconds per message, `-` for the allocations and
# the octets allocated, which the interpreter does not count, and the peak
# memory of the program in KiB. An EPS message is read as one from the
# network, then as one from a UE.
import contextlib
import io
import resource
import sys
import time

with contextlib.redirect_stdout(io.StringIO()):
    from pycrate_mobile.NAS5G import parse_NAS5G
    from pycrate_mobile.NASLTE import parse_NASLTE_MO, parse_NASLTE_MT


def messages(path):
    with open(path) as lines:
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            name, octets = line.rstrip("\n").split("\t", 1)
            yield name, bytes.fromhex(octets.strip())


def parser(system, octets):
    """The parser that reads the message without an error, if one does."""
    readers = [parse_NAS5G] if system == "5gs" else [parse_NASLTE_MT, parse_NASLTE_MO]
    for read in readers:
        try:
            message, error = read(octets)
        except Exception:
            continue
        if error == 0 and message is not None:
            return read, message
    return None, None


def check(system, path):
    for name, octets in messages(path):
        read, message = parser(system, octets)
        encodes = 0
        if message is not None:
            try:
                encodes = int(message.to_bytes() == octets)
            except Exception:
                pass
        print(f"{name}\t{int(message is not None)}\t{encodes}")


def run(operation, system, path, passes):
    readers = []
    for _, octets in messages(path):
        read, message = parser(system, octets)
        readers.append((read, octets, message))
    if operation == "decode":
        def one_pass():
            for read, octets, _ in readers:
                read(octets)
    else:
        def one_pass():
            for _, _, message in readers:
                message.to_bytes()
    one_pass()
    start = time.perf_counter_ns()
    for _ in range(passes):
        one_pass()
    elapsed = time.perf_counter_ns() - start
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"{elapsed / (passes * len(readers)):.1f} - - {peak}")


def main(arguments):
    usage = "pycrate_nas.py (check <5gs|eps> <fixtures> | run <decode|encode> <5gs|eps> <messages> <passes>)"
    if len(arguments) == 3 and arguments[0] == "check":
        with contextlib.redirect_stderr(io.StringIO()):
            check(arguments[1], arguments[2])
    elif len(arguments) == 5 and arguments[0] == "run":
        run(arguments[1], arguments[2], arguments[3], int(arguments[4]))
    else:
        sys.exit(usage)


if __name__ == "__main__":
    main(sys.argv[1:])
