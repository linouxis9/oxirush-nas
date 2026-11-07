#!/usr/bin/env python3
"""Compare Wireshark's reading of NAS messages with this crate's, field by field.

Inputs:
  --corpus   rows of system (5gs or eps), ..., octets in hexadecimal, by tabs
  --crate    one line of JSON a row: what the crate read (tests/wireshark.rs)
  --mapping  the table of Wireshark's fields and the crate's paths (mapping.tsv)
  --known    the differences that were triaged as Wireshark's or the
             specification's, which do not fail the run (known.tsv)

tshark dissects each message through a user link type bound to `nas-5gs` or
`nas-eps`, and writes PDML. Each message is then one of:

  agree          both read it, and every field that the mapping compares is
                 the same, with the same IEs of the same octets;
  both-refuse    the crate refuses it and Wireshark finds it malformed;
  ws-malformed   the crate reads it, Wireshark finds it malformed or reports
                 an expert error;
  crate-refuses  Wireshark reads it without an error, the crate refuses it;
  differs        both read it and at least one field differs;
  ciphered       its body is ciphered: neither reads it without keys.

Outputs in --output: report.json (each message, its class and each
difference), summary.txt, coverage.tsv (each field that Wireshark showed,
with what it was compared to or why not) and the PDML of each system.
The run fails when a difference is not in --known, or a tshark other than
the pinned one is used without --any-tshark.
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path

PINNED = "TShark (Wireshark) 4.6.4"
# The dissector of each system. `nas-eps_plain`, not `nas-eps`: the entry
# of S1AP takes a plain ESM message for one that should have been protected
# and reads its EPS bearer identity as a security header type.
LINK = {"5gs": (147, "nas-5gs"), "eps": (148, "nas-eps_plain")}
PROTOCOL = {"5gs": "nas-5gs", "eps": "nas-eps"}
WRAPPERS = ("Plain NAS 5GS Message", "Security protected NAS 5GS message")


class Node:
    """A field of PDML: its name, what it shows, where it is and its children."""

    __slots__ = ("name", "show", "showname", "pos", "size", "value", "children")

    def __init__(self, element):
        self.name = element.get("name", "")
        self.show = element.get("show", "")
        self.showname = element.get("showname", "")
        self.pos = int(element.get("pos", "0"))
        self.size = int(element.get("size", "0"))
        self.value = element.get("value", "")
        self.children = [Node(child) for child in element if child.tag in ("field", "proto")]

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def label(self):
        """What a coded value means, from `Name: meaning (code)`."""
        text = self.showname.split(" = ", 1)[-1] if " = " in self.showname else self.showname
        text = text.split(": ", 1)[1] if ": " in text else text
        return re.sub(r"\s*\((?:0x)?[0-9a-fA-F]+\)$", "", text).strip()


def normal(label):
    """An IE's label without the value that Wireshark adds to some: `Mobile identity - IMSI (001010123456789)`."""
    while True:
        stripped = re.sub(r"\s*-?\s*\([^()]*\)$", "", label)
        if stripped == label or not stripped:
            return label
        label = stripped


def kebab(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


# ---------------------------------------------------------------------------
# The mapping table

class Mapping:
    """mapping.tsv: what Wireshark shows, and what of the crate it is compared to.

    Rows, by tabs: kind, system, wireshark, crate, compare, note.
      ie      the label of an IE in Wireshark's tree -> the crate's IE name
      bare    a field that Wireshark shows in the message for a whole IE
              (a half octet) -> the crate's IE name
      header  a field of a header -> a code of the crate's reading
      field   in an IE whose type is `wireshark` (the label before " - "),
              a field -> a path in the crate's value, compared as `compare`
      message the label of a message type -> the crate's name of it
      value   a coded value: `field=label` -> the crate's name of it
      none    a field that is compared to nothing, with why (`crate` is the
              IE type, or * for any)
    """

    def __init__(self, path):
        self.ie = {}
        self.bare = {}
        self.header = {}
        self.fields = collections.defaultdict(list)
        self.messages = {}
        self.values = {}
        self.none = {}
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            columns = (line.split("\t") + [""] * 6)[:6]
            kind, system, wireshark, crate, compare, note = columns
            if kind == "ie":
                self.ie[(system, wireshark)] = crate
            elif kind == "bare":
                self.bare[(system, wireshark)] = crate
            elif kind == "header":
                self.header[(system, wireshark)] = (crate, compare)
            elif kind == "field":
                self.fields[(system, wireshark)].append((crate, compare, note))
            elif kind == "message":
                self.messages[(system, wireshark)] = crate
            elif kind == "value":
                field, _, label = wireshark.partition("=")
                self.values[(system, f"{field}={kebab(label)}")] = crate
            elif kind == "none":
                self.none[(system, crate, wireshark)] = compare or note
            else:
                raise ValueError(f"{path}:{number}: unknown kind {kind!r}")

    def field_rows(self, system, kind_label):
        return self.fields.get((system, kind_label), [])

    def is_none(self, system, kind_label, field):
        return (system, kind_label, field) in self.none or (system, "*", field) in self.none


# ---------------------------------------------------------------------------
# tshark

def dissect(system, rows, output):
    """The PDML packet of each row, in order."""
    dlt, dissector = LINK[system]
    protocol = PROTOCOL[system]
    dump = output / f"{system}.txt"
    with dump.open("w") as text:
        for row in rows:
            octets = row["octets"]
            for offset in range(0, len(octets), 32):
                text.write(f"{offset:06x} {octets[offset:offset + 32].hex(' ')}\n")
            text.write("\n")
    pcap = output / f"{system}.pcap"
    subprocess.run(["text2pcap", "-q", "-l", str(dlt), str(dump), str(pcap)], check=True, capture_output=True)
    pdml = output / f"{system}.pdml"
    preference = f'uat:user_dlts:"User {dlt - 147} (DLT={dlt})","{dissector}","0","","0",""'
    # The capture goes to tshark through a pipe, and its PDML comes back
    # through another: tshark may refuse a path, or a file as its standard
    # input or output, where the file is readable and writable.
    process = subprocess.Popen(["tshark", "-n", "-r", "-", "-o", preference, "-T", "pdml"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    feeder = threading.Thread(target=feed, args=(process.stdin, pcap.read_bytes()))
    feeder.start()
    errors = []
    reader = threading.Thread(target=lambda: errors.append(process.stderr.read()))
    reader.start()
    with pdml.open("wb") as sink:
        while chunk := process.stdout.read(1 << 20):
            sink.write(chunk)
    feeder.join()
    reader.join()
    if process.wait() != 0:
        raise RuntimeError(f"tshark failed ({process.returncode}): {errors[0].decode().strip()}")
    packets = []
    for _, element in ET.iterparse(pdml, events=("end",)):
        if element.tag != "packet":
            continue
        proto = None
        malformed = False
        experts = []
        for child in element:
            name = child.get("name")
            if name == protocol:
                proto = Node(child)
            elif name == "_ws.malformed":
                malformed = True
        for expert in element.iter("field"):
            if expert.get("name") == "_ws.expert":
                fields = {f.get("name"): f.get("show", "") for f in expert}
                experts.append({"message": fields.get("_ws.expert.message", ""),
                                "severity": int(fields.get("_ws.expert.severity", "0") or 0)})
        packets.append({"proto": proto, "malformed": malformed, "experts": experts})
        element.clear()
    if len(packets) != len(rows):
        raise AssertionError(f"{system}: {len(rows)} messages gave {len(packets)} packets")
    return packets


def feed(pipe, octets):
    with pipe:
        pipe.write(octets)


EXPERT_ERROR = 0x00800000


# ---------------------------------------------------------------------------
# The comparison of one message

class Comparison:
    def __init__(self, mapping, system, octets):
        self.mapping = mapping
        self.system = system
        self.octets = octets
        self.differences = []
        self.coverage = collections.Counter()
        self.proposals = collections.Counter()
        self.pairs = None  # (system, IE type, Wireshark fields, crate value) of each IE, when kept
        self.unknown = []  # the IEs of the message that the crate keeps unread, with where they are

    def differ(self, where, what, wireshark, crate):
        self.differences.append({"where": where, "what": what, "wireshark": wireshark, "crate": crate})

    # -- Wireshark's items of a message -----------------------------------

    def items(self, children, crate_ies):
        """The headers, IEs and bare fields of the children of a message."""
        items = []
        header = True  # until the message type: a field of a header is one of the header
        for node in children:
            if node.name == "":
                items.append(("ie", node))
            elif header and (self.system, node.name) in self.mapping.header:
                items.append(("header", node))
                if node.name in MESSAGE_TYPES:
                    header = False
            elif (self.system, node.name) in self.mapping.bare:
                key = self.mapping.bare[(self.system, node.name)]
                if "|" in key:
                    candidates = key.split("|")
                    key = next((k for k in candidates if k in crate_ies), candidates[0])
                if items and items[-1][0] == "bare" and items[-1][2] == key and items[-1][1][-1].pos == node.pos:
                    items[-1][1].append(node)
                else:
                    items.append(("bare", [node], key))
            elif node.name.startswith("_ws."):
                continue
            else:
                items.append(("other", node))
        return items

    # -- octets ----------------------------------------------------------

    @staticmethod
    def bits(node):
        """The bits of its octet that a field of one octet shows, or None."""
        match = re.match(r"^([01.]{4}) ([01.]{4}) = ", node.showname)
        if not match:
            return None
        pattern = match.group(1) + match.group(2)
        return {7 - i for i, c in enumerate(pattern) if c != "."}

    def half(self, nodes):
        """'high' or 'low' when the fields of nodes all lie in one half of an octet."""
        used = set()
        for node in nodes:
            for field in node.walk():
                if field is node and field.name == "":
                    continue
                if field.name.endswith("elem_id") or field.name.startswith("_ws.") or "spare" in field.name:
                    if field.name.endswith("elem_id"):
                        return "low"  # a type 1 IE: the IEI is the high half
                    continue
                if field.name == "":
                    continue
                bits = self.bits(field)
                if bits is None:
                    return None
                used |= bits
        if used and used <= {7, 6, 5, 4}:
            return "high"
        if used and used <= {3, 2, 1, 0}:
            return "low"
        return None

    def ws_value(self, node):
        """The octets of the value of an IE node, or its half octet: ('octets', bytes) or ('half', int)."""
        children = node.children
        start, end = node.pos, node.pos + node.size
        iei = next((c for c in children if c.name.endswith("elem_id")), None)
        if node.size == 1 and (iei is None or len(iei.value) == 1):
            half = self.half([node])
            if half is not None:
                octet = self.octets[start]
                return ("half", octet >> 4 if half == "high" else octet & 0x0F)
        if iei is not None and iei.pos == start and len(iei.value) == 2:
            start += 1
        length = next((c for c in children if c.name == "gsm_a.len" and c.pos == start), None)
        if length is not None:
            start += length.size
        return ("octets", self.octets[start:end])

    def compare_octets(self, where, wireshark, entry):
        kind, value = wireshark
        crate = entry.get("octets")
        if crate is None:
            self.differ(where, "no octets in the crate's view", "", "")
            return
        crate = bytes.fromhex(crate)
        if kind == "half":
            # The crate has a half octet in bits 4 to 1, with the spare half
            # octet beside it in bits 8 to 5 when the IE has one
            if len(crate) != 1 or crate[0] & 0x0F != value:
                self.differ(where, "half octet", f"{value:x}", crate.hex())
        elif crate != value:
            self.differ(where, "octets", value.hex(), crate.hex())

    # -- values ----------------------------------------------------------

    def compare_values(self, where, kind_label, node_fields, value):
        rows = self.mapping.field_rows(self.system, kind_label)
        mapped = {}
        for path, compare, _ in rows:
            for field in compare_fields(compare):
                mapped.setdefault(field, []).append((path, compare))
        compared = set()
        for path, compare, _ in rows:
            if run_compare(self, where, path, compare, node_fields, value):
                compared.update(compare_fields(compare))
        for field in {f.name for f in node_fields}:
            if field == "" or field.startswith("_ws."):
                continue
            if field in compared:
                state = "compared"
            elif field in mapped:
                state = "mapped, no value of the crate here"
            elif self.mapping.is_none(self.system, kind_label, field):
                state = "none"
            else:
                state = "unlisted"
            self.coverage[(self.system, kind_label, field, state)] += 1
        if self.pairs is not None:
            self.pairs.append((self.system, kind_label, node_fields, value))

    # -- a message -------------------------------------------------------

    def message(self, where, children, view, codes, layer=0):
        """Compare the message whose Wireshark children are `children` with its view.

        `codes` are the codes of the crate's headers, the outer one first, for
        the message at the top; `layer` is the header that `children` start
        with. A message inside an IE has no codes: its header fields are
        compared with the header values of its view.
        """
        crate_ies = {key: entry for key, entry in view.items()
                     if isinstance(entry, dict) and "octets" in entry}
        items = self.items(children, crate_ies)
        # The IEs that the crate keeps unread in this message, each where it is
        outer = self.unknown
        self.unknown = []
        if children:
            start = min(c.pos for c in children)
            end = max(c.pos + c.size for c in children)
            unread = ((view.get("unknown-ies") or {}).get("value") or "").split()
            for ie in unread:
                octets = bytes.fromhex(ie)
                position = self.octets.find(octets, start, end)
                self.unknown.append({"iei": octets[0], "data": octets[1:].hex(), "matched": False,
                                     "pos": position if position >= 0 else None})
                if position >= 0:
                    start = position + len(octets)
        seen = collections.Counter()
        stopped = False
        for item in items:
            kind = item[0]
            if kind == "header":
                node = item[1]
                name, compare = self.mapping.header[(self.system, node.name)]
                self.coverage[(self.system, "(header)", node.name, "compared")] += 1
                self.compare_header(where, node, name, compare, codes, layer, view)
                if node.name.endswith(".seq_no"):
                    layer += 1
                continue
            if kind == "other":
                node = item[1]
                if self.mapping.is_none(self.system, "(message)", node.name):
                    self.coverage[(self.system, "(message)", node.name, "none")] += 1
                else:
                    self.coverage[(self.system, "(message)", node.name, "unlisted")] += 1
                    self.differ(where, "a field of the message that the mapping does not list", node.name, "")
                continue
            if kind == "bare":
                nodes, key = item[1], item[2]
                label = key
                node = nodes[0]
                ws = ("half", None)
                half = self.half(nodes)
                if half is not None:
                    octet = self.octets[node.pos]
                    ws = ("half", octet >> 4 if half == "high" else octet & 0x0F)
                fields = [f for n in nodes for f in n.walk()]
                kind_label = "(bare) " + key
            else:
                node = item[1]
                if node.show.startswith(EXTRANEOUS):
                    # Wireshark reads no further: the first octet is an IEI that
                    # it does not know, or octets that are no IE
                    iei = self.octets[node.pos] if node.pos < len(self.octets) else None
                    unread = self.unread_at(node.pos, after=True)
                    what = ("Wireshark stops at an IE that the crate does not read either" if unread
                            else "Wireshark stops where the crate reads on")
                    self.differ(where, what, f"{iei:02x}" if iei is not None else "", " ".join(unread))
                    stopped = True
                    continue
                if node.show in WRAPPERS:
                    self.differ(where, "a message inside a message", node.show, "")
                    continue
                label = normal(node.show)
                key = self.mapping.ie.get((self.system, label))
                if key is not None and "|" in key:
                    # A label that Wireshark gives to the IEs of one type in
                    # several messages: the one of them that this message has
                    candidates = key.split("|")
                    present = [k for k in candidates if k in crate_ies and not seen[k]]
                    key = present[0] if present else candidates[0]
                if key is None:
                    unread = self.unread_at(node.pos)
                    if unread:
                        self.differ(where, "an IE that the crate keeps unread and Wireshark reads", label, unread[0])
                        continue
                    self.coverage[(self.system, label, "(ie)", "unlisted")] += 1
                    self.differ(where, "an IE that the mapping does not name", label, "")
                    self.propose(label, self.ws_value(node), crate_ies)
                    continue
                ws = self.ws_value(node)
                fields = list(node.walk())[1:]
                kind_label = label.split(" - ")[0]
            seen[key] += 1
            here = f"{where}/{key}"
            if seen[key] > 1:
                self.differ(here, "an IE that Wireshark shows again", label, "")
                continue
            entry = crate_ies.get(key)
            if entry is None:
                unread = self.unread_at(node.pos)
                if unread:
                    self.differ(here, "an IE that the crate keeps unread and Wireshark reads", label, unread[0])
                else:
                    self.differ(here, "an IE that only Wireshark shows", label, "")
                continue
            if ws[1] is not None:
                self.compare_octets(here, ws, entry)
            if "value" not in entry and self.mapping.field_rows(self.system, kind_label) and any(
                    f.name in compare_fields(c) for _, c, _ in self.mapping.field_rows(self.system, kind_label) for f in fields):
                # Wireshark reads values that the crate's view does not show:
                # it has the octets of the IE alone
                self.differ(here, "the crate shows the octets alone of an IE whose values Wireshark reads", label, entry.get("octets", ""))
            nested = [c for c in fields if c.name == "" and c.show in WRAPPERS]
            if nested or any(c.name in NESTED for c in fields):
                self.nested(here, node, entry)
            elif "value" in entry:
                self.compare_values(here, kind_label, fields, entry["value"])
        for key, entry in crate_ies.items():
            if key not in seen:
                what = "an IE after where Wireshark stopped" if stopped else "an IE that only the crate shows"
                self.differ(f"{where}/{key}", what, "", entry.get("octets", ""))
        for ie in self.unknown:
            if not ie["matched"]:
                self.differ(where, "an IE that the crate keeps unread", "", f"{ie['iei']:02x} {ie['data']}")
        self.unknown = outer

    def unread_at(self, position, after=False):
        """The IEs that the crate keeps unread at `position` (and after it), each as `iei data`."""
        found = []
        for ie in self.unknown:
            octets = bytes([ie["iei"]]) + bytes.fromhex(ie["data"])
            # Where the octets of the IE are at `position`, or after it: the
            # first place that the octets were found at may be another
            here = self.octets.startswith(octets, position)
            later = after and self.octets.find(octets, position) >= 0
            if not ie["matched"] and (here or later):
                ie["matched"] = True
                found.append(f"{ie['iei']:02x} {ie['data']}")
                if not after:
                    break
        return found

    def propose(self, label, ws, crate_ies):
        """The crate's IEs that an unnamed Wireshark IE could be: same octets, or same name."""
        label = normal(label)
        names = {kebab(label), kebab(label.split(" - ")[-1])}
        for key, entry in crate_ies.items():
            octets = bytes.fromhex(entry.get("octets") or "")
            same = (ws[0] == "half" and len(octets) == 1 and octets[0] == ws[1]) or (ws[0] == "octets" and octets == ws[1])
            if same or key in names:
                self.proposals[(self.system, label, key, "octets" if same else "name")] += 1

    def compare_header(self, where, node, name, compare, codes, layer, view):
        if compare == "none":
            return
        if codes is not None:
            if compare == "if-kept" and layer < len(codes) and name not in codes[layer]:
                return
            if layer >= len(codes) or name not in codes[layer]:
                self.differ(f"{where}/{name}", "a header field that the crate does not have", node.show, "")
                return
            value = codes[layer][name]
        else:
            value = (view.get(name) or {}).get("value")
            if not isinstance(value, int) or isinstance(value, bool):
                return
        wireshark = as_number(node.show)
        if value != wireshark:
            self.differ(f"{where}/{name}", "header", node.show, value)

    def nested(self, where, node, entry):
        """An IE that holds a message: compare that message with the IE's value."""
        value = entry.get("value")
        if not isinstance(value, dict):
            wrappers = [c.show for c in node.walk() if c.name == "" and c.show in WRAPPERS]
            if self.system == "5gs" and wrappers and "Plain NAS 5GS Message" not in wrappers:
                return  # a ciphered message: neither reads it
            self.differ(where, "a message that the crate does not read inside the IE", node.show, entry.get("octets", ""))
            return
        if self.system == "5gs":
            inner = [c for c in node.walk() if c.name == "" and c.show in WRAPPERS]
            for wrapper in inner:
                if wrapper.show == "Plain NAS 5GS Message":
                    self.check_message_type(where, wrapper.children, value)
                    self.message(where, wrapper.children, value, None)
                    return
            self.differ(where, "a message inside the IE that Wireshark shows only protected", node.show, "")
        else:
            container = next(c for c in node.walk() if c.name in NESTED)
            self.check_message_type(where, container.children, value)
            self.message(where, container.children, value, None)

    def check_message_type(self, where, children, view):
        node = next((c for c in children if c.name in MESSAGE_TYPES), None)
        crate = (view.get("message-type") or {}).get("value")
        if node is None:
            if crate is not None:
                self.differ(where, "message type", "", crate)
            return
        label = node.label()
        name = self.mapping.messages.get((self.system, label), kebab(label))
        if name != crate:
            self.differ(f"{where}/message-type", "message type", label, crate)


EXTRANEOUS = "Extraneous Data, dissector bug or later version spec"
MESSAGE_TYPES = {"nas-5gs.mm.message_type", "nas-5gs.sm.message_type", "nas-eps.nas_msg_emm_type", "nas-eps.nas_msg_esm_type"}
NESTED = {"nas-eps.emm.esm_msg_cont"}


# ---------------------------------------------------------------------------
# The comparison of fields: `compare` of a field row

def compare_fields(compare):
    """The Wireshark fields that a compare expression reads."""
    kind, _, argument = compare.partition(":")
    return [field for field in argument.split(",") if field] if kind else []


def descendants(item):
    yield item
    for child in (item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()):
        yield from descendants(child)


def select(value, path):
    """The values at `path` of a crate value: members by name, separated by `/`.

    `*` is each entry of a list or member of an object, `**` the value and
    all that it holds in their order, and `a|b` member `a` or member `b`,
    the entries of a list in its place.
    """
    current = [value]
    for part in filter(None, path.split("/")):
        following = []
        for item in current:
            if part == "**":
                following.extend(descendants(item))
            elif "|" in part:
                for name in part.split("|"):
                    if isinstance(item, dict) and name in item:
                        held = item[name]
                        following.extend(held if isinstance(held, list) else [held])
            elif part == "*" and isinstance(item, list):
                following.extend(item)
            elif part == "*" and isinstance(item, dict):
                following.extend(item.values())
            elif isinstance(item, dict) and part in item:
                following.append(item[part])
            elif isinstance(item, list) and part.isdigit() and int(part) < len(item):
                following.append(item[int(part)])
        current = following
    return [item for item in current if item is not None]


def present(value, path):
    """Whether the crate's value has the member that `path` ends with, null or not."""
    parent, _, last = path.rstrip("/").rpartition("/")
    if not last:
        return True
    parents = select(value, parent) if parent else [value]
    if last in ("*", "**"):
        return any(isinstance(p, (list, dict)) for p in parents)
    return any(isinstance(p, dict) and any(name in p for name in last.split("|")) for p in parents)


def as_number(text):
    try:
        return int(str(text), 0)
    except ValueError:
        try:
            return int(str(text), 16) if re.fullmatch(r"[0-9a-fA-F]+", str(text)) else None
        except ValueError:
            return None


def duration(showname):
    """Seconds of a timer as Wireshark shows it: `GPRS Timer: 10 min`, or `deactivated`."""
    text = showname.split(": ", 1)[-1].strip().lower()
    if "deactivated" in text:
        return "deactivated"
    match = re.match(r"(\d+)\s*(sec|s|min|hr|hour|hours|h)\b", text)
    if not match:
        return text
    scale = {"sec": 1, "s": 1, "min": 60, "hr": 3600, "hour": 3600, "hours": 3600, "h": 3600}[match.group(2)]
    return int(match.group(1)) * scale


def rate(showname):
    """kbit/s of a bit rate as Wireshark shows it: `Session-AMBR for downlink: 100 Mbps (100)`."""
    text = showname.split(": ", 1)[-1]
    match = re.match(r"\s*(\d+(?:\.\d+)?)\s*([kKMGTP])bps", text)
    if not match:
        return text
    return round(float(match.group(1)) * 1000 ** "KMGTP".index(match.group(2).upper()))


def run_compare(comparison, where, path, compare, node_fields, value):
    """Compare the Wireshark fields that `compare` names with the crate's values at `path`."""
    kind, _, argument = compare.partition(":")
    fields = argument.split(",")
    crate = select(value, path) if value is not None else []
    ws = [f for f in node_fields if f.name == fields[0]]
    here = f"{where}/{path}"
    system = comparison.system
    # A row compares what both have: a field that Wireshark does not show
    # here, or a member that the crate's value has not in this form (the
    # GUTI of an identity that is an S-TMSI), is no difference. That the
    # crate reads the IE in the form that Wireshark does is a row too.
    if not ws or (value is not None and not present(value, path)):
        return False

    def equal_lists(left, right, what):
        if left != right:
            comparison.differ(here, what, left, right)

    if kind == "int":
        equal_lists([as_number(f.show) for f in ws], [as_number(v) if not isinstance(v, bool) else int(v) for v in crate], f"{fields[0]} as a number")
    elif kind == "notbool":
        # a flag of the crate that is set when the bit that Wireshark shows is 0
        equal_lists([f.show in ("True", "1") for f in ws], [not v for v in crate], f"{fields[0]} as the negation of a flag")
    elif kind == "bool":
        equal_lists([f.show in ("True", "1") for f in ws], [bool(v) for v in crate], f"{fields[0]} as a flag")
    elif kind == "str":
        equal_lists([f.show for f in ws], [str(v) for v in crate], f"{fields[0]} as text")
    elif kind == "hex":
        equal_lists([f.value.lower() for f in ws], [str(v).lower() for v in crate], f"{fields[0]} as octets")
    elif kind == "name":
        # A coded value by its name; a value that the crate has no name for
        # is its number, and so is it compared
        names = []
        for f, v in zip(ws, crate + [None] * len(ws)):
            if isinstance(v, int) or (isinstance(v, str) and v.isdigit()):
                names.append(str(as_number(f.show)))
                continue
            label = f.label()
            names.append(comparison.mapping.values.get((system, f"{fields[0]}={kebab(label)}"), kebab(label)))
        equal_lists(names, [str(v) for v in crate], f"{fields[0]} by its name")
    elif kind == "bit":
        # fields[0]: a flag that is set when `bit` is in the crate's list
        bit = int(fields[1])
        if ws:
            members = crate[0] if crate and isinstance(crate[0], list) else crate
            equal_lists([f.show in ("True", "1") for f in ws][:1], [bit in members], f"{fields[0]} as bit {bit} of the list")
    elif kind == "code":
        # a name of the crate that ends with the code: nea2
        codes = [int(m.group(1)) if (m := re.search(r"(\d+)$", str(v))) else v for v in crate]
        equal_lists([as_number(f.show) for f in ws], codes, f"{fields[0]} as the number of a name")
    elif kind == "duration":
        equal_lists([duration(f.showname) for f in ws], crate, f"{fields[0]} as seconds")
    elif kind == "ksi":
        # fields: the flag of a mapped context, the key set identifier
        flags = [f.show in ("True", "1") for f in node_fields if f.name == fields[0]]
        keys = [as_number(f.show) for f in node_fields if f.name == fields[1]]
        read = ["no-key" if key == 7 else {"mapped" if flag else "native": key} for flag, key in zip(flags, keys)]
        equal_lists(read, crate, "key set identifier")
    elif kind == "key":
        # the member of an object of the crate that says which form its value has
        names = [comparison.mapping.values.get((system, f"{fields[0]}={kebab(f.label())}"), kebab(f.label())) for f in ws]
        equal_lists(names, [next(iter(v)) if isinstance(v, dict) and v else v for v in crate], f"{fields[0]} by the form of the value")
    elif kind == "kbps":
        equal_lists([rate(f.showname) for f in ws], crate, f"{fields[0]} as kbit/s")
    elif kind == "ambr":
        # fields: the rate, its extension, its second extension, the total
        # that Wireshark computes when there is a second extension
        def named(name):
            return [f for f in node_fields if f.name == name]
        total, extended = named(fields[3]), named(fields[1])
        if total:
            read = [as_number(f.show) for f in total]
        elif extended and as_number(extended[0].show):
            read = [rate(f.showname) for f in extended]
        else:
            read = [rate(f.showname) for f in ws]
        equal_lists(read, crate, "a bit rate in kbit/s")
    elif kind == "count":
        equal_lists([as_number(f.show) for f in ws], [len(v) if isinstance(v, list) else None for v in crate], f"{fields[0]} as a number of entries")
    elif kind == "plmn":
        mcc = [f.show for f in node_fields if f.name == fields[0]]
        mnc = [f.show for f in node_fields if f.name == fields[1]]
        equal_lists([f"{a}-{b}" for a, b in zip(mcc, mnc)], [str(v) for v in crate], "PLMN")
    else:
        raise ValueError(f"unknown comparison {compare!r}")
    return True


# ---------------------------------------------------------------------------
# One message

def compare_one(mapping, system, octets, packet, reading):
    comparison = Comparison(mapping, system, octets)
    proto = packet["proto"]
    errors = [e["message"] for e in packet["experts"] if e["severity"] >= EXPERT_ERROR]
    malformed = packet["malformed"] or bool(errors)
    result = {"system": system, "octets": octets.hex(), "wireshark-errors": errors,
              "wireshark-malformed": packet["malformed"],
              "experts": [e["message"] for e in packet["experts"]]}
    if "error" in reading:
        result["crate-error"] = reading["error"]
        result["class"] = "both-refuse" if malformed else "crate-refuses"
        return result, comparison
    codes = reading.get("codes", [])
    if any(layer.get("ciphered") for layer in codes):
        result["class"] = "ciphered"
        return result, comparison
    view = reading["view"]
    if proto is None:
        comparison.differ("", "Wireshark has no NAS tree", "", "")
    elif system == "5gs":
        wrappers = [c for c in proto.children if c.name == "" and c.show in WRAPPERS]
        plain = next((w for w in wrappers if w.show == "Plain NAS 5GS Message"), None)
        protected = next((w for w in wrappers if w.show != "Plain NAS 5GS Message"), None)
        layer = 0
        if protected is not None:
            comparison.message("", protected.children, {}, codes)
            layer = 1
        if plain is None:
            comparison.differ("", "Wireshark shows no plain message", "", "")
        else:
            comparison.check_message_type("", plain.children, view)
            comparison.message("", plain.children, view, codes, layer)
    else:
        children = proto.children
        comparison.check_message_type("", children, view)
        comparison.message("", children, view, codes)
    if comparison.differences:
        result["class"] = "ws-malformed" if malformed else "differs"
    else:
        result["class"] = "ws-malformed" if malformed else "agree"
    result["differences"] = comparison.differences
    return result, comparison


# ---------------------------------------------------------------------------
# Known differences

def load_known(path):
    """known.tsv: system, octets (`*`, or `re:` and a regular expression), where, what, verdict, reference.

    `where` is a regular expression over the path of a difference; for a
    message whose class is `what` (crate-refuses, ws-malformed,
    both-refuse), over the crate's error or Wireshark's errors.
    """
    known = []
    if path is None or not path.exists():
        return known
    for line in path.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        columns = (line.split("\t") + [""] * 6)[:6]
        system, octets, where, what, verdict, reference = columns
        known.append({"system": system, "octets": octets, "where": re.compile(where), "what": what,
                      "verdict": verdict, "reference": reference})
    return known


def explained(known, result, difference):
    for entry in known:
        if entry["system"] not in ("*", result["system"]):
            continue
        octets = entry["octets"]
        if octets.startswith("re:"):
            if not re.search(octets[3:], result["octets"]):
                continue
        elif octets not in ("*", result["octets"]):
            continue
        if difference is None:
            errors = result.get("crate-error", "") + " | " + "; ".join(result.get("wireshark-errors", []))
            if entry["what"] == result["class"] and entry["where"].search(errors):
                return entry
            continue
        if (entry["what"] == "*" or re.fullmatch(entry["what"], difference["what"])) and entry["where"].fullmatch(difference["where"]):
            return entry
    return None


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--crate", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--known", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--propose", type=Path, help="write the IE rows that the mapping lacks, as the octets suggest them")
    parser.add_argument("--any-tshark", action="store_true", help="compare with another version than " + PINNED)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    version = subprocess.check_output(["tshark", "--version"], text=True).splitlines()[0].rstrip(".")
    if version != PINNED and not args.any_tshark:
        print(f"skipped: {version} is not {PINNED}, which known.tsv was triaged with (--any-tshark compares anyway)")
        return 0

    mapping = Mapping(args.mapping)
    known = load_known(args.known)
    rows = []
    for line in args.corpus.read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        columns = line.split("\t")
        rows.append({"system": columns[0], "source": columns[1] if len(columns) > 2 else "",
                     "octets": bytes.fromhex(columns[-1])})
    readings = [json.loads(line) for line in args.crate.read_text().splitlines() if line.strip()]
    if len(readings) != len(rows):
        raise AssertionError(f"{len(rows)} messages but {len(readings)} readings of the crate")

    packets = [None] * len(rows)
    for system in LINK:
        indices = [i for i, row in enumerate(rows) if row["system"] == system]
        if not indices:
            continue
        for index, packet in zip(indices, dissect(system, [rows[i] for i in indices], args.output)):
            packets[index] = packet

    results = []
    coverage = collections.Counter()
    proposals = collections.Counter()
    verdicts = collections.Counter()
    for row, packet, reading in zip(rows, packets, readings):
        if reading["octets"] != row["octets"].hex():
            raise AssertionError(f"the readings are not those of the corpus at {row['octets'].hex()}")
        result, comparison = compare_one(mapping, row["system"], row["octets"], packet, reading)
        result["source"] = row["source"]
        coverage.update(comparison.coverage)
        proposals.update(comparison.proposals)
        unexplained = []
        whole = None
        if result["class"] in ("crate-refuses", "ws-malformed"):
            # A message that one of the two refuses: one entry explains it
            # and what differs in it
            whole = explained(known, result, None)
            if whole is not None:
                result["known"] = whole["verdict"] + " " + whole["reference"]
                verdicts[whole["verdict"]] += 1
        for difference in result.get("differences", []):
            entry = whole or explained(known, result, difference)
            if entry is None:
                unexplained.append(difference)
            else:
                difference["known"] = entry["verdict"] + " " + entry["reference"]
                if whole is None:
                    verdicts[entry["verdict"]] += 1
        # A message that Wireshark finds malformed at an IE that the crate
        # leaves unread is explained by what explains that difference
        explained_inside = result["class"] == "ws-malformed" and result.get("differences")
        if result["class"] in ("crate-refuses", "ws-malformed") and whole is None and not unexplained and not explained_inside:
            unexplained.append({"where": "", "what": result["class"], "wireshark": result["wireshark-errors"],
                                "crate": result.get("crate-error", "")})
        result["unexplained"] = len(unexplained)
        results.append(result)

    if args.propose:
        with args.propose.open("w") as table:
            table.write("# system\tWireshark label\tcrate IE\tmatched by\tmessages\n")
            for (system, label, key, by), count in sorted(proposals.items()):
                table.write(f"{system}\t{label}\t{key}\t{by}\t{count}\n")
    classes = collections.Counter((r["system"], r["class"]) for r in results)
    what = collections.Counter((r["system"], d["what"]) for r in results for d in r.get("differences", []))
    failing = [r for r in results if r["unexplained"]]
    report = {"wireshark": version, "messages": len(results),
              "classes": {f"{s} {c}": n for (s, c), n in sorted(classes.items())},
              "differences": {f"{s} {w}": n for (s, w), n in sorted(what.items())},
              "explained": dict(sorted(verdicts.items())),
              "unexplained": len(failing), "results": results}
    (args.output / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    with (args.output / "coverage.tsv").open("w") as table:
        table.write("# system\tIE type\tWireshark field\tstate\tmessages\n")
        for (system, kind_label, field, state), count in sorted(coverage.items()):
            table.write(f"{system}\t{kind_label}\t{field}\t{state}\t{count}\n")
    lines = [f"{version}: {len(results)} messages"]
    lines += [f"  {s} {c}: {n}" for (s, c), n in sorted(classes.items())]
    lines.append("differences by kind:")
    lines += [f"  {s} {w}: {n}" for (s, w), n in sorted(what.items(), key=lambda x: -x[1])]
    lines.append("explained by known.tsv:")
    lines += [f"  {verdict}: {n}" for verdict, n in sorted(verdicts.items())]
    lines.append(f"unexplained: {len(failing)} messages")
    summary = "\n".join(lines) + "\n"
    (args.output / "summary.txt").write_text(summary)
    print(summary, end="")
    for result in failing[:20]:
        print(f"{result['system']} {result['octets']}: {result['class']}")
        for difference in result.get("differences", [])[:5]:
            if "known" not in difference:
                print(f"    {difference['where']}: {difference['what']}: wireshark={difference['wireshark']!r} crate={difference['crate']!r}")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
