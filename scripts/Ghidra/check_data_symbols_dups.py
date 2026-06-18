#!/usr/bin/env python3
"""Check data_symbols.syms for duplicate names or addresses.

Duplicates make importDataSymbols.py create clashing Ghidra labels and overlapping
data definitions, so we reject them before they land. Run standalone (NOT inside
Ghidra):

    python scripts/Ghidra/check_data_symbols_dups.py [path/to/data_symbols.syms]

Exits non-zero and prints every offending entry if any duplicate is found, so it
can gate a pre-PR check or CI; exits 0 when clean. Parsing mirrors
importDataSymbols.py: lines shorter than 2 chars, '//' lines and '#' lines are
skipped, trailing // or # comments are stripped, and a valid entry needs at least
'name 0xADDR type'.
"""
import sys
from collections import defaultdict


def parse(path):
    """Return a list of (lineno, name, addr_int, stripped_line) symbol entries."""
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw
            if len(line) < 2:
                continue
            if line[:2] == "//":
                continue
            if line[:1] == "#":
                continue
            line = line.split("//")[0]
            line = line.split("#")[0]
            pieces = line.split()
            if len(pieces) < 3:
                continue
            name = pieces[0]
            try:
                addr_int = int(pieces[1], 16)
            except ValueError:
                print("WARN line {}: cannot parse address {!r}: {}".format(
                    lineno, pieces[1], raw.strip()))
                continue
            entries.append((lineno, name, addr_int, raw.strip()))
    return entries


def main(argv):
    path = argv[1] if len(argv) > 1 else "data_symbols.syms"
    entries = parse(path)

    by_name = defaultdict(list)
    by_addr = defaultdict(list)
    for lineno, name, addr, raw in entries:
        by_name[name].append((lineno, addr, raw))
        by_addr[addr].append((lineno, name, raw))

    dup_names = {n: v for n, v in by_name.items() if len(v) > 1}
    dup_addrs = {a: v for a, v in by_addr.items() if len(v) > 1}

    if dup_names:
        print("DUPLICATE NAMES ({}):".format(len(dup_names)))
        for name, occ in sorted(dup_names.items()):
            print("  {} appears {} times:".format(name, len(occ)))
            for lineno, addr, raw in occ:
                print("    line {}: {}".format(lineno, raw))

    if dup_addrs:
        print("DUPLICATE ADDRESSES ({}):".format(len(dup_addrs)))
        for addr, occ in sorted(dup_addrs.items()):
            names = {n for _, n, _ in occ}
            kind = "same name" if len(names) == 1 else "CONFLICTING names"
            print("  0x{:08x} appears {} times ({}):".format(addr, len(occ), kind))
            for lineno, name, raw in occ:
                print("    line {}: {}".format(lineno, raw))

    if dup_names or dup_addrs:
        print("\nFAIL: {} duplicate name(s), {} duplicate address(es).".format(
            len(dup_names), len(dup_addrs)))
        return 1

    print("OK: {} symbols, no duplicate names or addresses.".format(len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
