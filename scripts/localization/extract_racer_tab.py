#!/usr/bin/env python3
"""
extract_racer_tab.py - build the master English racer.tab from a SWEP1RCR.EXE.

The game localizes UI/dialogue via swrText_Translate (0x00421360): strings of the
form "/KEY/inline-english" are looked up by KEY in a racer.tab (KEY<TAB>VALUE per
line), falling back to the inline English when the key is missing or no tab is loaded.
The retail Steam build ships NO racer.tab, so English runs purely on these fallbacks.

This tool scans the exe for every "/KEY/english" literal and emits a KEY<TAB>english
racer.tab - the translation template AND the alignment key for extracting a localized
build's per-language columns.

Reference (from the decomp): keys are uppercase [A-Z0-9_] (occasionally a trailing
space); the value runs to the string's NUL terminator; the codepage is CP-1252.

Usage:
    python extract_racer_tab.py <SWEP1RCR.EXE> [-o out/racer.tab]
"""
import argparse
import re
import sys

# "/KEY/value" literal, value terminated by the string's NUL (matched as a zero-width
# lookahead so back-to-back pairs "/K1/v1\x00/K2/v2\x00" don't lose the shared NUL). The
# KEY must carry a numeric suffix (_NNN, optional trailing space) - the real translation
# namespaces are SCREENTEXT_N / MONDOTEXT_H_N. That suffix, not a leading-NUL anchor, is
# what separates a key from a path fragment ("/CONFIG/current"): it recovers keys that sit
# right after packed float data (no NUL gap) while still rejecting paths. A stray "/KEY/"
# inside a value can't false-match - the greedy value of its own entry already swallows it.
PAIR_RE = re.compile(rb"/([A-Z][A-Z0-9_]*_\d+ ?)/([^\x00]*)(?=\x00)")


def extract(exe_path):
    data = open(exe_path, "rb").read()
    pairs = []
    seen = {}
    dups = 0
    for m in PAIR_RE.finditer(data):
        key = m.group(1).decode("cp1252")
        val = m.group(2).decode("cp1252")
        if key in seen:
            dups += 1
            # keep the first; flag if a later literal disagrees
            if seen[key] != val:
                print(f"  ! duplicate key with different value: {key!r}", file=sys.stderr)
            continue
        seen[key] = val
        pairs.append((key, val))
    return pairs, dups


def escape_value(v):
    # racer.tab lines are split on \r/\n and cut at the first \t BEFORE swrText_UnescapeString
    # runs, so raw control bytes in a value corrupt the file. Emit the same escapes the tool
    # decodes on load (backslash first to avoid double-escaping). High/accented bytes pass raw.
    return (v.replace("\\", "\\\\")
             .replace("\t", "\\t")
             .replace("\r", "\\r")
             .replace("\n", "\\n"))


def natural_key(k):
    # sort SCREENTEXT_2 before SCREENTEXT_10, group by prefix
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", k)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="path to SWEP1RCR.EXE")
    ap.add_argument("-o", "--out", default="racer.tab", help="output racer.tab path")
    args = ap.parse_args()

    pairs, dups = extract(args.exe)
    pairs.sort(key=lambda kv: natural_key(kv[0]))

    with open(args.out, "w", encoding="cp1252", newline="\r\n") as f:
        for key, val in pairs:
            f.write(f"{key}\t{escape_value(val)}\n")

    prefixes = {}
    for key, _ in pairs:
        pfx = re.split(r"_\d", key, 1)[0]
        prefixes[pfx] = prefixes.get(pfx, 0) + 1
    print(f"wrote {len(pairs)} keys -> {args.out}  ({dups} duplicate literals skipped)")
    for pfx, n in sorted(prefixes.items(), key=lambda x: -x[1]):
        print(f"  {pfx:<16} {n}")


if __name__ == "__main__":
    main()
