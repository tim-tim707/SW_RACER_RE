# Scans every header in src/ for duplicate _ADDR definitions and reports:
#   - one address defined under more than one name (a parallel define that
#     should reuse the existing canonical name)
#   - one name defined at more than one address
#   - the exact same name+address #define written more than once
#
# This is the check tim-tim707 asked for: mapping PRs sometimes give a fresh
# name to an address that already has a canonical _ADDR in another header.
# Importing such a header into Ghidra then creates a second label at that
# address. Run this before regenerating master_header.h / opening a PR.
#
# Plain CPython (host side, no Ghidra). Usage:
#   python scripts\Ghidra\CheckHeaderDuplicates.py          # warn + exit 1 on dups
#   python scripts\Ghidra\CheckHeaderDuplicates.py --warn   # warn but exit 0

import os
import re
import sys

# Same set GenerateMasterHeader.py skips: pure type/global headers carry no _ADDR.
IGNORE_LIST = ["types.h", "types_a3d.h", "types_enums.h", "types_directx.h",
               "globals.h", "hook.h", "hook_addresses.h", "macros.h"]

SOURCE_DIR = "src"

# Anchored to start-of-line so commented-out "// #define X_ADDR (0x..)" lines
# are skipped. Leading whitespace is allowed; a leading // is not.
DEFINE_RE = re.compile(r"^\s*#define\s+(\w+)_ADDR\s*\(\s*0x0*([0-9A-Fa-f]+)\s*\)")


def find_headers(base_path):
    res = []
    for (dir_path, _, file_names) in os.walk(os.path.join(base_path, SOURCE_DIR)):
        for f in file_names:
            if f.endswith(".h") and f not in IGNORE_LIST:
                res.append(os.path.join(dir_path, f))
    return sorted(res)


def collect(base_path):
    # addr -> list of (name, "file:line"); name -> list of (addr, "file:line")
    addr_to_names = {}
    name_to_addrs = {}
    for path in find_headers(base_path):
        rel = os.path.relpath(path, base_path).replace(os.sep, "/")
        with open(path, "r", encoding="ascii") as fh:
            for lineno, line in enumerate(fh, 1):
                # Drop a trailing // comment before matching the define body.
                stripped = line.lstrip()
                if stripped.startswith("//"):
                    continue
                m = DEFINE_RE.match(line)
                if not m:
                    continue
                name = m.group(1)
                addr = "0x" + m.group(2).lower()
                where = "{}:{}".format(rel, lineno)
                addr_to_names.setdefault(addr, []).append((name, where))
                name_to_addrs.setdefault(name, []).append((addr, where))
    return addr_to_names, name_to_addrs


def report(addr_to_names, name_to_addrs):
    problems = 0

    # 1. One address, several distinct names (the main "parallel define" dup).
    addr_dups = {a: v for a, v in addr_to_names.items()
                 if len(set(n for n, _ in v)) > 1}
    if addr_dups:
        print("== Addresses defined under more than one name ==")
        for addr in sorted(addr_dups):
            print("  {}:".format(addr))
            for name, where in sorted(addr_dups[addr]):
                print("      {:<45s} {}".format(name, where))
            problems += 1

    # 2. One name, several distinct addresses.
    name_dups = {n: v for n, v in name_to_addrs.items()
                 if len(set(a for a, _ in v)) > 1}
    if name_dups:
        print("== Names defined at more than one address ==")
        for name in sorted(name_dups):
            print("  {}:".format(name))
            for addr, where in sorted(name_dups[name]):
                print("      {:<14s} {}".format(addr, where))
            problems += 1

    # 3. Exact name+address written more than once (a literal redefine).
    exact = []
    for name, entries in name_to_addrs.items():
        per_addr = {}
        for addr, where in entries:
            per_addr.setdefault(addr, []).append(where)
        for addr, wheres in per_addr.items():
            if len(wheres) > 1:
                exact.append((name, addr, wheres))
    if exact:
        print("== Identical name+address defined more than once ==")
        for name, addr, wheres in sorted(exact):
            print("  {} ({}): {}".format(name, addr, ", ".join(sorted(wheres))))
            problems += 1

    return problems


def find_repo_root():
    # Prefer cwd if it already holds src/ (lets the script run from the repo
    # root like the other Ghidra scripts), else fall back to the location of
    # this file (scripts/Ghidra/CheckHeaderDuplicates.py -> repo root is ../..).
    if os.path.isdir(os.path.join(os.getcwd(), SOURCE_DIR)):
        return os.getcwd()
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def main():
    warn_only = "--warn" in sys.argv
    base_path = find_repo_root()
    if not os.path.isdir(os.path.join(base_path, SOURCE_DIR)):
        print("Could not locate the src/ directory. Run from the repo root: "
              "python scripts\\Ghidra\\CheckHeaderDuplicates.py")
        return 1

    addr_to_names, name_to_addrs = collect(base_path)
    problems = report(addr_to_names, name_to_addrs)

    total_defines = sum(len(v) for v in name_to_addrs.values())
    if problems == 0:
        print("No duplicate _ADDR definitions found ({} defines scanned).".format(total_defines))
        return 0

    print("\n{} duplicate group(s) found ({} defines scanned).".format(problems, total_defines))
    return 0 if warn_only else 1


if __name__ == "__main__":
    sys.exit(main())
