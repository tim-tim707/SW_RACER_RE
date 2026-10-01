"""Symbolize an AddressSanitizer report from the game (crashes/asan.<pid>).

The ASan runtime starts before dinput.dll runs any code, so a Steam-launched game has no way to
tell it where llvm-symbolizer is and frames come out as `(DINPUT.dll+0x1004f00d)`. This rewrites
every frame of an instrumented module into `function file:line` using llvm-symbolizer.

    python scripts/asan_symbolize.py "<game dir>/crashes/asan.1234"
    python scripts/asan_symbolize.py report.txt --symbolizer C:/llvm-mingw/bin/llvm-symbolizer.exe

Modules are resolved from the path in the report; pass --module-dir to use copies elsewhere
(e.g. the build directory's libdinput_hook.dll for DINPUT.dll).
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

# `#5 0x62cf813d in some_fn+0x1d (C:\Program Files (x86)\...\DINPUT.dll+0x1041813d)` -- the path
# itself may contain parentheses, so anchor on the trailing `+0xOFFSET)`.
FRAME = re.compile(r"^(?P<head>\s*#\d+ 0x[0-9a-f]+) (?:in \S+ )?\s*\((?P<module>.+\.(?:dll|exe))\+(?P<offset>0x[0-9a-f]+)\)\s*$",
                   re.IGNORECASE)


def find_symbolizer(explicit):
    if explicit:
        return explicit
    found = shutil.which("llvm-symbolizer")
    if not found:
        sys.exit("llvm-symbolizer not found on PATH; pass --symbolizer")
    return found


def symbolize(symbolizer, module, offsets):
    out = subprocess.run([symbolizer, "--obj=" + module, "--demangle", "--no-inlines"] + offsets,
                         capture_output=True, text=True, check=False).stdout
    blocks = [b.split("\n") for b in out.strip().split("\n\n")]
    return {off: (b[0], b[1] if len(b) > 1 else "??") for off, b in zip(offsets, blocks)}


def resolve_module(path, module_dir):
    if module_dir:
        name = os.path.basename(path.replace("\\", "/"))
        for candidate in (name, name.lower(), "libdinput_hook.dll" if name.lower() == "dinput.dll" else None):
            if candidate and os.path.exists(os.path.join(module_dir, candidate)):
                return os.path.join(module_dir, candidate)
    return path if os.path.exists(path) else None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report")
    parser.add_argument("--symbolizer")
    parser.add_argument("--module-dir")
    args = parser.parse_args()

    symbolizer = find_symbolizer(args.symbolizer)
    with open(args.report, encoding="utf-8", errors="replace") as f:
        lines = f.read().splitlines()

    wanted = {}
    for line in lines:
        m = FRAME.match(line)
        if m:
            wanted.setdefault(m["module"], set()).add(m["offset"])

    resolved = {}
    for module, offsets in wanted.items():
        path = resolve_module(module, args.module_dir)
        if path:
            resolved[module] = symbolize(symbolizer, path, sorted(offsets))

    for line in lines:
        m = FRAME.match(line)
        sym = m and resolved.get(m["module"], {}).get(m["offset"])
        # Modules without DWARF (system DLLs) come back as ??; keep ASan's export-based name.
        if sym and not sym[1].startswith("??"):
            print(f"{m['head']} in {sym[0]} {sym[1]} ({os.path.basename(m['module'])}+{m['offset']})")
        else:
            print(line)


if __name__ == "__main__":
    main()
