#!/usr/bin/env python3
"""
Check that every "// 0xADDR" reverse-hook (and "// 0xADDR HOOK" forward-hook) comment
sits DIRECTLY above the function signature it annotates.

GenerateHooks.py recognizes a hook annotation, then expects the VERY NEXT line to be the
function signature. If a description comment (or a blank line) sits between the "// 0xADDR"
line and the signature, GenerateHooks silently drops the function from the hook table -- the
reimpl still compiles, but it is no longer registered / tracked as a hook.

This catches that before it ships. Run from the repo root:
    python scripts/check_hook_annotations.py
Exits non-zero (and lists each offender as file:line) if any annotation is misplaced.
"""
import os
import re
import sys

# Mirror GenerateHooks.py exactly: addresses are 8 hex digits, recognition needs trailing
# whitespace (the line's newline counts), and the signature must be on the immediate next line.
HOOK_RE = re.compile(r"//\s*(0x[0-9A-Fa-f]{8})\s+HOOK\s*")
NO_HOOK_RE = re.compile(r"//\s*(0x[0-9A-Fa-f]{8})\s+")
COMMENT_RE = re.compile(r"^\s*(//|/\*)")
FUNCTION_RE = re.compile(r"(\w+)(?=\()")

SRC = "src"


def find_misplaced():
    bad = []
    for dir_path, _, file_names in os.walk(SRC):
        if "generated" in dir_path.replace("\\", "/").split("/"):
            continue
        for name in sorted(file_names):
            if not name.endswith(".c"):
                continue
            path = os.path.join(dir_path, name).replace("\\", "/")
            # readlines() keeps the trailing newline, matching GenerateHooks' \s+ behavior.
            lines = open(path, encoding="ascii", errors="replace").readlines()
            for i, line in enumerate(lines):
                if not (HOOK_RE.search(line) or NO_HOOK_RE.search(line)):
                    continue
                nxt = lines[i + 1] if i + 1 < len(lines) else "\n"
                # GenerateHooks captures the function only if the next line is the signature.
                if COMMENT_RE.search(nxt) or FUNCTION_RE.search(nxt) is None:
                    sig = None
                    for j in range(i + 1, min(i + 12, len(lines))):
                        s = lines[j].strip()
                        if s == "" or COMMENT_RE.search(lines[j]):
                            continue
                        m = FUNCTION_RE.search(lines[j])
                        sig = m.group(1) if m else s[:48]
                        break
                    bad.append((path, i + 1, line.strip(), sig))
    return bad


def main():
    bad = find_misplaced()
    if not bad:
        print("OK: every // 0xADDR annotation is directly above its signature.")
        return 0
    print("FAIL: %d hook annotation(s) NOT directly above a signature "
          "(GenerateHooks.py would drop these functions):\n" % len(bad))
    for path, lineno, annotation, sig in bad:
        print("  %s:%d  %s  -> %s" % (path, lineno, annotation, sig or "(no signature found)"))
    print("\nFix: move the description above the // 0xADDR line (or delete a stray/orphan "
          "annotation) so the address sits on the line directly above the function.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
