#!/usr/bin/env python3
"""Hash-diff a localized voice/asset tree against the stock English one to find the files that
actually differ. SWE1R voice is mostly language-neutral alien speech, so the real per-language
delta (announcer/UI lines) is far smaller than the full ~240 MB tree -- only the delta needs to
be redirected/shipped for localized audio.

Usage: python diff_voice.py <english_root> <localized_root>
"""
import os, sys, hashlib
from pathlib import Path
from collections import Counter

EN = sys.argv[1]
LOC = sys.argv[2]

def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()

def index(root):
    root = Path(root)
    return {"/".join(p.relative_to(root).parts): p
            for p in root.rglob("*") if p.is_file()}

ei = index(EN)
li = index(LOC)

identical = differ = loconly = 0
delta_bytes = 0
delta = []
for rel, fp in li.items():
    if rel in ei:
        if md5(fp) == md5(ei[rel]):
            identical += 1
        else:
            differ += 1
            sz = fp.stat().st_size
            delta_bytes += sz
            delta.append((rel, sz))
    else:
        loconly += 1
        sz = fp.stat().st_size
        delta_bytes += sz
        delta.append((rel + " (loc-only)", sz))
enonly = sum(1 for rel in ei if rel not in li)
full = sum(p.stat().st_size for p in li.values())

print(f"localized files: {len(li)}  identical: {identical}  DIFFER: {differ}  "
      f"loc-only: {loconly}  en-only: {enonly}")
print(f"=> DELTA = {differ + loconly} files, {delta_bytes/1024/1024:.1f} MB "
      f"(vs {full/1024/1024:.0f} MB full tree)")
print("\ndelta by folder:")
for d, c in Counter(rel.rsplit('/', 1)[0] for rel, _ in delta).most_common():
    print(f"  {d}: {c}")
print("\nfirst 25 differing files:")
for rel, sz in sorted(delta)[:25]:
    print(f"  {rel}  {sz}B")
