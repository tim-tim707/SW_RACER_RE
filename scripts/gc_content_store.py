#!/usr/bin/env python3
"""Report (and optionally delete) content-store blobs no manifest references.

Usage:
    python scripts/gc_content_store.py <root> [--delete] [--verify]

    <root>      a folder holding tracks/<slug>/track.json and content/<hh>/<sha256>,
                i.e. the game directory's assets/ or a converter output directory

Blobs accumulate: converting a pack again writes new hashes and leaves the old
ones behind, and a removed track takes nothing with it. Nothing else can tell
whether a blob is still wanted, because the store is shared -- two tracks that
use the same texture reference one blob.

Reads every manifest, collects the hashes they name, and reports whatever the
store holds beyond that. Reports rather than deletes unless asked: a wrong
answer here silently breaks a track, and the failure would only show up the
next time somebody races it.

Also reports the two ways a store can be wrong in the other direction:
a manifest naming a blob that is not there (that track cannot load), and,
with --verify, a blob whose contents do not hash to its own name.
"""
import argparse
import hashlib
import json
import os
import sys


def manifest_paths(root):
    tracks_dir = os.path.join(root, "tracks")
    if not os.path.isdir(tracks_dir):
        sys.exit(f"no tracks directory under {root}")

    for name in sorted(os.listdir(tracks_dir)):
        path = os.path.join(tracks_dir, name, "track.json")
        if os.path.isfile(path):
            yield path


def referenced_hashes(root):
    """Every sha256 the manifests name, as {sha256: [slug, ...]}."""
    referenced = {}
    for path in manifest_paths(root):
        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)

        slug = manifest.get("slug", os.path.basename(os.path.dirname(path)))
        assets = []
        for key in ("model", "spline", "preview_model"):
            if isinstance(manifest.get(key), dict):
                assets.append(manifest[key])
        assets += [t for t in manifest.get("textures", []) if isinstance(t, dict)]
        for audio in (manifest.get("audio") or {}).values():
            if isinstance(audio, dict):
                assets.append(audio)

        for asset in assets:
            digest = asset.get("sha256")
            if digest:
                referenced.setdefault(digest, []).append(slug)
    return referenced


def stored_blobs(root):
    """Every blob in the store, as {sha256: path}."""
    content_dir = os.path.join(root, "content")
    blobs = {}
    if not os.path.isdir(content_dir):
        return blobs

    for prefix in sorted(os.listdir(content_dir)):
        prefix_dir = os.path.join(content_dir, prefix)
        if not os.path.isdir(prefix_dir):
            continue
        for name in sorted(os.listdir(prefix_dir)):
            path = os.path.join(prefix_dir, name)
            if os.path.isfile(path):
                blobs[name] = path
    return blobs


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root")
    parser.add_argument("--delete", action="store_true",
                        help="actually remove the unreferenced blobs (default: report only)")
    parser.add_argument("--verify", action="store_true",
                        help="also check that every referenced blob hashes to its own name")
    args = parser.parse_args()

    referenced = referenced_hashes(args.root)
    blobs = stored_blobs(args.root)

    missing = sorted(set(referenced) - set(blobs))
    orphans = sorted(set(blobs) - set(referenced))
    orphan_bytes = sum(os.path.getsize(blobs[h]) for h in orphans)
    kept_bytes = sum(os.path.getsize(blobs[h]) for h in blobs if h not in set(orphans))

    print(f"{len(list(manifest_paths(args.root)))} manifest(s) reference {len(referenced)} blob(s); "
          f"the store holds {len(blobs)}")
    print(f"  referenced: {len(blobs) - len(orphans)} blob(s), {kept_bytes} bytes")
    print(f"  unreferenced: {len(orphans)} blob(s), {orphan_bytes} bytes")

    for digest in missing:
        print(f"  MISSING {digest[:12]} -- named by {', '.join(referenced[digest])}, "
              f"that track cannot load")

    corrupt = []
    if args.verify:
        for digest, path in blobs.items():
            if digest in referenced and sha256_file(path) != digest:
                corrupt.append(digest)
                print(f"  CORRUPT {digest[:12]} -- contents do not match the name")
        if not corrupt:
            print(f"  verified {len(referenced)} referenced blob(s) against their hashes")

    if orphans and not args.delete:
        for digest in orphans[:10]:
            print(f"  orphan {digest[:12]} ({os.path.getsize(blobs[digest])} bytes)")
        if len(orphans) > 10:
            print(f"  ... and {len(orphans) - 10} more")
        print("re-run with --delete to remove them")
    elif orphans:
        for digest in orphans:
            os.remove(blobs[digest])
        print(f"deleted {len(orphans)} blob(s), freeing {orphan_bytes} bytes")
        # Leave no empty prefix directories behind.
        content_dir = os.path.join(args.root, "content")
        for prefix in sorted(os.listdir(content_dir)):
            prefix_dir = os.path.join(content_dir, prefix)
            if os.path.isdir(prefix_dir) and not os.listdir(prefix_dir):
                os.rmdir(prefix_dir)

    return 1 if missing or corrupt else 0


if __name__ == "__main__":
    sys.exit(main())
