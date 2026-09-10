#!/usr/bin/env python3
"""Convert a packed custom-track folder into discrete, content-addressed assets.

Usage:
    python scripts/convert_track_pack.py <pack_dir> <game_dir> <out_dir>
                                         [--namespace NAME] [--version 1.0.0]

    <pack_dir>  a folder holding out_modelblock.bin / out_splineblock.bin /
                out_textureblock.bin, i.e. today's assets/custom_tracks/<pack>
    <game_dir>  the game install (its data/lev01 blocks are the diff baseline,
                and SWEP1RCR.EXE holds the stock track table)
    <out_dir>   written as   <out_dir>/tracks/<slug>/track.json
                        and  <out_dir>/content/<hh>/<sha256>

A pack ships whole copies of the game's packed blocks, so its actual content is
whatever differs from stock. This diffs it entry by entry, carves those entries
out as discrete assets (see extract_raw_asset.py), and writes a track.json that
names them by hash.

Two things come out of the stock track table (TrackInfo[25], 0x004bfee8, read
straight from the EXE -- SteamStub only encrypts .text):

  * which spline belongs to a changed track model, instead of guessing by
    pairing changed entries positionally, and
  * the planet / track-number / favourite-pilot the overridden slot really has,
    so the manifest inherits real placement rather than a hardcoded default.

Textures keep the block index the model references. The model is copied
verbatim -- its texture words are absolute indices into the texture block, and
rewriting them would change the asset's hash for no gain -- so each texture
declares the index it must be served at, and the block the game reads is
assembled as "stock entry, unless a declared index overrides it".
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_raw_asset import be32, carve, entry_count  # noqa: E402

TRACK_INFO_ADDR = 0x004BFEE8
TRACK_INFO_COUNT = 25
TRACK_TAG = b"Trak"
TEXTURE_REF_TAG = 0x0A000000


def read_pe_data(exe_path, addr, size):
    """Read `size` bytes at a virtual address out of an on-disk PE image."""
    with open(exe_path, "rb") as f:
        image = f.read()

    pe = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe:pe + 4] != b"PE\0\0":
        sys.exit(f"{exe_path} is not a PE image")
    num_sections = struct.unpack_from("<H", image, pe + 6)[0]
    opt_size = struct.unpack_from("<H", image, pe + 20)[0]
    image_base = struct.unpack_from("<I", image, pe + 24 + 28)[0]

    rva = addr - image_base
    for i in range(num_sections):
        off = pe + 24 + opt_size + 40 * i
        virtual_size, virtual_addr, raw_size, raw_off = struct.unpack_from("<IIII", image, off + 8)
        if virtual_addr <= rva < virtual_addr + max(virtual_size, raw_size):
            start = raw_off + (rva - virtual_addr)
            return image[start:start + size]
    sys.exit(f"virtual address {addr:#x} is not inside any section of {exe_path}")


def read_track_table(game_dir):
    """The stock TrackInfo[25] as {model_id: {spline, planet, ...}}."""
    exe = os.path.join(game_dir, "SWEP1RCR.EXE")
    if not os.path.isfile(exe):
        sys.exit(f"no SWEP1RCR.EXE in {game_dir} (needed for the stock track table)")

    raw = read_pe_data(exe, TRACK_INFO_ADDR, 12 * TRACK_INFO_COUNT)
    table = {}
    for i in range(TRACK_INFO_COUNT):
        model, spline, track_number, planet, favourite, _ = struct.unpack_from("<IIBBBB", raw, 12 * i)
        table[model] = {
            "slot": i,
            "spline": spline,
            "planet_track_number": track_number,
            "planet": planet,
            "favorite_pilot": favourite,
        }
    return table


def load_block(path):
    with open(path, "rb") as f:
        return f.read()


def changed_entries(kind, stock, pack):
    """Entry ids whose carved bytes differ, plus ids the pack adds past stock."""
    shared = min(entry_count(stock), entry_count(pack))
    changed = [i for i in range(shared) if carve(kind, stock, i) != carve(kind, pack, i)]
    added = list(range(entry_count(stock), entry_count(pack)))
    return changed, added


def entry_tag(kind, block, asset_id):
    chunk = carve(kind, block, asset_id)
    if kind != "model":
        return None
    mask_size, _ = struct.unpack_from("<II", chunk, 4)
    return chunk[12 + mask_size:12 + mask_size + 4]


def referenced_texture_indices(chunk):
    """Absolute texture-block indices a RAWM chunk's mask-flagged words point at."""
    mask_size, model_size = struct.unpack_from("<II", chunk, 4)
    mask = chunk[12:12 + mask_size]
    model = chunk[12 + mask_size:]

    def bit(k):
        return (mask[k // 8] >> (7 - k % 8)) & 1 if k // 8 < len(mask) else 0

    if model[0:4] == b"Comp":
        return []# compressed; indices only exist after the loader inflates it

    found = []
    for word in range(model_size // 4):
        if not bit(word):
            continue
        value = be32(model, 4 * word)
        if (value & 0xFF000000) == TEXTURE_REF_TAG:
            found.append(value & 0xFFFFFF)
    return sorted(set(found))


class ContentStore:
    """assets/content/<first two hex chars>/<sha256>, written once per hash."""

    def __init__(self, root):
        self.root = root
        self.written = 0
        self.deduped = 0
        self.bytes_written = 0

    def put(self, payload):
        digest = hashlib.sha256(payload).hexdigest()
        path = os.path.join(self.root, digest[:2], digest)
        if os.path.exists(path):
            self.deduped += 1
        else:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(payload)
            self.written += 1
            self.bytes_written += len(payload)
        return digest


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def content_hash(model, spline, textures):
    """Identity of this build of the track: its assets, not its metadata."""
    parts = [f"model:{model['sha256']}:{model['block_id']}"]
    if spline:
        parts.append(f"spline:{spline['sha256']}:{spline['block_id']}")
    parts += [f"texture:{t['sha256']}:{t['block_index']}" for t in sorted(
        textures, key=lambda t: t["block_index"])]
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def convert(pack_dir, game_dir, out_dir, namespace, version, include_reexports=False):
    stock_dir = os.path.join(game_dir, "data", "lev01")
    blocks = {}
    for kind, name in (("model", "out_modelblock.bin"), ("spline", "out_splineblock.bin"),
                       ("texture", "out_textureblock.bin")):
        stock_path = os.path.join(stock_dir, name)
        pack_path = os.path.join(pack_dir, name)
        if not os.path.isfile(stock_path):
            sys.exit(f"missing stock block {stock_path}")
        blocks[kind] = (load_block(stock_path),
                        load_block(pack_path) if os.path.isfile(pack_path) else None)

    track_table = read_track_table(game_dir)
    store = ContentStore(os.path.join(out_dir, "content"))
    pack_name = os.path.basename(os.path.normpath(pack_dir))

    stock_models, pack_models = blocks["model"]
    if pack_models is None:
        sys.exit(f"{pack_dir} has no out_modelblock.bin")
    changed_models, added_models = changed_entries("model", stock_models, pack_models)

    track_models = [i for i in changed_models + added_models
                    if entry_tag("model", pack_models, i) == TRACK_TAG]
    other_models = [i for i in changed_models if i not in track_models]
    if other_models:
        print(f"note: {len(other_models)} changed non-track model entries ignored: {other_models}")
    if not track_models:
        sys.exit(f"{pack_name}: no changed 'Trak' entries -- nothing to convert")

    # A pack's own content is both what it rewrote and what it appended past the stock count --
    # blender-swe1r appends a track's textures, so treating only rewritten entries as custom finds
    # none of them.
    stock_splines, pack_splines = blocks["spline"]
    custom_splines = ([] if pack_splines is None
                      else [i for group in changed_entries("spline", stock_splines, pack_splines)
                            for i in group])
    stock_textures, pack_textures = blocks["texture"]
    custom_textures = ([] if pack_textures is None
                       else [i for group in changed_entries("texture", stock_textures, pack_textures)
                             for i in group])

    print(f"{pack_name}: {len(track_models)} custom track(s) {track_models}, "
          f"{len(custom_splines)} custom spline(s), {len(custom_textures)} custom texture(s)")

    manifests = []
    for n, model_id in enumerate(track_models):
        info = track_table.get(model_id)
        if info is None:
            print(f"  model {model_id}: not a stock track slot -- skipped "
                  f"(no spline or placement to inherit)")
            continue

        chunk = carve("model", pack_models, model_id)
        model_asset = {"sha256": store.put(chunk), "size": len(chunk), "format": "RAWM",
                       "block_id": model_id}

        spline_asset = None
        if info["spline"] in custom_splines:
            spline_chunk = carve("spline", pack_splines, info["spline"])
            spline_asset = {"sha256": store.put(spline_chunk), "size": len(spline_chunk),
                            "format": "RAWS", "block_id": info["spline"]}
        else:
            print(f"  model {model_id}: spline {info['spline']} is unchanged -- the track will "
                  f"race the stock line")

        referenced = referenced_texture_indices(chunk)
        custom = [i for i in referenced if i in custom_textures]
        texture_assets = []
        for index in custom:
            texture_chunk = carve("texture", pack_textures, index)
            texture_assets.append({"sha256": store.put(texture_chunk), "size": len(texture_chunk),
                                   "format": "RAWT", "block_index": index})
        print(f"  model {model_id}: {len(referenced)} texture refs, {len(custom)} custom "
              f"({len(referenced) - len(custom)} resolve to stock art)")

        # An entry with no art and no line of its own is almost certainly a passenger: the exporter
        # rewrote a stock track's bytes without its design being touched. Converting it puts a
        # vanilla track in the menus under the pack's name.
        if not custom and spline_asset is None:
            print(f"  model {model_id}: no custom textures and no custom spline -- looks like a "
                  f"re-export of the stock track, "
                  f"{'converting anyway' if include_reexports else 'skipping'}")
            if not include_reexports:
                continue

        slug_base = slugify(pack_name) or "track"
        slug = slug_base if len(track_models) == 1 else f"{slug_base}-{n + 1}"
        manifest = {
            "schema": 1,
            "slug": f"{namespace}.{slug}",
            "version": version,
            "name": pack_name if len(track_models) == 1 else f"{pack_name} {n + 1}",
            "author": {"name": namespace},
            "game_compat": ">=1.0",
            "model": model_asset,
            "textures": texture_assets,
            "placement": {
                "overrides_stock_slot": info["slot"],
                "planet": info["planet"],
                "planet_track_number": info["planet_track_number"],
                "favorite_pilot": info["favorite_pilot"],
            },
            "rules": {"laps_default": 3, "mirror_allowed": True},
        }
        if spline_asset:
            manifest["spline"] = spline_asset
        manifest["content_hash"] = content_hash(model_asset, spline_asset, texture_assets)

        track_dir = os.path.join(out_dir, "tracks", manifest["slug"])
        os.makedirs(track_dir, exist_ok=True)
        manifest_path = os.path.join(track_dir, "track.json")
        with open(manifest_path, "w", encoding="ascii") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        manifests.append((manifest_path, manifest))

    pack_bytes = sum(os.path.getsize(os.path.join(pack_dir, f))
                     for f in os.listdir(pack_dir)
                     if f.endswith(".bin") and os.path.isfile(os.path.join(pack_dir, f)))
    asset_bytes = sum(a["size"] for _, m in manifests
                      for a in [m["model"]] + m["textures"] + ([m["spline"]] if "spline" in m else []))
    print(f"wrote {len(manifests)} manifest(s); content store: {store.written} new blob(s) "
          f"({store.bytes_written} bytes), {store.deduped} already present")
    if pack_bytes:
        print(f"packed blocks {pack_bytes} bytes -> discrete assets {asset_bytes} bytes "
              f"({100 - asset_bytes * 100 // pack_bytes}% smaller)")
    for path, _ in manifests:
        print(f"  {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("pack_dir")
    parser.add_argument("game_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--namespace", default="local",
                        help="slug namespace, normally the author (default: local)")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--include-reexports", action="store_true",
                        help="also convert entries that only re-encode a stock track")
    args = parser.parse_args()
    convert(args.pack_dir, args.game_dir, args.out_dir, args.namespace, args.version,
            args.include_reexports)


if __name__ == "__main__":
    main()
