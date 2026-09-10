#!/usr/bin/env python3
"""Carve one asset out of a packed block into a discrete replacement file.

Supersedes extract_raw_model.py: same RAWM output for models, plus splines and
textures.

Usage:
    python scripts/extract_raw_asset.py model   <out_modelblock.bin>   <id> <out.bin>
    python scripts/extract_raw_asset.py spline  <out_splineblock.bin>  <id> <out.bin>
    python scripts/extract_raw_asset.py texture <out_textureblock.bin> <id> <out.bin>

    python scripts/extract_raw_asset.py verify <kind> <block.bin>
        Carve every entry, rebuild it, and compare against the block byte for
        byte -- proves the discrete format is lossless for that block.

Block layouts (all big-endian, all read through swrLoader_ReadAt):

    model    [count][3 words per entry: mask_off, model_off, (next entry's mask_off)]
    spline   [count][1 word per entry: entry_off, terminated by a final offset]
    texture  [count][2 words per entry: pixels_off, palette_off (0 = no palette)]
             an entry ends where the next entry's pixels_off begins

Discrete file formats. Sizes are little-endian; payloads are copied verbatim, so
they stay big-endian exactly as the game's loader expects to byte-swap them:

    RAWM  magic "RAWM" | u32 mask_size    | u32 model_size   | mask    | model
    RAWS  magic "RAWS" | u32 spline_size  | spline
    RAWT  magic "RAWT" | u32 pixels_size  | u32 palette_size | pixels  | palette

A RAWT with palette_size == 0 is a texture whose format carries no palette (138
of the 1672 stock textures); the block's palette word is 0 for those.
"""
import os
import struct
import sys

MAGIC = {"model": b"RAWM", "spline": b"RAWS", "texture": b"RAWT"}


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def entry_count(data):
    return be32(data, 0)


def carve(kind, data, asset_id):
    """Return the discrete-file bytes for one entry of a packed block."""
    count = entry_count(data)
    if not (0 <= asset_id < count):
        sys.exit(f"{kind} id {asset_id} out of range (block has {count} entries)")

    if kind == "model":
        # three consecutive offset words, 8-byte stride
        mask_off = be32(data, 8 * asset_id + 4)
        model_off = be32(data, 8 * asset_id + 8)
        end = be32(data, 8 * asset_id + 12)
        mask = data[mask_off:model_off]
        model = data[model_off:end]
        return MAGIC[kind] + struct.pack("<II", len(mask), len(model)) + mask + model

    if kind == "spline":
        begin = be32(data, 4 * (asset_id + 1))
        end = be32(data, 4 * (asset_id + 2))
        payload = data[begin:end]
        return MAGIC[kind] + struct.pack("<I", len(payload)) + payload

    if kind == "texture":
        pixels_off = be32(data, 8 * asset_id + 4)
        palette_off = be32(data, 8 * asset_id + 8)
        # the entry runs to the next entry's pixel data (the last one runs to EOF)
        end = be32(data, 8 * (asset_id + 1) + 4) if asset_id + 1 < count else len(data)
        if palette_off == 0:
            pixels = data[pixels_off:end]
            palette = b""
        else:
            pixels = data[pixels_off:palette_off]
            palette = data[palette_off:end]
        return MAGIC[kind] + struct.pack("<II", len(pixels), len(palette)) + pixels + palette

    sys.exit(f"unknown asset kind {kind!r}")


def payloads(kind, chunk):
    """Inverse of carve: the payload sections a discrete file holds, in order."""
    magic = chunk[0:4]
    if magic != MAGIC[kind]:
        sys.exit(f"bad magic {magic!r} (expected {MAGIC[kind]!r})")

    if kind == "spline":
        (size,) = struct.unpack_from("<I", chunk, 4)
        header_end = 8
        if header_end + size != len(chunk):
            sys.exit(f"size mismatch: 8 + {size} != {len(chunk)}")
        return [chunk[header_end:]]

    first, second = struct.unpack_from("<II", chunk, 4)
    header_end = 12
    if header_end + first + second != len(chunk):
        sys.exit(f"size mismatch: 12 + {first} + {second} != {len(chunk)}")
    return [chunk[header_end:header_end + first], chunk[header_end + first:]]


def verify_block(kind, data):
    """Carve and rebuild every entry; report any that does not round-trip."""
    count = entry_count(data)
    mismatched = []
    empty = 0
    for asset_id in range(count):
        if kind == "model":
            begin = be32(data, 8 * asset_id + 4)
            end = be32(data, 8 * asset_id + 12)
        elif kind == "spline":
            begin = be32(data, 4 * (asset_id + 1))
            end = be32(data, 4 * (asset_id + 2))
        else:
            begin = be32(data, 8 * asset_id + 4)
            end = be32(data, 8 * (asset_id + 1) + 4) if asset_id + 1 < count else len(data)

        original = data[begin:end]
        if not original:
            empty += 1
            continue
        if b"".join(payloads(kind, carve(kind, data, asset_id))) != original:
            mismatched.append(asset_id)

    print(f"{kind}: {count} entries, {empty} empty, {len(mismatched)} not byte-identical")
    if mismatched:
        print(f"  first mismatches: {mismatched[:10]}")
        return 1
    print(f"  every entry round-trips through {MAGIC[kind].decode()} unchanged")
    return 0


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "verify":
        kind, block_path = args[1], args[2]
        if kind not in MAGIC:
            sys.exit(f"unknown asset kind {kind!r}")
        with open(block_path, "rb") as f:
            sys.exit(verify_block(kind, f.read()))

    if len(args) != 4 or args[0] not in MAGIC:
        print(__doc__)
        sys.exit(1)

    kind, block_path, asset_id, out_path = args[0], args[1], int(args[2]), args[3]
    with open(block_path, "rb") as f:
        chunk = carve(kind, f.read(), asset_id)

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(chunk)

    sizes = " + ".join(str(len(p)) for p in payloads(kind, chunk))
    print(f"wrote {out_path}: {MAGIC[kind].decode()}, {sizes} bytes of payload")


if __name__ == "__main__":
    main()
