#!/usr/bin/env python3
"""Extract one model from out_modelblock.bin into a raw-chunk replacement file.

Usage:
    python scripts/extract_raw_model.py <out_modelblock.bin> <model_id> <output.bin>

Output format (consumed by dinput_hook/model_replacement.cpp):
    [0]  b"RAWM"
    [4]  uint32 mask_size   (little-endian)
    [8]  uint32 model_size  (little-endian)
    [12] mask payload   (big-endian, verbatim from the block)
    [..] model payload  (big-endian, verbatim from the block)

Round-trip sanity check: extract model N, drop it at
./assets/replacement_models/N.bin, and the game should render identically.
"""
import os
import struct
import sys


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)

    block_path = sys.argv[1]
    model_id = int(sys.argv[2])
    out_path = sys.argv[3]

    with open(block_path, "rb") as f:
        data = f.read()

    num_models = be32(data, 0)
    if not (0 <= model_id < num_models):
        sys.exit(f"model id {model_id} out of range (block has {num_models} models)")

    # TOC entry stride is 8 bytes; each model uses three consecutive offset words.
    mask_offset = be32(data, 8 * model_id + 4)
    model_offset = be32(data, 8 * model_id + 8)
    next_offset = be32(data, 8 * model_id + 12)

    mask = data[mask_offset:model_offset]
    model = data[model_offset:next_offset]

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "wb") as f:
        f.write(b"RAWM")
        f.write(struct.pack("<II", len(mask), len(model)))
        f.write(mask)
        f.write(model)

    kind = "compressed" if model[:4] == b"Comp" else "uncompressed"
    print(f"wrote {out_path}: mask={len(mask)} bytes, model={len(model)} bytes ({kind})")


if __name__ == "__main__":
    main()
