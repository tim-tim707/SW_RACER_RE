#!/usr/bin/env python3
"""Validate a raw-chunk model replacement file and report likely crash causes.

Usage:
    python scripts/validate_raw_model.py <chunk.bin> [<out_modelblock.bin> <model_id>]

Checks the RAWM container, the mask/model sizing, the model tag, and walks the
mask-flagged words to verify pointers land inside the model and texture indices
look sane. If the stock block + id are given, compares against stock.
"""
import struct
import sys

KNOWN_TAGS = {b"Modl", b"Trak", b"Podd", b"Part", b"Scen", b"MAlt", b"Pupp"}


def be32(data, off):
    return struct.unpack_from(">I", data, off)[0]


def analyze(chunk):
    problems = []
    notes = []

    if len(chunk) < 12:
        return ["file is smaller than the 12-byte header"], []

    magic = chunk[0:4]
    mask_size = struct.unpack_from("<I", chunk, 4)[0]
    model_size = struct.unpack_from("<I", chunk, 8)[0]
    notes.append(f"magic={magic!r}  mask_size={mask_size}  model_size={model_size}  "
                 f"file_size={len(chunk)}")

    if magic != b"RAWM":
        problems.append(f"bad magic {magic!r} (expected b'RAWM')")
    if 12 + mask_size + model_size != len(chunk):
        problems.append(f"size mismatch: 12 + {mask_size} + {model_size} = "
                        f"{12 + mask_size + model_size}, but file is {len(chunk)} bytes")
        return problems, notes
    if mask_size % 4 != 0:
        problems.append(f"mask_size {mask_size} is not a multiple of 4 "
                        f"(loader byte-swaps the mask as dwords; the tail won't swap)")
    if model_size % 4 != 0:
        problems.append(f"model_size {model_size} is not a multiple of 4")
    if mask_size > 153600:
        problems.append(f"mask_size {mask_size} exceeds the loader cap 153600 "
                        f"(swrLoader_MaskBuffer) -> loader bails, returns NULL")

    n_words = model_size // 4
    needed_mask = ((n_words + 31) // 32) * 4
    if mask_size != needed_mask:
        problems.append(f"mask covers {mask_size * 8} bits but the model has {n_words} words; "
                        f"expected mask_size = {needed_mask}")

    mask = chunk[12:12 + mask_size]
    model = chunk[12 + mask_size:]

    tag = model[0:4]
    if tag == b"Comp":
        notes.append("model is LZ77-compressed ('Comp'); decompressed by the original loader")
        return problems, notes
    if tag not in KNOWN_TAGS:
        problems.append(f"model does not start with a known tag (got {tag!r}); "
                        f"expected one of {sorted(t.decode() for t in KNOWN_TAGS)} or 'Comp'")

    # walk the mask-flagged words (bit k, MSB-first over bytes, governs word k)
    def bit(k):
        return (mask[k // 8] >> (7 - k % 8)) & 1 if k // 8 < len(mask) else 0

    n_ptr = n_tex = n_null = n_bad_ptr = 0
    bad_ptr_examples = []
    tex_ids = []
    if bit(0):
        problems.append("word 0 is mask-flagged, but the tag word should be literal (mask bit 0)")

    for i in range(n_words):
        if not bit(i):
            continue
        v = be32(model, 4 * i)
        if (v & 0xFF000000) == 0x0A000000:
            n_tex += 1
            tex_ids.append(v & 0xFFFFFF)
        elif v == 0:
            n_null += 1
        else:
            n_ptr += 1
            if v >= model_size:
                n_bad_ptr += 1
                if len(bad_ptr_examples) < 6:
                    bad_ptr_examples.append((i, v))

    notes.append(f"mask-flagged words: {n_ptr} pointers, {n_tex} texture refs, {n_null} null")
    if tex_ids:
        notes.append(f"texture indices referenced: min={min(tex_ids)} max={max(tex_ids)} "
                     f"count={len(tex_ids)}")
    if n_bad_ptr:
        ex = ", ".join(f"word#{i}=0x{v:X}" for i, v in bad_ptr_examples)
        problems.append(f"{n_bad_ptr} pointer(s) point past the end of the model "
                        f"(>= model_size {model_size}) -> rebased outside the buffer -> crash. "
                        f"e.g. {ex}")
    return problems, notes


def main():
    if len(sys.argv) not in (2, 4):
        print(__doc__)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        chunk = f.read()

    print(f"=== {sys.argv[1]} ===")
    problems, notes = analyze(chunk)
    for n in notes:
        print(f"  - {n}")

    if len(sys.argv) == 4:
        with open(sys.argv[2], "rb") as f:
            block = f.read()
        mid = int(sys.argv[3])
        m_off = be32(block, 8 * mid + 4)
        d_off = be32(block, 8 * mid + 8)
        nx_off = be32(block, 8 * mid + 12)
        print(f"  - stock model {mid}: mask_size={d_off - m_off} model_size={nx_off - d_off} "
              f"tag={block[d_off:d_off + 4]!r}")

    if problems:
        print("PROBLEMS:")
        for p in problems:
            print(f"  !! {p}")
        sys.exit(2)
    print("OK: no structural problems found "
          "(a crash may still come from out-of-range texture indices or n64 display-list quirks)")


if __name__ == "__main__":
    main()
