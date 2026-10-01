"""Write the synthetic seed corpus for fuzz_custom_track_blocks (no game data in the repo).

    python fuzz/make_seeds.py

Well-formed spline and model blocks shaped like the game's (big-endian count + offset table),
so the fuzzer starts from inputs that reach the per-entry parsing instead of bailing on the header.
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "corpus", "custom_track_blocks")
SPLINE_HEADER = 0x10
CONTROL_POINT = 0x54


def spline_entry(points):
    # swrSpline header (num_control_points at +0x4), then the control points.
    header = struct.pack(">IIII", 0, points, 0, 0)
    return header + bytes(CONTROL_POINT * points)


def spline_block(entries):
    offsets_end = 4 * (len(entries) + 2)
    offsets, pos = [], offsets_end
    for e in entries:
        offsets.append(pos)
        pos += len(e)
    offsets.append(pos)
    return struct.pack(">I", len(entries)) + b"".join(struct.pack(">I", o) for o in offsets) + b"".join(entries)


def model_block(entries):
    table_end = 8 + 8 * len(entries)
    table, pos = [], table_end
    for e in entries:
        table += [pos, pos + len(e)]
        pos += len(e)
    return struct.pack(">II", len(entries), 0) + b"".join(struct.pack(">I", o) for o in table) + b"".join(entries)


def main():
    os.makedirs(OUT, exist_ok=True)
    seeds = {
        "spline_one": spline_block([spline_entry(1)]),
        "spline_three": spline_block([spline_entry(2), spline_entry(0), spline_entry(5)]),
        "model_trak": model_block([b"Trak" + bytes(28), b"Podd" + bytes(12)]),
        "model_empty": model_block([]),
    }
    for name, data in seeds.items():
        with open(os.path.join(OUT, name), "wb") as f:
            f.write(data)
    print(f"wrote {len(seeds)} seeds to {OUT}")


if __name__ == "__main__":
    main()
