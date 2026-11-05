"""Write the synthetic seed corpora for the fuzz/ harnesses (no game data in the repo).

    python fuzz/make_seeds.py

Well-formed inputs (custom-track blocks shaped like the game's, a small glTF with and without an
animation) so each fuzzer starts past the header checks.
"""

import base64
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus")
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


def gltf_triangle(animated):
    """A one-triangle glTF with an embedded (data URI) buffer; optionally a translation animation."""
    positions = struct.pack("<9f", 0, 0, 0, 1, 0, 0, 0, 1, 0)
    indices = struct.pack("<3H", 0, 1, 2) + bytes(2)  # pad to 4-byte alignment
    times = struct.pack("<2f", 0.0, 1.0)
    moves = struct.pack("<6f", 0, 0, 0, 0, 1, 0)
    blob = positions + indices + (times + moves if animated else b"")
    views = [
        {"buffer": 0, "byteOffset": 0, "byteLength": 36, "target": 34962},
        {"buffer": 0, "byteOffset": 36, "byteLength": 6, "target": 34963},
    ]
    accessors = [
        {"bufferView": 0, "componentType": 5126, "count": 3, "type": "VEC3", "max": [1, 1, 0], "min": [0, 0, 0]},
        {"bufferView": 1, "componentType": 5123, "count": 3, "type": "SCALAR"},
    ]
    doc = {
        "asset": {"version": "2.0"},
        "scene": 0,
        "scenes": [{"nodes": [0]}],
        "nodes": [{"mesh": 0}],
        "meshes": [{"primitives": [{"attributes": {"POSITION": 0}, "indices": 1, "material": 0}]}],
        "materials": [{"pbrMetallicRoughness": {"baseColorFactor": [1, 1, 1, 1]}}],
        "buffers": [{"byteLength": len(blob),
                     "uri": "data:application/octet-stream;base64," + base64.b64encode(blob).decode()}],
        "bufferViews": views,
        "accessors": accessors,
    }
    if animated:
        views += [{"buffer": 0, "byteOffset": 44, "byteLength": 8}, {"buffer": 0, "byteOffset": 52, "byteLength": 24}]
        accessors += [
            {"bufferView": 2, "componentType": 5126, "count": 2, "type": "SCALAR", "max": [1.0], "min": [0.0]},
            {"bufferView": 3, "componentType": 5126, "count": 2, "type": "VEC3"},
        ]
        doc["animations"] = [{"samplers": [{"input": 2, "output": 3}],
                              "channels": [{"sampler": 0, "target": {"node": 0, "path": "translation"}}]}]
    return json.dumps(doc).encode()


def write(name, seeds):
    out = os.path.join(CORPUS, name)
    os.makedirs(out, exist_ok=True)
    for seed, data in seeds.items():
        with open(os.path.join(out, seed), "wb") as f:
            f.write(data)
    print(f"wrote {len(seeds)} seeds to {out}")


def main():
    write("gltf", {"triangle.gltf": gltf_triangle(False), "animated.gltf": gltf_triangle(True)})
    seeds = {
        "spline_one": spline_block([spline_entry(1)]),
        "spline_three": spline_block([spline_entry(2), spline_entry(0), spline_entry(5)]),
        "model_trak": model_block([b"Trak" + bytes(28), b"Podd" + bytes(12)]),
        "model_empty": model_block([]),
    }
    write("custom_track_blocks", seeds)


if __name__ == "__main__":
    main()
