#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "pydantic>=2",
# ]
# ///
"""Bake pod editor spin groups into the game's own model format.

Takes an edits file saved by pod_editor.html (<Pod>.json) and writes a modified copy of the pod's
model as a per-model replacement the mod loads instead of the stock one:

    <game>/assets/replacement_models/<model id>.bin      (RAWM: mask + model, see model_replacement.h)

Each spin group becomes real model data -- a NODE_TRANSFORMED_WITH_PIVOT node placed above the
mesh group holding the selected faces, plus a looping axis-angle (type 8) animation on that node in
the model's 'Anim' list, the same animation system the game uses for track machinery. The game
loads a race pod's animations (swrModel_LoadAllAnimationsOfModel) and the renderer honours the
pivot, so the part turns about the editor's pivot / axis at the editor's RPM. A group's Offset
(moved in the editor) becomes the pivot node's translation and its Scale the node's scale: the part
is shrunk / grown about its pivot and moved, then spins in place (the game's axis-angle update keeps
a node's scale and translation when it rebuilds the rotation).

A group's ellipse cut (its spin lines' "ellipse": { u, rx, ry }, mesh frame) splits the selected
meshes along an ellipse in the plane across the spin axis through the pivot (e.g. an intake face:
only the fan in the middle spins, the rim around it stays put). Every triangle is split exactly
along a 48-sided ellipse (positions, texture coordinates and colours / normals blended along the
cut): the inside stays in the spinning mesh (new vertex list + F3DEX2 display list), the outside
becomes a copy of the mesh in a static mesh group next to the spinning node:
    parent -> new BASIC node -> [ pivot node (spins) -> mesh group (inside),  static mesh group (outside) ]

The animation is written switched off: the racer-select preview would otherwise spin it too. The
mod switches baked pod animations on only during races (pod_edits_animations_frame).

layout.extraCables gives a 2-engine pod a second pair of cockpit -> engine cables: copies of its cable
nodes (part slots 10 / 11) in the 4-engine pods' cable slots 12 / 13, sharing the cable meshes and
added next to the originals in the model tree. The game would aim those at the (missing) second
engine pair, so the mod places them at the right / left engines from the edits file's
layout.extraCables ends (swrRace_delta.cpp).

Usage:
    uv run bake_pod_edits.py <game folder | Desktop/SWEP1R Pod Editor> <edits .json> [--export <pod .json>]
                             [--out <folder>] [--dry-run]
Writes <model id>.bin for each model the edits touch (a pod is drawn from two models, its "alt" model
and its pod model) to --out, or the folder's replacement_models (assets\replacement_models for a game
folder). --export (the pod's export) lets older plain mesh keys be matched to their model.

A spin group that does not cover whole mesh groups is split off: the selected faces of each mesh
move to a copy of the mesh (whole meshes move as they are) in a new mesh group under the pivot
node, the rest stays, and the original group, the pivot node (and a cut's static rim) sit side by
side under a new BASIC node in the group's place. Each mesh's faces may belong to one spin group.

Hide groups are skipped (they stay an in-game pod edit: the editor's Build & install writes them,
renumbered for the split meshes, to assets/pod_edits).

Mesh keys: "<model>:<hex offset>" (offset in that model's file; exports from the current mod) or a
plain hex offset (older exports: the in-memory offset, off the file offset by the buffer's alignment
at load time -- worked out per model from the keys, like pod_editor.html / bake.js).
"""
import argparse
import json
import math
import os
import struct
import sys
from typing import Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, model_validator


NODE_MESH_GROUP = 0x3064
NODE_TRANSFORMED_WITH_PIVOT = 0xD065
NODE_HAS_CHILDREN = 0x4000

ANIM_TYPE_AXIS_ANGLE = 0x8
ANIMATION_LOOP = 0x10
ANIMATION_ENABLED = 0x10000000
ANIM_SIZE = 300          # sizeof(swrModel_Animation): 220 bytes unk1 + 20 words
PIVOT_NODE_SIZE = 88     # node header (28) + rdMatrix34 (48) + pivot (12)


def be32(d, o):
    return struct.unpack_from('>I', d, o)[0]


# ----------------------------------------------------------------------------------------------
class Model:
    """One model payload (big-endian, pointers stored as offsets from the model start) and its
    pointer mask (one bit per 32-bit word, MSB first)."""

    def __init__(self, mask, data):
        self.data = bytearray(data)
        n_words = len(self.data) // 4
        self.bits = [bool((mask[(i // 8)] >> (7 - i % 8)) & 1) if i // 8 < len(mask) else False
                     for i in range(n_words)]

    # -- raw access
    def u32(self, o):
        return struct.unpack_from('>I', self.data, o)[0]

    def u16(self, o):
        return struct.unpack_from('>H', self.data, o)[0]

    def f32(self, o):
        return struct.unpack_from('>f', self.data, o)[0]

    def put32(self, o, v):
        struct.pack_into('>I', self.data, o, v & 0xFFFFFFFF)

    def putf(self, o, v):
        struct.pack_into('>f', self.data, o, v)

    def is_ptr(self, o):
        return self.bits[o // 4]

    def ptr(self, o):
        if not self.is_ptr(o):
            return None
        v = self.u32(o)
        if (v & 0xFF000000) == 0x0A000000:
            return None  # texture reference, not a pointer
        return v or None

    def set_ptr(self, o, target):
        self.put32(o, target)
        self.bits[o // 4] = True

    # -- editing
    def insert(self, at, nbytes):
        """Insert nbytes of zeros at `at` (word-aligned), fixing every pointer into the moved part."""
        assert at % 4 == 0 and nbytes % 4 == 0
        for w, flagged in enumerate(self.bits):
            if not flagged:
                continue
            v = self.u32(w * 4)
            if v == 0 or (v & 0xFF000000) == 0x0A000000:
                continue
            if v >= at:
                self.put32(w * 4, v + nbytes)
        self.data[at:at] = bytes(nbytes)
        wi = at // 4
        self.bits[wi:wi] = [False] * (nbytes // 4)

    def append(self, nbytes, align=8):
        """Reserve nbytes of zeros at the end (aligned); returns their offset."""
        while len(self.data) % align:
            self.data += b'\0'
            self.bits.append(False)
        o = len(self.data)
        self.data += bytes(nbytes)
        self.bits += [False] * (nbytes // 4)
        return o

    def mask_bytes(self):
        n_words = len(self.data) // 4
        out = bytearray(((n_words + 31) // 32) * 4)
        for i, b in enumerate(self.bits):
            if b:
                out[i // 8] |= 0x80 >> (i % 8)
        return bytes(out)

    # -- structure
    def header(self):
        """Offsets of the header sections (see swrModel_ByteSwapModelData)."""
        o = 4
        roots = []
        while self.u32(o) != 0xFFFFFFFF:
            roots.append(o)
            o += 4
        h = {'roots': roots, 'roots_end': o}
        o += 4
        if self.data[o:o + 4] == b'Data':
            o += 8 + 4 * self.u32(o + 4)
        h['after_data'] = o
        if self.data[o:o + 4] == b'Anim':
            h['anim'] = o
            o += 4
            while self.u32(o):
                o += 4
            h['anim_end'] = o  # the terminating 0
        return h

    def node(self, o):
        return {'off': o, 'type': self.u32(o), 'num_children': self.u32(o + 20), 'children': self.ptr(o + 24)}

    def child_slots(self, o):
        n = self.node(o)
        if not ((n['type'] & NODE_HAS_CHILDREN) or n['type'] == NODE_MESH_GROUP) or not n['children']:
            return []
        return [n['children'] + 4 * i for i in range(n['num_children'])]

    def walk(self):
        """Every node reachable from the header roots / AltN; returns {node: [parent child-slot offsets]},
        and mesh-group meshes."""
        h = self.header()
        starts = [self.ptr(r) for r in h['roots']]
        header_slots = list(h['roots'])  # header references count as parents too (after the tree's)
        o = h.get('anim_end', h['after_data'] - 4) + 4
        if self.data[o:o + 4] == b'AltN':
            o += 4
            while self.u32(o):
                starts.append(self.ptr(o))
                header_slots.append(o)
                o += 4
        parents, groups, seen = {}, {}, set()
        stack = [s for s in starts if s]
        while stack:
            n = stack.pop()
            if n in seen:
                continue
            seen.add(n)
            t = self.u32(n)
            slots = self.child_slots(n)
            if t == NODE_MESH_GROUP:
                groups[n] = [self.ptr(s) for s in slots if self.ptr(s)]
                continue
            for s in slots:
                c = self.ptr(s)
                if c:
                    parents.setdefault(c, []).append(s)
                    stack.append(c)
        # A part slot or AltN entry pointing straight at a node (e.g. the alt models' mesh groups
        # listed only in AltN): re-parenting must move that reference too.
        for s in header_slots:
            c = self.ptr(s)
            if c:
                parents.setdefault(c, []).append(s)
        return parents, groups

    def mesh_triangles(self, mesh):
        """Triangles in a mesh's F3DEX2 display list, in draw order (G_TRI1 / G_TRI2 / G_QUAD)."""
        dl = self.ptr(mesh + 48)
        n = 0
        o = dl
        for _ in range(100000):
            op = self.data[o]
            if op == 0x05:
                n += 1
            elif op in (0x06, 0x07):
                n += 2
            elif op == 0xDF:
                return n
            o += 8
        raise ValueError(f'display list of mesh {mesh:#x} never ends')


# ----------------------------------------------------------------------------------------------
# Ellipse cut: decode a mesh's triangles, clip them, write a new vertex list + display list.
def decode_mesh(m, mesh):
    """[(x, y, z, u, v, b0, b1, b2, b3) x 3] per triangle, in draw order, plus whether the 4 bytes are
    a normal (signed) + alpha rather than a colour."""
    material = m.ptr(mesh)
    has_normals = bool(material and (m.u32(material) & 0x11))
    cache = [None] * 256
    o = m.ptr(mesh + 48)
    tris = []

    def vtx(a):
        x, y, z = struct.unpack_from('>hhh', m.data, a)
        u, v = struct.unpack_from('>hh', m.data, a + 8)
        b = struct.unpack_from('>bbbB' if has_normals else '>BBBB', m.data, a + 12)
        return (float(x), float(y), float(z), float(u), float(v)) + tuple(float(c) for c in b)

    while True:
        op = m.data[o]
        if op == 0x01:
            n = (struct.unpack_from('>H', m.data, o + 1)[0] >> 4) & 0xFF
            v0 = (m.data[o + 3] >> 1) - n
            base = m.ptr(o + 4)
            for i in range(n):
                cache[v0 + i] = vtx(base + 16 * i)
        elif op == 0x05:
            tris.append([cache[m.data[o + k] // 2] for k in (1, 2, 3)])
        elif op == 0x06:
            tris.append([cache[m.data[o + k] // 2] for k in (1, 2, 3)])
            tris.append([cache[m.data[o + k] // 2] for k in (5, 6, 7)])
        elif op == 0xDF:
            break
        elif op != 0x03:
            raise ValueError(f'mesh {mesh:#x}: unsupported display list command {op:#x}')
        o += 8
    return tris, has_normals


def clip_to_ellipse(tris, centre, axis, u, rx, ry, sides=48):
    """Split triangles along the 48-gon inscribed in the ellipse (a prism along the axis).
    Returns (inside, outside): each triangle's inside part, and its outside part as the pieces cut
    off by each edge in turn -- an exact partition, so the two never overlap or leave gaps."""
    def norm(a):
        l = math.sqrt(sum(c * c for c in a)) or 1.0
        return tuple(c / l for c in a)

    def cross(a, b):
        return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])

    ax = norm(axis)
    uu = norm(tuple(u[i] - ax[i] * sum(u[j] * ax[j] for j in range(3)) for i in range(3)))
    vv = norm(cross(ax, uu))

    def ab(p):
        d = tuple(p[i] - centre[i] for i in range(3))
        return sum(d[i] * uu[i] for i in range(3)) / rx, sum(d[i] * vv[i] for i in range(3)) / ry

    lim = math.cos(math.pi / sides)

    def clip(poly, dist, keep_inside):
        out = []
        for i in range(len(poly)):
            p, q = poly[i], poly[(i + 1) % len(poly)]
            dp, dq = dist(p), dist(q)
            pin, qin = (dp <= 0) == keep_inside, (dq <= 0) == keep_inside
            if pin:
                out.append(p)
            if pin != qin:
                t = dp / (dp - dq)
                out.append(tuple(p[j] + (q[j] - p[j]) * t for j in range(len(p))))
        return out

    def fan(poly, out):
        for i in range(1, len(poly) - 1):
            out.append([poly[0], poly[i], poly[i + 1]])

    inside, outside = [], []
    for tri in tris:
        poly = list(tri)
        for k in range(sides):
            th = 2 * math.pi * (k + 0.5) / sides
            cs, sn = math.cos(th), math.sin(th)

            def dist(p, cs=cs, sn=sn):
                a, b = ab(p)
                return a * cs + b * sn - lim  # <= 0 inside this edge

            piece = clip(poly, dist, False)
            if len(piece) >= 3:
                fan(piece, outside)
            poly = clip(poly, dist, True)
            if len(poly) < 3:
                break
        if len(poly) >= 3:
            fan(poly, inside)
    return inside, outside


def write_mesh(m, mesh, tris, has_normals):
    """New vertex list (one entry per triangle corner) + display list for a mesh, appended to the
    model; the mesh's pointers, vertex count and bounds are updated."""
    verts = [v for t in tris for v in t]
    vbuf = m.append(16 * max(len(verts), 1))
    for i, v in enumerate(verts):
        o = vbuf + 16 * i
        x, y, z = (max(-32768, min(32767, int(round(c)))) for c in v[0:3])
        uq, vq = (max(-32768, min(32767, int(round(c)))) for c in v[3:5])
        struct.pack_into('>hhhHhh', m.data, o, x, y, z, 0, uq, vq)
        if has_normals:
            nx, ny, nz = v[5:8]
            l = math.sqrt(nx * nx + ny * ny + nz * nz) or 1.0
            packed = [max(-127, min(127, int(round(c / l * 127.0)))) for c in (nx, ny, nz)]
            struct.pack_into('>bbbB', m.data, o + 12, *packed, max(0, min(255, int(round(v[8])))))
        else:
            struct.pack_into('>BBBB', m.data, o + 12, *(max(0, min(255, int(round(c)))) for c in v[5:9]))
    # Batches of up to 42 triangles (126 vertices: G_VTX's v0 + n field is 7 bits).
    cmds = []
    batch = 42
    for b0 in range(0, len(tris), batch):
        nt = min(batch, len(tris) - b0)
        n = 3 * nt
        cmds.append(('vtx', n, vbuf + 16 * 3 * b0))
        for t in range(0, nt - 1, 2):
            cmds.append(('tri2', 3 * t, 3 * t + 1, 3 * t + 2, 3 * t + 3, 3 * t + 4, 3 * t + 5))
        if nt % 2:
            t = nt - 1
            cmds.append(('tri1', 3 * t, 3 * t + 1, 3 * t + 2))
    dl = m.append(8 * (len(cmds) + 1))
    for i, c in enumerate(cmds):
        o = dl + 8 * i
        if c[0] == 'vtx':
            n = c[1]
            m.data[o] = 0x01
            struct.pack_into('>H', m.data, o + 1, (n & 0xFF) << 4)
            m.data[o + 3] = (n & 0x7F) << 1  # (v0 + n) << 1, v0 = 0
            m.set_ptr(o + 4, c[2])
        elif c[0] == 'tri1':
            m.data[o] = 0x05
            m.data[o + 1:o + 4] = bytes(2 * x for x in c[1:4])
        else:
            m.data[o] = 0x06
            m.data[o + 1:o + 4] = bytes(2 * x for x in c[1:4])
            m.data[o + 5:o + 8] = bytes(2 * x for x in c[4:7])
    m.data[dl + 8 * len(cmds)] = 0xDF
    m.set_ptr(mesh + 48, dl)
    m.set_ptr(mesh + 52, vbuf)
    struct.pack_into('>H', m.data, mesh + 58, min(len(verts), 0xFFFF))
    if verts:
        lo = [min(v[k] for v in verts) for k in range(3)]
        hi = [max(v[k] for v in verts) for k in range(3)]
        for k in range(3):
            m.putf(mesh + 8 + 4 * k, lo[k])
            m.putf(mesh + 20 + 4 * k, hi[k])


MESH_SIZE = 64          # sizeof(swrModel_Mesh)
MESH_GROUP_SIZE = 0x3C  # mesh group node: node header (28) + aabb (24) + 2 cached matrix pointers
BASIC_NODE_SIZE = 28


def copy_block(m, src, size):
    """Append a copy of `size` bytes at `src`, pointer bits included; returns the copy's offset."""
    dst = m.append(size)
    m.data[dst:dst + size] = m.data[src:src + size]
    for w in range(size // 4):
        m.bits[dst // 4 + w] = m.bits[src // 4 + w]
    return dst


def cut_mesh(m, mesh, pivot, axis, cut):
    """Keep the inside of the ellipse in `mesh`; returns (inside count, a new mesh holding the
    outside or None)."""
    tris, has_normals = decode_mesh(m, mesh)
    ux, uy, uz, rx, ry = cut
    inside, outside = clip_to_ellipse(tris, pivot, axis, (ux, uy, uz), rx, ry)
    rim = None
    if outside:
        rim = copy_block(m, mesh, MESH_SIZE)
        write_mesh(m, rim, outside, has_normals)
    write_mesh(m, mesh, inside, has_normals)
    return len(inside), len(outside), rim


# ----------------------------------------------------------------------------------------------
CABLE_SLOTS = ((10, 12), (11, 13))  # (stock cable, extra cable) part slots: right, left


def clone_next_to(m, src, roots):
    """A copy of a node (its children shared) hung next to it under the same parent node."""
    size = PIVOT_NODE_SIZE if m.u32(src) == NODE_TRANSFORMED_WITH_PIVOT else 76
    node = copy_block(m, src, size)
    n_kids = m.u32(src + 20)
    kids = m.ptr(src + 24)
    if kids:
        m.set_ptr(node + 24, copy_block(m, kids, 4 * max(n_kids, 1)))
    parents, _ = m.walk()
    slot = parents[src][0]
    owner = next((o for o in list(dict.fromkeys(list(parents) + [m.ptr(r) for r in roots if m.ptr(r)]))
                  if o and slot in m.child_slots(o)), None)
    if owner is None:
        sys.exit(f'{src:#x} has no parent node to hang a copy under')
    n = m.u32(owner + 20)
    old = m.ptr(owner + 24)
    lst = m.append(4 * (n + 1))
    for i in range(n):
        c = m.ptr(old + 4 * i)
        if c:
            m.set_ptr(lst + 4 * i, c)
    m.set_ptr(lst + 4 * n, node)
    m.put32(owner + 20, n + 1)
    m.set_ptr(owner + 24, lst)
    return node


def add_trails(m, trails):
    """Extra exhaust trails: a copy of that side's stock exhaust node (part slot 0x43 right, 0x44
    left) per trail, sharing its trail; the mod places them (the edits' trailNodes)."""
    roots = m.header()['roots']
    out = []
    for side, pos, scale in trails:
        src = m.ptr(roots[0x43 if side == 'R' else 0x44])
        if not src:
            sys.exit(f'extra trail: this pod has no exhaust node for the {side} engine')
        node = clone_next_to(m, src, roots)
        out.append((node, side, pos, scale))
        print(f'  extra trail ({side}): copy of the exhaust node {src:#x} -> {node:#x}')
    return out


def add_extra_cables(m):
    """Copies of cable nodes 10 / 11 in part slots 12 / 13 (2-engine pods only)."""
    h = m.header()
    roots = h['roots']
    if m.ptr(roots[3]) or m.ptr(roots[4]):
        sys.exit('extra cables: this pod already has four engines (and their cables)')
    for src_slot, dst_slot in CABLE_SLOTS:
        src = m.ptr(roots[src_slot])
        if not src:
            sys.exit(f'extra cables: this pod has no cable in part slot {src_slot} to copy')
        if m.ptr(roots[dst_slot]):
            print(f'  part slot {dst_slot} already holds a cable: kept')
            continue
        size = PIVOT_NODE_SIZE if m.u32(src) == NODE_TRANSFORMED_WITH_PIVOT else 76
        node = copy_block(m, src, size)
        n_kids = m.u32(src + 20)
        kids = m.ptr(src + 24)
        if kids:
            m.set_ptr(node + 24, copy_block(m, kids, 4 * max(n_kids, 1)))
        # Hang it next to the original cable (same parent), so it is drawn.
        parents, _ = m.walk()
        slot = parents[src][0]
        owner = next(o for o in set(list(parents) + [m.ptr(r) for r in roots if m.ptr(r)])
                     if o and slot in m.child_slots(o))
        n = m.u32(owner + 20)
        old = m.ptr(owner + 24)
        lst = m.append(4 * (n + 1))
        for i in range(n):
            c = m.ptr(old + 4 * i)
            if c:
                m.set_ptr(lst + 4 * i, c)
        m.set_ptr(lst + 4 * n, node)
        m.put32(owner + 20, n + 1)
        m.set_ptr(owner + 24, lst)
        m.set_ptr(roots[dst_slot], node)
        print(f'  extra cable: part slot {dst_slot} = copy of cable {src_slot} ({src:#x} -> {node:#x}, under {owner:#x})')


def strip_embedded(data):
    """The model data without the in-game edits a model can carry at its end (pod_editor.html's
    Build appends them: <text> <padding> <u32 length, little-endian> b'SWRPEDT1'). This script
    doesn't write them; it bakes from the model without them, like bake.js."""
    if len(data) < 20 or bytes(data[-8:]) != b'SWRPEDT1':
        return data
    n = struct.unpack_from('<I', data, len(data) - 12)[0]
    padded = n
    while (padded + 12) % 8:
        padded += 1
    start = len(data) - 12 - padded
    return data[:start] if start >= 0 else data


def fingerprint(mask, data):
    """A short fingerprint of a model's mask + data ("<mask bytes>.<data bytes>-<FNV-1a 32>", hex), the
    same as bake.js and the mod compute. A baked model is stamped with its base model's (<id>.hash),
    so the mod can tell when a model built on other game data doesn't fit this game."""
    h = 2166136261
    for b in bytes(mask) + bytes(data):
        h = ((h ^ b) * 16777619) & 0xFFFFFFFF
    return f'{len(mask):x}.{len(data):x}-{h:08x}'


def read_block_entry(block, model_id):
    mask_off, model_off, end = struct.unpack_from('>III', block, 8 * model_id + 4)
    return block[mask_off:model_off], block[model_off:end]


Vec2 = Tuple[float, float]
Vec3 = Tuple[float, float, float]


class EditsModel(BaseModel):
    # Unknown fields are kept out of the way rather than refused: newer editors may add some.
    model_config = ConfigDict(extra='ignore')


class Ellipse(EditsModel):
    u: Vec3  # the ellipse's first axis (mesh frame)
    rx: float
    ry: float


class Mirror(EditsModel):
    linear: Tuple[float, float, float, float, float, float, float, float, float]
    move: Vec3


class Piece(EditsModel):
    merged: bool = False
    move: Vec3 = (0.0, 0.0, 0.0)


class Signature(EditsModel):
    mesh: str
    meshHash: str
    faces: Dict[str, str] = {}


class Line(EditsModel):
    """One mesh's faces in a group: hidden (a "hide" group) or spun (a "spin" group, mesh frame)."""
    mesh: str
    faces: List[Tuple[int, int]]
    rpm: Optional[float] = None
    pivot: Optional[Vec3] = None
    axis: Optional[Vec3] = None
    offset: Vec3 = (0.0, 0.0, 0.0)
    scale: float = 1.0
    ellipse: Optional[Ellipse] = None
    rot: Optional[Vec3] = None
    rotm: Optional[Tuple[float, float, float, float, float, float, float, float, float]] = None
    stretch: Optional[Vec3] = None
    mirror: Optional[Mirror] = None
    reshape: bool = False
    piece: Optional[Piece] = None

    def face_set(self):
        out = set()
        for a, b in self.faces:
            out.update(range(a, b + 1))
        return out


class Group(EditsModel):
    name: str = ''
    type: Literal['spin', 'hide']
    lines: List[Line] = []
    signatures: List[Signature] = []

    @model_validator(mode='after')
    def spin_lines_have_motion(self):
        if self.type == 'spin':
            for ln in self.lines:
                if ln.rpm is None or ln.pivot is None or ln.axis is None:
                    raise ValueError(f'spin group "{self.name}": a line for mesh {ln.mesh} has no rpm / pivot / axis')
        return self


class OwnCable(EditsModel):
    cable: int
    cockpit: Optional[Vec3] = None
    engine: Optional[Vec3] = None


class CablePair(EditsModel):
    cockpit: Optional[Vec3] = None
    engine: Optional[Vec3] = None


class Layout(EditsModel):
    cableCockpit: Optional[Vec3] = None
    cableEngine: Optional[Vec3] = None
    binder: Optional[Vec3] = None
    exhaust: Optional[Vec3] = None
    exhaustScale: Optional[Vec3] = None
    ownCables: List[OwnCable] = []
    extraCables: Optional[CablePair] = None


class Pod(EditsModel):
    height: Optional[float] = None
    engineGap: Optional[float] = None
    cockpitGap: Optional[float] = None
    cockpitMove: Optional[Vec3] = None
    chaseCamNear: Optional[Vec2] = None
    chaseCamFar: Optional[Vec2] = None
    rearCam: Optional[Vec2] = None


class Nozzle(EditsModel):
    pos: Vec3
    size: float = 0.0
    length: float = 1.0
    height: float = 1.0
    width: float = 1.0


class Point(EditsModel):
    pos: Vec3


class Trail(EditsModel):
    pos: Vec3
    scale: Vec3 = (1.0, 1.0, 1.0)


class Sides(EditsModel):
    R: List[Point] = []
    L: List[Point] = []


class NozzleSides(EditsModel):
    R: List[Nozzle] = []
    L: List[Nozzle] = []


class TrailSides(EditsModel):
    R: List[Trail] = []
    L: List[Trail] = []


class NozzleFlame(EditsModel):
    width: float = 1.0
    length: float = 1.0
    height: float = 1.0


class ExhaustLight(EditsModel):
    aim: float = 0.7
    reach: float = 1.0
    width: float = 1.0
    strength: float = 1.0


class GameFireStreak(EditsModel):
    length: float = 1.0
    turn: Vec3 = (0.0, 0.0, 0.0)


class Effects(EditsModel):
    nozzles: Optional[NozzleSides] = None
    fireSpots: Optional[Sides] = None
    dustSpots: Optional[Sides] = None
    gameFire: Optional[Sides] = None
    trails: Optional[TrailSides] = None
    nozzleFlame: Optional[NozzleFlame] = None
    exhaustLight: Optional[ExhaustLight] = None
    gameFireStreak: Optional[GameFireStreak] = None


class SpinNode(EditsModel):
    node: str
    rpm: float
    axis: Vec3


class TrailNode(EditsModel):
    node: str
    side: Literal['R', 'L']
    pos: Vec3
    scale: Vec3 = (1.0, 1.0, 1.0)


class Edits(EditsModel):
    """A pod's edits: the JSON document pod_editor.html writes (described in bake.js, "edits documents")."""
    format: Literal['swr-pod-edits']
    version: int
    model: str = ''
    rpmSense: Literal['mesh', 'pod'] = 'mesh'
    baseModels: Dict[str, str] = {}
    groups: List[Group] = []
    layout: Optional[Layout] = None
    pod: Optional[Pod] = None
    effects: Optional[Effects] = None
    spinNodes: List[SpinNode] = []
    trailNodes: List[TrailNode] = []


class BakeInput:
    """What the bake takes from the edits: spin groups by motion, piece moves, hidden meshes, the extra
    cable pair and the extra trails."""

    def __init__(self, edits):
        self.groups = {}  # (rpm, pivot, axis, offset, scale, cut): {mesh key: {faces}}
        self.pre = {}  # spin group pieces: {group params: {mesh key: {face: (dx, dy, dz)}}} (mesh frame)
        self.hide_keys = []
        self.extra_cables = edits.layout is not None and edits.layout.extraCables is not None
        self.trails = []
        placed = False
        for g in edits.groups:
            for ln in g.lines:
                key = ln.mesh.lower()
                if g.type == 'hide':
                    self.hide_keys.append(key)
                    print(f'note: hide line for mesh {ln.mesh} skipped (it stays an in-game edit: keep the edits '
                          f'file in assets/pod_edits)')
                    continue
                placed |= ln.rotm is not None or ln.mirror is not None or ln.reshape
                cut = (*ln.ellipse.u, ln.ellipse.rx, ln.ellipse.ry) if ln.ellipse else None
                params = (ln.rpm, tuple(ln.pivot), tuple(ln.axis), tuple(ln.offset), ln.scale, cut)
                faces = ln.face_set()
                self.groups.setdefault(params, {}).setdefault(key, set()).update(faces)  # a mesh's pieces add up
                if ln.piece is not None and any(ln.piece.move):
                    self.pre.setdefault(params, {}).setdefault(key, {}).update({t: tuple(ln.piece.move) for t in faces})
        if placed:
            print('note: turned / mirrored parts and reshapes are baked by the pod editor (Build & install), not by this '
                  'script: their placement is left out here')
        if edits.effects is not None and edits.effects.trails is not None:
            for side in ('R', 'L'):
                for t in getattr(edits.effects.trails, side):
                    self.trails.append((side, tuple(t.pos), tuple(t.scale)))


def parse_edits(path):
    """The edits file (JSON) at path, checked against the Edits model."""
    with open(path, encoding='utf-8') as f:
        return BakeInput(Edits.model_validate_json(f.read()))


def pod_index(block):
    """{model id: (tag, set of mesh file offsets)} for every pod model."""
    out = {}
    for mid in range(be32(block, 0)):
        mask, data = read_block_entry(block, mid)
        if len(data) < 8 or data[:4] not in (b'Podd', b'MAlt'):
            continue
        try:
            _, groups = Model(mask, data).walk()
        except Exception:
            continue
        out[mid] = (data[:4], {x for g in groups.values() for x in g})
    return out


def resolve_keys(idx, keys, export_keys=()):
    """{key: (model, file offset)}. Older plain keys: each (model, alignment) pair that would explain
    one is scored by how many of the keys it explains, and the best wins."""
    legacy = [k for k in dict.fromkeys(list(keys) + list(export_keys)) if ':' not in k]

    def cands(k):
        off = int(k, 16)
        return [(mid, sh) for mid, (_, meshes) in idx.items() for sh in range(-16, 36, 4) if off - sh in meshes]

    support = {}
    for k in legacy:
        for c in cands(k):
            support[c] = support.get(c, 0) + 1
    out = {}
    for k in keys:
        if ':' in k:
            a, b = k.split(':', 1)
            out[k] = (int(a), int(b, 16))
            continue
        c = sorted(cands(k), key=lambda c: -support[c])  # stable, like the JS sort
        if c:
            out[k] = (c[0][0], int(k, 16) - c[0][1])
    return out


def pod_model_of(idx, keys):
    """The 'Podd' model among the models the keys resolve to (most keys first)."""
    count = {}
    for mid, _ in resolve_keys(idx, keys, keys).values():
        count[mid] = count.get(mid, 0) + 1
    for mid in sorted(count, key=lambda i: -count[i]):
        if idx[mid][0] == b'Podd':
            return mid
    return None


def bake(game_dir, edits_path, out_dir=None, dry_run=False, export_path=None):
    workspace = os.path.isfile(os.path.join(game_dir, 'out_modelblock.bin'))
    block_path = os.path.join(game_dir, 'out_modelblock.bin') if workspace else \
        os.path.join(game_dir, 'data', 'lev01', 'out_modelblock.bin')
    block = open(block_path, 'rb').read()
    edits = parse_edits(edits_path)
    spin_groups, extra_cables, trails = edits.groups, edits.extra_cables, edits.trails
    if not spin_groups and not extra_cables and not trails:
        sys.exit('nothing to bake: no spin groups, extra cables or extra trails in the edits file')
    export_keys = []
    if export_path:
        export_keys = [x['key'].lower() for x in json.load(open(export_path, encoding='utf-8'))['meshes']]
    keys = list(dict.fromkeys([k for g in spin_groups.values() for k in g] + edits.hide_keys))
    idx = pod_index(block)
    resolved = resolve_keys(idx, keys, export_keys)
    missing = [k for k in keys if k not in resolved]
    if missing:
        sys.exit(f'no pod model has the mesh(es) {", ".join(missing)} (export from other game data, or made while a '
                 f'baked model was loaded?)')
    # Spin groups split by model (a group can hold meshes of both of the pod's models).
    per_model = {}
    moves_per_model = {}
    for params, meshes in spin_groups.items():
        by_model = {}
        for k, tris in meshes.items():
            mid, off = resolved[k]
            by_model.setdefault(mid, {})[off] = tris
        for mid, ms in by_model.items():
            per_model.setdefault(mid, {})[params] = ms
        for k, faces in edits.pre.get(params, {}).items():
            mid, off = resolved[k]
            moves_per_model.setdefault(mid, {}).setdefault(off, {}).update(faces)
    cable_model = None
    if extra_cables or trails:
        cable_model = pod_model_of(idx, export_keys or keys)
        if cable_model is None:
            sys.exit('extra cables / trails: cannot find this pod\'s model (pass --export <the pod\'s export .json>)')
        per_model.setdefault(cable_model, {})
    if out_dir is None:
        out_dir = os.path.join(game_dir, 'replacement_models') if workspace else \
            os.path.join(game_dir, 'assets', 'replacement_models')
    written = []
    for mid in sorted(per_model):
        entry_mask, entry_data = read_block_entry(block, mid)
        m = Model(entry_mask, strip_embedded(entry_data))
        print(f'model {mid}: {m.data[:4].decode()}, {len(m.data)} bytes')
        out = bake_model(m, mid, per_model[mid], mid == cable_model and extra_cables, dry_run, moves_per_model.get(mid, {}),
                         trails if mid == cable_model else [])
        if out is None:
            continue
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f'{mid}.bin')
        open(path, 'wb').write(out)
        print(f'wrote {path} ({len(out)} bytes)')
        written.append(path)
        open(os.path.join(out_dir, f'{mid}.hash'), 'w').write(fingerprint(*read_block_entry(block, mid)) + '\n')
        r4 = lambda v: round(v * 1e4) / 1e4
        if bake_model.trail_nodes:
            print('  add to the in-game edits\' "trailNodes" (assets/pod_edits/<Pod>.json) so the mod places them:')
            for node, side, pos, scale in bake_model.trail_nodes:
                print('    ' + json.dumps({'node': f'{mid}:{node:x}', 'side': side, 'pos': [r4(c) for c in pos],
                                         'scale': [r4(c) for c in scale]}))
        if bake_model.spin_nodes:
            print('  add to the in-game edits\' "spinNodes" (assets/pod_edits/<Pod>.json) so the mod turns them:')
            for node, rpm, ax in bake_model.spin_nodes:
                print('    ' + json.dumps({'node': f'{mid}:{node:x}', 'rpm': r4(rpm), 'axis': [r4(c) for c in ax]}))
    return written


def bake_model(m, mid, spin_groups, extra_cables, dry_run=False, moves=None, trails=()):
    """One model: its spin groups ({params: {mesh file offset: faces}}) and maybe the extra cable
    pair. Returns the RAWM file bytes (None for a dry run)."""
    parents, mesh_groups = m.walk()
    mesh_to_group = {x: g for g, ms in mesh_groups.items() for x in ms}

    # Spin group pieces: their faces moved first (mesh frame), in place in their meshes; the split and
    # spin below then take them from there.
    for mesh, faces in (moves or {}).items():
        if mesh not in mesh_to_group:
            sys.exit(f'mesh {mid}:{mesh:x} is not in a mesh group of this model')
        tris, has_normals = decode_mesh(m, mesh)
        moved = []
        for t, tri in enumerate(tris):
            v = faces.get(t)
            moved.append([(p[0] + v[0], p[1] + v[1], p[2] + v[2]) + tuple(p[3:]) for p in tri] if v else tri)
        write_mesh(m, mesh, moved, has_normals)
        print(f'  moved {len(faces)} face(s) of mesh {mid}:{mesh:x} (spin group pieces)')

    # Each spin group's mesh groups: whole groups spin as they are, otherwise the faces are split off.
    plan = []
    mesh_owner = {}
    for si, ((rpm, pivot, axis, offset, scale, cut), meshes) in enumerate(spin_groups.items()):
        offs = meshes
        for mesh, tris in offs.items():
            if mesh not in mesh_to_group:
                sys.exit(f'mesh {mid}:{mesh:x} is not in a mesh group of this model')
            total = m.mesh_triangles(mesh)
            if any(t < 0 or t >= total for t in tris):
                sys.exit(f'mesh {mid}:{mesh:x}: the spin group names faces past its {total} faces')
            if mesh_owner.get(mesh, si) != si:
                sys.exit(f'mesh {mid}:{mesh:x} has faces in two spin groups')
            mesh_owner[mesh] = si
        for g in sorted({mesh_to_group[x] for x in offs}):
            if g not in parents:
                sys.exit(f'mesh group {g:#x} has no parent node')
            sel = [x for x in mesh_groups[g] if x in offs]
            whole = len(sel) == len(mesh_groups[g]) and all(len(offs[x]) == m.mesh_triangles(x) for x in sel)
            plan.append({'group': g, 'rpm': rpm, 'pivot': pivot, 'axis': axis, 'offset': offset, 'scale': scale,
                         'cut': cut, 'meshes': list(mesh_groups[g]) if whole else sel, 'whole': whole,
                         'select': {x: offs[x] for x in sel}})
            what = (f'{len(mesh_groups[g])} meshes' if whole else
                    ', '.join(f'{len(offs[x])}/{m.mesh_triangles(x)} faces of {mid}:{x:x}' for x in sel))
            print(f'  spin {"mesh group" if whole else "faces of mesh group"} {g:#x} ({what}, under {len(parents[g])} '
                  f'parent(s)) at {rpm:g} rpm, pivot {pivot}, axis {axis}, moved by {offset}, scale {scale:g}'
                  + (f', cut to an ellipse {cut[3]:g} x {cut[4]:g}' if cut else ''))
    if dry_run:
        return

    # 1) Room in the header's 'Anim' list for the new animations (shifts everything after it). Not in
    # an alt model ('MAlt'): the game merges its AltN parts into the pod model only when AltN follows
    # the part slots directly, and never runs an alt model's animations -- its spinning nodes are
    # printed as spinNodes instead (the mod turns them; the editor's Build & install writes
    # them to the in-game edits file).
    is_alt = m.data[:4] == b'MAlt'
    bake_model.spin_nodes = []
    h = m.header()
    anim_slots = []
    n_new = 0 if is_alt else sum(1 for p in plan if p['rpm'])
    if n_new == 0:
        pass
    elif 'anim' in h:
        at = h['anim_end']
        m.insert(at, 4 * n_new)
        anim_slots = [at + 4 * i for i in range(n_new)]
    else:
        at = h['after_data']
        m.insert(at, 4 + 4 * n_new + 4)
        m.data[at:at + 4] = b'Anim'
        anim_slots = [at + 4 + 4 * i for i in range(n_new)]
    for slot in anim_slots:  # placeholders: a 0 would end the list early and hide AltN from the walk
        m.put32(slot, 1)
    parents, mesh_groups = m.walk()  # offsets moved

    # 2) New pivot node + animation per spin group, appended at the end of the model.
    shift = (4 + 4 * n_new + 4 if 'anim' not in h else 4 * n_new) if n_new else 0
    for p in plan:
        p['static'] = []
        if not p['cut'] or not p['whole']:  # partial groups are cut after their split
            continue
        for mesh in p['meshes']:
            before = m.mesh_triangles(mesh + shift)
            n_in, n_out, rim = cut_mesh(m, mesh + shift, p['pivot'], p['axis'], p['cut'])
            if rim is not None:
                p['static'].append(rim)
            print(f'  cut mesh {mesh:#x} along the ellipse: {before} faces -> {n_in} spinning + {n_out} static')
    slot_i = 0
    wrappers = {}  # mesh group -> BASIC node holding it + the spinning parts split off it
    for p in plan:
        g = p['group'] + shift
        assert m.u32(g) == NODE_MESH_GROUP, f'{g:#x} is not a mesh group after the move'
        flags1, flags2, flags5 = m.u32(g + 4), m.u32(g + 8), m.u32(g + 16)
        spinning = g
        if not p['whole']:
            # Split: selected faces of each mesh to a copy of it (whole meshes move as they are), in
            # a new mesh group the pivot node turns; the rest stays in the original group.
            keep, moved = [], []
            n, lst = m.u32(g + 20), m.ptr(g + 24)
            for i in range(n):
                x = m.ptr(lst + 4 * i)
                if not x:
                    continue
                sel = p['select'].get(x - shift)
                if sel is None:
                    keep.append(x)
                    continue
                total = m.mesh_triangles(x)
                if len(sel) == total:
                    moved.append(x)
                    continue
                tris, has_normals = decode_mesh(m, x)
                part = copy_block(m, x, MESH_SIZE)
                write_mesh(m, part, [t for i2, t in enumerate(tris) if i2 in sel], has_normals)
                write_mesh(m, x, [t for i2, t in enumerate(tris) if i2 not in sel], has_normals)
                keep.append(x)
                moved.append(part)
                print(f'  split mesh {mid}:{x - shift:x}: {len(sel)} faces spin, {total - len(sel)} stay')
            keep_list = m.append(4 * max(len(keep), 1))
            for i, x in enumerate(keep):
                m.set_ptr(keep_list + 4 * i, x)
            m.put32(g + 20, len(keep))
            m.set_ptr(g + 24, keep_list)
            spinning = copy_block(m, g, MESH_GROUP_SIZE)
            moved_list = m.append(4 * len(moved))
            for i, x in enumerate(moved):
                m.set_ptr(moved_list + 4 * i, x)
            m.put32(spinning + 20, len(moved))
            m.set_ptr(spinning + 24, moved_list)
            if p['cut']:
                for x in moved:
                    before = m.mesh_triangles(x)
                    n_in, n_out, rim = cut_mesh(m, x, p['pivot'], p['axis'], p['cut'])
                    if rim is not None:
                        p['static'].append(rim)
                    print(f'  cut the spinning faces along the ellipse: {before} faces -> {n_in} spinning + {n_out} static')

        node = m.append(PIVOT_NODE_SIZE)
        kids = m.append(4)
        m.put32(node, NODE_TRANSFORMED_WITH_PIVOT)
        m.put32(node + 4, flags1)
        m.put32(node + 8, flags2)
        struct.pack_into('>HH', m.data, node + 12, 0x1B, 0)  # flags_3: 0x0b like the pod's own pivots + 0x10 = use pivot
        m.put32(node + 16, flags5)
        m.put32(node + 20, 1)
        m.set_ptr(node + 24, kids)
        ox, oy, oz = p['offset']
        k = p['scale']
        for j, v in enumerate((k, 0, 0, 0, k, 0, 0, 0, k, ox, oy, oz)):  # rdMatrix34: scaled, moved by the offset
            m.putf(node + 28 + 4 * j, v)
        for j, v in enumerate(p['pivot']):
            m.putf(node + 76 + 4 * j, v)
        m.set_ptr(kids, spinning)
        top = node
        if not p['whole']:
            # The original group (faces that stay), the pivot node and any static rim, side by side
            # under one BASIC node in the group's place (shared by later splits of the same group).
            add = [node]
            if p['static']:
                static_group = copy_block(m, g, MESH_GROUP_SIZE)
                static_list = m.append(4 * len(p['static']))
                for i, rim in enumerate(p['static']):
                    m.set_ptr(static_list + 4 * i, rim)
                m.put32(static_group + 20, len(p['static']))
                m.set_ptr(static_group + 24, static_list)
                add.append(static_group)
            w = wrappers.get(g)
            if w is None:
                w = m.append(BASIC_NODE_SIZE)
                m.put32(w, 0x5064)
                m.put32(w + 4, flags1)
                m.put32(w + 8, flags2)
                m.put32(w + 16, flags5)
                wl = m.append(4)
                m.set_ptr(wl, g)
                m.put32(w + 20, 1)
                m.set_ptr(w + 24, wl)
                for slot in parents[g]:
                    m.set_ptr(slot, w)
                wrappers[g] = w
            n, old = m.u32(w + 20), m.ptr(w + 24)
            wl = m.append(4 * (n + len(add)))
            for i in range(n):
                m.set_ptr(wl + 4 * i, m.ptr(old + 4 * i))
            for i, x in enumerate(add):
                m.set_ptr(wl + 4 * (n + i), x)
            m.put32(w + 20, n + len(add))
            m.set_ptr(w + 24, wl)
        elif p['static']:
            # The part of the cut faces outside the ellipse stays put: a static copy of the mesh
            # group holding those pieces, next to the spinning node under a new BASIC node.
            static_group = copy_block(m, g, MESH_GROUP_SIZE)
            static_list = m.append(4 * len(p['static']))
            for i, rim in enumerate(p['static']):
                m.set_ptr(static_list + 4 * i, rim)
            m.put32(static_group + 20, len(p['static']))
            m.set_ptr(static_group + 24, static_list)
            top = m.append(BASIC_NODE_SIZE)
            top_kids = m.append(8)
            m.put32(top, 0x5064)  # NODE_BASIC
            m.put32(top + 4, flags1)
            m.put32(top + 8, flags2)
            m.put32(top + 16, flags5)
            m.put32(top + 20, 2)
            m.set_ptr(top + 24, top_kids)
            m.set_ptr(top_kids, node)
            m.set_ptr(top_kids + 4, static_group)
        if p['whole']:
            for slot in parents[g]:  # re-parent: every parent now points at the new node
                m.set_ptr(slot, top)

        if not p['rpm']:
            continue  # moved only: no animation
        # Looping axis-angle animation: 5 keys, a quarter turn apart (slerp needs < 180 deg steps).
        rpm = p['rpm']
        ax = p['axis']
        al = math.sqrt(sum(c * c for c in ax)) or 1.0
        ax = tuple(c / al for c in ax)
        if is_alt:
            bake_model.spin_nodes.append((node, rpm, ax))
            continue
        period = 60.0 / abs(rpm)
        sign = 1.0 if rpm > 0 else -1.0
        nk = 5
        times = m.append(4 * nk)
        values = m.append(16 * nk)
        for k in range(nk):
            m.putf(times + 4 * k, period * k / (nk - 1))
            for j in range(3):
                m.putf(values + 16 * k + 4 * j, ax[j])
            m.putf(values + 16 * k + 12, sign * 360.0 * k / (nk - 1))
        anim = m.append(ANIM_SIZE)
        b = anim + 220
        # loop_transition_speed, transition_speed, interp, from_key, from_time stay 0;
        # start / end / duration / duration3 are reset from duration4/5 by swrModel_LoadAnimation.
        m.putf(b + 24, period)  # animation_end_time
        m.putf(b + 28, period)  # animation_duration
        m.putf(b + 32, period)  # duration3
        m.put32(b + 36, ANIM_TYPE_AXIS_ANGLE | ANIMATION_LOOP)  # enabled by the mod during races only
        m.put32(b + 40, nk)
        m.putf(b + 44, period)  # duration4
        m.putf(b + 48, period)  # duration5
        m.putf(b + 52, 1.0)     # animation_speed
        m.set_ptr(b + 64, times)
        m.set_ptr(b + 68, values)
        m.set_ptr(b + 72, node)
        m.set_ptr(anim_slots[slot_i], anim)
        slot_i += 1

    if extra_cables:
        add_extra_cables(m)
    bake_model.trail_nodes = add_trails(m, trails) if trails else []

    while len(m.data) % 8:
        m.data += b'\0'
        m.bits.append(False)
    mask = m.mask_bytes()
    print(f'  baked model {mid} with {n_new + len(bake_model.spin_nodes)} spinning part(s)'
          + (' (turned by the mod)' if bake_model.spin_nodes else '') + (' and an extra cable pair' if extra_cables else ''))
    return b'RAWM' + struct.pack('<II', len(mask), len(m.data)) + mask + bytes(m.data)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('game_dir')
    ap.add_argument('edits')
    ap.add_argument('--out', help='folder for the <model id>.bin files')
    ap.add_argument('--export', help="the pod's export .json (matches older plain mesh keys)")
    ap.add_argument('--dry-run', action='store_true')
    a = ap.parse_args()
    bake(a.game_dir, a.edits, a.out, a.dry_run, a.export)


if __name__ == '__main__':
    main()
