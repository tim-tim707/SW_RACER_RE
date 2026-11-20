#!/usr/bin/env python3
"""Bake pod editor spin groups into the game's own model format.

Takes an edits file saved by pod_editor.html (<Pod>.txt) and writes a modified copy of the pod's
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

A group's ellipse cut ("ellipse ux uy uz rx ry" on its spin lines, mesh frame) splits the selected
meshes along an ellipse in the plane across the spin axis through the pivot (e.g. an intake face:
only the fan in the middle spins, the rim around it stays put). Every triangle is split exactly
along a 48-sided ellipse (positions, texture coordinates and colours / normals blended along the
cut): the inside stays in the spinning mesh (new vertex list + F3DEX2 display list), the outside
becomes a copy of the mesh in a static mesh group next to the spinning node:
    parent -> new BASIC node -> [ pivot node (spins) -> mesh group (inside),  static mesh group (outside) ]

The animation is written switched on, so the game plays it as soon as it loads the pod -- no mod
code needed (it also turns in the racer-select preview).

A spin group in the pod's alt model ('MAlt') works the same through the pod model: the game never
animates an alt model, but when it loads a pod it merges the alt model's AltN nodes into the pod
model, writing each one wherever the pod model's AltN entry at the same index points. So the alt
model's pivot node is added to its AltN list, and the pod model gets the animation plus an AltN
entry pointing at that animation's node pointer: the game links the two itself.

"cables extra" gives a 2-engine pod a second pair of cockpit -> engine cables: copies of its cable
nodes (part slots 10 / 11) in the 4-engine pods' cable slots 12 / 13, sharing the cable meshes and
added next to the originals in the model tree. The game would aim those at the (missing) second
engine pair, so the mod places them at the right / left engines from the edit file's "cable2"
lines (swrRace_delta.cpp).

Usage:
    python bake_pod_edits.py <game folder | Desktop/SWEP1R Pod Editor> <edits .txt> [--export <pod .json>]
                             [--out <folder>] [--dry-run]
Writes <model id>.bin for each model the edits touch (a pod is drawn from two models, its "alt" model
and its pod model) to --out, or the folder's replacement_models (assets\replacement_models for a game
folder). --export (the pod's export) lets older plain mesh keys be matched to their model.

A spin group that does not cover whole mesh groups is split off: the selected faces of each mesh
move to a copy of the mesh (whole meshes move as they are) in a new mesh group under the pivot
node, the rest stays, and the original group, the pivot node (and a cut's static rim) sit side by
side under a new BASIC node in the group's place. Each mesh's faces may belong to one spin group.

A hide group's faces are removed from their meshes (any spin selection in the same mesh is
renumbered to the faces that are left).

Mesh keys: "<model>:<hex offset>" (offset in that model's file; exports from the current mod) or a
plain hex offset (older exports: the in-memory offset, off the file offset by the buffer's alignment
at load time -- worked out per model from the keys, like pod_editor.html / bake.js).
"""
import argparse
import math
import os
import struct
import sys


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
    left) per trail, sharing its trail; the mod places them ("trailnode" lines)."""
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
        sys.exit('"cables extra": this pod already has four engines (and their cables)')
    for src_slot, dst_slot in CABLE_SLOTS:
        src = m.ptr(roots[src_slot])
        if not src:
            sys.exit(f'"cables extra": this pod has no cable in part slot {src_slot} to copy')
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


def read_block_entry(block, model_id):
    mask_off, model_off, end = struct.unpack_from('>III', block, 8 * model_id + 4)
    return block[mask_off:model_off], block[model_off:end]


def parse_edits(path):
    groups = {}
    parse_edits.extra_cables = False
    parse_edits.hides = {}
    parse_edits.trails = []
    for raw in open(path, encoding='utf-8'):
        line = raw.split('#', 1)[0].split()
        if not line:
            continue
        if line[0] == 'spin':
            key, rpm = line[1].lower(), float(line[2])
            pivot, axis = tuple(map(float, line[3:6])), tuple(map(float, line[6:9]))
            offset = tuple(map(float, line[10:13])) if len(line) >= 13 else (0.0, 0.0, 0.0)
            scale = float(line[13]) if len(line) >= 14 else 1.0
            cut = None
            if 'ellipse' in line:
                i = line.index('ellipse')
                cut = tuple(map(float, line[i + 1:i + 6]))  # ux uy uz rx ry (mesh frame)
            tris = set()
            for r in line[9].split(','):
                a, _, b = r.partition('-')
                tris.update(range(int(a), int(b or a) + 1))
            g = groups.setdefault((rpm, pivot, axis, offset, scale, cut), {})
            g[key] = tris
        elif line[0] == 'hide' and len(line) >= 3:
            tris = parse_edits.hides.setdefault(line[1].lower(), set())
            for r in line[2].split(','):
                a, _, b = r.partition('-')
                tris.update(range(int(a), int(b or a) + 1))
        elif line[:2] == ['cables', 'extra']:
            parse_edits.extra_cables = True
        elif line[0] == 'trail' and len(line) >= 5 and line[1] in ('R', 'L'):
            scale = tuple(map(float, line[5:8])) if len(line) >= 8 else (1.0, 1.0, 1.0)  # optional
            parse_edits.trails.append((line[1], tuple(map(float, line[2:5])), scale))
    return groups


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
    spin_groups = parse_edits(edits_path)
    extra_cables = parse_edits.extra_cables
    trails = parse_edits.trails
    hides = parse_edits.hides
    if not spin_groups and not hides and not extra_cables and not trails:
        sys.exit('nothing to bake: no spin or hide lines in the edits file')
    export_keys = []
    if export_path:
        import json
        export_keys = [x['key'].lower() for x in json.load(open(export_path, encoding='utf-8'))['meshes']]
    keys = list(dict.fromkeys([k for g in spin_groups.values() for k in g] + list(hides)))
    idx = pod_index(block)
    resolved = resolve_keys(idx, keys, export_keys)
    missing = [k for k in keys if k not in resolved]
    if missing:
        sys.exit(f'no pod model has the mesh(es) {", ".join(missing)} (export from other game data, or made while a '
                 f'baked model was loaded?)')
    # Spin groups split by model (a group can hold meshes of both of the pod's models).
    per_model = {}
    for params, meshes in spin_groups.items():
        by_model = {}
        for k, tris in meshes.items():
            mid, off = resolved[k]
            by_model.setdefault(mid, {})[off] = tris
        for mid, ms in by_model.items():
            per_model.setdefault(mid, {})[params] = ms
    hides_per_model = {}
    for k, tris in hides.items():
        mid, off = resolved[k]
        hides_per_model.setdefault(mid, {}).setdefault(off, set()).update(tris)
        per_model.setdefault(mid, {})
    pod_id = pod_model_of(idx, export_keys or keys)
    cable_model = None
    if extra_cables or trails:
        cable_model = pod_id
        if cable_model is None:
            sys.exit('"cables extra": cannot find this pod\'s model (pass --export <the pod\'s export .json>)')
        per_model.setdefault(cable_model, {})
    is_alt_model = lambda mid: idx.get(mid, (b'',))[0] == b'MAlt'
    # Spins in the alt model are animated from the pod model: bake the alt model first.
    if any(is_alt_model(mid) and any(params[0] for params in groups) for mid, groups in per_model.items()):
        if pod_id is None:
            sys.exit('spinning parts in the alt model: cannot find this pod\'s main model (pass --export <the pod\'s export .json>)')
        per_model.setdefault(pod_id, {})
    alt_anims = []
    if out_dir is None:
        out_dir = os.path.join(game_dir, 'replacement_models') if workspace else \
            os.path.join(game_dir, 'assets', 'replacement_models')
    written = []
    for mid in sorted(per_model, key=lambda i: (not is_alt_model(i), i)):
        m = Model(*read_block_entry(block, mid))
        print(f'model {mid}: {m.data[:4].decode()}, {len(m.data)} bytes')
        out = bake_model(m, mid, per_model[mid], mid == cable_model and extra_cables, dry_run,
                         trails if mid == cable_model else [], hides_per_model.get(mid, {}),
                         alt_anims if mid == pod_id else [])
        alt_anims += getattr(bake_model, 'alt_spins', [])
        if out is None:
            continue
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, f'{mid}.bin')
        open(path, 'wb').write(out)
        print(f'wrote {path} ({len(out)} bytes)')
        written.append(path)
        fmt = lambda v: f'{round(v * 1e4) / 1e4:g}'
        if bake_model.trail_nodes:
            print('  add to the in-game edits (assets/pod_edits/<Pod>.txt) so the mod places them:')
            for node, side, pos, scale in bake_model.trail_nodes:
                print(f'    trailnode {mid}:{node:x} {side} {" ".join(fmt(c) for c in pos + scale)}')
    return written


def bake_model(m, mid, spin_groups, extra_cables, dry_run=False, trails=(), hides=None, alt_anims=()):
    """One model: its spin groups ({params: {mesh file offset: faces}}), hidden faces ({mesh file
    offset: faces}) and maybe the extra cable pair. alt_anims: the alt model's spinning parts
    [(rpm, axis)] to animate from this (the pod) model, in the order the alt model's AltN lists them.
    Returns the RAWM file bytes (None for a dry run); bake_model.alt_spins: this alt model's."""
    parents, mesh_groups = m.walk()
    mesh_to_group = {x: g for g, ms in mesh_groups.items() for x in ms}
    bake_model.alt_spins = []

    # 0) Hidden faces leave their meshes for good; spin selections in the same meshes are renumbered.
    spin_groups = {params: dict(ms) for params, ms in spin_groups.items()}
    for mesh, hid in (hides or {}).items():
        if mesh not in mesh_to_group:
            sys.exit(f'mesh {mid}:{mesh:x} is not in a mesh group of this model')
        tris, has_normals = decode_mesh(m, mesh)
        if any(t < 0 or t >= len(tris) for t in hid):
            sys.exit(f'mesh {mid}:{mesh:x}: the hide group names faces past its {len(tris)} faces')
        remap, k = [], 0
        for t in range(len(tris)):
            remap.append(-1 if t in hid else k)
            k += t not in hid
        write_mesh(m, mesh, [tr for t, tr in enumerate(tris) if t not in hid], has_normals)
        print(f'  hid {len(hid)} of {len(tris)} faces of mesh {mid}:{mesh:x}')
        for ms in spin_groups.values():
            if mesh in ms:
                kept = {remap[t] for t in ms[mesh] if 0 <= t < len(remap) and remap[t] >= 0}
                if kept:
                    ms[mesh] = kept
                else:
                    del ms[mesh]
    spin_groups = {params: ms for params, ms in spin_groups.items() if ms}

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
    # printed as "spinnode" lines instead (the mod turns them; the editor's Build & install writes
    # them to the in-game edits file).
    # An alt model's spinning pivot nodes go into its AltN list instead, and the pod model gets their
    # animations, each linked through the pod model's AltN entry at the same index (see the notes).
    is_alt = m.data[:4] == b'MAlt'
    bake_model.spin_nodes = []
    h = m.header()
    anim_slots = []
    n_own = 0 if is_alt else sum(1 for p in plan if p['rpm'])
    n_new = n_own + len(alt_anims)
    n_altn = sum(1 for p in plan if p['rpm']) if is_alt else len(alt_anims)
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
    altn_slots = []
    if n_altn:
        h2 = m.header()
        o = h2.get('anim_end', h2['after_data'] - 4) + 4
        if m.data[o:o + 4] != b'AltN':
            sys.exit(f"model {mid} has no AltN list to link the alt model's spinning parts through")
        o += 4
        while m.u32(o):
            o += 4
        m.insert(o, 4 * n_altn)
        altn_slots = [o + 4 * i for i in range(n_altn)]
        for slot in altn_slots:
            m.put32(slot, 1)
    parents, mesh_groups = m.walk()  # offsets moved

    # 2) New pivot node + animation per spin group, appended at the end of the model.
    shift = ((4 + 4 * n_new + 4 if 'anim' not in h else 4 * n_new) if n_new else 0) + 4 * n_altn
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
            m.set_ptr(altn_slots[len(bake_model.alt_spins)], node)
            bake_model.alt_spins.append((rpm, ax))
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
        m.put32(b + 36, ANIM_TYPE_AXIS_ANGLE | ANIMATION_LOOP | ANIMATION_ENABLED)
        m.put32(b + 40, nk)
        m.putf(b + 44, period)  # duration4
        m.putf(b + 48, period)  # duration5
        m.putf(b + 52, 1.0)     # animation_speed
        m.set_ptr(b + 64, times)
        m.set_ptr(b + 68, values)
        m.set_ptr(b + 72, node)
        m.set_ptr(anim_slots[slot_i], anim)
        slot_i += 1

    # The alt model's spinning parts: their animations, each node pointer filled in by the game from
    # the alt model's AltN list when it merges the two (this model's AltN entry points at it).
    for i, (rpm, ax) in enumerate(alt_anims):
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
        m.putf(b + 24, period)
        m.putf(b + 28, period)
        m.putf(b + 32, period)
        m.put32(b + 36, ANIM_TYPE_AXIS_ANGLE | ANIMATION_LOOP | ANIMATION_ENABLED)
        m.put32(b + 40, nk)
        m.putf(b + 44, period)
        m.putf(b + 48, period)
        m.putf(b + 52, 1.0)
        m.set_ptr(b + 64, times)
        m.set_ptr(b + 68, values)  # b + 72 (the node): from the alt model
        m.set_ptr(anim_slots[slot_i], anim)
        slot_i += 1
        m.set_ptr(altn_slots[i], b + 72)
        print(f"  animation for the alt model's spinning part {i + 1} at {rpm:g} rpm (linked through AltN)")

    if extra_cables:
        add_extra_cables(m)
    bake_model.trail_nodes = add_trails(m, trails) if trails else []

    while len(m.data) % 8:
        m.data += b'\0'
        m.bits.append(False)
    mask = m.mask_bytes()
    print(f'  baked model {mid} with {n_own + len(bake_model.spin_nodes)} spinning part(s)'
          + (' (animated from the pod model)' if bake_model.spin_nodes else '')
          + (f' and {len(alt_anims)} animation(s) for the alt model' if alt_anims else '')
          + (f', {len(hides)} mesh(es) with hidden faces' if hides else '')
          + (' and an extra cable pair' if extra_cables else ''))
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
