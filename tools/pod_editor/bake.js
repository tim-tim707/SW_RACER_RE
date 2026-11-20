// Bake pod editor edits into the game's own model format -- the in-browser twin of
// bake_pod_edits.py (same algorithm, same output; see that file's notes for the details).
//
//   bakePod(blockBytes, editsText, exportKeys) -> { models: [{ modelId, bytes, keyShift, triRemap }], resolved, log }
//   resolveKeys(blockBytes, keys, exportKeys) -> Map(key -> { model, off })
//
// blockBytes: <game>/data/lev01/out_modelblock.bin (Uint8Array)
// editsText:  an edits file from pod_editor.html (spin lines, "cables extra"; hide / cable /
//             cable2 / binder lines are runtime edits and are left to the mod)
// exportKeys: every mesh key of the pod's export (finds its models; resolves older keys)
//
// Mesh keys: "<model>:<hex offset>" (offset in that model's file data; current exports) or a plain hex
// offset (older exports: the asset-buffer offset, off the file offset by the buffer's alignment at
// load time -- worked out per model from the export's keys). A pod is drawn from two models (its
// "alt" model and its pod model), so one edits file can touch both: each gets its own .bin.
// bytes:      <game>/assets/replacement_models/<modelId>.bin (RAWM: mask + model)
//
// A plain script (not an ES module), so pod_editor.html can load it straight from disk (file://
// blocks module imports): it defines window.PodBake = { bakePod, findPodModel, BakeError }.
// keyShift:   bytes every original mesh moved by (for re-keying the runtime edit lines)

(function () {
'use strict';

const KEY_SHIFT = 4;
const NODE_MESH_GROUP = 0x3064;
const NODE_TRANSFORMED_WITH_PIVOT = 0xD065;
const NODE_HAS_CHILDREN = 0x4000;
const ANIM_TYPE_AXIS_ANGLE = 0x8;
const ANIMATION_LOOP = 0x10;
const ANIM_SIZE = 300;
const PIVOT_NODE_SIZE = 88;
const MESH_SIZE = 64;
const MESH_GROUP_SIZE = 0x3C;
const BASIC_NODE_SIZE = 28;

class BakeError extends Error {}

// Python's round(): halves go to the even neighbour (keeps the output identical to the script).
function pyRound(x) {
  const f = Math.floor(x), d = x - f;
  if (d > 0.5) return f + 1;
  if (d < 0.5) return f;
  return f % 2 === 0 ? f : f + 1;
}
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const hex = v => '0x' + v.toString(16);

// One model payload (big-endian, pointers stored as offsets from the model start) and its pointer
// mask (one bit per 32-bit word, MSB first).
class Model {
  constructor(mask, data) {
    this.data = new Uint8Array(data);
    this.len = this.data.length;
    const nWords = this.len >> 2;
    this.bits = new Array(nWords);
    for (let i = 0; i < nWords; i++) this.bits[i] = (i >> 3) < mask.length ? ((mask[i >> 3] >> (7 - (i & 7))) & 1) === 1 : false;
  }
  get dv() { return new DataView(this.data.buffer, this.data.byteOffset, this.len); }
  u32(o) { return this.dv.getUint32(o, false); }
  u16(o) { return this.dv.getUint16(o, false); }
  f32(o) { return this.dv.getFloat32(o, false); }
  put32(o, v) { this.dv.setUint32(o, v >>> 0, false); }
  putf(o, v) { this.dv.setFloat32(o, v, false); }
  isPtr(o) { return this.bits[o >> 2]; }
  ptr(o) {
    if (!this.isPtr(o)) return null;
    const v = this.u32(o);
    if ((v & 0xFF000000) >>> 0 === 0x0A000000) return null;// texture reference
    return v || null;
  }
  setPtr(o, target) { this.put32(o, target); this.bits[o >> 2] = true; }
  grow(newLen) {
    if (newLen <= this.data.length) { this.len = newLen; return; }
    const d = new Uint8Array(Math.max(newLen, this.data.length * 2));
    d.set(this.data.subarray(0, this.len)); this.data = d; this.len = newLen;
  }
  // Insert nbytes of zeros at `at`, fixing every pointer into the moved part.
  insert(at, nbytes) {
    for (let w = 0; w < this.bits.length; w++) {
      if (!this.bits[w]) continue;
      const v = this.u32(w * 4);
      if (v === 0 || (v & 0xFF000000) >>> 0 === 0x0A000000) continue;
      if (v >= at) this.put32(w * 4, v + nbytes);
    }
    const old = this.len;
    this.grow(old + nbytes);
    this.data.copyWithin(at + nbytes, at, old);
    this.data.fill(0, at, at + nbytes);
    this.bits.splice(at >> 2, 0, ...new Array(nbytes >> 2).fill(false));
  }
  // Reserve nbytes of zeros at the end (aligned); returns their offset.
  append(nbytes, align = 8) {
    while (this.len % align) { this.grow(this.len + 1); this.data[this.len - 1] = 0; if (this.len % 4 === 0) this.bits.push(false); }
    const o = this.len;
    this.grow(o + nbytes); this.data.fill(0, o, o + nbytes);
    for (let i = 0; i < nbytes >> 2; i++) this.bits.push(false);
    return o;
  }
  tag(o) { return String.fromCharCode(...this.data.subarray(o, o + 4)); }
  maskBytes() {
    const nWords = this.len >> 2, out = new Uint8Array(((nWords + 31) >> 5) * 4);
    this.bits.forEach((b, i) => { if (b) out[i >> 3] |= 0x80 >> (i & 7); });
    return out;
  }
  header() {
    let o = 4; const roots = [];
    while (this.u32(o) !== 0xFFFFFFFF) { roots.push(o); o += 4; }
    const h = { roots, roots_end: o };
    o += 4;
    if (this.tag(o) === 'Data') o += 8 + 4 * this.u32(o + 4);
    h.after_data = o;
    if (this.tag(o) === 'Anim') {
      h.anim = o; o += 4;
      while (this.u32(o)) o += 4;
      h.anim_end = o;
    }
    return h;
  }
  childSlots(o) {
    const t = this.u32(o), n = this.u32(o + 20), kids = this.ptr(o + 24);
    if (!((t & NODE_HAS_CHILDREN) || t === NODE_MESH_GROUP) || !kids) return [];
    return Array.from({ length: n }, (_, i) => kids + 4 * i);
  }
  // { parents: Map(node -> [parent child-slot offsets]), groups: Map(mesh group -> [meshes]) }
  walk() {
    const h = this.header();
    const starts = h.roots.map(r => this.ptr(r));
    const headerSlots = [...h.roots];// header references count as parents too (after the tree's)
    let o = (h.anim_end ?? h.after_data - 4) + 4;
    if (this.tag(o) === 'AltN') { o += 4; while (this.u32(o)) { starts.push(this.ptr(o)); headerSlots.push(o); o += 4; } }
    const parents = new Map(), groups = new Map(), seen = new Set();
    const stack = starts.filter(Boolean);
    while (stack.length) {
      const n = stack.pop();
      if (seen.has(n)) continue;
      seen.add(n);
      const slots = this.childSlots(n);
      if (this.u32(n) === NODE_MESH_GROUP) { groups.set(n, slots.map(s => this.ptr(s)).filter(Boolean)); continue; }
      for (const s of slots) {
        const c = this.ptr(s);
        if (c) { if (!parents.has(c)) parents.set(c, []); parents.get(c).push(s); stack.push(c); }
      }
    }
    // A part slot or AltN entry pointing straight at a node (e.g. the alt models' engine parts,
    // mesh groups listed only in AltN): re-parenting it must move that reference too.
    for (const s of headerSlots) {
      const c = this.ptr(s);
      if (c) { if (!parents.has(c)) parents.set(c, []); parents.get(c).push(s); }
    }
    return { parents, groups };
  }
  meshTriangles(mesh) {
    let o = this.ptr(mesh + 48), n = 0;
    for (let i = 0; i < 100000; i++) {
      const op = this.data[o];
      if (op === 0x05) n += 1;
      else if (op === 0x06 || op === 0x07) n += 2;
      else if (op === 0xDF) return n;
      o += 8;
    }
    throw new BakeError(`display list of mesh ${hex(mesh)} never ends`);
  }
}

// ---- ellipse cut ----------------------------------------------------------------------------
function decodeMesh(m, mesh) {
  const material = m.ptr(mesh);
  const hasNormals = !!(material && (m.u32(material) & 0x11));
  const cache = new Array(256).fill(null), dv = m.dv, tris = [];
  let o = m.ptr(mesh + 48);
  const vtx = a => {
    const b = hasNormals ? [dv.getInt8(a + 12), dv.getInt8(a + 13), dv.getInt8(a + 14), dv.getUint8(a + 15)]
                         : [dv.getUint8(a + 12), dv.getUint8(a + 13), dv.getUint8(a + 14), dv.getUint8(a + 15)];
    return [dv.getInt16(a), dv.getInt16(a + 2), dv.getInt16(a + 4), dv.getInt16(a + 8), dv.getInt16(a + 10), ...b];
  };
  for (;;) {
    const op = m.data[o];
    if (op === 0x01) {
      const n = (dv.getUint16(o + 1) >> 4) & 0xFF, v0 = (m.data[o + 3] >> 1) - n, base = m.ptr(o + 4);
      for (let i = 0; i < n; i++) cache[v0 + i] = vtx(base + 16 * i);
    } else if (op === 0x05) tris.push([1, 2, 3].map(k => cache[m.data[o + k] >> 1]));
    else if (op === 0x06) {
      tris.push([1, 2, 3].map(k => cache[m.data[o + k] >> 1]));
      tris.push([5, 6, 7].map(k => cache[m.data[o + k] >> 1]));
    } else if (op === 0xDF) break;
    else if (op !== 0x03) throw new BakeError(`mesh ${hex(mesh)}: unsupported display list command ${hex(op)}`);
    o += 8;
  }
  return { tris, hasNormals };
}

function clipToEllipse(tris, centre, axis, u, rx, ry, sides = 48) {
  const norm = a => { const l = Math.sqrt(a.reduce((s, c) => s + c * c, 0)) || 1; return a.map(c => c / l); };
  const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
  const ax = norm(axis);
  const ud = u[0] * ax[0] + u[1] * ax[1] + u[2] * ax[2];
  const uu = norm([0, 1, 2].map(i => u[i] - ax[i] * ud)), vv = norm(cross(ax, uu));
  const ab = p => {
    const d = [p[0] - centre[0], p[1] - centre[1], p[2] - centre[2]];
    return [(d[0] * uu[0] + d[1] * uu[1] + d[2] * uu[2]) / rx, (d[0] * vv[0] + d[1] * vv[1] + d[2] * vv[2]) / ry];
  };
  const lim = Math.cos(Math.PI / sides);
  const clip = (poly, dist, keepInside) => {
    const out = [];
    for (let i = 0; i < poly.length; i++) {
      const p = poly[i], q = poly[(i + 1) % poly.length], dp = dist(p), dq = dist(q);
      const pin = (dp <= 0) === keepInside, qin = (dq <= 0) === keepInside;
      if (pin) out.push(p);
      if (pin !== qin) { const t = dp / (dp - dq); out.push(p.map((x, j) => x + (q[j] - x) * t)); }
    }
    return out;
  };
  const fan = (poly, out) => { for (let i = 1; i < poly.length - 1; i++) out.push([poly[0], poly[i], poly[i + 1]]); };
  const inside = [], outside = [];
  for (const tri of tris) {
    let poly = tri.slice();
    for (let k = 0; k < sides; k++) {
      const th = 2 * Math.PI * (k + 0.5) / sides, cs = Math.cos(th), sn = Math.sin(th);
      const dist = p => { const [a, b] = ab(p); return a * cs + b * sn - lim; };
      const piece = clip(poly, dist, false);
      if (piece.length >= 3) fan(piece, outside);
      poly = clip(poly, dist, true);
      if (poly.length < 3) break;
    }
    if (poly.length >= 3) fan(poly, inside);
  }
  return { inside, outside };
}

function writeMesh(m, mesh, tris, hasNormals) {
  const verts = tris.flat();
  const vbuf = m.append(16 * Math.max(verts.length, 1));
  let dv = m.dv;
  verts.forEach((v, i) => {
    const o = vbuf + 16 * i;
    for (let k = 0; k < 3; k++) dv.setInt16(o + 2 * k, clamp(pyRound(v[k]), -32768, 32767));
    dv.setUint16(o + 6, 0);
    dv.setInt16(o + 8, clamp(pyRound(v[3]), -32768, 32767));
    dv.setInt16(o + 10, clamp(pyRound(v[4]), -32768, 32767));
    if (hasNormals) {
      const [nx, ny, nz] = v.slice(5, 8), l = Math.sqrt(nx * nx + ny * ny + nz * nz) || 1;
      [nx, ny, nz].forEach((c, k) => dv.setInt8(o + 12 + k, clamp(pyRound(c / l * 127), -127, 127)));
      dv.setUint8(o + 15, clamp(pyRound(v[8]), 0, 255));
    } else for (let k = 0; k < 4; k++) dv.setUint8(o + 12 + k, clamp(pyRound(v[5 + k]), 0, 255));
  });
  // Batches of up to 42 triangles (126 vertices: G_VTX's v0 + n field is 7 bits).
  const cmds = [], batch = 42;
  for (let b0 = 0; b0 < tris.length; b0 += batch) {
    const nt = Math.min(batch, tris.length - b0);
    cmds.push(['vtx', 3 * nt, vbuf + 16 * 3 * b0]);
    for (let t = 0; t < nt - 1; t += 2) cmds.push(['tri2', 3 * t, 3 * t + 1, 3 * t + 2, 3 * t + 3, 3 * t + 4, 3 * t + 5]);
    if (nt % 2) { const t = nt - 1; cmds.push(['tri1', 3 * t, 3 * t + 1, 3 * t + 2]); }
  }
  const dl = m.append(8 * (cmds.length + 1));
  dv = m.dv;
  cmds.forEach((c, i) => {
    const o = dl + 8 * i;
    if (c[0] === 'vtx') {
      const n = c[1];
      m.data[o] = 0x01; dv.setUint16(o + 1, (n & 0xFF) << 4); m.data[o + 3] = (n & 0x7F) << 1;
      m.setPtr(o + 4, c[2]);
    } else if (c[0] === 'tri1') {
      m.data[o] = 0x05; for (let k = 0; k < 3; k++) m.data[o + 1 + k] = 2 * c[1 + k];
    } else {
      m.data[o] = 0x06;
      for (let k = 0; k < 3; k++) { m.data[o + 1 + k] = 2 * c[1 + k]; m.data[o + 5 + k] = 2 * c[4 + k]; }
    }
  });
  m.data[dl + 8 * cmds.length] = 0xDF;
  m.setPtr(mesh + 48, dl);
  m.setPtr(mesh + 52, vbuf);
  m.dv.setUint16(mesh + 58, Math.min(verts.length, 0xFFFF));
  if (verts.length) for (let k = 0; k < 3; k++) {
    m.putf(mesh + 8 + 4 * k, Math.min(...verts.map(v => v[k])));
    m.putf(mesh + 20 + 4 * k, Math.max(...verts.map(v => v[k])));
  }
}

function copyBlock(m, src, size) {
  const dst = m.append(size);
  m.data.copyWithin(dst, src, src + size);
  for (let w = 0; w < size >> 2; w++) m.bits[(dst >> 2) + w] = m.bits[(src >> 2) + w];
  return dst;
}

function cutMesh(m, mesh, pivot, axis, cut) {
  const { tris, hasNormals } = decodeMesh(m, mesh);
  const [ux, uy, uz, rx, ry] = cut;
  const { inside, outside } = clipToEllipse(tris, pivot, axis, [ux, uy, uz], rx, ry);
  let rim = null;
  if (outside.length) { rim = copyBlock(m, mesh, MESH_SIZE); writeMesh(m, rim, outside, hasNormals); }
  writeMesh(m, mesh, inside, hasNormals);
  return { nIn: inside.length, nOut: outside.length, rim };
}

// ---- edits / model lookup -------------------------------------------------------------------
function readBlockEntry(block, id) {
  const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
  const maskOff = dv.getUint32(8 * id + 4), modelOff = dv.getUint32(8 * id + 8), end = dv.getUint32(8 * id + 12);
  return [block.subarray(maskOff, modelOff), block.subarray(modelOff, end)];
}

// Spin lines grouped like the script: one group per (rpm, pivot, axis, offset, scale, cut).
function parseEdits(text) {
  const groups = new Map(), notes = [], hideKeys = [], trails = [];
  let extraCables = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#', 1)[0].trim().split(/\s+/).filter(Boolean);
    if (!line.length) continue;
    if (line[0] === 'spin') {
      // A spin group piece's faces: "piece" / "pre" <dx dy dz> (mesh frame) after the other fields --
      // moved by that much before the group spins.
      let pre = null;
      const pi = line.findIndex(x => x === 'piece' || x === 'pre');
      if (pi >= 0) { pre = line.slice(pi + 1, pi + 4).map(Number); line.length = pi; if (!pre.every(Number.isFinite) || !pre.some(Boolean)) pre = null; }
      const key = line[1].toLowerCase(), rpm = +line[2];
      const pivot = line.slice(3, 6).map(Number), axis = line.slice(6, 9).map(Number);
      const offset = line.length >= 13 && line[10] !== 'ellipse' ? line.slice(10, 13).map(Number) : [0, 0, 0];
      const scale = line.length >= 14 && line[13] !== 'ellipse' ? +line[13] : 1;
      const ei = line.indexOf('ellipse');
      const cut = ei >= 0 ? line.slice(ei + 1, ei + 6).map(Number) : null;
      const tris = new Set();
      for (const r of line[9].split(',')) { const [a, b] = r.split('-').map(Number); for (let t = a; t <= (isNaN(b) ? a : b); t++) tris.add(t); }
      const gk = JSON.stringify([rpm, pivot, axis, offset, scale, cut]);
      if (!groups.has(gk)) groups.set(gk, { rpm, pivot, axis, offset, scale, cut, meshes: new Map(), pre: new Map() });
      const g = groups.get(gk);
      // One group can have several lines for a mesh (its pieces): their faces add up.
      if (g.meshes.has(key)) for (const t of tris) g.meshes.get(key).add(t); else g.meshes.set(key, tris);
      if (pre) {
        if (!g.pre.has(key)) g.pre.set(key, new Map());
        for (const t of tris) g.pre.get(key).set(t, pre);
      }
    } else if (line[0] === 'hide') { hideKeys.push(line[1].toLowerCase()); notes.push(`hide line for mesh ${line[1]} stays an in-game edit`); }
    else if (line[0] === 'cables' && line[1] === 'extra') extraCables = true;
    else if (line[0] === 'trail' && (line[1] === 'R' || line[1] === 'L')) {
      const pos = line.slice(2, 5).map(Number), sc = line.slice(5, 8).map(Number);
      const scale = sc.length === 3 && sc.every(Number.isFinite) ? sc : [1, 1, 1];// optional
      if (pos.length === 3 && pos.every(Number.isFinite)) trails.push({ side: line[1], pos, scale });
    }
  }
  return { groups: [...groups.values()], notes, hideKeys, extraCables, trails };
}

// "cables extra": copies of cable nodes 10 / 11 in part slots 12 / 13 (2-engine pods), sharing the
// cable meshes, hung next to the originals; the mod places them (see bake_pod_edits.py).
const CABLE_SLOTS = [[10, 12], [11, 13]];
// "trail R|L x y z": an extra exhaust trail -- a copy of that side's stock exhaust node (part slot
// 0x43 right, 0x44 left) next to it, sharing its children (the trail ribbon the game scales); the mod
// places each copy at its point ("trailnode" lines). Returns [{ node, side, pos }].
function addTrails(m, trails, log) {
  const roots = m.header().roots, out = [];
  for (const t of trails) {
    const src = m.ptr(roots[t.side === 'R' ? 0x43 : 0x44]);
    if (!src) throw new BakeError(`Extra trail: this pod has no exhaust node for the ${t.side === 'R' ? 'right' : 'left'} engine.`);
    const node = cloneNextTo(m, src, roots);
    out.push({ node, side: t.side, pos: t.pos, scale: t.scale });
    log.push(`extra trail (${t.side}): copy of the exhaust node ${hex(src)} -> ${hex(node)}`);
  }
  return out;
}

// A copy of a node (its children shared) hung next to it under the same parent node.
function cloneNextTo(m, src, roots) {
  const size = m.u32(src) === NODE_TRANSFORMED_WITH_PIVOT ? PIVOT_NODE_SIZE : 76;
  const node = copyBlock(m, src, size);
  const nKids = m.u32(src + 20), kids = m.ptr(src + 24);
  if (kids) m.setPtr(node + 24, copyBlock(m, kids, 4 * Math.max(nKids, 1)));
  const { parents } = m.walk();
  const slot = parents.get(src)[0];
  const candidates = new Set([...parents.keys(), ...roots.map(r => m.ptr(r)).filter(Boolean)]);
  let owner = null;
  for (const o of candidates) if (m.childSlots(o).includes(slot)) { owner = o; break; }
  if (owner === null) throw new BakeError(`${hex(src)} has no parent node to hang a copy under.`);
  const n = m.u32(owner + 20), old = m.ptr(owner + 24), lst = m.append(4 * (n + 1));
  for (let i = 0; i < n; i++) { const c = m.ptr(old + 4 * i); if (c) m.setPtr(lst + 4 * i, c); }
  m.setPtr(lst + 4 * n, node);
  m.put32(owner + 20, n + 1);
  m.setPtr(owner + 24, lst);
  return node;
}

function addExtraCables(m, log) {
  const roots = m.header().roots;
  if (m.ptr(roots[3]) || m.ptr(roots[4])) throw new BakeError('Extra cables: this pod already has four engines (and their cables).');
  for (const [srcSlot, dstSlot] of CABLE_SLOTS) {
    const src = m.ptr(roots[srcSlot]);
    if (!src) throw new BakeError(`Extra cables: this pod has no cable in part slot ${srcSlot} to copy.`);
    if (m.ptr(roots[dstSlot])) { log.push(`part slot ${dstSlot} already holds a cable: kept`); continue; }
    const size = m.u32(src) === NODE_TRANSFORMED_WITH_PIVOT ? PIVOT_NODE_SIZE : 76;
    const node = copyBlock(m, src, size);
    const nKids = m.u32(src + 20), kids = m.ptr(src + 24);
    if (kids) m.setPtr(node + 24, copyBlock(m, kids, 4 * Math.max(nKids, 1)));
    const { parents } = m.walk();
    const slot = parents.get(src)[0];
    const candidates = new Set([...parents.keys(), ...roots.map(r => m.ptr(r)).filter(Boolean)]);
    let owner = null;
    for (const o of candidates) if (m.childSlots(o).includes(slot)) { owner = o; break; }
    const n = m.u32(owner + 20), old = m.ptr(owner + 24), lst = m.append(4 * (n + 1));
    for (let i = 0; i < n; i++) { const c = m.ptr(old + 4 * i); if (c) m.setPtr(lst + 4 * i, c); }
    m.setPtr(lst + 4 * n, node);
    m.put32(owner + 20, n + 1);
    m.setPtr(owner + 24, lst);
    m.setPtr(roots[dstSlot], node);
    log.push(`extra cable: part slot ${dstSlot} = copy of cable ${srcSlot} (${hex(src)} -> ${hex(node)}, under ${hex(owner)})`);
  }
}

// Every pod model's meshes (file offsets), once per model block.
const podIndexCache = new WeakMap();
function podIndex(block) {
  if (podIndexCache.has(block)) return podIndexCache.get(block);
  const count = new DataView(block.buffer, block.byteOffset, block.byteLength).getUint32(0), out = new Map();
  for (let id = 0; id < count; id++) {
    const [mask, data] = readBlockEntry(block, id);
    if (data.length < 8) continue;
    const tag = String.fromCharCode(...data.subarray(0, 4));
    if (tag !== 'Podd' && tag !== 'MAlt') continue;
    try { out.set(id, { tag, meshes: new Set([...new Model(mask, data).walk().groups.values()].flat()) }); } catch { /* skip */ }
  }
  podIndexCache.set(block, out);
  return out;
}
const parseKey = k => { const i = k.indexOf(':'); return i >= 0 ? { model: parseInt(k.slice(0, i), 10), off: parseInt(k.slice(i + 1), 16) } : { model: null, off: parseInt(k, 16) }; };
// Key -> { model, off } for the given keys. Older (plain) keys: each (model, alignment) pair that
// would explain it is scored by how many of the export's keys it explains, and the best wins.
function resolveKeys(block, keys, exportKeys = []) {
  const idx = podIndex(block), out = new Map(), support = new Map();
  const legacy = [...new Set([...keys, ...exportKeys])].filter(k => !k.includes(':'));
  const cands = k => {
    const off = parseInt(k, 16), c = [];
    for (const [id, { meshes }] of idx) for (let sh = -16; sh <= 32; sh += 4) if (meshes.has(off - sh)) c.push(id + '/' + sh);
    return c;
  };
  for (const k of legacy) for (const c of cands(k)) support.set(c, (support.get(c) || 0) + 1);
  for (const k of keys) {
    const pk = parseKey(k);
    if (pk.model !== null) { out.set(k, pk); continue; }
    const best = cands(k).sort((a, b) => support.get(b) - support.get(a))[0];
    if (best) { const [id, sh] = best.split('/').map(Number); out.set(k, { model: id, off: pk.off - sh }); }
  }
  return out;
}
// The pod's models (from its export keys): { alt, pod } block ids (pod = the 'Podd' model).
function podModels(block, exportKeys) {
  const idx = podIndex(block), r = resolveKeys(block, exportKeys, exportKeys), count = new Map();
  for (const { model } of r.values()) count.set(model, (count.get(model) || 0) + 1);
  const ids = [...count.keys()].sort((a, b) => count.get(b) - count.get(a));
  return { pod: ids.find(id => idx.get(id)?.tag === 'Podd') ?? null, ids };
}

// ---- bake -----------------------------------------------------------------------------------
function bakePod(block, editsText, exportKeys = []) {
  const log = [];
  const { groups: spinGroups, notes, hideKeys, extraCables, trails } = parseEdits(editsText);
  log.push(...notes);
  if (!spinGroups.length && !extraCables && !trails.length)
    throw new BakeError('Nothing to bake: no spin groups, extra cables or extra trails (cable, binder and hide edits are applied in game from the .txt).');
  const keys = [...new Set([...spinGroups.flatMap(g => [...g.meshes.keys()]), ...hideKeys])];
  const resolved = resolveKeys(block, keys, exportKeys);
  const missing = keys.filter(k => !resolved.has(k));
  if (missing.length)
    throw new BakeError(`No pod model has the mesh${missing.length > 1 ? 'es' : ''} ${missing.join(', ')} (export made from other game data, or while a baked model was loaded? Remove the pod's .bin, restart the game and export again).`);
  // Spin groups split by model (a group can hold meshes of both of the pod's models).
  const perModel = new Map();
  for (const sg of spinGroups) {
    const byModel = new Map(), preByModel = new Map();
    for (const [k, tris] of sg.meshes) {
      const { model, off } = resolved.get(k);
      if (!byModel.has(model)) { byModel.set(model, new Map()); preByModel.set(model, new Map()); }
      byModel.get(model).set(off, tris);
      if (sg.pre && sg.pre.has(k)) preByModel.get(model).set(off, sg.pre.get(k));
    }
    for (const [model, meshes] of byModel) {
      if (!perModel.has(model)) perModel.set(model, []);
      perModel.get(model).push({ ...sg, meshes, pre: preByModel.get(model) });
    }
  }
  let cableModel = null;
  if (extraCables || trails.length) {
    cableModel = podModels(block, exportKeys.length ? exportKeys : keys).pod;
    if (cableModel === null) throw new BakeError('Extra cables / trails: cannot find this pod\'s model (export again with the current mod).');
    if (!perModel.has(cableModel)) perModel.set(cableModel, []);
  }
  const models = [];
  for (const [mid, groups] of [...perModel].sort((a, b) => a[0] - b[0])) {
    const m = new Model(...readBlockEntry(block, mid));
    log.push(`model ${mid}: ${m.tag(0)}, ${m.len} bytes`);
    models.push({ modelId: mid, ...bakeModel(m, mid, groups, mid === cableModel && extraCables, log,
                                              mid === cableModel ? trails : []) });
  }
  return { models, resolved, log };
}

// One model: its spin groups (meshes by file offset) and maybe the extra cable pair.
function bakeModel(m, mid, spinGroups, extraCables, log, trails = []) {

  let { parents, groups: meshGroups } = m.walk();
  const meshToGroup = new Map();
  for (const [g, ms] of meshGroups) for (const x of ms) meshToGroup.set(x, g);

  // Spin group pieces: their faces moved first (mesh frame), in place in their meshes; the split and
  // spin below then take them from there.
  const moves = new Map();// mesh -> face -> move
  for (const sg of spinGroups) for (const [mesh, faces] of sg.pre || []) {
    if (!moves.has(mesh)) moves.set(mesh, new Map());
    for (const [t, v] of faces) moves.get(mesh).set(t, v);
  }
  for (const [mesh, faces] of moves) {
    if (!meshToGroup.has(mesh)) throw new BakeError(`Mesh ${mid + ':' + hex(mesh)} is not in a mesh group of this model.`);
    const { tris, hasNormals } = decodeMesh(m, mesh);
    const moved = tris.map((tri, t) => {
      const v = faces.get(t);
      return v ? tri.map(p => [p[0] + v[0], p[1] + v[1], p[2] + v[2], ...p.slice(3)]) : tri;
    });
    writeMesh(m, mesh, moved, hasNormals);
    log.push(`moved ${faces.size} face(s) of mesh ${mid}:${hex(mesh)} (spin group pieces)`);
  }

  // A spin group covering whole mesh groups spins those groups as they are; otherwise ("partial")
  // its faces are split off into new meshes in a new mesh group, and the rest stays where it was.
  const plan = [], meshOwner = new Map();
  spinGroups.forEach((sg, si) => {
    const offs = sg.meshes;
    for (const [mesh, tris] of offs) {
      if (!meshToGroup.has(mesh)) throw new BakeError(`Mesh ${mid + ':' + hex(mesh)} is not in a mesh group of this model.`);
      const total = m.meshTriangles(mesh);
      if ([...tris].some(t => t < 0 || t >= total))
        throw new BakeError(`Mesh ${mid + ':' + hex(mesh)}: the spin group names faces past its ${total} faces (export from different game data?).`);
      if (meshOwner.has(mesh) && meshOwner.get(mesh) !== si)
        throw new BakeError(`Mesh ${mid + ':' + hex(mesh)} has faces in two spin groups: give each mesh's faces to one spin group.`);
      meshOwner.set(mesh, si);
    }
    for (const g of [...new Set([...offs.keys()].map(x => meshToGroup.get(x)))].sort((a, b) => a - b)) {
      if (!parents.has(g)) throw new BakeError(`Mesh group ${hex(g)} has no parent node`);
      const sel = meshGroups.get(g).filter(x => offs.has(x));
      const whole = sel.length === meshGroups.get(g).length && sel.every(x => offs.get(x).size === m.meshTriangles(x));
      plan.push({ group: g, ...sg, meshes: whole ? meshGroups.get(g).slice() : sel, whole, select: new Map(sel.map(x => [x, offs.get(x)])) });
      log.push(`spin ${whole ? 'mesh group' : 'faces of mesh group'} ${hex(g)} (${whole ? meshGroups.get(g).length + ' meshes' :
               sel.map(x => `${offs.get(x).size}/${m.meshTriangles(x)} faces of ${mid}:${hex(x)}`).join(', ')}, under ${parents.get(g).length} parent(s)) at ${sg.rpm} rpm` +
               (sg.scale !== 1 ? `, scale ${sg.scale}` : '') + (sg.cut ? `, cut to an ellipse ${sg.cut[3]} x ${sg.cut[4]}` : ''));
    }
  });

  // 1) Room in the header's 'Anim' list for the new animations. Not in an alt model ('MAlt'): the
  // game merges its AltN parts into the pod model only when AltN follows the part slots directly
  // (swrModel_FixupAltNodePointers), and never runs an alt model's animations anyway -- its spinning
  // nodes are listed instead ("spinnode" lines) and the mod turns them.
  const isAlt = m.tag(0) === 'MAlt', spinNodes = [];
  const h = m.header();
  let animSlots = [];
  const nNew = isAlt ? 0 : plan.filter(p => p.rpm).length;
  if (nNew === 0) { /* nothing */ }
  else if (h.anim !== undefined) {
    const at = h.anim_end; m.insert(at, 4 * nNew);
    animSlots = Array.from({ length: nNew }, (_, i) => at + 4 * i);
  } else {
    const at = h.after_data; m.insert(at, 4 + 4 * nNew + 4);
    m.data.set([0x41, 0x6e, 0x69, 0x6d], at);// 'Anim'
    animSlots = Array.from({ length: nNew }, (_, i) => at + 4 + 4 * i);
  }
  // Placeholders until the animations exist: a 0 would end the list early and hide the AltN list
  // after it (the alt models' parts) from the walk.
  for (const s of animSlots) m.put32(s, 1);
  ({ parents, groups: meshGroups } = m.walk());

  // 2) Cuts, then a pivot node (+ animation) per spin group, appended at the end.
  const shift = nNew ? (h.anim === undefined ? 4 + 4 * nNew + 4 : 4 * nNew) : 0;
  for (const p of plan) {
    p.static = [];
    if (!p.cut || !p.whole) continue;// partial groups are cut after their split
    for (const mesh of p.meshes) {
      const before = m.meshTriangles(mesh + shift);
      const { nIn, nOut, rim } = cutMesh(m, mesh + shift, p.pivot, p.axis, p.cut);
      if (rim !== null) p.static.push(rim);
      log.push(`cut mesh ${mid + ':' + hex(mesh)} along the ellipse: ${before} faces -> ${nIn} spinning + ${nOut} static`);
    }
  }
  let slotI = 0;
  const triRemap = {};// original mesh key -> new face index of each old face (-1: moved to a spinning part)
  const wrappers = new Map();// mesh group -> the BASIC node holding it + the spinning parts split off it
  for (const p of plan) {
    const g = p.group + shift;
    if (m.u32(g) !== NODE_MESH_GROUP) throw new BakeError(`${hex(g)} is not a mesh group after the move`);
    const flags1 = m.u32(g + 4), flags2 = m.u32(g + 8), flags5 = m.u32(g + 16);
    let spinning = g;
    if (!p.whole) {
      // Split: the selected faces of each mesh move to a copy of it (whole meshes move as they
      // are) in a new mesh group the pivot node turns; the rest stays in the original group.
      const keep = [], moved = [];
      const n = m.u32(g + 20), list = m.ptr(g + 24);
      for (let i = 0; i < n; i++) {
        const x = m.ptr(list + 4 * i); if (!x) continue;
        const sel = p.select.get(x - shift);
        if (!sel) { keep.push(x); continue; }
        const total = m.meshTriangles(x);
        if (sel.size === total) { moved.push(x); triRemap[x - shift] = new Array(total).fill(-1); continue; }
        const { tris, hasNormals } = decodeMesh(m, x);
        const part = copyBlock(m, x, MESH_SIZE);
        writeMesh(m, part, tris.filter((_, t) => sel.has(t)), hasNormals);
        writeMesh(m, x, tris.filter((_, t) => !sel.has(t)), hasNormals);
        let k = 0;
        triRemap[x - shift] = tris.map((_, t) => sel.has(t) ? -1 : k++);
        keep.push(x); moved.push(part);
        log.push(`split mesh ${mid}:${hex(x - shift)}: ${sel.size} faces spin, ${total - sel.size} stay`);
      }
      const keepList = m.append(4 * Math.max(keep.length, 1));
      keep.forEach((x, i) => m.setPtr(keepList + 4 * i, x));
      m.put32(g + 20, keep.length); m.setPtr(g + 24, keepList);
      spinning = copyBlock(m, g, MESH_GROUP_SIZE);
      const movedList = m.append(4 * moved.length);
      moved.forEach((x, i) => m.setPtr(movedList + 4 * i, x));
      m.put32(spinning + 20, moved.length); m.setPtr(spinning + 24, movedList);
      if (p.cut) for (const x of moved) {
        const before = m.meshTriangles(x);
        const { nIn, nOut, rim } = cutMesh(m, x, p.pivot, p.axis, p.cut);
        if (rim !== null) p.static.push(rim);
        log.push(`cut the spinning faces along the ellipse: ${before} faces -> ${nIn} spinning + ${nOut} static`);
      }
    }
    const node = m.append(PIVOT_NODE_SIZE), kids = m.append(4);
    m.put32(node, NODE_TRANSFORMED_WITH_PIVOT);
    m.put32(node + 4, flags1); m.put32(node + 8, flags2);
    m.dv.setUint16(node + 12, 0x1B); m.dv.setUint16(node + 14, 0);
    m.put32(node + 16, flags5); m.put32(node + 20, 1);
    m.setPtr(node + 24, kids);
    const [ox, oy, oz] = p.offset, k = p.scale;
    [k, 0, 0, 0, k, 0, 0, 0, k, ox, oy, oz].forEach((v, j) => m.putf(node + 28 + 4 * j, v));
    p.pivot.forEach((v, j) => m.putf(node + 76 + 4 * j, v));
    m.setPtr(kids, spinning);
    let top = node;
    if (!p.whole) {
      // The original group (the faces that stay), the pivot node and any static rim, side by
      // side under one BASIC node in the group's place (shared by later splits of the same group).
      const add = [node];
      if (p.static.length) {
        const staticGroup = copyBlock(m, g, MESH_GROUP_SIZE), staticList = m.append(4 * p.static.length);
        p.static.forEach((rim, i) => m.setPtr(staticList + 4 * i, rim));
        m.put32(staticGroup + 20, p.static.length); m.setPtr(staticGroup + 24, staticList);
        add.push(staticGroup);
      }
      let w = wrappers.get(g);
      if (!w) {
        w = m.append(BASIC_NODE_SIZE);
        m.put32(w, 0x5064);
        m.put32(w + 4, flags1); m.put32(w + 8, flags2); m.put32(w + 16, flags5);
        const wl = m.append(4); m.setPtr(wl, g);
        m.put32(w + 20, 1); m.setPtr(w + 24, wl);
        for (const slot of parents.get(g)) m.setPtr(slot, w);
        wrappers.set(g, w);
      }
      const n = m.u32(w + 20), old = m.ptr(w + 24), wl = m.append(4 * (n + add.length));
      for (let i = 0; i < n; i++) m.setPtr(wl + 4 * i, m.ptr(old + 4 * i));
      add.forEach((x, i) => m.setPtr(wl + 4 * (n + i), x));
      m.put32(w + 20, n + add.length); m.setPtr(w + 24, wl);
    } else if (p.static.length) {
      const staticGroup = copyBlock(m, g, MESH_GROUP_SIZE), staticList = m.append(4 * p.static.length);
      p.static.forEach((rim, i) => m.setPtr(staticList + 4 * i, rim));
      m.put32(staticGroup + 20, p.static.length);
      m.setPtr(staticGroup + 24, staticList);
      top = m.append(BASIC_NODE_SIZE);
      const topKids = m.append(8);
      m.put32(top, 0x5064);
      m.put32(top + 4, flags1); m.put32(top + 8, flags2); m.put32(top + 16, flags5); m.put32(top + 20, 2);
      m.setPtr(top + 24, topKids);
      m.setPtr(topKids, node); m.setPtr(topKids + 4, staticGroup);
    }
    if (p.whole) for (const slot of parents.get(g)) m.setPtr(slot, top);

    if (!p.rpm) continue;
    const al = Math.hypot(...p.axis) || 1, ax = p.axis.map(c => c / al), nk = 5;
    if (isAlt) { spinNodes.push({ node, rpm: p.rpm, axis: ax }); continue; }
    const period = 60 / Math.abs(p.rpm), sign = p.rpm > 0 ? 1 : -1;
    const times = m.append(4 * nk), values = m.append(16 * nk);
    for (let i = 0; i < nk; i++) {
      m.putf(times + 4 * i, period * i / (nk - 1));
      for (let j = 0; j < 3; j++) m.putf(values + 16 * i + 4 * j, ax[j]);
      m.putf(values + 16 * i + 12, sign * 360 * i / (nk - 1));
    }
    const anim = m.append(ANIM_SIZE), b = anim + 220;
    m.putf(b + 24, period); m.putf(b + 28, period); m.putf(b + 32, period);
    m.put32(b + 36, ANIM_TYPE_AXIS_ANGLE | ANIMATION_LOOP);// enabled by the mod during races only
    m.put32(b + 40, nk);
    m.putf(b + 44, period); m.putf(b + 48, period); m.putf(b + 52, 1);
    m.setPtr(b + 64, times); m.setPtr(b + 68, values); m.setPtr(b + 72, node);
    m.setPtr(animSlots[slotI++], anim);
  }

  if (extraCables) addExtraCables(m, log);
  const trailNodes = trails.length ? addTrails(m, trails, log) : [];

  while (m.len % 8) { m.grow(m.len + 1); m.data[m.len - 1] = 0; if (m.len % 4 === 0) m.bits.push(false); }
  const mask = m.maskBytes();
  const out = new Uint8Array(12 + mask.length + m.len);
  out.set([0x52, 0x41, 0x57, 0x4d]);// 'RAWM'
  const odv = new DataView(out.buffer);
  odv.setUint32(4, mask.length, true); odv.setUint32(8, m.len, true);
  out.set(mask, 12); out.set(m.data.subarray(0, m.len), 12 + mask.length);
  log.push(`baked model ${mid} with ${nNew + spinNodes.length} spinning part(s)${spinNodes.length ? ' (turned by the mod)' : ''}` +
           `${extraCables ? ' and an extra cable pair' : ''}${trails.length ? ` and ${trails.length} extra trail(s)` : ''}: ${out.length} bytes`);
  // keyShift: how far every original mesh moved (the header grew); triRemap: faces renumbered in
  // meshes the bake split (by file offset) -- both for the in-game hide lines. spinNodes: the
  // pivot nodes the mod turns (alt models), by file offset.
  return { bytes: out, keyShift: shift, triRemap, spinNodes, trailNodes };
}

(typeof window !== 'undefined' ? window : globalThis).PodBake = { bakePod, resolveKeys, podModels, BakeError, Model, readBlockEntry };
})();
