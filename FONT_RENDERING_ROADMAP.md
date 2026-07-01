# Font Rendering Roadmap — Crisp (SDF) Text

North star: resolution-independent, crisp in-game text (menus, HUD, lap counter,
timers, standings) at modern resolutions, while staying **byte-faithful to vanilla
when the feature is OFF**. Opt-in behind an imgui toggle, exactly like the blue-flash
(#127) and overhead-labels (#154) deltas.

## Status (2026-07-01)

The Phase 2 pivot (own the text path) is IMPLEMENTED: `swrText_RenderString_delta`
reverse-hooks the universal chokepoint (0x0042ec50) with a faithful vanilla-bitmap
OFF path and a TTF typography ON path; `sdf_text.cpp` is the packed-SDF atlas
engine (DejaVu + Anton, kerning, format codes, own shader, batched flush at
std3D_EndScene). Branch merged up to upstream master (incl. the resolution-independent
UI un-stretch): SDF text reads `swrText_designWidthRecip/HeightRecip` directly, so it
tracks whatever the un-stretch patches those to -- the two features compose, no
double-scale. Draft PR #182. Toggle persists in the ini (`sdf_text` key), default OFF.

Relationship to upstream's "HD fonts" (`set_hd_fonts`, default ON): that feature is the
page-swap approach this roadmap superseded -- it journals HD PNG pages into
`swrText_fonts[i].pages[p]`, keeping the game's exact bitmap glyph layout/metrics. The two
paths layer cleanly and don't conflict: `sdf_text` OFF -> bitmap path runs and HD pages
apply; `sdf_text` ON -> `swrText_RenderString_delta` returns before the bitmap draw, so the
SDF typography engine fully takes over (HD-font state is irrelevant). SDF's font
classification reads the descriptor glyph tables, which the page-swap does not touch.

Open: playtest the merged build (both toggles on), then the Phase 2/3 polish below.

## Background — how the game renders text today (RE-grounded)

Glyph path (all addresses verified in Ghidra):

```
swrText_DrawString (0x0042e150)        parses "~" codes, walks metrics, handles
   |                                   center/right/outline/shadow/bold/newline
   +-- swrText_SetupGlyph (0x0042edc0) loads one glyph's metrics into DAT_00e996fc.. globals
   +-- swrText_DrawGlyph  (0x0042eeb0) emits the glyph + style re-stamps
        +-- rdProcEntry_Add2DQuad2 (0x0042d990)   per-quad; normalizes UVs
             +-- rdProcEntry_Add2DQuad (0x004329c0)
                  +-- ... rd 2D cache flush ...
                       +-- std3D_DrawRenderList_delta (std3D_delta.cpp)  binds font page
                            +-- renderer_drawRenderList (renderer_utils.cpp:255)
                                 uses assets/shaders/renderList.{vert,frag}
```

Font construction: `swrText_InitFonts (0x0042d720)` builds **7 fonts** from `.rdata`
blobs via `swrModel_ConvertTextureDataToRdMaterial(3, 0, 0x40, 0x80, 0x40, 0x80, ...)`
-> each font page is a **64x128 RdMaterial (bitmap atlas)**. `swrText_BindFontPage
(0x0042ddf0)` = `rdModel_SetCurrentMaterial(font->pages[page])`. The 7 font pointers are
stashed at DAT_00e99720.. and the current font at DAT_0050c0c4 (= &DAT_004bf918).

Font struct (from disasm; to be added to types.h as `swrFont`):
- +0x04 (int)    page material count
- +0x08 (ptr[])  page material array (RdMaterial*)
- +0x4c (u16)    line height (newline advance)
- +0x5a (u8)     firstChar
- +0x5b (u8)     lastChar
- +0x5c (ptr)    glyph table, 0x10 bytes/glyph, index = c - firstChar
- +0x60 (ptr)    extended/Latin-1 glyph table (chars > 0x96)

Glyph entry (`swrTextGlyph`, 0x10 bytes; verified via SetupGlyph + Add2DQuad2):
- +0x00 (u8)     page index (which page this glyph is on; gates the per-pass draw)
- +0x02 (u16)    advance width (cursor step; used by GetCharSize/GetStringWidth)
- +0x04 (i16)    y render offset (bearing) -- screen geometry only, NOT atlas UV
- +0x06 (i16)    x render offset (bearing) -- screen geometry only, NOT atlas UV
- +0x08 (i16)    atlas startU in texels  (== -1 means glyph ABSENT)
- +0x0a (i16)    atlas startV in texels
- +0x0c (u16)    glyph width  in texels
- +0x0e (u16)    glyph height in texels

UV normalization — THE enabling fact: `rdProcEntry_Add2DQuad2` computes
```
u0 = startU * _DAT_004ac644 ; u1 = (width  + startU) * _DAT_004ac644
v0 = startV * _DAT_004ac648 ; v1 = (height + startV) * _DAT_004ac648
```
`_DAT_004ac644` / `_DAT_004ac648` are **read-only constants** (xref scan: read only
inside Add2DQuad2, never written) = the page reciprocals (1/64, 1/128). So UVs are
normalized against the **logical** 64x128 layout, NOT the bound texture's physical
size. => A higher-res page with the SAME cell layout is sampled correctly by the
EXACT SAME emitted quads. No game-side change needed.

Outline (`~o`), shadow (`~s`), bold (`~f`) = the same glyph quad re-stamped at +-1px
offsets in 640x480 virtual space. These map naturally onto an SDF shader and stay
faithful (they remain multi-quad re-stamps; just crisp).

## PIVOT (2026-06-23): full proper typography, not page-swap

Phase 1 shipped the SDF page-swap (below) and it works, but cramming a proportional TTF
into the game's fixed per-glyph cells looks wrong: the cell advances are effectively
MONOSPACE, so a proportional face has bad spacing, and ink-to-cell fitting can only
approximate. Since the UI roadmap [[ui_resolution_independent_roadmap]] is going to redo
text POSITIONING anyway, the faithful-layout constraint that motivated the page-swap no
longer applies -> do real typography.

NEW ARCHITECTURE (Phase 2+): own the text render path and lay out strings with the TTF's
own metrics + kerning, drawn from a packed SDF glyph atlas.
- SEAM (verified universal chokepoint): `swrText_RenderString` (0x0042ec50). `DrawString`
  (0x42e150) is called ONLY by RenderString; RenderString is called by RenderEntries1/2 +
  UpdateTimedMessage. So ALL text flows through it.
- Reverse-hook RenderString in a dinput_hook delta. Toggle OFF = faithful vanilla reimpl
  (replicates the disasm: SetCurrentFont(0), ~b scan, ~f/~F font-select prefix, per-page
  DrawString loop, dirty-rect); also advances the decomp. Toggle ON = TTF typography path.
  (Hook generator gives no trampoline -> reverse-hooks fully replace, so OFF must be a real
  reimpl, not a call-through.)
- Packed SDF glyph atlas per TTF (stbtt_GetCodepointSDF + shelf/rect packing), storing per
  glyph: atlas UV + metrics (advance, bearing, size); plus face v-metrics (ascent/descent/
  linegap) and kerning (stbtt_GetCodepointKernAdvance). Shear baked into rasterization for
  the Anton/Impact italic (fixes the integer-shear jaggies from Phase 1).
- Layout+draw: parse the same inline format codes (~0-9 color, ~c/~r align, ~k/~o/~s style,
  ~n newline, ~~/~t), step the pen by TTF advance+kerning, emit a quad per glyph (atlas UV +
  baseline-relative screen rect) into a batch, transform game 2D coords -> screen px (same
  scale rdProcEntry_Add2DQuad2 uses: screen_w * swrText_designWidthRecip, clamped), draw via
  the SDF shader. Pixel size chosen to match the game font's nominal glyph height.
- Reuses from Phase 1: stb_truetype, the TTFs, renderList.frag SDF branch, the toggle.
  Replaces: the per-cell page builder (sdf_text.cpp) and the std3D texture-swap routing.

## Architecture (Phase 1, SUPERSEDED) — SDF font-page swap

Touch **zero** game text logic (`DrawString` / format codes / metrics / alignment all
stay vanilla). Only two things change, both opt-in:

1. **Build SDF pages at init.** Reverse-reimplement `swrText_InitFonts` as a delta
   (header-only today -> also advances the decomp). After the original page build, for
   each font + glyph, read the cell rect (+0x08..+0x0e) and rasterize a **TTF glyph
   SDF** (via `stbtt_GetCodepointSDF`) into the matching upscaled cell of a new SDF
   page (e.g. 4x = 256x512, R8). Keep a map `bitmapGLHandle -> sdfGLHandle` + the set
   of SDF handles + the SDF px-range. Glyph layout/advances are the game's, so on-screen
   positioning is byte-identical; only the imagery upgrades.

2. **SDF branch in the shader.** `renderList.frag` gains `uniform bool isSDF;` +
   `uniform float sdfRange;`. When set, `alpha = smoothstep(0.5 - w, 0.5 + w, dist)`
   with `w = fwidth(dist)` (screen-space AA), `rgb = passColor.rgb`. Else the current
   `texel * passColor`.

3. **Per-draw routing.** In `std3D_DrawRenderList_delta`, if `imgui_state.sdf_text` and
   `(GLuint)pTex` is a known font bitmap handle, bind its SDF handle instead and flag
   this draw as SDF; `renderer_drawRenderList` sets the uniforms. Symbol/button fonts
   not covered by the TTF stay on their bitmap (not tagged) -> graceful vanilla
   fallback.

4. **Toggle.** `imgui_state.sdf_text` (default OFF). OFF = original materials =
   byte-identical vanilla.

Why not the alternatives: a loose-file HD atlas can't work (pages are baked .rdata
bitmaps, not hashed loose textures); intercepting at Add2DQuad2/std3D and reverse-
mapping UV->char is fragile. Owning InitFonts + a shader branch is the clean seam.

## Dependencies / decisions

- **stb_truetype.h** (standalone, public domain) vendored under a third-party dir.
  Provides both rasterization and `stbtt_GetCodepointSDF`. (imgui ships a *namespaced*
  `imstb_truetype.h`; vendor a clean standalone copy rather than reuse it.)
- **Bundled TTFs** shipped as loose assets (e.g. assets/fonts/). The game uses two
  proprietary faces: **Verdana** (body / smaller fonts) and **Impact, italicized**
  (headline / larger font). Libre substitutes:
  - Impact -> **Anton** (SIL OFL). Anton is upright-only; the game's italic is
    reproduced by **synthesizing oblique** (~12-15 deg horizontal shear applied during
    rasterization) -- clean on a heavy display face, no italic cut needed.
  - Verdana -> **DejaVu Sans** (permissive Bitstream Vera license) or Open Sans (OFL).
  - Need to confirm which of the 7 game font pages map to Verdana vs Impact (size/weight
    variants of the two typefaces).
- Glyph fit: rasterize each TTF glyph's SDF **stretched to the cell's width x height**,
  so we inherit the game's advances/layout regardless of the TTF's own metrics -- only
  shape aesthetic needs to be close, not metric-compatibility. Tune spread/AA in Phase 2.

## Phases

- **Phase 0 — decomp + scaffold. DONE (built green + playtested 2026-06-23).**
  `swrFont` (0x68) / `swrTextGlyph` (0x10) added to types.h (every field verified against
  live .rdata bytes via read_memory); named `swrText_fonts[5]` (0x4bf7e0),
  `swrText_fontTable[7]` (0xe99720), `swrText_fontCount` (0x50c0c0), `swrText_currentFont`
  (0x50c0c4) in data_symbols.syms. `swrText_InitFonts` faithfully reverse-reimplemented in
  swrText.c (build order {3,0,1,2,4}, page loops + font-table wiring match the disasm). Live
  reverse-hook, fonts render identically to vanilla. NOT yet committed. (`_DAT_004ac644/648`
  = 1/64, 1/128 confirmed -- naming them is deferred to Phase 1 since they live in the
  still-original rdProcEntry_Add2DQuad2.)
- **Phase 1 — SDF pipeline, one font.** Vendor stb_truetype; bundle a TTF; build an SDF
  page for the main UI font (DAT_0050c0c4) at init; add the `renderList.frag` SDF branch
  + uniforms; route the draw in std3D_DrawRenderList_delta; wire the imgui toggle.
  Playtest: crisp main-menu text, vanilla when OFF.
- **Phase 2 — all fonts + polish.** Extend to all 7 fonts (skip symbol fonts the TTF
  can't cover); tune SDF spread/AA; verify outline/shadow/center/right alignment across
  menus, HUD, lap counter, timers, standings, splitscreen.
- **Phase 3 (optional).** Per-font TTF selection; extended glyph coverage (Latin-1 via
  the +0x60 table); optional MSDF for sharper corners.

## Faithfulness gate

Toggle OFF must be byte-identical to vanilla (original bitmap materials, original
shader path). Mandatory full dinput.dll link before any PR (WinLibs cmake recipe).
Run /pre-pr-check (dup _ADDR/name scan, canonical Ghidra names, K&R, ASCII headers,
struct progress folded into types.h, no raw 0x literals in the hook layer).
