#pragma once

// Crisp text via proper TTF typography. Lays out a string with the bundled font's own
// metrics + kerning from a packed SDF glyph atlas and draws it through the SDF shader,
// replacing the game's bitmap glyph rendering. Used by the swrText_RenderString delta
// when imgui_state.sdf_text is on. See FONT_RENDERING_ROADMAP.md.

// Render a formatted string at the current text pen (currentTextPosX/Y), color
// (currentSpriteColor) and font (swrText_currentFont), mirroring swrText_RenderString's
// inputs. Handles the ~f/~F font-select prefix and the inline ~0-9 / ~c / ~r / ~n / ~~
// codes. Returns false if the engine isn't ready (fonts/atlas not built), so the caller
// can fall back to the vanilla path.
bool sdf_text_render_string(const char* text);

// Draw all glyph quads queued by sdf_text_render_string this frame, then clear them.
// Call once per frame at the end of the 2D scene (std3D_EndScene).
void sdf_text_flush();

// Register the exact (fractional) design-space position of a world-locked label (overhead racer
// number / name), keyed by the integer design coordinate the text entry stores. The next string
// rendered from that rounded pen position is placed at the exact position instead, so the label
// tracks smoothly instead of snapping to the design grid at high resolution. Per-frame; reset in
// sdf_text_flush. No-op unless the SDF path renders the string.
void sdf_text_set_subpos(int rounded_x, int rounded_y, float exact_x, float exact_y);

// ---- per-slot font customization (the "SDF Fonts" debug panel) -----------------------
// The engine renders the game's 5 distinct font descriptors (swrText_fonts[0..4]); the 7 logical
// ~f<n> codes alias into those 5. Each slot's look is a SdfFontSlot the panel edits in place and
// the ini persists. The live tunables (weight/scale/offset/lineHeight/letterSpacing/shadow) are
// read straight from the slot every frame -- no rebuild. Changing the font file or shear rebuilds
// that slot's atlas asynchronously (the old atlas keeps rendering until the new one is ready).

#define SDF_SLOT_COUNT 5
#define SDF_FONT_PATH_MAX 260

struct SdfFontSlot {
    char file[SDF_FONT_PATH_MAX];// TTF/OTF path; "" = built-in default (DejaVu/Anton by role)
    bool fileAuto;               // file[] not user-set -> resolve by role at build time
    float shear;                 // faux-italic slant baked into the atlas (0 = upright)
    bool shearAuto;              // shear not user-set -> role default at build time
    float weight;                // SDF weight bias (live shader uniform; >0 = heavier)
    float scale;                 // size multiplier vs the vanilla cap height (1.0 = match)
    float offsetX, offsetY;      // pen nudge, fraction of cap (positive x = right, y = down)
    float lineHeight;            // line-advance multiplier applied to ~n (1.0 = font default)
    float letterSpacing;         // extra advance after every glyph, fraction of em
    bool shadowForceOff;         // ignore the ~s code: never draw a drop shadow for this slot
    float shadowDx, shadowDy;    // drop-shadow offset in game-2D design units (default 1,1)
};

// Number of editable slots (== SDF_SLOT_COUNT).
int sdf_text_slot_count();

// The live config for slot i (null if out of range); edited in place by the panel and filled from
// the ini at startup. Live tunables (weight/scale/offset/lineHeight/letterSpacing/shadow) take
// effect immediately; call sdf_text_apply_slot after changing file/fileAuto or shear to rebuild
// that slot's atlas.
SdfFontSlot *sdf_text_slot(int i);

// Re-resolve slot i's face from its current file/shear and kick an async atlas rebuild if needed.
void sdf_text_apply_slot(int i);

// Whether slot i's face is built and rendering. *status_out (optional) receives a short
// human-readable state ("ready" / "building..." / "waiting for fonts" / "missing font file").
bool sdf_text_slot_ready(int i, const char **status_out);

// Short label for the panel row, e.g. "~f1 ~f3 | Display | cap 20". Valid until the next call.
const char *sdf_text_slot_desc(int i);

// Restore slot i to its built-in defaults (sets the *Auto flags) and rebuild.
void sdf_text_reset_slot(int i);
