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
