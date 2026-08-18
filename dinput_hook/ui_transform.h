#pragma once
/*
 * Shared UI coordinate transform -- the single definition of the
 * design<->framebuffer mapping that every 2D consumer routes through.
 *
 * Representation: a uniform scale plus a framebuffer-space translation (a
 * similarity with NO rotation -- in-race HUD wobble is position-only). It
 * composes and inverts, so a UI-scale slider, repositionable elements, and HUD
 * wobble all drop in as additional inputs rather than as rewrites.
 *
 * C-linkage so both the .c and .cpp deltas in game_deltas/ can consume it.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Authoring reference dims -- the ONLY place 640/480 live in the layout path. */
#define UI_DESIGN_W 640.0f
#define UI_DESIGN_H 480.0f

typedef struct UiVec2 {
    float x;
    float y;
} UiVec2;

/* Uniform scale + framebuffer-space translation. No rotation term. */
typedef struct UiXform {
    float scale;
    float tx;
    float ty;
} UiXform;

typedef enum UiAnchorH {
    UI_H_LEFT,
    UI_H_CENTER,
    UI_H_RIGHT,
} UiAnchorH;

typedef enum UiAnchorV {
    UI_V_TOP,
    UI_V_MIDDLE,
    UI_V_BOTTOM,
} UiAnchorV;

/* --- transform algebra --- */
UiXform ui_xform_identity(void);
/* Apply `inner` first, then `outer` (outer after inner). */
UiXform ui_xform_compose(UiXform outer, UiXform inner);
UiXform ui_xform_invert(UiXform x);
UiVec2 ui_xform_apply(UiXform x, UiVec2 p);

/* --- shared design<->framebuffer mapping --- */
/* Uniform layout scale for the WIDGET / cursor / hit-test space (640x480 == UI_DESIGN_W/H):
 * (screenHeight / UI_DESIGN_H) * ui_scale slider. Square pixels => no horizontal stretch. */
float ui_layout_scale(void);
/* Uniform scale for the SPRITE / TEXT DRAW space, which the engine defines via its own height
 * reciprocal (NOT 640x480 -- it is ~320x240, so this is ~2x ui_layout_scale). Use this for the
 * sprite draw scale (GetUIScale) and the text reciprocal so they un-stretch to full size and stay
 * aligned with the (separately scaled) widget/hit space (two distinct design spaces). */
float ui_sprite_scale(void);
/* The screen-pinned origin for an anchor, evaluated vs the live framebuffer. */
UiVec2 ui_anchor_point(UiAnchorH h, UiAnchorV v);
/* design-space coordinate (0..640, 0..480) -> framebuffer px. */
UiVec2 ui_design_to_screen(UiAnchorH h, UiAnchorV v, UiVec2 design);
/* framebuffer px -> design-space coordinate (inverse: cursor + drag-reposition). */
UiVec2 ui_screen_to_design(UiAnchorH h, UiAnchorV v, UiVec2 screen);

/* Projected-element seam: convert a framebuffer-pixel coordinate (as produced by
 * swrViewport_ProjectToScreen for lens flares / light streaks / world sprites / weather /
 * the distance+name HUD text) into the sprite/text DESIGN coordinate that the draw then scales
 * back up. swrSprite_SetPosF and swrText_CreateTextEntry2 are exactly this seam in the engine
 * (pixel/screen * design). When res-independence is on the draw multiplies by the uniform
 * ui_sprite_scale on BOTH axes, so dividing the pixel by ui_sprite_scale here makes the round
 * trip land the element on its true projected pixel (spanning the full framebuffer, not the
 * letterboxed UI box). When off, reproduces the vanilla per-axis normalization. */
UiVec2 ui_project_px_to_design(UiVec2 px);

/* Design-space (640x480 widget units) horizontal shift that re-anchors a hit-testable menu ELEMENT
 * from the centered 4:3 default to a screen edge. An element's stored rect drives BOTH its drawn
 * sprites AND its hit-rect, and the cursor is centered uniformly, so shifting the element's x by this
 * amount moves the visual and the click target together and stays aligned (unlike shifting only the
 * emitted sprite, which would desync clicks from visuals). UI_H_LEFT hugs the real left edge,
 * UI_H_RIGHT the real right edge, UI_H_CENTER is 0 (the unchanged, centered default). 0 when
 * res-independence is off. */
float ui_anchor_element_dx(UiAnchorH h);

/* Horizontal framebuffer translation that centers the uniform-width 2D UI box in the window:
 * (screenWidth - UI_DESIGN_W * ui_layout_scale()) / 2, or 0 when res-independence is off. The
 * whole 2D UI layer (menu + in-race HUD sprites, text, clip rects) shifts right by this; the
 * cursor subtracts it so hit-tests stay aligned. Projected/world elements (lens flares, weather,
 * markers) are NOT shifted -- they route through the DLL-internal seam copies, not the EXE hooks. */
float ui_center_offset_px(void);

/* Menu-text scope depth. Incremented while a swrUI / front-end text path is active (swrUI_DrawText,
 * swrUI_DrawTextAligned, the swrObjHang_F0 hangar dispatcher, the in-race pause menu) so that
 * swrText_CreateTextEntry1's centering offset uses the widget (640) scale instead of the HUD (320)
 * scale. Shared because the wrapping deltas live in several translation units. > 0 means "menu". */
extern int ui_menu_text_depth;

/* In-race position-marker scope. swrObjJdge_DrawRaceHUD_delta sets this to the live hud_mode while the
 * game draws the per-racer position markers (sprites 0x2b-0x34 + their number text) and clears it to -1
 * after. Those markers live in a different place each HUD mode, so the sprite + text sinks remap their
 * X by mode (ui_hud_marker_x) instead of applying the plain centering. -1 means "not drawing markers". */
extern int ui_hud_marker_mode;

/* Remap an in-race position-marker's design X for the given hud_mode (called only inside the marker
 * scope above). Mode 0 (catch-up arrows, right strip) right-anchors to the real right edge; mode 1
 * (the progress ring the flags travel around) stretches X to fill the window width so the ring spans
 * the whole screen; every other mode falls back to the plain centering shift. Returns design X
 * unchanged when res-independence is off. */
float ui_hud_marker_x(float design_x, int mode);

/* In-race HUD scope. swrObjJdge_UpdatePlayerHUD_delta holds this > 0 while the game draws the per-player
 * HUD (header bar, speedometer, engine readout + their text). The id-based HUD edge-anchoring
 * (hud_sprite_anchor / hud_text_anchor and the header full-width fills) keys off low sprite ids and
 * fixed design-x columns that OTHER screens (e.g. the race-settings pilot portrait / track favorite)
 * reuse, so it must only fire inside this scope -- otherwise it stretches/offsets those unrelated
 * sprites. 0 means "not drawing the in-race HUD"; texture-keyed menu anchoring (backdrops/logo) and the
 * position markers (their own ui_hud_marker_mode scope) are unaffected by this. */
extern int ui_in_race_hud;

/* --- layer/group stack (the in-race HUD pushes a translation for wobble) --- */
void ui_layer_push(UiXform x);
void ui_layer_pop(void);
UiXform ui_layer_current(void);

/* Is the resolution-independent path active? (toggle gate). When 0, consumers
 * must reproduce vanilla behavior. */
int ui_enabled(void);

#ifdef __cplusplus
}
#endif
