#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// 0x0044f640 -- swrSprite_GetUIScale. When the resolution-independent toggle is on, returns one
// uniform scale on both axes (no 4:3 stretch) for the swrSprite_array layer (menu frames via
// swrUI_RenderElementSprites + the in-race HUD), and patches the text X reciprocal so menu TEXT
// un-stretches to match the frames. Otherwise reproduces the vanilla stretch and restores the recip.
void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale);

// 0x0042bb00 -- swrSprite_SetPosF. The seam that places every PROJECTED sprite (lens flares, light
// streaks, world/target sprites, weather particles): it takes a framebuffer-pixel coordinate from
// swrViewport_ProjectToScreen and normalizes it into design space (pixel/screen * design) for
// swrSprite_SetPos; swrSprite_DrawSprites later scales it back up by GetUIScale. When the toggle is
// on, the draw scale is uniform, so this re-derives the design coordinate via ui_project_px_to_design
// to keep projected sprites on their true pixel across the full framebuffer. (The args are int16 in
// the binary -- callers __ftol then push -- not the float the swrSprite.h prototype claims.)
void swrSprite_SetPosF_delta(short id, short x, short y);

// 0x00428660 -- swrSprite_SetPos. The single chokepoint every menu/HUD sprite position flows
// through (swrUI_RenderElementSprites, the in-race HUD). When centering is active, shifts normal
// sprites right by the UI-centering offset (in design units). Projected sprites reach SetPos via
// the DLL-internal copy (called from swrSprite_SetPosF_delta), not this EXE hook, so they are not
// centered. Negative special ids (e.g. the cursor sprite) keep their vanilla position.
void swrSprite_SetPos_delta(short id, short x, short y);

// 0x004151f0 -- swrUI_RenderElementSprites. Wraps the original to flag "emitting element-tree
// sprites" so swrSprite_SetPos_delta scales the centering offset by the widget space (640) for menu
// sprites, vs the HUD/game space (320) for direct SetPos callers.
void swrUI_RenderElementSprites_delta(void *ui);

// 0x00408220 -- swrSprite_DisplayCursor. On the GLFW/OS-cursor path the real mouse pointer is the
// only cursor that should be visible, so the game's software cursor sprite
// (swrUISprite_d_cursor_rgb_0 = 249) must stay hidden. The vanilla routine (called every
// swrMain2_GuiAdvance) SHOWS sprite 249 whenever swrSprite_mouseVisible >= 1, and it is only
// re-hidden as a side effect of swrUI_ProcessMouse -> swrUI_UpdateMouseState ->
// stdConsole_GetCursorPos. On screens where swrUI_ProcessMouse takes an early-out (e.g. the post-race
// results screen) that re-hide never runs, so the software cursor leaks on top of the OS cursor -> a
// double cursor (issue #192). This wrapper force-hides sprite 249 instead of showing it, WITHOUT
// touching swrSprite_mouseVisible (so swrUI hit-testing still works). Falls back to the vanilla
// routine when imgui/OS-cursor management is absent (RENDERER_REPLACEMENT=OFF).
void swrSprite_DisplayCursor_delta(void);

#ifdef __cplusplus
}
#endif
