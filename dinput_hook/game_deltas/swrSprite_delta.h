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

#ifdef __cplusplus
}
#endif
