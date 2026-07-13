#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct swrSpriteTexture swrSpriteTexture;

// 0x004114d0 -- swrSprite_GetTextureFromTGA. Records the texture id of each full-screen backdrop
// (greyedsplash / podhangar_backdrop / podhangar_backdrop2 / splash) and each title-logo part
// (episode1 / star / wars / racer) as it loads, so the sprite sinks can stretch the backdrops to fill
// and left-anchor the logo. Passthrough for every other texture.
swrSpriteTexture *swrSprite_GetTextureFromTGA_delta(char *filename_tga, int id);

// 0x004286f0 -- swrSprite_SetDim. When res-independence is on, resizes a recognized backdrop sprite to
// cover the whole framebuffer (fill) instead of its authored 4:3 size; everything else passes through.
void swrSprite_SetDim_delta(short id, float width, float height);

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

// Edge-anchor the standard Quit/Cancel/Back button (0x00411170) and the Settings button to the real
// left edge, and the OK button (0x00411210) to the real right edge, on wide screens.
// AddNavButton/AddOkButton flag which button swrUI_NewButton (0x004132a0) is creating; the Settings
// button (element id 0xf) is recognized in NewButton, which then MOVES the element (position + clip
// bbox) to its edge. swrUI_SetPos (0x00414b60) re-applies the shift on relayout so it sticks, and
// swrUI_RenderElementSprites (0x004151f0) advances it to the live edge each frame so it follows a
// window resize. Because the whole element moves, its sprites, label, click test, and hit-test all
// follow. All are exact passthroughs when res-independence is off.
void swrUI_AddNavButton_delta(void *page, int id, int x, int y, int kind);
void swrUI_AddOkButton_delta(void *page, int x, int y);
void *swrUI_NewButton_delta(void *parent, int id, int font, char *text, int x, int y, int width,
                            int height, int flags, int param10);
void swrUI_SetPos_delta(void *ui, int x, int y);

// 0x00428030 -- swrSprite_Draw2. Draws one array sprite. For projected sprites (placed via SetPosF)
// it draws at a subdivided scale so their int16 position keeps sub-pixel precision, eliminating the
// high-res stairstepping; all other sprites draw exactly as vanilla. See the .cpp for the math.
struct swrSprite;
void swrSprite_Draw2_delta(struct swrSprite *sprite, int pass_flags, float xscale, float yscale);

#ifdef __cplusplus
}
#endif
