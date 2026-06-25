#ifndef SWRPLAYERHUD_H
#define SWRPLAYERHUD_H

#include "types.h"

// Per-player split-screen HUD/overlay subsystem.
//
// Call graph per frame:
//   swrPlayerHUD_RenderAllViewports (the per-frame render loop, from FUN_00445980)
//     -> swrViewport_Activate / swrViewport_Setup  (per viewport, see swrViewport.h)
//     -> swrPlayerHUD_RenderViewport(viewport, secondaryPass)
//          if (InRaceSpritesEnabled)  // HUD orchestrator enable, set by swrPlayerHUD_Enable
//              -> FUN_0042c1a0            (target indicators -- not yet named)
//              -> UpdateLightStreakSprites     (light-streak motion-blur sprites, see swrModel.h)
//              -> swrPlayerHUD_RenderWorldSprites
//              -> swrWeather_RenderParticles   (see swrWeather.h)
//              -> swrPlayerHUD_RenderDistanceText
//          else only RenderDistanceText runs.
//
// Race HUD setup (at track load):
//   swrPlayerHUD_LoadRaceHUD  -> swrSprite_ResetAllSprites, loads speedometer / engine /
//     starting-grid / flag sprites, then -> swrPlayerHUD_SetupTrackOverlay, which loads
//     the per-track HUD elements AND configures weather (swrWeather_Enable/SetColor/
//     SetVelocity/SetParticleCap/SetStretchFactor) based on the track/weather scenario.
//
// swrPlayerHUD_SampleOcclusion runs once per frame before the loop (also from
// FUN_00445980); it CPU-reads the back buffer for HUD-marker occlusion -- see the
// high-resolution caveat below and the fuller analysis in swrWeather.h.

#define swrPlayerHUD_RenderDistanceText_ADDR (0x0042c510)

// NOTE: 0x0042c800 (the light-streak motion-blur updater) is declared as
// UpdateLightStreakSprites in swrModel.h, alongside the rest of the light-streak
// family (InitLightStreak / ResetLightStreakSprites / SetLightStreakSpriteIDs).

#define swrPlayerHUD_RenderWorldSprites_ADDR (0x0042cb00)

#define swrPlayerHUD_Enable_ADDR (0x0042d500)

#define swrPlayerHUD_RenderViewport_ADDR (0x0042d490)

#define swrPlayerHUD_SampleOcclusion_ADDR (0x0042be60)

#define swrPlayerHUD_RenderAllViewports_ADDR (0x00483cb0)

#define swrPlayerHUD_SetupTrackOverlay_ADDR (0x00464010)

#define swrPlayerHUD_LoadRaceHUD_ADDR (0x00464630)

// swrPlayerHUD_SampleOcclusion is called once per frame at the start of the
// render phase (from FUN_00445980, before the per-viewport render loop). It
// locks the back buffer via DirectDraw_LockZBuffer and samples raw pixel
// data around every HUD marker's projected screen position to detect
// occlusion by world geometry. The resulting "coverage" counts are stored at
// DAT_00e9a3c0 (target indicators), player_sprite_depth_values (0x00e9a7e0,
// minimap player markers), light_streak_depth_values (0x00e99d80, light-streak
// points), and DAT_00e9a8e0 (world sprites); each sub-renderer reads them later
// to decide whether to draw its marker.
//
// KNOWN ISSUE -- broken on modern high-resolution displays:
//   The inner 8x8 sample loop's per-pixel comparison only handles bpp == 1
//   (8-bit) and bpp == 2 (16-bit). For bpp 3 (24-bit) and bpp 4 (32-bit) --
//   which is what modern DirectDraw wrappers emulate -- the pixel-coverage
//   test is silently skipped, degrading occlusion to "out-of-screen-margin
//   pixels only." HUD markers then draw through walls.
//   The function also has the same buggy bpp dispatch switch documented in
//   swrWeather.h (no default case, cases 3 and 4 read swapped globals).

void swrPlayerHUD_RenderDistanceText(void* viewport, bool secondaryPass);

void swrPlayerHUD_RenderWorldSprites(void* viewport);

void swrPlayerHUD_Enable(void);

void swrPlayerHUD_RenderViewport(void* viewport, bool secondaryPass);

void swrPlayerHUD_SampleOcclusion(void);

// Per-frame render loop: iterates the active player viewports (struct array at
// DAT_00dfb040, stride 0x16c, up to 4), activates each, and calls
// swrPlayerHUD_RenderViewport. Interleaves swrSprite render-all passes (modes 1/2/3).
void swrPlayerHUD_RenderAllViewports(void);

// Loads the per-track HUD element sprites and configures the weather subsystem
// (enable/color/velocity/cap/stretch) for the given HUD type + weather level.
// hudType selects the layout (cockpit variants, etc.); weatherLevel selects
// none/light/heavy precipitation. Called by swrPlayerHUD_LoadRaceHUD.
void swrPlayerHUD_SetupTrackOverlay(int hudType, int weatherLevel);

// Master race-HUD loader: resets all sprites, loads speedometer / engine / starting
// grid / placement-flag sprites, then calls swrPlayerHUD_SetupTrackOverlay.
void swrPlayerHUD_LoadRaceHUD(int hudType, int weatherLevel, int racerData);

#endif // SWRPLAYERHUD_H
