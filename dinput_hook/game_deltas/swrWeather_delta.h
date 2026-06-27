#pragma once

#include "types.h"

// Weather (rain/snow) rendering fixes for modern high-resolution displays.
//
// See the KNOWN ISSUES block in src/Swr/swrWeather.h for the full Layer 1/2/3 analysis.
//
// LAYER 2 fix (this file): at screen_width >= 1000 the weather particle pool stops respawning and
// weather vanishes. swrViewport_ProjectToScreen seeds its out screen X/Y with a -1000.0f sentinel
// and only overwrites it when the point projects in-bounds; swrWeather_RenderParticles despawns a
// particle when its screen X < -screen_width. With the sentinel pinned at -1000.0f the despawn
// never fires for >= 1000-px-wide screens (-1000.0 < -1000.0 is false), so off-screen particles
// are stuck "active but invisible" forever and the pool never recycles. Patching the sentinel to
// -INF makes the despawn fire at any resolution. Empirically verified (DDrawCompat reproduces the
// same threshold as dgVoodoo2, so it is the EXE, not the DirectDraw wrapper).
//
// Applied as a verified in-place byte patch at startup (mirrors swrObjJdge_PatchRaceTimeCap): two
// 4-byte float immediates inside swrViewport_ProjectToScreen, 0xC47A0000 (-1000.0f) -> 0xFF800000
// (-INF). The function's other callers (HUD distance text, rearview, world sprites, target
// indicators) use the output only as a sprite coordinate that the sprite renderer clips naturally,
// so -INF vs -1000.0f is a no-op for them.
void swrWeather_PatchHiResParticleSentinel();

// LAYER 3 (snow/rain vanish when the pod moves; reimplement the cut motion-blur streaks): the PC
// port stubbed the streak draw (swr_noop2), and at high resolution any camera motion crosses the
// absolute 3 px threshold that selects the streak path -- so moving weather drew nothing. We take
// over the whole particle draw via swrSprite_Draw2 (gated on weather pool membership): each particle
// draws as a soft round point or, when moving, a motion-blur streak (rotated quad from the head,
// swrSprite.x/.y, to the stored trail endpoint, swrSprite.unk0x4/.unk0x6) through the existing
// render-list path -- sub-pixel smooth, alpha-gradient tail, additive (rain) / alpha (snow) blend,
// and depth-tested against the scene. See swrWeather_delta.cpp.
void swrSprite_Draw2_delta(swrSprite *a1, int a2, float a3, float a4);

// Graceful SNW <-> NSNW transitions: stop the spawner on Disable and let existing particles fall
// out (RenderParticles keeps running) instead of instantly clearing/hiding all weather. Weather is
// turned fully off only once the particle pool has emptied. See swrWeather_delta.cpp.
void swrWeather_Enable_delta(void);
void swrWeather_Disable_delta(void);
void swrWeather_RenderParticles_delta(void *viewport);

// Denser weather: multiply each track's configured particle count (clamped to the 80-slot pool).
void swrWeather_SetParticleCap_delta(int max);

// Depth occlusion: the renderer hands us the scene view/projection each frame so the particle draw
// can place each particle at its real window-z and depth-test it against the scene depth (blitted
// to the default framebuffer), instead of drawing weather as a flat overlay over everything.
extern "C" void swrWeather_SetSceneMatrices(const rdMatrix44 *proj, const rdMatrix44 *view);
