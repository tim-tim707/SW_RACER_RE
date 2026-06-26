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

// LAYER 3-A fix (snow vanishes when the pod moves): swrWeather_RenderParticles picks a render mode
// per flake from its per-frame screen movement -- < 3 px uses the point-sprite path (renders fine),
// >= 3 px sets sprite flag 0x4000 and uses the streak/motion-blur path (renders nothing at modern
// resolutions). The 3 px threshold is absolute, not resolution-scaled, so at high resolution any
// camera motion pushes every flake past it -> all snow flips to the broken streak path and
// disappears (parked = visible, moving = gone; slight motion straddles the threshold = flicker).
//
// Until the streak draw path is fixed, force the point-sprite path: NOP the two JGE branches that
// select the streak path (at 0x0042d20f / 0x0042d214 inside swrWeather_RenderParticles) so the code
// always falls through to swrSprite_UnsetFlag(0x4000). Moving snow then renders as points (the same
// way it already renders when parked) instead of vanishing. Scoped to the weather particle loop.
void swrWeather_PatchForcePointParticles();

// LAYER 3-A, proper streaks (Tier 1): reimplement the cut motion-blur trail in the GL layer.
// The PC port stubbed the streak draw (swr_noop2), but the engine still computes everything we
// need: for each streaking weather sprite it stores the current head position (swrSprite.x/.y) and
// the trail endpoint (swrSprite.unk0x4/.unk0x6), both in 320x240-normalized space, plus colour and
// the 0x4000 streak flag. We hook swrSprite_Draw2 (called per sprite); for a streaking weather
// sprite (flag 0x4000) we draw a rotated quad from head to tail through the existing render-list
// path. Used INSTEAD of swrWeather_PatchForcePointParticles (which suppresses the 0x4000 flag).
void swrSprite_Draw2_delta(swrSprite *a1, int a2, float a3, float a4);

// Graceful SNW <-> NSNW transitions: stop the spawner on Disable and let existing particles fall
// out (RenderParticles keeps running) instead of instantly clearing/hiding all weather. Weather is
// turned fully off only once the particle pool has emptied. See swrWeather_delta.cpp.
void swrWeather_Enable_delta(void);
void swrWeather_Disable_delta(void);
void swrWeather_RenderParticles_delta(void *viewport);

// Depth occlusion: the renderer hands us the scene view/projection each frame so the particle draw
// can place each particle at its real window-z and depth-test it against the scene depth (blitted
// to the default framebuffer), instead of drawing weather as a flat overlay over everything.
extern "C" void swrWeather_SetSceneMatrices(const rdMatrix44 *proj, const rdMatrix44 *view);
