#pragma once

#include "types.h"

// Weather (rain/snow) rendering for modern high-resolution displays. See the KNOWN ISSUES block in
// src/Swr/swrWeather.h for the full analysis.

// Weather particle system reimplemented in the renderer layer (swrWeather_delta.cpp). The
// game's 80-slot, fixed-box, 4:3-projected, sprite-based system (whose streak draw was stubbed out)
// is replaced with our own: an arbitrary-size pool spawned in a world box around the camera,
// integrated by the per-track world velocity, projected through the actual GL scene view/projection
// (so it aligns with the scene and depth-tests against it), drawn as soft round points or motion-blur
// streaks batched into one draw call. Colour/velocity/stretch/intensity still come from the game
// globals so it stays faithful per planet. Enable/Disable flip the per-region spawner (Disable fades
// out gracefully); RenderParticles_delta is a no-op that suppresses the game's own weather setup.
void swrWeather_RenderParticles_delta(void *viewport);
void swrWeather_Enable_delta(void);
void swrWeather_Disable_delta(void);

// Hooked on the game's race-context reset (called at swrObjJdge_InitTrack start, before the track
// re-enables weather, and at swrObjJdge_TeardownRace end -- never mid-race). Forces weather fully off
// so it can't bleed into the post-race standings/hangar/galaxy menus, where InRaceSpritesEnabled and
// swrWeather_enabled both remain set.
void swrWeather_ResetParticles_delta(void);

// Ticks + draws our particles. The renderer calls this from swrViewport_Render_Hook right after the
// 3D scene is blitted to the default framebuffer (so FB0 + scene depth are bound and the view/proj
// are current) -- drawing there, not in RenderParticles (pre-scene setup), avoids corrupting the
// scene render. Passed the scene view/projection so particles align with the scene + depth-test.
void swrWeather_TickAndDraw(const rdMatrix44 *proj, const rdMatrix44 *view);
