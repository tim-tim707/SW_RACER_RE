#pragma once

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
