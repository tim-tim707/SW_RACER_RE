#ifndef SWRWEATHER_H
#define SWRWEATHER_H

#include "types.h"

// Weather particle effects (rain/snow/dust).
//
// swrWeather_RenderParticles is invoked per viewport from swrPlayerHUD_RenderViewport
// (only when the HUD orchestrator flag InRaceSpritesEnabled is set), and only runs when
// the weather enable flag swrWeather_enabled is set. Each particle slot has a state
// machine (0 = empty, 1 = active, 2 = visible-this-frame). Particles spawn around the
// camera world position with random offsets along the camera basis vectors, integrate
// against the velocity set via swrWeather_SetVelocity, and despawn when projected
// off-screen.
//
// Per-track configuration (enable, color, velocity, particle cap, stretch) is set by
// swrPlayerHUD_SetupTrackOverlay during race HUD load. The SNW / NSNW collision tags on
// the track toggle swrWeather_enabled on/off per region as the camera moves, so weather
// is a dynamic per-region effect, not a static per-track one.
//
// =====================================================================================
// GLOBAL STATE
//
//   Per-run configuration (set by swrPlayerHUD_SetupTrackOverlay through the setters):
//     swrWeather_enabled         0x004b9520  int         master on/off (swrWeather_Enable/
//                                                         _Disable + SNW/NSNW track tags)
//     swrWeather_particleColor   0x004b9524  uint8_t[4]  RGBA tint (swrWeather_SetColor)
//     swrWeather_velocityX       0x004b9528  float       drift/fall velocity X (swrWeather_SetVelocity)
//     swrWeather_velocityY       0x004b952c  float       drift/fall velocity Y (swrWeather_SetVelocity)
//     swrWeather_stretchFactor   0x004b9530  float       rain-streak stretch (swrWeather_SetStretchFactor)
//     swrWeather_particleCap     0x004b9534  int         active slot count, <= 80 (swrWeather_SetParticleCap)
//
//   Particle pool -- four parallel arrays of 80 slots, walked in lockstep (slot index)
//   by swrWeather_RenderParticles and swrWeather_HideAllParticles:
//     swrWeather_particlePositions        0x00e99860  rdVector3[80]  world-space position
//     swrWeather_particleScreenPositions  0x00e9a000  rdVector2[80]  last projected screen x/y
//     swrWeather_particleSpriteIds        0x00e9a280  int[80]        swrSprite id (-1 = unallocated)
//     swrWeather_particleStates           0x00e9a960  char[80]       0 = empty, 1 = active, 2 = visible-this-frame
//
// =====================================================================================
// KNOWN ISSUES -- weather visibility on modern displays.
//
// What "weather doesn't work at high resolutions" actually splits into THREE
// independent layers. Layer 1 is by design, Layer 2 has been root-caused and has
// a patch, Layer 3 is partially understood with a workaround.
//
// LAYER 1 -- TRACK DATA (by design, not a bug): many "weather planet" tracks ship
//   with planet_track_number == 0, which selects swrWeather_SetParticleCap(0) and produces
//   zero particles regardless of resolution or renderer. planet_track_number is
//   swrObjJdge.planet_track_number (offset 0x1c0), bulk-loaded from the level .dat file
//   into swrObjScen + 0x28 by the swrObj loader, then copied to the Jdge in
//   swrObjJdge_F4's "Begn" handler (0x00463a50).
//   Empirical per-track caps measured in-game (cap stored at swrWeather_particleCap):
//
//     Snow planet (planetId == 1):
//       Howler Gorge ............. cap 20  (planet_track_number 1, light)
//       Andobi Mountain Run ...... cap 40  (planet_track_number 2, heavy)
//       Andobi Prime Centrum ..... cap  0  (planet_track_number 0, no configured particles)
//     Rain planet (planetId == 4):
//       Baroo Coast .............. cap 20  (planet_track_number 0 in rain path -> 0x14)
//       Grabvine Gateway ......... cap 60  (planet_track_number 1/2)
//       Fire Mountain Rally ...... cap 60  (planet_track_number 1/2)
//       Inferno .................. cap  0  (planet_track_number 3 disables, or non-rain path)
//
//   So the "Ando Prime has no snow" symptom many users report on the Centrum track
//   is NOT a renderer bug -- that track is shipped without particles. Layers 2 and 3
//   below only affect tracks with cap > 0.
//
// LAYER 2 -- HARDCODED -1000.0f SENTINEL IN swrViewport_ProjectToScreen (ROOT CAUSE
//   FOUND, PATCH AVAILABLE):
//
//   At screen_width (0x00ec86c4) >= 1000, the initial batch of particles renders
//   for one cycle and then never respawns. Particles all end up stuck at state 1
//   (active but invisible, drifting off-screen forever) because the way-off-screen
//   despawn at swrWeather_RenderParticles+0x42D078 never fires.
//
//   The reason: swrViewport_ProjectToScreen initializes its outputs to a sentinel
//   value of -1000.0f and only overwrites them with the real projected coordinate
//   when the projected point falls within the viewport bounds box:
//
//     0042b868: MOV dword ptr [ESI], 0xC47A0000   ; *outScreenX = -1000.0f
//     0042b87f: MOV dword ptr [EDI], 0xC47A0000   ; *outScreenY = -1000.0f
//     ... projection math, four bounds-box checks ...
//     0042ba06: MOV [ESI], EDX                    ; only if in bounds, write real X
//     0042ba08: MOV [EDI], EAX                    ; only if in bounds, write real Y
//
//   The weather despawn condition reads:
//
//     if (local_3c < (float)-screen_width || ...)   // < -screen_width
//         state = 0;
//
//   With the sentinel held at exactly -1000.0f:
//     screen_width = 999   -> -1000.0 < -999.0  TRUE  -> despawn fires
//     screen_width = 1000  -> -1000.0 < -1000.0 FALSE -> particles immortal
//     screen_width = 1080+ -> -1000.0 > -1080.0 FALSE -> particles immortal
//
//   That is the exact 999/1000 threshold, originating from a developer assuming
//   in 1999 that no screen would ever be >= 1000 pixels wide.
//
//   Earlier investigation hypothesized this was a dgVoodoo2 (DirectDraw -> D3D
//   wrapper) limit on lockable back-buffer width. That hypothesis was REFUTED
//   empirically: running under DDrawCompat (an independent DirectDraw
//   implementation) reproduces the exact same < 1000 threshold. Two different
//   wrappers, same threshold -> the wrapper is not the cause; the EXE is.
//
//   PATCH (8 bytes total, two 4-byte immediate edits inside two MOV instructions):
//
//     +-----------------+--------------------+--------------------+
//     | address         | original bytes (4) | patched bytes (4)  |
//     +-----------------+--------------------+--------------------+
//     | 0x0042B86A      | 00 00 7A C4        | 00 00 80 FF        |
//     | 0x0042B881      | 00 00 7A C4        | 00 00 80 FF        |
//     +-----------------+--------------------+--------------------+
//
//   The 4-byte immediate at +2 inside each MOV is the IEEE-754 single-precision
//   float being stored. 0xC47A0000 LE = -1000.0f. 0xFF800000 LE = -INF.
//
//   After the patch, the sentinel is -INFINITY instead of -1000.0f. Effects:
//     - Despawn comparison local_3c < -screen_width fires at any resolution
//       (-INF is strictly less than any finite number).
//     - On-screen check local_3c <= 0 still routes off-screen particles to the
//       despawn branch as before (-INF <= 0 is true).
//     - The other 4 callers of swrViewport_ProjectToScreen (HUD distance text,
//       rearview, world sprites, target indicators) use the output only as a
//       sprite coordinate; the sprite renderer clips naturally, so changing the
//       sentinel from -1000.0f to -INF is a no-op for them in practice.
//     - Tested: snow renders correctly at 1920x1080 on Howler Gorge and Andobi
//       Mountain Run.
//
// LAYER 3 -- ARTIFACTS AFTER LAYER 2 PATCH (3-A root-caused + fixed; 3-B open):
//
//   With Layer 2 patched, two artifacts remain:
//
//     A. Snow/rain vanish the moment the camera moves (parked = renders fine,
//        any motion = flickers then disappears). ROOT-CAUSED + FIXED.
//
//        swrWeather_RenderParticles picks a render mode per particle from its
//        per-frame screen movement: < 3 px uses the point-sprite path (clears
//        sprite flag 0x4000) and renders fine; >= 3 px sets flag 0x4000 and takes
//        the "streak" path. That 3 px threshold is absolute, never scaled by
//        resolution, so at high resolution any camera motion pushes every particle
//        past it and the whole field flips to the streak path (slight motion
//        straddles the threshold -> the flicker).
//
//        And the streak path renders NOTHING: it is a stub, not a bug. The PC port
//        never implemented the N64/Dreamcast motion-blur streaks. Trace: instance
//        flag 0x4000 -> swrSprite_Draw2 (0x428030) maps it to draw flag 0x400000 ->
//        swrSprite_Draw (0x44f160) routes 0x400000 to swr_noop2 (0x426910, a single
//        RET). So a streaking sprite emits zero geometry at any resolution, and the
//        streak endpoints the code computes + stores (swrSprite_array[id].unk0x4 /
//        unk0x6, normalized to 320x240 by swrSprite_SetStreakEndpoints_Maybe) are
//        dead data. (An earlier guess of a precision bug in the streak math was
//        wrong -- there is no streak draw to be buggy.)
//
//        FIX (3-A): force the working point-sprite path -- NOP the two JGE branches
//        in swrWeather_RenderParticles (0x0042d20f / 0x0042d214) that select the
//        streak path, so moving particles render as points exactly like parked
//        ones. This is the faithful PC behaviour (PC only ever had point
//        particles); restoring real streaks would mean implementing the cut
//        feature, not fixing a bug.
//
//     B. Rain (planetId == 4) renders only intermittently even after 3-A. STILL
//        OPEN. Rain's very high vertical velocity (vy = 1000 for heavy rain) drops
//        a particle through the viewport in ~1 frame, and respawn is only
//        probabilistic per frame, so density stays sparse. Candidate workaround:
//        force swrWeather_SetStretchFactor(1.0) for planetId == 4 (point path) and/
//        or clamp the per-frame displacement; not yet implemented.
//
// SECONDARY (real, but neither a Layer 2 nor Layer 3 root cause): the bpp dispatch
//   in the occlusion pixel-sampling (here and in swrPlayerHUD_SampleOcclusion) has
//   no default case for bpp outside {1,2,3,4} (default path leaves the scale factor
//   as (bpp-1) reinterpreted as a denormal float), and cases 3/4 read swapped scale
//   globals (case 3 -> DAT_004b94bc, case 4 -> DAT_004b94b8; slots are calibrated
//   1/255, 1/65535, 1/2^24-1, 1/2^32-1). These break occlusion accuracy at 24/32-bit,
//   but particles are SetVisible(1) regardless of occlusion outcome, so they do not
//   by themselves prevent rendering.
//
// MODERN FIX SUMMARY (implemented as reversible EXE byte-patches in
// dinput_hook/game_deltas/swrWeather_delta.cpp, applied at renderer init):
//   - Layer 2 (no weather at high res): swrWeather_PatchHiResParticleSentinel
//     patches the two 4-byte sentinel immediates above (-1000.0f -> -INF). 8 bytes.
//     Closes the primary "no weather at high res" bug.
//   - Layer 3-A (weather vanishes when the pod moves):
//     swrWeather_PatchForcePointParticles NOPs the two streak-select JGEs so the
//     point-sprite path always runs. Snow/rain render as points while moving.
//   - Layer 3-B (rain intermittent) and real motion-blur streaks (a cut PC
//     feature, stubbed by swr_noop2) are not addressed; see Layer 3 above.
// =====================================================================================

#define swrWeather_RenderParticles_ADDR (0x0042cca0)

#define swrWeather_HideAllParticles_ADDR (0x0042d380)

#define swrWeather_SetVelocity_ADDR (0x0042d3c0)

#define swrWeather_SetColor_ADDR (0x0042d3e0)

#define swrWeather_SetParticleCap_ADDR (0x0042d410)

#define swrWeather_SetStretchFactor_ADDR (0x0042d430)

#define swrWeather_Disable_ADDR (0x0042d440)

#define swrWeather_Enable_ADDR (0x0042d450)

#define swrWeather_SetParticleSpriteId_ADDR (0x0042d460)

#define swrWeather_ResetParticles_ADDR (0x0042d470)

void swrWeather_RenderParticles(void* viewport);

void swrWeather_HideAllParticles(void);

void swrWeather_SetVelocity(float vx, float vy);

void swrWeather_SetColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrWeather_SetParticleCap(int max);

// Sets swrWeather_stretchFactor, the rain-streak stretch factor (1.0 = point particle, 7.0 = long
// rain streak). With the Layer 2 patch applied, rain still does not render reliably
// even with stretch_factor = 1.0 -- see Layer 3 of the KNOWN ISSUES block above.
// Forcing this to 1.0 makes rain take the point-particle code path and become
// somewhat visible (partial workaround), but the underlying cause of "rain doesn't
// render properly at modern resolutions" is not yet root-caused.
void swrWeather_SetStretchFactor(float factor);

// swrWeather_Disable clears swrWeather_enabled and hides all particle sprites.
// swrWeather_Enable sets swrWeather_enabled. Both are driven by the SNW/NSNW collision tags.
void swrWeather_Disable(void);

void swrWeather_Enable(void);

// Set the swrSprite id for a particle-pool slot (swrWeather_particleSpriteIds[slot]).
void swrWeather_SetParticleSpriteId(int slot, int spriteId);

// Reset the particle pool: clear every slot state and set every sprite id to -1 (unallocated).
void swrWeather_ResetParticles(void);

#endif // SWRWEATHER_H
