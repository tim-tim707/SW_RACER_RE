#pragma once

// Fixed-timestep spike: decouple the gameplay simulation from the render framerate.
//
// SWE1R's physics tick scales with FPS in one gross spot (swrRace_ApplyTraction's velocity-
// direction blend, where the dt term algebraically cancels -> a fixed per-frame lerp) and in a
// long tail of first-order-accurate integrators. Rather than retune every coefficient, we run the
// whole world-sim at a FIXED timestep and let render run free -- the maintainer-preferred fix, and
// the one that also unlocks deterministic replay / multiplayer.
//
// How: swrMain_RunFrame phase-1 bundles input + sound + pause + the world sim + cameras, and is
// called once per frame by swrMain_GuiAdvance. We DECOMPOSE it: the once-per-frame parts (audio,
// input edge detection, sound, pause poll, camera) run once at render cadence, and only the world
// sim (swrModel_UpdateAnimations + swrEvent_CallAllF0..F3) repeats on a wall-clock accumulator at a
// fixed dt -- reusing the engine's own fixed-dt path (swr_FastMode -> swrRace_IncrementFrameTimer
// emits swr_fixedDeltaTimeSecs). Phase-2 (render) still runs once per real frame.
//
// Because only the world sim repeats, the earlier whole-phase-1 problems are designed out:
//   - Input is sampled once per frame; the press AND held bits are latched (OR'd) across tickless
//     frames and presented to the first tick (consume-once), so taps and brief holds aren't dropped.
//   - The 2D overlay (minimap dots + text entries) is rebuilt fresh per tick (resetOverlayDrawQueues
//     between ticks) so dots don't stack, and is held across tickless frames (count replay).
//   - The race/lap clock stays real-time: swrRace_dt_raw_d (which the clock accumulates) is pinned to
//     the fixed dt for the ticks, and frametotal (which gates looping-sound keep-alive) advances once
//     per tick-frame and is held constant across the ticks, so engine/beep loops don't restart.
//
// Engaged only when the pod is actually being driven: spike on, not paused (GetPauseState), not
// stopped (swrGui_Stopped), and the game's own "live driving" test from swrControl_UpdateForceFeedback
// (currentPlayer_Test != null, swrRace_resultsScreenActive != 0, and the pod not respawning/dead).
// That is exactly when the traction/impact force effects play, so menus / pause / post-race keep
// vanilla timing.
//
// SPIKE limitation (intentional, for evaluation -- not a finished feature): no render interpolation
// yet, so when render outruns the sim the 3D view repeats frames (judder). This validates physics
// CONSISTENCY across framerates, not visual smoothness.

extern bool swr_fixedTimestep;          // master toggle (default off)
extern float swr_fixedTimestepHz;       // fixed simulation rate in Hz (timestep = 1 / Hz)
extern int swr_fixedTimestep_lastSteps; // sim sub-steps taken last render frame (live readout)

// Hook for swrMain_RunFrame (0x00445980). When engaged, runs the once-per-frame phase-1 work once and
// sub-steps only the world sim on a fixed-timestep accumulator; otherwise passes straight through.
void __cdecl swrMain_RunFrame_delta(short flags, short phase);
