#pragma once

// Fixed-timestep spike: decouple the gameplay simulation from the render framerate.
//
// SWE1R's physics scales with FPS in one gross spot (swrRace_ApplyTraction's velocity-direction
// blend, where the dt term algebraically cancels into a fixed per-frame lerp) and in a long tail of
// first-order integrators. Rather than retune every coefficient, the whole world sim runs at a fixed
// timestep while render runs free.
//
// swrMain_RunFrame phase-1 bundles input + sound + pause + world sim + cameras. This DECOMPOSES it:
// the once-per-frame parts run at render cadence and only the world sim (swrModel_UpdateAnimations +
// swrEvent_CallAllF0..F3) repeats on a wall-clock accumulator, reusing the engine's own fixed-dt
// path (swr_FastMode -> swrRace_IncrementFrameTimer emits swr_fixedDeltaTimeSecs).
//
// SPIKE limitation, intentional: no render interpolation, so when render outruns the sim the 3D view
// repeats frames. This validates physics consistency across framerates, not visual smoothness.

extern bool swr_fixedTimestep;          // master toggle (default off)
extern float swr_fixedTimestepHz;       // fixed simulation rate in Hz (timestep = 1 / Hz)
extern int swr_fixedTimestep_lastSteps; // sim sub-steps taken last render frame (live readout)

// Hook for swrMain_RunFrame (0x00445980). When engaged, runs the once-per-frame phase-1 work once and
// sub-steps only the world sim on a fixed-timestep accumulator; otherwise passes straight through.
void __cdecl swrMain_RunFrame_delta(short flags, short phase);
