#pragma once

// Fixed-timestep world sim, decoupled from render FPS (physics scales with FPS, worst in
// swrRace_ApplyTraction's velocity blend, a fixed per-frame lerp). Reuses the engine's swr_FastMode
// fixed-dt path. No render interpolation: when render outruns the sim, the 3D view repeats frames.

extern bool swr_fixedTimestep;          // master toggle (default off)
extern float swr_fixedTimestepHz;       // fixed simulation rate in Hz (timestep = 1 / Hz)
extern int swr_fixedTimestep_lastSteps; // sim sub-steps taken last render frame (live readout)

// Hook for swrMain_RunFrame (0x00445980); passes straight through unless engaged.
void __cdecl swrMain_RunFrame_delta(short flags, short phase);
