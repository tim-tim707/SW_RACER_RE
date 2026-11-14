#pragma once

// Fixed-timestep world sim, decoupled from render FPS (physics scales with FPS, worst in
// swrRace_ApplyTraction's velocity blend, a fixed per-frame lerp). Reuses the engine's swr_FastMode
// fixed-dt path. No render interpolation: when render outruns the sim, the 3D view repeats frames.

extern bool swr_fixedTimestep;          // master toggle (default off)
extern float swr_fixedTimestepHz;       // fixed simulation rate in Hz (timestep = 1 / Hz)

// Hook for swrMain_RunFrame (0x00445980); passes straight through unless engaged.
void __cdecl swrMain_RunFrame_delta(short flags, short phase);

// Hook for swrSound_UpdateIfEnabled (0x004270d0): skipped in phase 2 while the fixed step is engaged,
// which runs it right after the ticks on tick poses instead (3D doppler consistency).
void __cdecl swrSound_UpdateIfEnabled_delta(void);
