#pragma once

// Tick-level lockstep check for the src/ reimpls.
//
// `record` captures, for every race frame, the derived player inputs plus a hash of the sim state
// (RNG, racers, judge, animation clocks). `replay` pins those inputs back each frame and compares
// hashes, so a run under a different reimpl_config.txt reports the first frame the sim diverges.
// Both modes force retail's fixed-dt path (swr_FastMode), making each frame exactly one tick.
//
// Configured by lockstep.txt in the game directory; no file = inactive.

#ifdef __cplusplus
extern "C" {
#endif

// Forward hook on swrRace_IncrementFrameTimer (0x00480540): runs once per frame after inputs
// are processed and before the world sim.
void __cdecl swrRace_IncrementFrameTimer_lockstep(void);

// Called at the end of swrControl_ProcessInputs_delta: records or pins this frame's inputs.
void lockstep_pin_inputs(void);

// Once per presented frame: reads lockstep.txt and updates the fast-forward state.
void lockstep_frame_service(void);
// After swrObjHang_F0: autostarts a replay from the main menu.
void lockstep_hang_f0(struct swrObjHang *hang);
// True while a replay runs on the pinned dt: the frame limiter and vsync are skipped.
bool lockstep_fast_forward(void);
// `vanilla` in lockstep.txt: drop every sim-affecting delta and mod, so the run is retail + reimpls.
bool lockstep_vanilla(void);
// Called by init_hooks() before the reimpl table is installed.
void lockstep_vanilla_filter(void);

// Forward hook on swrObjHang_StartRace (0x0045b290): pins the RNG the AI roster is rolled from.
struct swrObjHang;
void __cdecl swrObjHang_StartRace_lockstep(struct swrObjHang *hang, int *rosterArg, int noBroadcast);

#ifdef __cplusplus
}
#endif
