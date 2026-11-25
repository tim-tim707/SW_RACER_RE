#pragma once

// Tick-level lockstep check for the src/ reimpls.
//
// `record` captures, for every race frame, the derived player inputs plus a hash of the sim state
// (RNG, racers, judge, animation clocks). `replay` pins those inputs back each frame and compares
// hashes, so a run under a different reimpl_config.txt reports the first frame the sim diverges.
// Both modes force retail's fixed-dt path (swr_FastMode), making each frame exactly one tick.
//
// Configured by lockstep.txt in the game directory; no file = inactive.

#include <stddef.h>

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
// After swrObjHang_F0: autostarts the race from the main menu (replay: the recorded one; record:
// the hangar's choice, overridden by `track`/`laps`/`pod`/`mirror`/`racers` in lockstep.txt).
void lockstep_hang_f0(struct swrObjHang *hang);
// True while a replay runs on the pinned dt: the frame limiter and vsync are skipped.
bool lockstep_fast_forward(void);
// `texture_hash` in lockstep.txt: hash every uploaded texture into lockstep_textures.txt.
void lockstep_log_texture(int width, int height, int format, const void *pixels, size_t bytes);
// `vanilla` in lockstep.txt: drop every sim-affecting delta and mod, so the run is retail + reimpls.
bool lockstep_vanilla(void);
// Frame number inside a running lockstep race, -1 outside one (the shadow harness logs it).
int lockstep_shadow_frame(void);

// Called by init_hooks() before the reimpl table is installed.
void lockstep_vanilla_filter(void);

// Forward hook on swrObjHang_StartRace (0x0045b290): pins the RNG the AI roster is rolled from.
struct swrObjHang;
void __cdecl swrObjHang_StartRace_lockstep(struct swrObjHang *hang, int *rosterArg, int noBroadcast);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <cstdint>

// Read-out and controls for the Verification window (Debug > Verification).
struct LockstepStatus {
    int mode;// 0 off, 1 record, 2 replay
    bool armed;// record: waiting for the next race to start
    bool active;// inside a captured race
    bool finished;
    uint32_t frame;
    float hz;
    uint32_t mismatches;// replay
    int first_mismatch;
    const char *path;
    const char *last_result;// last race's outcome, "" before one
    bool continuous;
    bool auto_name;
    bool fixed_timestep_on;// recording refuses to start while it is on
    bool vanilla;
    bool dt_pinned;
};

void lockstep_get_status(LockstepStatus *st);
// Arms recording of the next race started from the menus (a race already under way is skipped),
// to recordings/race_<time>_t<track>.bin at a fixed dt of 1/hz. False while a replay or capture runs.
bool lockstep_arm_record(float hz, bool continuous);
void lockstep_set_continuous(bool on);
// Stops a capture in progress (the file keeps what was recorded) or cancels the armed one.
void lockstep_disarm(void);
#endif
