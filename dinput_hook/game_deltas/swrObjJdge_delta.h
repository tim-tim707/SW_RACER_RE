#pragma once

#include "types.h"

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore * scores);

// Fast restart (speedrunner hotkey): restart the current race with no loading screen via an
// in-place reset (no teardown/reload) that keeps every pod and asset resident and replays each
// pod's captured swrRace_Init. The pause-menu Restart stays on the full reload. See
// swrObjJdge_delta.cpp. swrRace_Init_capture records each pod's spawn args (hooked by address).
void swrRace_Init_capture(swrRace *player, float a2_spline, int a3_podModel, void *a4_trackModel,
                          int a5_light, float *a6_transform, int a7_grid, int a8_numPlayers,
                          int a9_numLocal, int a10_dup);
// Trigger dispatcher hook: snapshot each fired trigger's armed description + the nodes it hides, so
// a fast restart can re-arm every trigger and re-show anything hidden. Hooked by address.
void swrRace_TriggerHandler_delta(int player, int a, char b);
// Records which swrObjTrig_AnimationArray FX index each trigger enables this run, so a fast restart
// resets only valid (current-track) FX lists -- the array is populated per-planet and unused
// indices hold stale/freed lists. Hooked by address.
void swrObjTrig_EnableFXAnimation_delta(int index);
// Hotkey entry point (C linkage so the C key callback in Window_delta.c can call it): if the
// feature is on and a live single-player race is running, arm a fast restart and return true so the
// caller consumes the key. Returns false otherwise (key keeps its normal function).
#ifdef __cplusplus
extern "C" {
#endif
bool fast_restart_try_request(void);
#ifdef __cplusplus
}
#endif
// Per-frame on the game thread (called from imgui_Update): kicks off a requested fast restart.
void service_fast_restart();

// Wraps stdControl_ReadControls: after a fast restart, zeroes the held restart-key (Enter) so it
// can't feed the fresh countdown as accelerate input and cancel the boost start. Hooked by address
// (only needed with ENABLE_GLFW_INPUT_HANDLING=0, where the game reads the real DirectInput keyboard).
void stdControl_ReadControls_boostfix_delta(void);
// Wraps swrObjJdge_F0: after a fast restart, advances the judge past the pre-race track sweep + pod
// orbit straight to the countdown (speedrunners skip the ~9s intro). Hooked by address.
void swrObjJdge_F0_delta(swrObjJdge *jdge);

// 100-lap support: de-index swrObjJdge_F2's fixed 5-element per-lap split-time array
// (swrScore::results_P1_Lap1..Lap5) so lap counts above 5 stop corrupting the score struct.
// Applied as a verified in-place byte patch at startup. See swrObjJdge_delta.cpp.
void swrObjJdge_PatchLapTimeOverflow();

// 1hr+ race-time support: raises swrObjJdge_F2's 50:00 (3000.0s) race-time / lap-time clamp to 24h
// so the in-game timer and every total-time readout can show past one hour. Verified byte patch.
void swrObjJdge_PatchRaceTimeCap();

// 1hr+ race-time support: time formatters reimplemented to show an hours field (H:MM:SS.frac) once
// the time reaches an hour; identical to stock under one hour. Cover all total-time readouts.
void swrText_CreateTimeEntry_delta(int x, int y, int unused, int r, int g, int b, int a, char *screenText);
void swrText_CreateTimeEntryPrecise_delta(int x, int y, int unused, int r, int g, int b, int a, char *screenText);

// 100-lap support: reconstructs per-lap times from the running total (de-index drops per-lap
// storage) to report best/worst/average for any lap count.
void swrObjJdge_F2_delta(swrObjJdge *jdge);

// 100-lap support: replaces the on-track per-lap results list (which can't fit >5 rows) with a
// best/worst/average/total/position summary.
void swrRace_InRaceEndStatistics_delta(void *jdge, void *score);

// 1hr+ race-time support follow-up: re-assigns finishing positions finished-first so a finished
// racer always places above a still-racing one. The vanilla rank key (10000 - total_time) goes
// negative once a race passes ~2h46m, which PatchRaceTimeCap's 24h ceiling now allows.
void swrObjJdge_UpdateStandings_delta(swrObjJdge *jdge);

// Cutscene auto-skip ("Game" settings panel): fast-forward the end-credits scroll. See .cpp.
void swrObjJdge_ScrollCredits_delta(swrObjJdge *jdge);

// Cutscene auto-skip ("Game" settings panel): skip the pre-race camera sweep by raising the
// accept edge in the race manager's intro states (the game's own skip path). See .cpp.
void swrObjJdge_F0_delta(swrObjJdge *jdge);

// Cinematic letterbox ("Game" settings panel): advances the black-bar state machine one frame (dt =
// real seconds) and returns the current 0..1 bar extension. Bars snap in over the pre-race binder
// cinematic, slide out ~7s into the binder-ignition orbit (or on a skip press), and return for the
// victory lap (sliding out on the button that ends it). Drawn under the HUD text by
// DrawTextEntries_delta (renderer_hook.cpp). C linkage for the renderer's C++ caller.
#ifdef __cplusplus
extern "C" {
#endif
float swrObjJdge_UpdateLetterbox(float dt);
#ifdef __cplusplus
}
#endif
