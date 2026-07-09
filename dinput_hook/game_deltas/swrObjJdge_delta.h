#pragma once

#include "types.h"

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore * scores);

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

// Manual in-race HUD-mode cycle (a Caps Lock alternative for remote desktop, where Caps Lock does not
// emulate). The debug overlay sets g_request_hud_mode_cycle; swrObjJdge_CycleHudMode_delta consumes it
// and advances jdge->hud_mode with the vanilla wrap, publishing the active mode in g_current_hud_mode.
extern bool g_request_hud_mode_cycle;
extern int g_current_hud_mode;
void swrObjJdge_CycleHudMode_delta(swrObjJdge *jdge);

// Publishes the live hud_mode into ui_hud_marker_mode while the game draws the per-racer position
// markers, so the sprite/text sinks remap those markers by mode (right strip / full-width ring / etc.).
void swrObjJdge_DrawRaceHUD_delta(swrObjJdge *jdge);
