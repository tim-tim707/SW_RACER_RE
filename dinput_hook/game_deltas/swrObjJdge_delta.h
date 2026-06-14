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
void swrObjJdge_RegisterTimeFormatHooks();

// 100-lap support: reconstructs per-lap times from the running total (de-index drops per-lap
// storage) to report best/worst/average for any lap count.
void swrObjJdge_F2_delta(swrObjJdge *jdge);

// 100-lap support: replaces the on-track per-lap results list (which can't fit >5 rows) with a
// best/worst/average/total/position summary.
void swrRace_InRaceEndStatistics_delta(void *jdge, void *score);
