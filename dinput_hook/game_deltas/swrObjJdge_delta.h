#pragma once

#include "types.h"

// Force a 2nd 'Locl' racer into the roster so swrObjJdge_InitTrack counts numLocalPlayers >= 2 and
// turns on the dormant splitscreen cascade (split viewports / dual cameras / per-half HUD / fog
// clamp / catch-up). Needs >= 2 racers on the grid.
extern bool swrObjJdge_forceSplitscreen;

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore * scores);

// Splitscreen spike: corrects a native 2-player fall-through bug in KeyDownForPlayer1Or2 that
// otherwise spams pause/HUD-cycle/in-race-menu every frame. See the .cpp for detail.
int KeyDownForPlayer1Or2_delta(int mask);

// Splitscreen speed-dial fix: P2's bar draws full and P1's shows P2's speed. See the .cpp.
void swrRace_InRaceTimer_delta(void *score, void *jdge);
void swrSprite_Draw_delta(int *arg0, swrSpriteTexture *tex, RdMaterial **mat, float a4, float a5,
                          float a6, float a7, int a8, int a9, int a10, int a11, int a12, int a13,
                          int a14, short a15, float a16, float a17, int a18);

// Splitscreen opponent-marker fix: occlusion is sampled for the primary viewport only, so the
// markers are force-drawn on the secondary pass. See the .cpp.
void __cdecl swrPlayerHUD_RenderDistanceText_delta(void *viewport, bool secondaryPass);

// Splitscreen P2 boost fix: the pump-boost charge reads P1's main-device input globals, so P2 can't
// boost. Swaps P2's per-player input into those globals around the original call. See the .cpp.
void __cdecl swrRace_UpdatePlayerControl_delta(swrRace *player);

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
