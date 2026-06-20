#pragma once

#include "types.h"

// SPIKE / probe (LOCAL_MULTIPLAYER_ROADMAP P1): force a 2nd 'Locl' racer into the roster so
// swrObjJdge_InitTrack counts numLocalPlayers >= 2 and turns on the dormant splitscreen cascade
// (split viewports / dual cameras / per-half HUD / fog clamp / catch-up). Throwaway: this only
// confirms the render cascade; routing a real 2nd input device (P2) is not wired yet, so the 2nd
// pod will not be independently drivable. Needs >= 2 racers on the grid (e.g. freeplay + 1 AI).
extern bool swrObjJdge_forceSplitscreen;

unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore * scores);

// Splitscreen spike: corrects a native 2-player fall-through bug in KeyDownForPlayer1Or2 that
// otherwise spams pause/HUD-cycle/in-race-menu every frame. See the .cpp for detail.
int KeyDownForPlayer1Or2_delta(int mask);

// Splitscreen speed-dial fix: the 2-player speedometer fill is a single-player design (P2's bar
// draws full, P1's bar shows P2's speed). InRaceTimer snapshots each player's fill ratio; the
// swrSprite_Draw hook then re-points the per-player gradient/ratio so both the fill dispatch and the
// trim agree per player. See the .cpp for the full rationale.
void swrRace_InRaceTimer_delta(void *score, void *jdge);
void swrSprite_Draw_delta(int *arg0, swrSpriteTexture *tex, RdMaterial **mat, float a4, float a5,
                          float a6, float a7, int a8, int a9, int a10, int a11, int a12, int a13,
                          int a14, short a15, float a16, float a17, int a18);

// Splitscreen opponent-marker fix: the racer-position number over opponents only draws on P1's half
// because occlusion is sampled for the primary viewport only. Force-draws the markers on the
// secondary (P2) pass. See the .cpp for the full rationale.
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
