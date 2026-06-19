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
