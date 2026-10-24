#pragma once

#include "types.h"

void swrObjHang_F0_delta(swrObjHang *hang);

// Cutscene auto-skip deltas (the "Game" settings panel). Each completes its scene via the game's
// own path when the matching toggle is on; see swrObjHang_delta.cpp. (The Pod Unlock Scene's toggle
// skip is handled upstream in swrRace_ResultsMenu_delta; its delta here only normalizes the advance.)
void swrObjHang_UpdatePlanetSelectIntro_delta(swrObjHang *hang);
void swrObjHang_UpdateVehicleSelectIntro_delta(swrObjHang *hang);
void swrObjHang_UpdateResultsIntro_delta(swrObjHang *hang);
