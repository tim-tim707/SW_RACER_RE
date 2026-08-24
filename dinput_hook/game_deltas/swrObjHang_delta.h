#pragma once

#include "types.h"

void swrObjHang_F0_delta(swrObjHang *hang);

// Cutscene auto-skip deltas (the "Game" settings panel). Each completes its scene via the game's
// own path when the matching toggle is on; see swrObjHang_delta.cpp. (The Pod Unlock Scene is
// handled upstream in swrRace_ResultsMenu_delta, not here.)
void swrObjHang_UpdatePlanetSelectIntro_delta(swrObjHang *hang);
void swrObjHang_UpdateVehicleSelectIntro_delta(swrObjHang *hang);
