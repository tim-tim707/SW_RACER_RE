#pragma once

#include "types.h"

void swrRace_PoddAnimateVariousThings_delta(swrRace* player);

// Hook for the display-pod animator (FUN_004337e0): hangar inspect, selection menu, cutscenes.
// Registers the display pod's cables so they curve in the GL path outside racing.
void swrRace_AnimateDisplayPod_delta(swrModel_Node** nodes, void* transform, int a3, float a4,
                                     float a5, float a6, float a7, int animated, float a9,
                                     float a10);

// Cable-curve amplitude for a curently-curved cable node (-1.0 = not a curved cable). Consumed by
// the renderer to bend the cable mesh in the GL path.
float swrRace_GetCableBendAmplitude(const swrModel_Node* node);

// Drop all recorded cable nodes (call on track load so freed node pointers aren't reused).
void swrRace_ClearCableBends();
