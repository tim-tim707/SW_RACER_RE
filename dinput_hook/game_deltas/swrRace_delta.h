#pragma once

#include "types.h"

void swrRace_PoddAnimateVariousThings_delta(swrRace* player);

// Hook for the display-pod animator (FUN_004337e0): hangar inspect, selection menu, cutscenes.
// Registers the display pod's cables so they curve in the GL path outside racing.
void swrRace_AnimateDisplayPod_delta(swrModel_Node** nodes, void* transform, int a3, float a4,
                                     float a5, float a6, float a7, int animated, float a9,
                                     float a10);

// Multiplayer "no collision" toggle: skips pod-to-pod collision (all pods, on this machine) so the
// local player passes through other racers; track/wall collision is kept. Hooked by address.
void swrRace_ResolvePodCollision_delta(swrRace* player);

// Cable-curve amplitude for a curently-curved cable node (-1.0 = not a curved cable). Consumed by
// the renderer to bend the cable mesh in the GL path.
float swrRace_GetCableBendAmplitude(const swrModel_Node* node);

// Drop all recorded cable nodes (call on track load so freed node pointers aren't reused).
void swrRace_ClearCableBends();

// Post-race results handler. When the Pod Unlock Scene skip is on, stops the results flow from
// transitioning to that scene while still doing the favorite-pilot unlock it would have done.
void swrRace_ResultsMenu_delta(swrObjHang* hang);
