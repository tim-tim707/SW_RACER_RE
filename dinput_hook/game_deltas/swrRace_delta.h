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

// ai_full_lod dust/splash fix (hooked by address, both dormant/reverse-hooked originals):
// - swrRace_SpawnGroundDustKick_Maybe_delta: for non-local pods, reserve Toss-pool headroom (so AI
//   dust never starves the player's trail) and suppress the splash sound.
// - playASound_delta: drops the dust-splash sound while a non-local dust kick is being spawned.
void swrRace_SpawnGroundDustKick_Maybe_delta(swrRace* player, float* transform, float sx, float sy,
                                             float sz, float param_6, int param_7);
void playASound_delta(int sound_id, short priority, float volume, float pitch, int flags);

// Rebuilds the dust-kick Toss pool with more slots (stock is 16) so full-LOD AI dust no longer
// starves the player's trail. Replaces swrObjToss_AddDustKickModelsToScene (hooked by address).
void swrObjToss_AddDustKickModelsToScene_delta();

// Widens far-AI ground contact (clamps unk1998 for visible non-local pods) so distant AI run their
// full ground/shadow pipeline and kick up dust. Hooks swrObjTest_F0 by address.
void swrObjTest_F0_delta(swrRace* player);

// Cable-curve amplitude for a curently-curved cable node (-1.0 = not a curved cable). Consumed by
// the renderer to bend the cable mesh in the GL path.
float swrRace_GetCableBendAmplitude(const swrModel_Node* node);

// Drop all recorded cable nodes (call on track load so freed node pointers aren't reused).
void swrRace_ClearCableBends();

// Post-race results handler. When the Pod Unlock Scene skip is on, stops the results flow from
// transitioning to that scene while still doing the favorite-pilot unlock it would have done.
void swrRace_ResultsMenu_delta(swrObjHang* hang);
