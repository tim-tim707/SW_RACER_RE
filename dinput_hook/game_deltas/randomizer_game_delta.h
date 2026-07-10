#pragma once

extern "C" {
#include "types.h"
}

// Snapshot/arm the randomizer when a profile is written to disk (fires on creation
// and every autosave). Address-only wrapper; calls through to the original.
bool swrRace_SaveProfile_delta(char *playerName);

// After the original sets the track's AI difficulty, overwrite it with the profile's
// randomized (deterministic per-track) values when the AI category is active.
void InitAISettingsForTrack_delta(swrObjJdge *judge);

// Rebuild g_aTrackIDs for the active profile: a deterministic per-circuit shuffle when
// the track-order category is active, or the vanilla order otherwise. Called from the
// (C) course-selection menu delta before it reads g_aTrackIDs, so it has C linkage.
extern "C" void randomizer_apply_track_order(void);

// Permute swrRacer_PodHandlingData for the active profile (or restore vanilla). Applied
// by the single-player roster-build wrapper below, before pod stats are loaded.
void randomizer_apply_pod_handling(void);

// Single-player roster builder wrapper: applies pod-handling randomization pre-build.
// Address-only; calls through to the original.
void *swrObjHang_BuildRosterSinglePlayer_delta(swrObjHang *hang, int *out);

// Randomize the new profile's starting money + extra pod unlocks into the working profile.
void randomizer_apply_starting_state(void);

// Randomize each track's FavoritePilot (the pod you unlock by winning it). C linkage, called
// from the (C) course-selection menu delta alongside the track-order shuffle.
extern "C" void randomizer_apply_track_favorite(void);

// Autosave wrapper: applies the Class-A starting state once at creation, then calls through.
void swrRace_SaveCurrentProfile_delta(void);
