//
// AI tuning -- debug-overlay control over the AI opponents.
//
// The vanilla AI has exactly two authored inputs, both seeded per track by
// InitAISettingsForTrack: swrRace_AILevel (base speed multiplier, already scaled by the
// AI Speed menu setting) and ai_spread (how far apart the field paces itself). Everything
// else the field does comes out of swrRace_AI, whose pacing is player-relative: the
// track-favorite pace-setter chases local player 1 directly, the 1-2 AI nearest the player
// pace on their raw gap to them, and the rest station-keep behind the pace-setter. All of
// it lands on one field, swrRace.speedMultiplier, committed by swrRace_UpdateCatchup. Those
// are two of the three seams the panel drives; the third is the pod-avoidance steering nudge.
//
#pragma once

#include "types.h"

// Registers the AI hooks. Call from init_renderer_hooks(), before init_hooks() applies the
// detours. All three originals are dormant (reverse-hooked), so they are hooked by address.
void ai_tuning_RegisterHooks();

// Registers the "AI" and "AI Racers" panels and loads persisted settings. Call once at
// startup where the other debug panels are registered.
void ai_tuning_RegisterPanels();

extern "C" {
// Seeds swrRace_AILevel / ai_spread / ai_track_script for the track about to start. We let it
// run, snapshot what it chose (the panel shows those as the "track default"), then apply the
// overrides on top.
void InitAISettingsForTrack_delta(swrObjJdge *judge);

// Commits swrRace.speedMultiplier for one racer. We adjust the result: rubberband strength and
// AI speed scale for AI pods, single-player catch-up assist for the local human.
void swrRace_UpdateCatchup_delta(swrRace *player);

// The nearest-pod steering nudge. Replaced (rather than post-processed) when either knob is off
// its default, because the force is added into turnRateTarget and its sign is what turns
// avoidance into blocking.
void swrRace_ApplyPodProximityForce_delta(swrRace *player);
}
