#pragma once

#include "types.h"

// "Movie pod motion": visual-only secondary motion layered on the pod parts, to make the
// podracers move more like the films -- the cockpit swings out wide on its cables through turns
// and bobs over bumps, and each engine banks into turns on its own spring so the pair drifts
// slightly out of sync. Physics, handling and collision are untouched: only the per-part render
// transforms (engineXf*/cockpitXf) are modified, after swrRace_PoddAnimateEngines writes them and
// before swrObjTest_F3 bends the cables between them and pushes them onto the model nodes.

// Hooks swrRace_PoddAnimateEngines (0x00470ae0) by address; not reimplemented in src.
void __cdecl swrRace_PoddAnimateEngines_delta(swrRace* player);

// Loads the [pod_motion] settings from SW_RACER_RE.ini and registers the "Mods/Pod Motion"
// overlay panel. Call once at startup with the other panels.
void pod_motion_register_panel();
