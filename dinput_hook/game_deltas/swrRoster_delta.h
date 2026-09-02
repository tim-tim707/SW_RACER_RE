// Extensible roster foundation: make the two "secret" pilots separately selectable.
//
// Stock hardwires a 23-pilot roster across three parallel fixed-address, id-indexed tables
// (swrRacer_PodData @0x4c2700, swrRacer_PodHandlingData @0x4c2bb0, the pod engine/cockpit transform
// table @0x4c7088) plus the SELECT_VEHICLE menu buffer (swrRace_SelectIndex @0xe99240). This
// relocates them to larger heap arrays, byte-copies the stock 23 so ids 0..22 are unchanged, and
// appends Jinn Reeso (23) and Cy Yunga (24). Every reader is repointed by shifting the
// table-address immediate in its instruction, so the original logic runs byte-for-byte.
//
#pragma once

extern "C" {
#include <Swr/swrObj.h>
}

// Call once at startup (from init_renderer_hooks), after the game's static data tables are present.
// Idempotent: a second call detects the already-relocated operands and no-ops.
void swrRoster_InstallExtensibleRoster();

// Reimplemented swrRace_BuildPartMenuList (forward-hooked): enumerates the extended roster into the
// relocated SelectIndex buffer and sets swrRace_MenuMaxSelection.
extern "C" void swrRace_BuildPartMenuList_delta(swrObjHang *hang);

// The racer id crosses the wire raw and swrObjHang_BuildRosterMultiplayer indexes the per-character
// tables with it, so an id a peer's build lacks reads past the end of their arrays.
extern "C" void swrMultiplayer_RacerPick_delta(int a);
extern "C" int swrMultiplayer_ApplyRacerPick_delta(void *message);
