//
// Extensible roster foundation: make the two "secret" pilots separately selectable.
//
// The stock game hardwires a 23-pilot roster across three parallel fixed-address, id-indexed
// tables (swrRacer_PodData @0x4c2700, swrRacer_PodHandlingData @0x4c2bb0, the pod engine/cockpit
// transform table @0x4c7088) plus the SELECT_VEHICLE menu buffer (swrRace_SelectIndex @0xe99240).
// This module relocates those tables to larger heap-backed arrays, byte-copies the stock 23 so
// ids 0..22 are unchanged, and appends the two "secret" pilots -- Jinn Reeso (id 23) and Cy Yunga
// (id 24) -- as real, separately selectable racers. Every reader is repointed by shifting the
// table-address immediate in its instruction by the relocation delta, so the original game logic
// runs byte-for-byte; only the addresses it reads from move. The site lists in the .cpp come from
// an exhaustive Ghidra xref scan of the three tables (every code reference into their address range).
//
#pragma once

extern "C" {
#include <Swr/swrObj.h>
}

// Relocate the per-character tables + SelectIndex and seed the secret pilots. Call once at startup
// (from init_renderer_hooks), after the game's static data tables are present. Idempotent: a second
// call detects the already-relocated operands and no-ops.
void swrRoster_InstallExtensibleRoster();

// Reimplemented swrRace_BuildPartMenuList (forward-hooked): enumerates the extended roster into the
// relocated SelectIndex buffer and sets swrRace_MenuMaxSelection. Replaces the stock 0..22 loop.
extern "C" void swrRace_BuildPartMenuList_delta(swrObjHang *hang);
