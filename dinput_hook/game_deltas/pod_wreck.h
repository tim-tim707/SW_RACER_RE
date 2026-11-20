#pragma once

#include <cstdint>
#include <vector>

#include "types.h"

// Pod wrecks: engines knocked off the pod tumble away as debris instead of vanishing.
//
// The game blows one engine side at a time (swrRace_Explode, on a hard crash or when an engine
// part's damage has sat at full for a few seconds) and then spins the pod out. With "keep racing"
// on, the first engine lost is survivable: the pod keeps going on the other one (the game's own
// damaged-engine pull toward the missing side, a lower top speed), and only losing the second
// engine is the stock death. Either way the lost engine (and its twin on a four-engine pod)
// breaks off with the pod's speed plus a kick, falls, bounces and rolls along the track (the
// game's own collision raycast), spins up on each hit, sheds faces, throws sparks, trails fire
// and smoke, and ends in a burst. Its cable(s), the binder beam and its exhaust are hidden on the
// pod. Everything comes back when the pod respawns.

// swrRace_Explode hook: returns true when the explosion was handled here (a survivable engine
// loss) and the original must not run.
// crash = set off by a collision (not by engine damage).
bool pod_wreck_on_explode(swrRace* player, int side_arg, bool crash);
// After the original swrRace_Explode ran (a fatal explosion): the blown engine becomes debris.
void pod_wreck_after_explode(swrRace* player, int side_arg, bool crash);

// swrRace_HandleDeathExplosion hook, before the original: the pod blows up for good (head-on
// crash, end of a death spin) -- what's left on it flies apart.
void pod_wreck_before_death_explosion(swrRace* player);

// Once per pod per frame, after the game placed its parts (PoddAnimateVariousThings).
void pod_wreck_frame(swrRace* player);
// After swrObjTest_F3 (which copies the engine matrices onto their nodes): the debris again.
void pod_wreck_after_f3(swrRace* player);
// After UpdateEngineDamageFX: the game's engine smoke follows a knocked-off engine.
void pod_wreck_after_damage_fx(swrRace* player);

// Renderer: the debris of blown-apart pods, to draw on their own after the scene (the game hides a
// dead pod), once per viewport; and whether a node is one of them (skipped in the scene walk).
void pod_wreck_apart_nodes(std::vector<swrModel_Node*>& out);
bool pod_wreck_drawn_apart(const swrModel_Node* node);
// Renderer: a debris node's breakup (0 = whole .. 1 = gone) and its seed, or -1 if not debris.
float pod_wreck_breakup(const swrModel_Node* node, uint32_t* seed);
// Whether side (0 = right / partNodes[1], 1 = left / partNodes[2]) has been knocked off.
bool pod_wreck_side_gone(const swrRace* racer, int side);

// Model memory is going away (race unload): drop every wreck.
void pod_wreck_clear();

void pod_wreck_register_panel();
