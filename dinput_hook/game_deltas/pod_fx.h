#pragma once

#include <vector>

#include "types.h"

// Pod particle effects drawn in the GL layer (projected through the scene matrices and
// depth-tested, like the weather particles). Experimental / for testing. Purely visual.
//   - Engine damage: once an engine segment (swrRace::engineHealth, 0..1 damage, [0..2] left
//     top/mid/bottom, [3..5] right) passes the "orange" threshold it throws sparks, smoke and,
//     near red, fire trails; repairing winds it down gradually.
//   - Ground dust: billowing dust clouds wherever the game kicks up its own dust trail.
//   - Exhaust: Galactic Racer-style glow -- white-hot core, wide orange halo and a flickering
//     flame that lengthens with speed and boost, plus a few embers.
//   - Physics: per-type drag, gravity/buoyancy, turbulence, and sparks bouncing off the ground.

// Tick (once per real frame) and draw. Call from the viewport render hook after the 3D scene and
// its depth are in the default framebuffer. `in_race` gates spawning to the race scene.
void pod_fx_tick_and_draw(const rdMatrix44* proj, const rdMatrix44* view, bool in_race);

// Called from the ground dust-kick hook with the kick's transform (a 4x4, position in [12..14]).
void pod_fx_on_ground_dust(const swrRace* player, const float* transform);

// Called by the renderer for every mesh drawn inside a pod's exhaust (kind 0, partNodes[0x43/44])
// or afterburner-glow (kind 1, partNodes[0x45/46]) subtree, side 0 = right / 1 = left, with the
// mesh's world (model) matrix. Pod FX clusters the mesh vertices into individual nozzles and
// remembers them relative to the engine, so the exhaust effects sit on every real nozzle.
void pod_fx_report_nozzle_mesh(const swrRace* racer, int side, int kind, const swrModel_Mesh* mesh,
                               const rdMatrix44& model);

// Diagnostics ("Dump pod parts" button): while armed for one frame, the renderer reports every
// partNodes[] node of the local pod it visits (part index + world matrix) and every mesh under it;
// pod_fx writes them to hook.log in engine-local coordinates.
bool pod_fx_debug_armed();
void pod_fx_debug_part(const swrRace* racer, int part, const swrModel_Node* node, const rdMatrix44& model);
void pod_fx_debug_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model);

// Whether the renderer should skip the stock dust-kick models (Pod FX dust replaces them).
bool pod_fx_hide_stock_dust();

// How visibly damaged an engine side is (0 = fine .. 1 = blown), counting only segments the HUD
// shows orange or worse; side 0 = right, 1 = left. Used by pod motion for the damaged-engine wobble.
float pod_fx_engine_damage(const swrRace* racer, int side);

// Lights for the screen-space lighting pass (shadows.cpp), from each pod's CURRENT engine
// positions: a backward spotlight per exhaust nozzle while moving (stronger on boost) and a
// flickering point light per burning damage segment.
struct SceneLight;
void pod_fx_gather_lights(std::vector<SceneLight>& out);

// An energy-binder mesh drawn this frame (world-space centre, its material colour 0..1): a soft
// omni-directional glow light is added there. Pods without binders (Neva Kee) report none; Ben
// Quadinaros's two binders each get their own.

// a / b = the ends of the mesh's long axis (world space); r, g, b = its colour (0..1).
void pod_fx_report_binder(const swrRace* racer, const rdVector3& a, const rdVector3& b, float r, float g, float bl);
// Skip the game's own binder glow card (texture #1411); Pod FX draws its own glow instead.
bool pod_fx_hide_stock_binder_glow();

// Loads [pod_fx] from SW_RACER_RE.ini and registers the "Mods/Pod FX" panel.
void pod_fx_register_panel();
