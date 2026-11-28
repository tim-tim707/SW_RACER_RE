#pragma once

// Pod edits: per-pod changes made in the HTML pod editor (tools/pod_editor/pod_editor.html),
// applied on top of the game's own pod models -- so shadows, Pod FX, cables, binders and flames keep
// working.
//
// Workflow:
//   1. Mods > Pod Editor > "Export my pod": the next race frame records every mesh of your pod
//      (part, triangles, UVs, textures) into assets/pod_edits/export/<Pod>_pod.json.
//   2. Open that file in the HTML editor: select faces (e.g. an intake turbine), split them into a
//      spin group (animated in game) or a hide group. Build writes assets/pod_edits/<Pod>.json.
//   3. "Reload edits" (or restart): the mod applies them to every pod using that model.
//
// Edits file: a JSON document ("format": "swr-pod-edits"; the full description is in
// tools/pod_editor/bake.js, "edits documents"). Its groups' lines edit one mesh each:
//   { "mesh": "<model>:<offset>", "faces": [[first, last], ...], "rpm", "pivot": [3], "axis": [3],
//     "offset": [3], "scale" }   spin a mesh's faces about a pivot / axis in that mesh's own frame
//                                (scaled about the pivot first, then moved by the offset; rpm 0 =
//                                just move); <offset> = the mesh's byte offset in the model file (hex)
//   { "mesh", "faces" }          (a "hide" group's line) hide those faces
// faces = triangle index ranges in draw order.

#include <cstdint>
#include <vector>

#include "types.h"

struct PodEditRange {
    uint32_t first, count;
};
struct PodEditSpin {
    std::vector<PodEditRange> tris;
    float pivot[3];
    float axis[3];
    float rpm;
    float offset[3];// move after spinning (mesh frame)
    float scale = 1.0f;// about the pivot, before spinning
};
struct PodMeshEdit {
    std::vector<PodEditSpin> spins;
    std::vector<PodEditRange> hidden;
};

// Edits for a mesh about to be drawn, or nullptr.
const PodMeshEdit* pod_edits_find(const swrModel_Mesh* mesh);
// Seconds, for the spin angle.
float pod_edits_time();

// Export of the local pod (see above). While armed, the renderer reports every mesh it draws for
// the local pod, then calls pod_edits_export_end_frame() once the scene traversal is done.
bool pod_edits_export_armed();
void pod_edits_export_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model_matrix,
                           const std::vector<float>& world_pos, const std::vector<float>& uv, unsigned texture,
                           bool textured);
void pod_edits_export_end_frame(bool in_race);
// Motion recording: while a pod motion is being recorded the renderer also reports where each mesh it
// draws for the local pod is (the exported meshes' own motion: steering flaps, game-driven spinning
// parts ... goes into the .motion.json for the editor's Idle / Top speed preview).
bool pod_edits_recording();
void pod_edits_record_mesh(const swrRace* racer, int part, const swrModel_Mesh* mesh, const rdMatrix44& model_matrix);

void pod_edits_register_panel();

// Cable clearance: the margin (game units) cables keep from the pod's engines and cockpit, which
// the renderer pushes them out of; < 0 when switched off.
float pod_edits_cable_clearance();

// The game's overheat fire streak: effects.gameFireStreak { length, turn: [rx, ry, rz] } -- the flames' drift
// (stock: straight back at 20 x the engine's forward axis) scaled by length and turned by the angles
// (degrees, about the engine's x, y, z in that order; mirrored on the left). False when not set.
bool pod_edits_gamefire_streak(int pilot, float out[4]);
// One cable's own settings (index 0..3 = part slots 10..13: right, left, second right, second left),
// overriding the shared ones for that cable only, with no mirroring: layout.ownCables
// [{ cable: N (index + 1), cockpit: [3] (cockpit frame), engine: [3] (its engine's frame) }].
// Each returns false when that cable has no such end.
bool pod_edits_cable_end(int pilot, int index, int end, float out[3]);// end: 0 = cockpit, 1 = engine

// The exhaust light (the warm spotlight each nozzle throws onto the ground behind the engine, the
// orange streak on the track): effects.exhaustLight { aim, reach, width, strength } -- aim = how far behind
// the nozzle it lands (pod lengths, stock 0.7), reach / width / strength = multipliers of its range,
// cone angle and brightness. False (out untouched) when the pod's edits don't set it.
bool pod_edits_exhaust_light(int pilot, float out[4]);
// effects.nozzleFlame { width, length, height }: the nozzle flame cones (the mod's exhaust glow / flame) made
// wider, longer and taller by those factors (1 = stock). False when not set.
bool pod_edits_nozzle_flame(int pilot, float out[3]);
// Each edited nozzle's own flame length factor (effects.nozzles: { pos, size, length, ... }), in the order of its
// points (pod_edits_fx_points kind 0); nullptr when the pod's nozzles aren't edited.
#ifdef __cplusplus
#include <vector>
const std::vector<float>* pod_edits_nozzle_lengths(int pilot, int side);
// ... and each one's height factor (its vertical size relative to its
// width, 1 = round), same order.
const std::vector<float>* pod_edits_nozzle_heights(int pilot, int side);
// ... and each one's width factor (its horizontal size relative to its size).
const std::vector<float>* pod_edits_nozzle_widths(int pilot, int side);
#endif

// The pod editor's workspace: Desktop\SWEP1R Pod Editor. Browsers won't write into Program Files,
// so tools/pod_editor/pod_editor.html builds into this folder, and the mod reads from it too:
//   out_modelblock.bin      copy of the game's data/lev01/out_modelblock.bin (input of the bake)
//   replacement_models\     baked models (<id>.bin), used before assets/replacement_models
//   pod_edits\              in-game edits (<Pod>.json), used before assets/pod_edits
//   export\                 "Export my pod" JSONs (also written to assets/pod_edits/export)
// Empty path if the Desktop can't be found or the folder created.
#ifdef __cplusplus
#include <filesystem>
const std::filesystem::path& pod_workspace();
#endif

// Spinning parts baked into a pod model (tools/pod_editor/bake_pod_edits.py) are model animations.
// The racer-select preview registers a pod's animations, a race doesn't keep them -- so the mod
// tracks the animations of every loaded pod model and runs them only during races. Like the stock
// fans (e.g. Ratts Tyrell's), they turn slowly while the pod idles and speed up with the pod: the
// baked RPM is the top-speed rate.
void pod_edits_note_model(swrModel_Header* header, const char* asset_begin, const char* asset_end, int model_id);// after a model loads
// How many spinning parts the mod turns (baked into alt models) / baked pod animations are loaded.
size_t pod_edits_spin_node_count();
size_t pod_edits_baked_anim_count();
void pod_edits_drop_models_from(const char* asset_begin);                     // buffer rewound
void pod_edits_animations_frame(bool in_race);                                 // once per frame

// Pod layout edits (an edits file's layout) are values of the game's per-pilot pod table
// swrRacer_PodVisualData, which the game reads every frame to place the cables and the energy binder.
// Written in (and the stock values put back when the edits go away) once per frame.
//   cableCockpit [x, y, z]      cable end on the cockpit (cockpit frame; x mirrored per side)
//   cableEngine [x, y, z]       cable end on each engine (engine frame; x / z mirrored per side)
//   binder [x, y, z]            energy binder end on each engine (engine frame; z mirrored per side)
//   extraCables { cockpit, engine }  a second cable pair for a 2-engine pod (baked), see below
void pod_edits_layout_frame();
// pod.engineGap k / pod.cockpitGap k / pod.height dz: after the game places the pod's parts
// (PoddAnimateEngines), the engines are spread sideways from the pod's middle (k x their stock gap),
// the cockpit moved toward / away from the engines (k x its stock distance), and the whole drawn pod
// raised / lowered by dz along its up axis; pod.cockpitMove [x, y, z] moves the cockpit freely (pod's
// right, forward, up). Visual only: physics, collision and hitboxes untouched.
void pod_edits_apply_gaps(swrRace* player);
// The same spacing / height / cockpit move on the racer-select display pod (its node transforms,
// after the display animator placed them). Returns true if anything moved (the cables need
// rebuilding between the moved parts).
bool pod_edits_apply_display_gaps(swrModel_Node** nodes, int pilot);
// Camera offsets from where the game puts each camera (game units: further from the pod, higher):
// which 0 = chase near (pod.chaseCamNear [f, h]), 1 = chase far (pod.chaseCamFar), 2 = looking behind
// with Tab (pod.rearCam). Camera only.
bool pod_edits_camera_offset(int pilot, int which, float out[2]);

// Extra exhaust trails baked into the pod model (the editor's effects.trails, installed as trailNodes
// { node: "<model>:<offset>", side, pos, scale }): placed for this racer right after the game placed its
// stock exhaust (call after swrRace_PoddAnimateVariousThings). The stock trail's own position is
// layout.exhaust [x, y, z] (swrRacer_PodVisualData fields 21..23; z mirrored on the left).
void pod_edits_place_trails(swrRace* player);

// A 2-engine pod baked with extraCables has cable nodes in part slots 12 / 13 (the 4-engine
// pods' second pair). The mod places them on the right / left engines with these values (same
// frames and mirroring as the stock cable values); without its ends: the stock cockpit end and
// the stock engine end mirrored vertically (a lower pair).
void pod_edits_extra_cable_values(int pilot, float cockpit[3], float engine[3]);

// Engine effect points of a pilot's pod (effects.<kind>.R / .L), each in its engine's own frame
// (engineXfR / engineXfL):
//   nozzles    { pos, size, length, height, width }  exhaust nozzles (the mod's flame cones, glow, embers, trails)
//   fireSpots  { pos }   damage fire / smoke spots (the mod's and the game's)
//   dustSpots  { pos }   ground dust spots (dropped to the ground under that engine)
//   gameFire   { pos }   the game's overheat engine fire (its fire / smoke emitter, swrObjSmok type 6):
//                        the first moves the stock one, more add more
// kind: 0 = nozzle, 1 = fire spot, 2 = dust spot, 3 = game fire; side: 0 = right engine, 1 = left. nullptr when the
// pod's edits don't set that kind (the effect keeps its automatic points); otherwise the side's list
// (possibly empty). Points are {x, y, z, radius (nozzles; 0 otherwise)}.
#ifdef __cplusplus
#include <array>
#include <vector>
const std::vector<std::array<float, 4>>* pod_edits_fx_points(int pilot, int kind, int side);
#endif
