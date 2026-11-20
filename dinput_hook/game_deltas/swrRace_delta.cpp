#include "swrControl_delta.h"
#include <macros.h>
#include "swrRace_delta.h"

#include <cmath>
#include <unordered_map>
#include <utility>

extern "C" {
#include <Swr/swrObj.h> // swrObjTest_F0_ADDR
#include <Swr/swrRace.h>
#include <Swr/swrEvent.h> // swrEvent_GetItem/AllocateAndLoadObjs/FreeObjs (Toss pool)
#include <Swr/swrModel.h> // swrModel_NodeInit / swrModel_NodeModifyFlags (dust-kick nodes)
#include <swr.h>          // playASound
#include <globals.h>      // someRootNodeChildNodes
#include <types_enums.h>  // swrObjTest_FLAG0_LOCAL, MODELID_dustkick1_vlec

extern FILE* hook_log;
}

#include "../hook_helper.h"
#include "../imgui_utils.h"// imgui_state: mp_disable_collision + "Game" panel cutscene toggles
#include "swrModel_delta.h"// swrModel_LoadFromId_delta (loads dust models through the GL path)
#include "pod_fx.h"        // pod_fx_on_ground_dust
#include "pod_edits.h"     // pod_edits_extra_cable_values, pod_edits_fx_points
#include "pod_wreck.h"     // engines knocked off as debris
#include "../node_utils.h"  // find_asset_offset (display pod's pilot from its model)
#include <array>
#include <cstring>

// The pod's cockpit->engine cables (partNodes[10] and [11]) are bent into a curve each
// frame by swrRace's connection-mesh deformer (FUN_00481c30 @ 0x481c30). That deformation is
// written to the rd3d-converted mesh, which the OpenGL renderer replacement never builds or
// uses - it renders the original mesh plus the node transform, i.e. the flat/straight cable.
// To reproduce the curve in the GL path we record, per frame, the bend amplitude the game would
// apply to each cable (keyed by its node); the renderer then bends the cable mesh's ring
// vertices to match (see parse_display_list_commands / debug_render_node in renderer_hook.cpp).
//
// node -> bend amplitude. Holds only the cables curved this update; not frame-gated, so the set
// stays put while the game is paused (entity updates stop but the scene keeps rendering) and the
// cables keep their curve. Cleared on track load (swrRace_ClearCableBends) to drop freed nodes.
static std::unordered_map<const swrModel_Node*, float> cable_bend_by_node;
// node -> (racer, engine part) for the renderer's cable clearance.
struct CableOwner {
    const swrRace* racer;
    int engine_part;// 1..4
    int index;      // 0..3 = part slots 10..13
};
static std::unordered_map<const swrModel_Node*, CableOwner> cable_owner_by_node;
struct DisplayCable {
    const swrModel_Node* cockpit;
    const swrModel_Node* engine;
    int pilot;
    int index;
};
static std::unordered_map<const swrModel_Node*, DisplayCable> display_cable_by_node;

// Amplitude A = (1 - (dist/50)^2) * bend, replicating FUN_00481c30:
//   dist = lodDistance (camera distance); the cable is only curved when 1-(dist/50)^2 >= 0.1,
//          i.e. roughly dist < 47 (farther than that the game restores the straight cable).
//   bend = (turnRate*k > 1) ? min(turnRate*k*0.3, 1.0) : 0.3
//   k    = -0.03 for cable 10, +0.03 for cable 11 (0x4adb38 / 0x4adb3c), so the two cables
//          flare in opposite directions as the pod steers.
static float compute_cable_amplitude(const swrRace* player, float k) {
    const float dist = (float) player->lodDistance;
    const float falloff = 1.0f - (dist / 50.0f) * (dist / 50.0f);
    if (falloff < 0.1f)
        return -1.0f;
    const float temp = player->turnRate * k;
    const float bend = (temp > 1.0f) ? (temp * 0.3f < 1.0f ? temp * 0.3f : 1.0f) : 0.3f;
    return falloff * bend;
}

// Extra cable pair (pod editor "cables extra"): a 2-engine pod whose model has cable nodes in the
// 4-engine pods' cable slots 12 / 13. The game would stretch those to the second engine pair
// (engineXfR2 / L2, never set on a 2-engine pod; the hangar / racer-select display pod even
// dereferences the missing engine nodes 3 / 4), so they are placed here instead: the game's own
// cable builder (swrRace_BuildStretchedQuad, 0x46f0e0), aimed at the right / left engines with the
// extra pair's values swapped into the pilot's swrRacer_PodVisualData row for the call.
typedef void(__cdecl* BuildStretchedQuad_t)(const rdMatrix44* cockpit, const rdMatrix44* engine, float mirror_x,
                                            float mirror_pair, int pilot, rdMatrix44* out);
typedef void(__cdecl* NodeSetTransform_t)(swrModel_Node* node, const rdMatrix44* m);
typedef void(__cdecl* NodeGetTransform_t)(const swrModel_Node* node, rdMatrix44* out);

static bool has_extra_cables(swrModel_Node** nodes) {
    return nodes && (nodes[12] || nodes[13]) && !nodes[3] && !nodes[4];
}

static void place_extra_cables(swrModel_Node** nodes, int pilot, const rdMatrix44& cockpit, const rdMatrix44& engine_r,
                               const rdMatrix44& engine_l) {
    if (pilot < 0 || pilot >= 23)
        return;
    float c[3], e[3];
    pod_edits_extra_cable_values(pilot, c, e);
    float* row = (float*) &swrRacer_PodVisualData[pilot];
    float saved[6];
    for (int j = 0; j < 6; j++)
        saved[j] = row[9 + j];// cable cockpit end (9..11), engine end (12..14)
    for (int j = 0; j < 3; j++) {
        row[9 + j] = c[j];
        row[12 + j] = e[j];
    }
    const auto build = (BuildStretchedQuad_t) swrRace_BuildStretchedQuad_ADDR;
    const auto set = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    rdMatrix44 m;
    if (nodes[12]) {
        build(&cockpit, &engine_r, 1.0f, 1.0f, pilot, &m);// right: like cable 10
        set(nodes[12], &m);
    }
    if (nodes[13]) {
        build(&cockpit, &engine_l, -1.0f, 1.0f, pilot, &m);// left: like cable 11
        set(nodes[13], &m);
    }
    for (int j = 0; j < 6; j++)
        row[9 + j] = saved[j];
}

// Cables with their own ends (the pod editor's "cable<N> cockpit / engine" lines): rebuilt with the
// game's cable builder from those values (unmirrored), replacing the shared, mirrored ones for that
// cable only. `engines` = the matrices of the engine each cable runs to (cables 10..13).
static void place_own_cables(swrModel_Node** nodes, int pilot, const rdMatrix44& cockpit, const rdMatrix44* engines[4]) {
    if (pilot < 0 || pilot >= 23)
        return;
    float* row = (float*) &swrRacer_PodVisualData[pilot];
    float saved[6];
    for (int j = 0; j < 6; j++)
        saved[j] = row[9 + j];
    const auto build = (BuildStretchedQuad_t) swrRace_BuildStretchedQuad_ADDR;
    const auto set = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
    for (int i = 0; i < 4; i++) {
        if (nodes[10 + i] == nullptr || engines[i] == nullptr)
            continue;
        float c[3], e[3];
        const bool own_c = pod_edits_cable_end(pilot, i, 0, c), own_e = pod_edits_cable_end(pilot, i, 1, e);
        if (!own_c && !own_e)
            continue;
        // The shared values for whichever end isn't its own, mirrored as the game would for it.
        const float mx = (i % 2 == 0) ? 1.0f : -1.0f;
        const float pair = (i < 2 || !(nodes[3] && nodes[4])) ? 1.0f : -1.0f;
        if (!own_c)
            c[0] = saved[0] * mx, c[1] = saved[1], c[2] = saved[2];
        if (!own_e)
            e[0] = saved[3] * mx, e[1] = saved[4], e[2] = saved[5] * pair;
        for (int j = 0; j < 3; j++) {
            row[9 + j] = c[j];
            row[12 + j] = e[j];
        }
        rdMatrix44 m;
        build(&cockpit, engines[i], 1.0f, 1.0f, pilot, &m);
        set(nodes[10 + i], &m);
    }
    for (int j = 0; j < 6; j++)
        row[9 + j] = saved[j];
}

void swrRace_PoddAnimateVariousThings_delta(swrRace* player) {
    swrModel_Node** nodes = player->partNodes;
    const bool extra = has_extra_cables(nodes);
    if (extra) {
        // The game builds cables 12 / 13 towards the second engine pair: keep that finite.
        player->engineXfR2 = player->engineXfR;
        player->engineXfL2 = player->engineXfL;
    }
    hook_call_original(swrRace_PoddAnimateVariousThings, player);
    if (!nodes)
        return;
    if (extra && player->lodDistance <= 75 && player->score_ptr && player->score_ptr->pilotId)
        place_extra_cables(nodes, *player->score_ptr->pilotId, player->cockpitXf, player->engineXfR, player->engineXfL);
    if (player->lodDistance <= 75 && player->score_ptr && player->score_ptr->pilotId) {
        const bool four = nodes[3] && nodes[4];
        const rdMatrix44* engines[4] = {&player->engineXfR, &player->engineXfL, four ? &player->engineXfR2 : &player->engineXfR,
                                        four ? &player->engineXfL2 : &player->engineXfL};
        place_own_cables(nodes, *player->score_ptr->pilotId, player->cockpitXf, engines);
    }
    pod_wreck_frame(player);       // knocked-off engines: debris, and what hung off them hidden
    pod_edits_place_trails(player);// extra exhaust trails, right after the game placed the stock ones

    // The game only runs its cable deformer on cables 10/11, but 4-engine pods (e.g. Ben
    // Quadinaros) also have cables 12/13 to the extra engines. Register all four so they render
    // as the same rebuilt tube and stay visually consistent; the extra pair is null on 2-engine
    // pods so they're skipped. k sign mirrors the front pair (right -0.03 / left +0.03).
    const float k[4] = {-0.03f, 0.03f, -0.03f, 0.03f};
    const bool four = nodes[3] && nodes[4];
    for (int i = 0; i < 4; i++) {
        swrModel_Node* node = nodes[10 + i];
        if (!node)
            continue;
        // The engine this cable runs to: 10 / 11 right / left, 12 / 13 the second pair (or, on a
        // 2-engine pod with the pod editor's extra cables, right / left again).
        cable_owner_by_node[node] = {player, i == 0 ? 1 : i == 1 ? 2 : (four ? i + 1 : i - 1), i};
        const float a = compute_cable_amplitude(player, k[i]);
        if (a >= 0.0f)
            cable_bend_by_node[node] = a;// curved this frame
        else
            cable_bend_by_node.erase(node);// went straight (too far) - stop curving it
    }
}

// swrRace_AnimateDisplayPod (0x004337e0) is the display-pod animator used outside racing - the
// hangar "inspect vehicle" (swrObjHang_UpdateLookAtVehicle), the racer selection menu
// (swrRace_SelectVehicle) and the taunt/results cutscenes. It positions the pod's engine/cockpit/
// cable nodes and curves cables [10..13] through the same deformer (FUN_00481c30) with a fixed
// amplitude: 1.3 if the pod is animated (param_8 != 0) else 0.5 (distance is passed as 0, so the
// falloff is 1 and the cable amplitude is exactly that value). Register those cables so the GL
// path bends them too. Not reimplemented in src: declared (swrRace_AnimateDisplayPod_ADDR +
// prototype) in swrObj.h, so call the original through its address via this typedef.
typedef void(__cdecl* swrRace_AnimateDisplayPod_t)(swrModel_Node** nodes, void* transform, int a3,
                                                   float a4, float a5, float a6, float a7,
                                                   int animated, float a9, float a10);

// The display pod's pilot: the display code keeps it in node slot 60; if that isn't a pilot
// index, find the pilot whose pod model the cockpit / cable nodes come from.
static int display_pod_pilot(swrModel_Node** nodes) {
    const int p = (int) (intptr_t) nodes[60];
    if (p >= 0 && p < 23)
        return p;
    for (int slot: {10, 11, 5, 1}) {
        MODELID id;
        uint32_t off;
        if (nodes[slot] == nullptr || !find_asset_offset(nodes[slot], &id, &off))
            continue;
        for (int pilot = 0; pilot < 23; pilot++)
            if (swrRacer_PodData[pilot].pod_modelID == id || swrRacer_PodData[pilot].pod_alt_modelID == id)
                return pilot;
    }
    return -1;
}

void __cdecl swrRace_AnimateDisplayPod_delta(swrModel_Node** nodes, void* transform, int a3,
                                             float a4, float a5, float a6, float a7, int animated,
                                             float a9, float a10) {
    // An extra cable pair on a 2-engine pod: the display code would read engine nodes 3 / 4 for
    // cables 12 / 13 (null here), so hide them from it and place them ourselves afterwards.
    const bool extra = has_extra_cables(nodes);
    swrModel_Node* saved12 = extra ? nodes[12] : nullptr;
    swrModel_Node* saved13 = extra ? nodes[13] : nullptr;
    if (extra)
        nodes[12] = nodes[13] = nullptr;
    hook_call_original((swrRace_AnimateDisplayPod_t) swrRace_AnimateDisplayPod_ADDR, nodes,
                       transform, a3, a4, a5, a6, a7, animated, a9, a10);
    if (!nodes)
        return;
    // The display code sizes its cables for the display (thicker than the racing builder's); note
    // the stock cable's thickness so the cables we rebuild below match it.
    float thick_x = 0.0f, thick_z = 0.0f;
    if (nodes[10]) {
        rdMatrix44 m;
        ((NodeGetTransform_t) swrModel_NodeGetTransform_ADDR)(nodes[10], &m);
        thick_x = std::sqrt(m.vA.x * m.vA.x + m.vA.y * m.vA.y + m.vA.z * m.vA.z);
        thick_z = std::sqrt(m.vC.x * m.vC.x + m.vC.y * m.vC.y + m.vC.z * m.vC.z);
    }
    // The pod editor's spacing / height / cockpit move, as in races; the stock cables are then
    // rebuilt between the moved parts with the game's cable builder (thickness fixed below).
    {
        const int dpilot = display_pod_pilot(nodes);
        if (dpilot >= 0 && pod_edits_apply_display_gaps(nodes, dpilot)) {
            const auto get = (NodeGetTransform_t) swrModel_NodeGetTransform_ADDR;
            const auto set = (NodeSetTransform_t) swrModel_NodeSetTransform_ADDR;
            const auto build = (BuildStretchedQuad_t) swrRace_BuildStretchedQuad_ADDR;
            const bool four = nodes[3] && nodes[4];
            rdMatrix44 cockpit, eng[4];
            get(nodes[5], &cockpit);
            for (int k = 0; k < 4; k++)
                if (nodes[1 + k])
                    get(nodes[1 + k], &eng[k]);
            for (int i = 0; i < 4; i++) {
                if (nodes[10 + i] == nullptr || (i >= 2 && !four))
                    continue;// (extra cables are placed below)
                rdMatrix44 out;
                build(&cockpit, &eng[i], (i % 2) ? -1.0f : 1.0f, i < 2 ? 1.0f : -1.0f, dpilot, &out);
                set(nodes[10 + i], &out);
            }
        }
    }
    if (extra) {
        nodes[12] = saved12;
        nodes[13] = saved13;
        if (nodes[5] && nodes[1] && nodes[2]) {
            // The display code works in the nodes' own transforms (cockpit / engines / cables are
            // siblings), with the pilot id in node slot 60.
            const auto get = (NodeGetTransform_t) swrModel_NodeGetTransform_ADDR;
            rdMatrix44 cockpit, engine_r, engine_l;
            get(nodes[5], &cockpit);
            get(nodes[1], &engine_r);
            get(nodes[2], &engine_l);
            place_extra_cables(nodes, display_pod_pilot(nodes), cockpit, engine_r, engine_l);
        }
        // Shown / hidden with the stock cable on the same side (the display code only manages 10 / 11).
        for (int k = 0; k < 2; k++)
            if (nodes[12 + k] && nodes[10 + k])
                nodes[12 + k]->flags_1 = (nodes[12 + k]->flags_1 & ~0x2u) | (nodes[10 + k]->flags_1 & 0x2u);
    }
    if (nodes[5] && nodes[1] && nodes[2]) {
        // Cables with their own ends, in the display pod's node transforms.
        const auto get = (NodeGetTransform_t) swrModel_NodeGetTransform_ADDR;
        rdMatrix44 cockpit, eng[4];
        get(nodes[5], &cockpit);
        for (int k = 0; k < 4; k++)
            if (nodes[1 + k])
                get(nodes[1 + k], &eng[k]);
        const bool four = nodes[3] && nodes[4];
        const rdMatrix44* engines[4] = {&eng[0], &eng[1], four ? &eng[2] : &eng[0], four ? &eng[3] : &eng[1]};
        place_own_cables(nodes, display_pod_pilot(nodes), cockpit, engines);
    }
    if (thick_x > 1e-6f && thick_z > 1e-6f)
        for (int i = 10; i <= 13; i++) {
            if (nodes[i] == nullptr)
                continue;
            rdMatrix44 m;
            ((NodeGetTransform_t) swrModel_NodeGetTransform_ADDR)(nodes[i], &m);
            const float lx = std::sqrt(m.vA.x * m.vA.x + m.vA.y * m.vA.y + m.vA.z * m.vA.z);
            const float lz = std::sqrt(m.vC.x * m.vC.x + m.vC.y * m.vC.y + m.vC.z * m.vC.z);
            if (lx < 1e-6f || lz < 1e-6f || (std::fabs(lx - thick_x) < 1e-4f * thick_x && std::fabs(lz - thick_z) < 1e-4f * thick_z))
                continue;
            const float sx = thick_x / lx, sz = thick_z / lz;
            m.vA = {m.vA.x * sx, m.vA.y * sx, m.vA.z * sx, m.vA.w};
            m.vC = {m.vC.x * sz, m.vC.y * sz, m.vC.z * sz, m.vC.w};
            ((NodeSetTransform_t) swrModel_NodeSetTransform_ADDR)(nodes[i], &m);
        }
    const float amplitude = (animated != 0) ? 1.3f : 0.5f;
    const int pilot = display_pod_pilot(nodes);
    const bool four = nodes[3] && nodes[4];
    for (int i = 10; i <= 13; i++)
        if (nodes[i]) {
            cable_bend_by_node[nodes[i]] = amplitude;
            const int k = i - 10, engine_slot = (k < 2 || !four) ? 1 + (k % 2) : 3 + (k % 2);
            if (nodes[5] && nodes[engine_slot])
                display_cable_by_node[nodes[i]] = {nodes[5], nodes[engine_slot], pilot, k};
        }
}

// Multiplayer "no collision" / ghost mode. swrRace_ResolvePodCollision (called each physics step
// from swrObjTest_UpdatePhysicsContact) finds the nearest pod and resolves a pod-to-pod collision, pushing both
// pods apart and bleeding speed off both. When the local player turns collision off in multiplayer,
// skip it so they pass straight through other racers.
//
// We skip it for EVERY pod, not just the local one: the function mutates BOTH pods it resolves, and
// remote pods run their physics locally too -- so skipping only the local pod still lets a remote
// pod's call bump us via the other-pod side (confirmed in-game). Skipping all pods means our pod can
// never be pushed by a collision on our machine. Remote pod positions come from the network anyway,
// so dropping their local collision response desyncs nothing; track/wall collision is a separate
// path (swrRace_CollideTrack / UpdateWallContact / UpdateGroundContact) and is untouched. This is
// per-player by nature -- it governs collisions on OUR machine -- so if everyone in a lobby enables
// it, nobody collides. Not reimplemented in src (declared in swrRace.h), so the original is called
// back through its address via this typedef.
typedef void(__cdecl* swrRace_ResolvePodCollision_t)(swrRace* player);

void __cdecl swrRace_ResolvePodCollision_delta(swrRace* player) {
    if (imgui_state.mp_disable_collision && multiplayer_enabled != 0 && player != nullptr) {
        // Mirror the original's "no pod nearby" outcome: it always clears speedLoss before the
        // collision test, so do the same here instead of leaving a stale value from a prior hit.
        player->speedLoss = 0.0f;
        return;
    }
    hook_call_original((swrRace_ResolvePodCollision_t) swrRace_ResolvePodCollision_ADDR, player);
}

// --- Ground dust/splash effect: fix the AI-full-LOD contention -------------------------------------
// swrRace_PoddAnimateVariousThings -> swrRace_SpawnGroundDustKick spawns the ground dust/splash
// trail. Each spawn takes a Toss entity from a FIXED 16-slot pool (swrEvent_AllocObj) and, on
// swamp/soft terrain, plays the splash sound (playASound id 0x45). That path only runs for full-model
// pods, so in vanilla only the local player triggers it. With ai_full_lod every AI pod is a full
// model and runs it too, which (a) drains the shared Toss pool so the player's (and everyone's) trail
// keeps gapping/restarting, and (b) hammers the single shared splash voice at full, non-spatial
// volume so the player's continuous splash loop restarts over and over.
//
// Keep the AI dust VISUAL but stop it breaking the player's: enlarge the Toss pool (below) so AI dust
// no longer starves it, suppress the splash SOUND for non-local pods, and keep a small reserve as
// insurance for the local player on a fully-saturated grid.
static const int DUST_SPLASH_SOUND_ID = 0x45; // ground dust/splash loop sound id (see the function above)
static const int TOSS_EVENT = 0x546f7373;     // 'Toss' - the dust-kick entity pool
static const int SWR_OBJ_FLAG_FREE = 0x100;   // swrObj.flags: slot is free/unused (see swrEvent_AllocObj)
static const int DUST_LOCAL_RESERVE_SLOTS = 4; // Toss slots kept free for local player(s)

static bool g_suppress_dust_splash_sound = false;

// Free slots left in the fixed Toss pool. Walks the pool through the public event API (cheap: <=16).
static int count_free_toss_slots() {
    int free_slots = 0;
    for (int i = 0;; i++) {
        void* obj = swrEvent_GetItem(TOSS_EVENT, i);
        if (obj == nullptr)
            break;// past the end of the pool
        if ((((swrObj*) obj)->flags & SWR_OBJ_FLAG_FREE) != 0)
            free_slots++;
    }
    return free_slots;
}

// playASound is dormant (reverse-hooked); the original .text runs and is reached via its address.
typedef void(__cdecl* playASound_t)(int, short, float, float, int);

void __cdecl playASound_delta(int sound_id, short priority, float volume, float pitch, int flags) {
    // Drop the ground-dust splash sound while a non-local pod is spawning its dust kick (flag set by
    // swrRace_SpawnGroundDustKick_delta below). Only the local player's splash should be heard;
    // AI/remote splashes play non-spatially and restart the player's looping voice.
    if (g_suppress_dust_splash_sound && sound_id == DUST_SPLASH_SOUND_ID)
        return;
    hook_call_original((playASound_t) playASound_ADDR, sound_id, priority, volume, pitch, flags);
}

typedef void(__cdecl* swrRace_SpawnGroundDustKick_t)(swrRace*, float*, float, float, float,
                                                           float, int);

static void spawn_ground_dust_kick(swrRace* player, float* transform, float sx, float sy, float sz,
                                   float param_6, int param_7);

// A direction turned by Euler angles (degrees, about the frame's x, then y, then z axes).
static rdVector3 turn_in_frame(const rdMatrix44& f, rdVector3 d, float rx, float ry, float rz) {
    rdVector3 ax[3] = {{f.vA.x, f.vA.y, f.vA.z}, {f.vB.x, f.vB.y, f.vB.z}, {f.vC.x, f.vC.y, f.vC.z}};
    for (rdVector3& a: ax) {
        const float l = std::sqrt(a.x * a.x + a.y * a.y + a.z * a.z);
        if (l > 1e-6f)
            a = {a.x / l, a.y / l, a.z / l};
    }
    float l[3] = {d.x * ax[0].x + d.y * ax[0].y + d.z * ax[0].z, d.x * ax[1].x + d.y * ax[1].y + d.z * ax[1].z,
                  d.x * ax[2].x + d.y * ax[2].y + d.z * ax[2].z};
    const float deg = 3.14159265f / 180.0f;
    auto rot = [&](int i, int j, float a) {// rotate the (i, j) plane
        const float c = std::cos(a * deg), s = std::sin(a * deg), u = l[i], v = l[j];
        l[i] = u * c - v * s;
        l[j] = u * s + v * c;
    };
    rot(1, 2, rx);// about x
    rot(2, 0, ry);// about y
    rot(0, 1, rz);// about z
    return {l[0] * ax[0].x + l[1] * ax[1].x + l[2] * ax[2].x, l[0] * ax[0].y + l[1] * ax[1].y + l[2] * ax[2].y,
            l[0] * ax[0].z + l[1] * ax[1].z + l[2] * ax[2].z};
}

// An engine side's frame applied to a point of the pod editor's (that engine's own frame).
static rdVector3 engine_point(const swrRace* player, int side, const std::array<float, 4>& p) {
    const rdMatrix44& e = side == 0 ? player->engineXfR : player->engineXfL;
    return {e.vD.x + e.vA.x * p[0] + e.vB.x * p[1] + e.vC.x * p[2], e.vD.y + e.vA.y * p[0] + e.vB.y * p[1] + e.vC.y * p[2],
            e.vD.z + e.vA.z * p[0] + e.vB.z * p[1] + e.vC.z * p[2]};
}
static int pilot_of(const swrRace* player) {
    return (player && player->score_ptr && player->score_ptr->pilotId) ? *player->score_ptr->pilotId : -1;
}

void __cdecl swrRace_SpawnGroundDustKick_delta(swrRace* player, float* transform, float sx,
                                                     float sy, float sz, float param_6,
                                                     int param_7) {
    // Pod FX dust clouds key off the same ground contact (before any pool-reserve early-out).
    pod_fx_on_ground_dust(player, transform);
    // The pod editor's dust spots: the game kicks dust once per engine, from that engine's shadow
    // (shadowXf1 = right, shadowXf2 = left); spawn it at each of that engine's spots instead, on the
    // same ground height.
    const int side = player == nullptr ? -1
                     : transform == (float*) &player->shadowXf1 ? 0
                     : transform == (float*) &player->shadowXf2 ? 1
                                                                 : -1;
    if (side >= 0) {
        if (const auto* spots = pod_edits_fx_points(pilot_of(player), 2, side)) {
            for (const auto& p: *spots) {
                rdMatrix44 m;
                memcpy(&m, transform, sizeof(m));
                const rdVector3 w = engine_point(player, side, p);
                m.vD.x = w.x;
                m.vD.y = w.y;
                spawn_ground_dust_kick(player, &m.vA.x, sx, sy, sz, param_6, param_7);
            }
            return;
        }
    }
    spawn_ground_dust_kick(player, transform, sx, sy, sz, param_6, param_7);
}

static void spawn_ground_dust_kick(swrRace* player, float* transform, float sx, float sy, float sz,
                                   float param_6, int param_7) {
    const bool is_local = player != nullptr && (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0;

    if (!is_local) {
        // Reserve headroom so a full grid of AI dust never starves the local player's trail.
        if (count_free_toss_slots() <= DUST_LOCAL_RESERVE_SLOTS)
            return;
        // Keep the AI dust visual, but silence its splash sound for the duration of this call.
        g_suppress_dust_splash_sound = true;
        hook_call_original(
            (swrRace_SpawnGroundDustKick_t) swrRace_SpawnGroundDustKick_ADDR, player,
            transform, sx, sy, sz, param_6, param_7);
        g_suppress_dust_splash_sound = false;
        return;
    }

    hook_call_original((swrRace_SpawnGroundDustKick_t) swrRace_SpawnGroundDustKick_ADDR,
                       player, transform, sx, sy, sz, param_6, param_7);
}

// --- The game's engine damage smoke / fire at the pod editor's fire spots ---------------------------
// swrRace_UpdateEngineDamageFX (0x46f9a0) keeps one swrObjSmok (type 6) per burning engine,
// engineDamageSmoke[0] = left, [1] = right, 2 units behind that engine's origin and drifting back
// (velocity -20 x its forward row), its lifetime topped up to 5 s each frame. With the pod's
// "firespot" edits the first spot of each engine carries that emitter, and every further spot gets
// one of ours, kept alive and placed the same way while that engine burns.
typedef void(__cdecl* swrRace_UpdateEngineDamageFX_t)(swrRace*);
typedef swrObjSmok*(__cdecl* SmokSpawn_t)(int type, int flags, float lifetime, rdVector3* pos, float scale);
typedef void(__cdecl* SmokSetVec_t)(swrObjSmok*, rdVector3*);
typedef void(__cdecl* SmokSetLifetime_t)(swrObjSmok*, float);
typedef void(__cdecl* SmokSetOwner_t)(swrObjSmok*, swrObjSmok**);

namespace {
    constexpr int kMaxExtraFire = 8;
    struct ExtraFire {
        swrObjSmok* smoke[2][kMaxExtraFire] = {};// [game slot][spot - 1]; nulled by the game when they die
    };
    // Node-based: the addresses handed to swrObjSmok_SetOwnerHandle stay valid (never erased).
    std::unordered_map<const swrRace*, ExtraFire> g_extra_fire;
}// namespace

typedef void(__cdecl* swrRace_HandleDeathExplosion_t)(swrRace* player, int arg);
void __cdecl swrRace_HandleDeathExplosion_delta(swrRace* player, int arg) {
    pod_wreck_before_death_explosion(player);
    hook_call_original((swrRace_HandleDeathExplosion_t) swrRace_HandleDeathExplosion_ADDR, player, arg);
}

typedef void(__cdecl* swrObjTest_F3_t)(swrRace* player);
void __cdecl swrObjTest_F3_delta(swrRace* player) {
    hook_call_original((swrObjTest_F3_t) swrObjTest_F3_ADDR, player);
    pod_wreck_after_f3(player);
}

typedef void(__cdecl* swrRace_Explode_t)(swrRace* player, int side);
void __cdecl swrRace_Explode_delta(swrRace* player, int side) {
    side &= 0xff;// a char argument
    // Who blew it: the engine-damage check (its call returns to 0x46aeac), or a crash
    // (swrRace_DeathSpeed, the track's kill triggers).
    const bool crash = (uintptr_t) __builtin_return_address(0) != 0x0046aeac;
    if (pod_wreck_on_explode(player, side, crash))
        return;// a survivable engine loss, handled there
    // Only the call that actually sets it off counts: once exploding, the game ignores repeats (a
    // second wall hit in the spin, the damage check), and so must we.
    const bool was_exploding = player != nullptr && (player->flags1 & swrObjTest_FLAG1_EXPLODING) != 0;
    hook_call_original((swrRace_Explode_t) swrRace_Explode_ADDR, player, side);
    if (!was_exploding)
        pod_wreck_after_explode(player, side, crash);
}

void __cdecl swrRace_UpdateEngineDamageFX_delta(swrRace* player) {
    hook_call_original((swrRace_UpdateEngineDamageFX_t) swrRace_UpdateEngineDamageFX_ADDR, player);
    pod_wreck_after_damage_fx(player);
    if (player == nullptr || player->partNodes == nullptr)
        return;
    const int pilot = pilot_of(player);
    const auto spawn = (SmokSpawn_t) swrObjSmok_Spawn_ADDR;
    const auto set_pos = (SmokSetVec_t) swrObjSmok_SetPosition_ADDR;
    const auto set_vel = (SmokSetVec_t) swrObjSmok_SetVelocity_ADDR;
    const auto set_life = (SmokSetLifetime_t) swrObjSmok_SetLifetime_ADDR;
    const auto set_owner = (SmokSetOwner_t) swrObjSmok_SetOwnerHandle_ADDR;
    for (int slot = 0; slot < 2; slot++) {
        const int side = slot == 0 ? 1 : 0;// edits: 0 = right engine
        // The pod editor's "gamefire" points (else the stock spot) and "gamefirestreak".
        const auto* spots = pod_edits_fx_points(pilot, 3, side);
        float streak[4] = {1.0f, 0.0f, 0.0f, 0.0f};
        const bool has_streak = pod_edits_gamefire_streak(pilot, streak);
        if (spots == nullptr && !has_streak)
            continue;
        const rdMatrix44& e = side == 0 ? player->engineXfR : player->engineXfL;
        rdVector3 vel = {-20.0f * e.vB.x, -20.0f * e.vB.y, -20.0f * e.vB.z};
        if (has_streak) {
            const float mirror = side == 1 ? -1.0f : 1.0f;// the left engine's turns mirrored
            vel = turn_in_frame(e, vel, streak[1], streak[2] * mirror, streak[3] * mirror);
            vel = {vel.x * streak[0], vel.y * streak[0], vel.z * streak[0]};
        }
        swrObjSmok* game = player->engineDamageSmoke[slot];
        if (game != nullptr) {
            if (spots != nullptr && !spots->empty()) {
                rdVector3 p = engine_point(player, side, (*spots)[0]);
                set_pos(game, &p);
            }
            set_vel(game, &vel);
        }
        if (spots == nullptr)
            continue;
        ExtraFire& ex = g_extra_fire[player];
        for (int i = 0; i < kMaxExtraFire; i++) {
            swrObjSmok*& h = ex.smoke[slot][i];
            const bool want = game != nullptr && (size_t) i + 1 < spots->size();
            if (!want) {
                if (h != nullptr)
                    set_life(h, 0.5f);// let it burn out (the game nulls h when it dies)
                continue;
            }
            rdVector3 p = engine_point(player, side, (*spots)[(size_t) i + 1]);
            if (h == nullptr) {
                h = spawn(6, 0, 1000.0f, &p, 1.0f);
                if (h != nullptr)
                    set_owner(h, &h);
            } else {
                set_life(h, 5.0f);
            }
            if (h != nullptr) {
                set_pos(h, &p);
                set_vel(h, &vel);
            }
        }
    }
}

// Enlarged dust-kick pool. The stock swrObjToss_AddDustKickModelsToScene builds a 16-slot Toss pool
// backed by a fixed 16-entry node array (each Toss draws its node from dustWhirlChildNodesPtr[id], so
// the pool count and the node array must match). 16 is fine when only the player kicks up dust, but
// with ai_full_lod every pod does, so the pool needs to be bigger. This delta rebuilds the setup with
// DUST_POOL_SIZE slots and delta-owned node buffers. Each Toss still needs its OWN dust-model copy
// (swrObjToss_F3 tints the per-particle material), so the model is loaded once per slot -- the stock
// function does the same. A NODE_TRANSFORMED_WITH_PIVOT node writes slots [0..3] in
// swrModel_NodeInit, so each wrapper reserves 4 contiguous swrModel_Node slots.
// Sized so the shared pool isn't exhausted once far AI also spawn dust (see the reserve in
// swrRace_SpawnGroundDustKick_delta): when free slots hit the reserve, ALL AI skip that frame
// and their trails gap while the (unchecked) player stays smooth. More headroom keeps AI continuous.
static const int DUST_POOL_SIZE = 128;
static swrModel_Node g_dustWrappers[DUST_POOL_SIZE * 4];
static swrModel_Node* g_dustChildNodes[DUST_POOL_SIZE];
static swrModel_Node* g_dustChildArray2[DUST_POOL_SIZE];
static swrModel_Node g_dustRootNode;

bool swrRace_IsDustKickNode(const swrModel_Node* node) {
    return node >= &g_dustWrappers[0] && node < &g_dustWrappers[DUST_POOL_SIZE * 4];
}

void swrObjToss_AddDustKickModelsToScene_delta() {
    swrEvent_AllocateAndLoadObjs(TOSS_EVENT, DUST_POOL_SIZE);
    swrEvent_FreeObjs(TOSS_EVENT);

    for (int i = 0; i < DUST_POOL_SIZE; i++) {
        // Load through the delta so the model registers its asset range like every other GL-path
        // model (the stock function calls swrModel_LoadFromId, which is detoured to this).
        swrModel_Header* header = swrModel_LoadFromId_delta(MODELID_dustkick1_vlec);
        if (header == nullptr) {
            g_dustChildNodes[i] = nullptr;
            continue;
        }
        swrModel_Node* wrapper = &g_dustWrappers[i * 4];
        swrModel_NodeInit(wrapper, NODE_TRANSFORMED_WITH_PIVOT);
        wrapper->num_children = 1;
        wrapper->children.nodes = &g_dustChildArray2[i];
        g_dustChildArray2[i] = header->entries[0].node;
        g_dustChildNodes[i] = wrapper;
        swrModel_NodeModifyFlags(wrapper, 2, -4, 0x10, 3);// start hidden (shown on spawn)
    }

    swrModel_NodeInit(&g_dustRootNode, NODE_BASIC);
    g_dustRootNode.num_children = DUST_POOL_SIZE;
    g_dustRootNode.children.nodes = g_dustChildNodes;
    someRootNodeChildNodes[6] = &g_dustRootNode;
    swrObjToss_SetDustKickChildNodesPtr(g_dustChildNodes);
}

// Widen far-AI ground contact so distant AI kick up dust. Distant non-local pods run simplified
// on-rails physics, so their ground-contact / shadow pipeline (which the dust spawns from) is not
// refreshed and no dust appears beyond a short range. Every gate in that pipeline keys on lodDistance
// (linear camera distance, set each frame by swrObjTest_F0). After F0 sets it, clamp it down for
// visible non-local pods so their ground contact + shadow (and thus dust) run like a nearby pod.
// Only within FAR_AI_GROUND_RADIUS, so off-screen pods keep their cheap LOD. This runs more physics
// on those pods (the AI-LOD "gate 2"): the same full ground handling they already use up close, just
// applied farther out -- so behavior stays consistent, at a per-frame cost that scales with how many
// AI are on screen. Tunables: raise CLAMP (>=100 skips the hover-pad detail) or lower RADIUS to trade
// dust range for performance.
//
// Local pods too: their physics gates already bypass lodDistance, so for them this only keeps the
// distance-gated cosmetics (shadows past 100, cables, hover) when a far camera pulls away.
static const int FAR_AI_GROUND_CLAMP = 90;     // treat a widened pod as this camera distance
static const int FAR_AI_GROUND_RADIUS = 20000; // only widen pods within this real distance

typedef void(__cdecl* swrObjTest_F0_t)(swrRace*);

void __cdecl swrObjTest_F0_delta(swrRace* player) {
    hook_call_original((swrObjTest_F0_t) swrObjTest_F0_ADDR, player);
    if (player != nullptr && player->lodDistance > FAR_AI_GROUND_CLAMP &&
        player->lodDistance < FAR_AI_GROUND_RADIUS) {
        player->lodDistance = FAR_AI_GROUND_CLAMP;
    }
}

// Boost cheats. swrRace_UpdatePlayerControl (called from within F0 via CalcTargetTurnRate) snapshots
// flags0 into a local at its top and gates the actual BOOSTING set on that snapshot, then calls
// swrRace_BoostCharge -- which also requires FLAG0_CAN_CHARGE_BOOST. F0 clears that flag and only
// re-sets it above ~50% top speed, just before this call. So we must force it here, BEFORE the
// original runs (a post-hook set, or a set inside BoostCharge, is too late for the snapshot). That
// gives "boost at any speed". "No charge timer" pushes the boost charge timer past the ~1s stock
// hold (boostIndicatorStatus 1 == charging) so BoostCharge advances it to ready immediately.
typedef void(__cdecl* swrRace_UpdatePlayerControl_t)(swrRace* player);

static const uint32_t BOOST_INDICATOR_CHARGING = 1;   // boostIndicatorStatus: 0 not ready, 1 charging, 2 ready
static const float BOOST_CHARGE_SKIP_SECONDS = 2.0f;  // > the ~1s stock charge hold, so it reads ready at once

void __cdecl swrRace_UpdatePlayerControl_delta(swrRace* player) {
    if (player != nullptr && imgui_state.cheats_enabled &&
        (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) {
        if (imgui_state.cheat_boost_any_speed)
            player->flags0 =
                (swrObjTest_FLAG0) (player->flags0 | swrObjTest_FLAG0_CAN_CHARGE_BOOST);
        if (imgui_state.cheat_no_boost_charge &&
            player->boostIndicatorStatus == BOOST_INDICATOR_CHARGING)
            player->boostChargeTimer = BOOST_CHARGE_SKIP_SECONDS;
    }
    hook_call_original((swrRace_UpdatePlayerControl_t) swrRace_UpdatePlayerControl_ADDR, player);
}

// Tilt-at-any-speed. The stock swrRace_Tilt zeroes the requested bank when speedValue is below the
// tilt gate (~200), and that threshold is a shared constant used elsewhere (the high-speed ram-kill
// check), so it can't be poked directly. Tilt reads speedValue only for that gate, so lift it for
// the single call and restore it untouched afterwards. swrRace_Tilt is reimplemented (reverse-hooked)
// in src, so it's force-hooked at its raw address like swrObjTest_F0 -- see renderer_hook.cpp.
typedef void(__cdecl* swrRace_Tilt_t)(swrRace* player, float b);

static const float TILT_GATE_BYPASS_SPEED = 1000.0f;// any value clear of the ~200 stock tilt gate

void __cdecl swrRace_Tilt_delta(swrRace* player, float b) {
    if (player != nullptr && imgui_state.cheats_enabled && imgui_state.cheat_tilt_any_speed &&
        (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) {
        const float saved = player->speedValue;
        player->speedValue = TILT_GATE_BYPASS_SPEED;
        hook_call_original((swrRace_Tilt_t) swrRace_Tilt_ADDR, player, b);
        player->speedValue = saved;
        return;
    }
    hook_call_original((swrRace_Tilt_t) swrRace_Tilt_ADDR, player, b);
}

// Time-correct traction. swrRace_ApplyTraction (0x00478a70) blends the pod's travel direction
// toward its heading once per physics step:
//     traction = (1 - grip^2) * 0.996666            grip = antiSkid * surfaceGripFactor * slide2
//     v' = desired * (1 - traction) + v * traction  (then normalised and scaled by |b|)
// with no dt, so the slide decays per STEP: at a higher sim rate it dies out faster in real time
// (less sliding, weaker anti-grav drift). We let the original run untouched (it also eases slide2
// afterwards), then re-do only its blend with the per-step retention raised to the power
// dt * reference_hz, so the slide decays at the same rate per SECOND as at the reference rate:
//     v_fixed = desired + (v' - desired) * (traction^k / traction),   k = dt * reference_hz
// At exactly the reference rate k = 1 and nothing changes.
bool swrRace_tractionDtCorrect = true;
float swrRace_tractionReferenceHz = 60.0f;

typedef void(__cdecl* swrRace_ApplyTraction_t)(swrRace* player, float b, rdVector3* c, rdVector3* d);

void __cdecl swrRace_ApplyTraction_delta(swrRace* player, float b, rdVector3* c, rdVector3* d) {
    if (!swrRace_tractionDtCorrect || player == nullptr || c == nullptr || d == nullptr) {
        hook_call_original((swrRace_ApplyTraction_t) swrRace_ApplyTraction_ADDR, player, b, c, d);
        return;
    }
    // The traction the original is about to use (its inputs are read before it eases slide2).
    const float grip = player->podStats.antiSkid * player->surfaceGripFactor * player->slide2;
    float traction = (1.0f - grip * grip) * 0.99666601f;
    if (1.0f < player->paceMultiplier)
        traction = player->paceMultiplier <= 2.0f ? (2.0f - player->paceMultiplier) * traction : 0.0f;
    const rdVector3 desired = {c->x * b, c->y * b, c->z * b};

    hook_call_original((swrRace_ApplyTraction_t) swrRace_ApplyTraction_ADDR, player, b, c, d);

    const float dt = (float) swrRace_deltaTimeSecs;
    if (!(traction > 1e-4f && traction < 1.0f) || !(dt > 0.0f))
        return;
    const float k = dt * (swrRace_tractionReferenceHz > 1.0f ? swrRace_tractionReferenceHz : 1.0f);
    if (std::fabs(k - 1.0f) < 1e-4f)
        return;// running at the reference rate: identical to vanilla
    const float ratio = std::pow(traction, k) / traction;
    rdVector3& v = player->velocityDir;
    v.x = desired.x + (v.x - desired.x) * ratio;
    v.y = desired.y + (v.y - desired.y) * ratio;
    v.z = desired.z + (v.z - desired.z) * ratio;
    // Re-derive the output the original wrote: normalised velocityDir scaled by |b|.
    const float l = std::sqrt(v.x * v.x + v.y * v.y + v.z * v.z);
    const float mag = b < 0.0f ? -b : b;
    if (l > 1e-9f) {
        d->x = v.x / l * mag;
        d->y = v.y / l * mag;
        d->z = v.z / l * mag;
    }
}

bool swrRace_GetCableOwner(const swrModel_Node* node, const swrRace** racer, int* engine_part, int* index) {
    const auto it = cable_owner_by_node.find(node);
    if (it == cable_owner_by_node.end())
        return false;
    *racer = it->second.racer;
    *engine_part = it->second.engine_part;
    if (index != nullptr)
        *index = it->second.index;
    return true;
}

float swrRace_GetCableBendAmplitude(const swrModel_Node* node) {
    if (!node)
        return -1.0f;
    const auto it = cable_bend_by_node.find(node);
    return it == cable_bend_by_node.end() ? -1.0f : it->second;
}

bool swrRace_GetDisplayCable(const swrModel_Node* node, int* pilot, int* index, rdMatrix44* cable,
                             rdMatrix44* cockpit, rdMatrix44* engine) {
    const auto it = display_cable_by_node.find(node);
    if (node == nullptr || it == display_cable_by_node.end() || it->second.pilot < 0)
        return false;
    const auto get = (NodeGetTransform_t) swrModel_NodeGetTransform_ADDR;
    *pilot = it->second.pilot;
    *index = it->second.index;
    get(const_cast<swrModel_Node*>(node), cable);
    get(const_cast<swrModel_Node*>(it->second.cockpit), cockpit);
    get(const_cast<swrModel_Node*>(it->second.engine), engine);
    return true;
}

void swrRace_ClearCableBends() {
    pod_wreck_clear();
    cable_bend_by_node.clear();
    cable_owner_by_node.clear();
    display_cable_by_node.clear();
}

void swrRace_DropCableBendsFrom(const char* begin) {
    pod_wreck_clear();// its nodes may be in the memory going away
    std::erase_if(cable_bend_by_node, [&](const auto& elem) {
        return (const char*) elem.first >= begin;
    });
    std::erase_if(cable_owner_by_node, [&](const auto& elem) {
        return (const char*) elem.first >= begin;
    });
    std::erase_if(display_cable_by_node, [&](const auto& elem) {
        return (const char*) elem.first >= begin || (const char*) elem.second.cockpit >= begin ||
               (const char*) elem.second.engine >= begin;
    });
}

// The save image has a fixed 50 record slots per record kind, indexed `bMirror + track_index * 2`
// -- the 25 vanilla tracks times their mirror variant. A custom track (id >= DEFAULT_NB_TRACKS)
// has no slot, so committing a record for one writes past the array: into the record-holder
// names, and past the end of swrRace_saveData high in the inflated id range.
static bool track_has_record_slot(int trackIndex) {
    const int numSlots = (int) (sizeof(swrRace_saveData.record3LapTimes) / sizeof(float));
    return trackIndex >= 0 && trackIndex * 2 + 1 < numSlots;
}

// swrRace_ResultsMenu (the post-race standings, STATE_POST_RACE_INFO). When the "Pod Unlock Scene"
// skip is on, keep the results flow from ever transitioning to that scene (RESULTS_INTRO, state 17):
// the scene sets up its pod + backdrop the instant it's entered, so skipping it at the scene handler
// always flashes a frame. Instead pre-set the milestone bit the original uses to gate the scene, so
// it never calls swrObjHang_SetMenuState for it -- then replicate just the pilot-unlock bookkeeping
// that suppressed branch would have done, so beating a track's favorite pilot still unlocks its pod.
// Everything else (standings, truguts, track unlock, name entry) runs unchanged in the original.
void __cdecl swrRace_ResultsMenu_delta(swrObjHang* hang) {
    swrControl_NormalizeResultsAdvance();
    const bool skip = cutscene_skip_effective(imgui_state.skip_results);
    if (skip)
        swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_PILOT_UNLOCK_SHOWN;
    if (!track_has_record_slot(hang->track_index))
        swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_NAME_ENTRY_P1 |
            swrRace_RESULTSFLAG_NAME_ENTRY_P2 | swrRace_RESULTSFLAG_RECORDS_COMMITTED;
    hook_call_original(swrRace_ResultsMenu, hang);

    // Circuit Winner Scene (state 16) clean-skip. Advancing from the tournament results with a top-3
    // finish on the circuit's last track makes the original queue state 16 (the winners' podium),
    // which sets up its models the instant it's entered -- so skipping it inside the scene handler
    // always flashes a frame. When the toggle is on, redirect the pending transition straight to the
    // scene's own destination (Select Planet) so it never loads. (The manual button skip still ends
    // the scene from within swrObjHang_UpdatePlanetSelectIntro_delta when the toggle is off.)
    if (cutscene_skip_effective(imgui_state.skip_circuit_winner) &&
        swrObjHang_state2 == swrObjHang_STATE_PLANET_SELECT_INTRO)
        swrObjHang_state2 = swrObjHang_STATE_SELECT_PLANET;

    if (skip && hang->num_local_players == 1 && hang->isTournamentMode != 0 &&
        hang->num_players > 3 && swrRace_resultsPlaceP1 == 1) {
        char fav = g_aTrackInfos[hang->track_index].FavoritePilot;
        if (fav == 2 && hang->track_index != 1)
            fav = 0;
        if (fav > 0) {
            uint32_t bit = 1u << (fav & 0x1f);
            if ((swrRace_favPilotUnlockMask & bit) == 0) {
                swrRace_favPilotUnlockMask |= bit;
                swrRace_unlockedPilotsMask |= swrRace_favPilotUnlockMask;
                ((void (*)(void)) swrRace_SaveCurrentProfile_ADDR)();
            }
        }
    }
}

// swrRace_CopyProfileFromSave (0x44e500), reached from boot (swrRace_InitGameData) and profile
// load (swrRace_LoadProfile). Free-play track lists read g_aBeatTracksGlobal, which stock only
// folds the active profile's unlocks into on the results screen (swrRace_ResultsMenu). A profile
// whose unlocks are ahead of the machine's tgfd.dat (loaded from its .sav, or after tgfd.dat was
// recreated) therefore showed too few free-play tracks until a race finished. Fold on load too,
// with the results screen's own rule.
void swrRace_CopyProfileFromSave_delta(int workingSlot, int savedSlot) {
    hook_call_original(swrRace_CopyProfileFromSave, workingSlot, savedSlot);
    if (workingSlot != 0)
        return;
    const swrSaveProfile& profile = swrRace_aProfiles[0];
    const uint8_t progress[4] = {profile.tracksUnlocked[0], profile.tracksUnlocked[1],
                                 profile.tracksUnlocked[2], profile.circuitsCompleted};
    for (int i = 0; i < 4; i++) {
        if (g_aBeatTracksGlobal[i] < progress[i])
            g_aBeatTracksGlobal[i] = progress[i];
    }
}
