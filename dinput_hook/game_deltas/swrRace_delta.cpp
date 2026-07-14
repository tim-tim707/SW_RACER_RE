#include <macros.h>
#include "swrRace_delta.h"

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
#include "../imgui_utils.h"  // imgui_state.mp_disable_collision (the debug-menu toggle)
#include "swrModel_delta.h"  // swrModel_LoadFromId_delta (loads dust models through the GL path)

// The pod's cockpit->engine cables (unk344_nodeArray[10] and [11]) are bent into a curve each
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

void swrRace_PoddAnimateVariousThings_delta(swrRace* player) {
    hook_call_original(swrRace_PoddAnimateVariousThings, player);

    swrModel_Node** nodes = player->unk344_nodeArray;
    if (!nodes)
        return;

    // The game only runs its cable deformer on cables 10/11, but 4-engine pods (e.g. Ben
    // Quadinaros) also have cables 12/13 to the extra engines. Register all four so they render
    // as the same rebuilt tube and stay visually consistent; the extra pair is null on 2-engine
    // pods so they're skipped. k sign mirrors the front pair (right -0.03 / left +0.03).
    const float k[4] = {-0.03f, 0.03f, -0.03f, 0.03f};
    for (int i = 0; i < 4; i++) {
        swrModel_Node* node = nodes[10 + i];
        if (!node)
            continue;
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

void __cdecl swrRace_AnimateDisplayPod_delta(swrModel_Node** nodes, void* transform, int a3,
                                             float a4, float a5, float a6, float a7, int animated,
                                             float a9, float a10) {
    hook_call_original((swrRace_AnimateDisplayPod_t) swrRace_AnimateDisplayPod_ADDR, nodes,
                       transform, a3, a4, a5, a6, a7, animated, a9, a10);
    if (!nodes)
        return;
    const float amplitude = (animated != 0) ? 1.3f : 0.5f;
    for (int i = 10; i <= 13; i++)
        if (nodes[i])
            cable_bend_by_node[nodes[i]] = amplitude;
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
// swrRace_PoddAnimateVariousThings -> swrRace_SpawnGroundDustKick_Maybe spawns the ground dust/splash
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
    // swrRace_SpawnGroundDustKick_Maybe_delta below). Only the local player's splash should be heard;
    // AI/remote splashes play non-spatially and restart the player's looping voice.
    if (g_suppress_dust_splash_sound && sound_id == DUST_SPLASH_SOUND_ID)
        return;
    hook_call_original((playASound_t) playASound_ADDR, sound_id, priority, volume, pitch, flags);
}

typedef void(__cdecl* swrRace_SpawnGroundDustKick_Maybe_t)(swrRace*, float*, float, float, float,
                                                           float, int);

void __cdecl swrRace_SpawnGroundDustKick_Maybe_delta(swrRace* player, float* transform, float sx,
                                                     float sy, float sz, float param_6,
                                                     int param_7) {
    const bool is_local = player != nullptr && (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0;

    if (!is_local) {
        // Reserve headroom so a full grid of AI dust never starves the local player's trail.
        if (count_free_toss_slots() <= DUST_LOCAL_RESERVE_SLOTS)
            return;
        // Keep the AI dust visual, but silence its splash sound for the duration of this call.
        g_suppress_dust_splash_sound = true;
        hook_call_original(
            (swrRace_SpawnGroundDustKick_Maybe_t) swrRace_SpawnGroundDustKick_Maybe_ADDR, player,
            transform, sx, sy, sz, param_6, param_7);
        g_suppress_dust_splash_sound = false;
        return;
    }

    hook_call_original((swrRace_SpawnGroundDustKick_Maybe_t) swrRace_SpawnGroundDustKick_Maybe_ADDR,
                       player, transform, sx, sy, sz, param_6, param_7);
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
// swrRace_SpawnGroundDustKick_Maybe_delta): when free slots hit the reserve, ALL AI skip that frame
// and their trails gap while the (unchecked) player stays smooth. More headroom keeps AI continuous.
static const int DUST_POOL_SIZE = 128;
static swrModel_Node g_dustWrappers[DUST_POOL_SIZE * 4];
static swrModel_Node* g_dustChildNodes[DUST_POOL_SIZE];
static swrModel_Node* g_dustChildArray2[DUST_POOL_SIZE];
static swrModel_Node g_dustRootNode;

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
static const int FAR_AI_GROUND_CLAMP = 90;     // treat a widened pod as this camera distance
static const int FAR_AI_GROUND_RADIUS = 20000; // only widen non-local pods within this real distance

typedef void(__cdecl* swrObjTest_F0_t)(swrRace*);

void __cdecl swrObjTest_F0_delta(swrRace* player) {
    hook_call_original((swrObjTest_F0_t) swrObjTest_F0_ADDR, player);
    if (player != nullptr && (player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 &&
        player->lodDistance > FAR_AI_GROUND_CLAMP && player->lodDistance < FAR_AI_GROUND_RADIUS) {
        player->lodDistance = FAR_AI_GROUND_CLAMP;
    }
}

float swrRace_GetCableBendAmplitude(const swrModel_Node* node) {
    if (!node)
        return -1.0f;
    const auto it = cable_bend_by_node.find(node);
    return it == cable_bend_by_node.end() ? -1.0f : it->second;
}

void swrRace_ClearCableBends() {
    cable_bend_by_node.clear();
}
