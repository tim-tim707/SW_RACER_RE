#include <macros.h>
#include "swrRace_delta.h"

#include <unordered_map>
#include <utility>

extern "C" {
#include <Swr/swrObj.h>
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"

// The pod's cockpit->engine cables (unk344_nodeArray[10] and [11]) are bent each frame by
// FUN_00481c30 @ 0x481c30, which writes the rd3d-converted mesh -- a mesh the GL renderer never
// builds, so it draws the flat cable. Recording the bend amplitude per node lets the renderer bend
// the ring vertices instead (see parse_display_list_commands / debug_render_node).
//
// NOT frame-gated, so the set stays put while paused (entity updates stop but the scene keeps
// rendering). Cleared on track load (swrRace_ClearCableBends) to drop freed nodes.
static std::unordered_map<const swrModel_Node*, float> cable_bend_by_node;

// Amplitude A = (1 - (dist/50)^2) * bend, replicating FUN_00481c30:
//   dist = unk1998 (camera distance); the cable is only curved when 1-(dist/50)^2 >= 0.1,
//          i.e. roughly dist < 47 (farther than that the game restores the straight cable).
//   bend = (turnRate*k > 1) ? min(turnRate*k*0.3, 1.0) : 0.3
//   k    = -0.03 for cable 10, +0.03 for cable 11 (0x4adb38 / 0x4adb3c), so the two cables
//          flare in opposite directions as the pod steers.
static float compute_cable_amplitude(const swrRace* player, float k) {
    const float dist = (float) player->unk1998;
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

    // The deformer only runs on cables 10/11, but 4-engine pods (Ben Quadinaros) also have 12/13.
    // All four are registered so they render as the same rebuilt tube; the extra pair is null on
    // 2-engine pods. k sign mirrors the front pair (right -0.03 / left +0.03).
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

// FUN_004337e0 is the display-pod animator (hangar inspect, selection menu, taunt/results
// cutscenes). It curves cables [10..13] through the same deformer at a FIXED amplitude: 1.3 when
// animated (param_8 != 0) else 0.5 -- distance is passed as 0, so the falloff is 1.
typedef void(__cdecl* swrRace_AnimateDisplayPod_t)(swrModel_Node** nodes, void* transform, int a3,
                                                   float a4, float a5, float a6, float a7,
                                                   int animated, float a9, float a10);
static const uint32_t swrRace_AnimateDisplayPod_ADDR = 0x004337e0;

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

float swrRace_GetCableBendAmplitude(const swrModel_Node* node) {
    if (!node)
        return -1.0f;
    const auto it = cable_bend_by_node.find(node);
    return it == cable_bend_by_node.end() ? -1.0f : it->second;
}

void swrRace_ClearCableBends() {
    cable_bend_by_node.clear();
}
