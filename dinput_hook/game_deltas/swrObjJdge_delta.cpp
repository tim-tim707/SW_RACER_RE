#include <macros.h>
#include "swrObjJdge_delta.h"
#include "swrRace_delta.h"

extern "C" {
#include <Swr/swrObj.h>
#include <globals.h>

extern FILE* hook_log;
}

#include "../hook_helper.h"

// SPIKE: off by default; flipped from the ImGui overlay. See header for the full rationale.
bool swrObjJdge_forceSplitscreen = false;

// Fixes a native 2-player bug surfaced by the splitscreen spike. KeyDownForPlayer1Or2 (0x0045e120)
// reports whether a key (mask) is down for local player 0 or 1, but when numLocalPlayers >= 2 and
// neither player is pressing it, the function falls through and returns the (nonzero) mask instead
// of 0 (verified in disasm at 0x0045e19c). Every caller -- pause, HUD-cycle, in-race menu -- then
// fires every frame in splitscreen; this is the "stuck paused, unpause re-pauses" symptom. Keep the
// original behavior and only correct the buggy no-press case. Inert in single-player (numLocalPlayers
// is always 1 there), so this is a no-op unless forced splitscreen is active.
int KeyDownForPlayer1Or2_delta(int mask) {
    const int original = hook_call_original(KeyDownForPlayer1Or2, mask);
    if (numLocalPlayers >= 2 && (inRaceLocalPlayerInputBitset1[0] & mask) == 0 &&
        (inRaceLocalPlayerInputBitset1[1] & mask) == 0)
        return 0;
    return original;
}

int fixup_invalid_node_ptrs(swrModel_Node *&node) {
    if (!node)
        return 0;

    switch (node->type) {
        case NODE_MESH_GROUP:
            break;
        case NODE_BASIC:
            break;
        case NODE_SELECTOR:
            break;
        case NODE_LOD_SELECTOR:
            break;
        case NODE_TRANSFORMED:
            break;
        case NODE_TRANSFORMED_WITH_PIVOT:
            break;
        case NODE_TRANSFORMED_COMPUTED:
            break;
        default:
            // this model type is invalid, set it to null.
            node = nullptr;
            return 1;
    }

    int num_removed_nodes = 0;
    if (node->type & NODE_HAS_CHILDREN) {
        for (int i = 0; i < node->num_children; i++)
            num_removed_nodes += fixup_invalid_node_ptrs(node->children.nodes[i]);
    }
    return num_removed_nodes;
}

// TODO hack: this is a workaround for a crash when loading custom tracks. sometimes the scene graph
//  contains nodes with invalid child pointers, this happens after playing a vanilla track and
//  afterwards a custom track. can be reproduced playing "Spice Mine Run" and then "Bowsers Castle 1".
unsigned int swrObjJdge_InitTrack_delta(swrObjJdge *judge, swrScore *scores) {
    // Drop cable nodes from the previous track so freed pointers aren't matched against new meshes.
    swrRace_ClearCableBends();

    // SPIKE (LOCAL_MULTIPLAYER_ROADMAP P1): stamp the 2nd roster slot as 'Locl' before the original
    // counts identifiers. The original derives numLocalPlayers purely from the count of 'Locl'
    // entries; a count > 1 sets the splitscreen master flag (DAT_0050ccf0) and assigns
    // secondLocalPlayer, which cascades into the split viewport/camera/HUD path. Confirms the
    // dormant splitscreen renderer is intact without touching the input chokepoint yet.
    if (swrObjJdge_forceSplitscreen && judge->num_players >= 2) {
        scores[1].identifier = 0x4c6f636c;// 'Locl'
        fprintf(hook_log, "[splitscreen probe] forced scores[1] -> 'Locl' (num_players=%d)\n",
                judge->num_players);
        fflush(hook_log);
    }

    const unsigned int x = hook_call_original(swrObjJdge_InitTrack, judge, scores);
    const int num_removed_nodes = fixup_invalid_node_ptrs(swrViewport_array[0].model_root_node);
    if (num_removed_nodes != 0)
    {
        fprintf(hook_log, "[swrObjJdge_InitTrack_delta] HACK: removed %d nodes with an invalid node type.\n", num_removed_nodes);
        fflush(hook_log);
    }
    return x;
}
