#include <macros.h>
#include "swrObjJdge_delta.h"
#include "swrRace_delta.h"
#include "swrControl_delta.h"

extern "C" {
#include <Swr/swrObj.h>
#include <Swr/swrPlayerHUD.h>
#include <Swr/swrRace.h>
#include <Swr/swrSprite.h>
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

// Splitscreen speed-dial (speedometer) fix. Another native 2-player bug the spike surfaced: in 2P
// each local player owns its own speed-fill gradient sprite (P1 = 0xf speed / 0x10 overheat,
// P2 = 0x13 / 0x14 -- the +4 offset in the shared dial drawer FUN_0045fe70), but the whole fill
// pipeline is a single-player design keyed on two globals (swrSpriteTexture_dial_gradient_rgb /
// _rgb2) that swrPlayerHUD_LoadRaceHUD only ever points at P1's two fill sprites:
//   * swrSprite_Draw (0x0044f160) decides per sprite whether to draw a trimmed fill polygon
//     (rdProcEntry_Add2DPolygon) or a plain full quad (rdProcEntry_Add2DQuad3) by matching the
//     sprite's texture against those two globals. P2's fill sprites match neither, so they take the
//     full-quad branch and P2's bar draws permanently full.
//   * The fill ratios are two scalar globals, speedDialPosition1 / 2, written unconditionally by
//     FUN_0045fe70 for whichever player swrRace_InRaceTimer processed last. Only the P1-textured
//     sprite reaches Add2DPolygon (which re-reads those same globals), so P1's bar shows the last
//     writer's (P2's) speed.
// Fix without disturbing the single-player path (gated on numLocalPlayers >= 2 so SP is unchanged):
//   1. swrRace_InRaceTimer_delta snapshots, per player, the fill ratios the original just wrote and
//      the fill sprites' texture pointers, before the next player's pass clobbers the globals.
//   2. swrSprite_Draw_delta wraps the per-sprite draw: when the sprite being drawn is one of the
//      snapshotted per-player fill sprites, it points the matching gradient global at that sprite's
//      texture and loads that player's ratio, runs the original, then restores. This makes both
//      gates inside the original agree -- the dispatch now routes P2's fill sprite to the trimming
//      Add2DPolygon path (not a full quad), and Add2DPolygon then reads the correct per-player ratio.
//      Any non-fill sprite matches none of the four textures and passes straight through.
static float s_speedDialFill[2] = {0.0f, 0.0f};      // speed gradient fill ratio, per local player
static float s_overheatDialFill[2] = {0.0f, 0.0f};   // overheat gradient fill ratio, per local player
static swrSpriteTexture *s_speedDialTex[2] = {nullptr, nullptr};   // fill sprites 0xf / 0x13
static swrSpriteTexture *s_overheatDialTex[2] = {nullptr, nullptr};// fill sprites 0x10 / 0x14

void swrRace_InRaceTimer_delta(void *score, void *jdge) {
    hook_call_original(swrRace_InRaceTimer, score, jdge);
    if (numLocalPlayers < 2)
        return;
    const int idx = (score == (void *) secondLocalPlayer) ? 1 : 0;
    // The original just ran FUN_0045fe70 for this player and left its fill ratios in the shared
    // scalar globals. speedDialPosition2 is only refreshed while overheating, but the overheat fill
    // sprite is hidden otherwise, so a stale value is never drawn.
    s_speedDialFill[idx] = speedDialPosition1;
    s_overheatDialFill[idx] = speedDialPosition2;
    // Fill sprites are (re)assigned at HUD load; refresh the texture table each pass so it tracks
    // track reloads.
    s_speedDialTex[0] = swrSprite_array[0xf].texture;
    s_overheatDialTex[0] = swrSprite_array[0x10].texture;
    s_speedDialTex[1] = swrSprite_array[0x13].texture;
    s_overheatDialTex[1] = swrSprite_array[0x14].texture;
}

void swrSprite_Draw_delta(int *arg0, swrSpriteTexture *tex, RdMaterial **mat, float a4, float a5,
                          float a6, float a7, int a8, int a9, int a10, int a11, int a12, int a13,
                          int a14, short a15, float a16, float a17, int a18) {
    if (numLocalPlayers >= 2 && tex != nullptr) {
        for (int idx = 0; idx < 2; idx++) {
            if (tex == s_speedDialTex[idx]) {
                swrSpriteTexture *savedTex = swrSpriteTexture_dial_gradient_rgb;
                const float savedFill = speedDialPosition1;
                swrSpriteTexture_dial_gradient_rgb = tex;
                speedDialPosition1 = s_speedDialFill[idx];
                hook_call_original(swrSprite_Draw, arg0, tex, mat, a4, a5, a6, a7, a8, a9, a10, a11,
                                   a12, a13, a14, a15, a16, a17, a18);
                swrSpriteTexture_dial_gradient_rgb = savedTex;
                speedDialPosition1 = savedFill;
                return;
            }
            if (tex == s_overheatDialTex[idx]) {
                swrSpriteTexture *savedTex = swrSpriteTexture_dial_gradient_rgb2;
                const float savedFill = speedDialPosition2;
                swrSpriteTexture_dial_gradient_rgb2 = tex;
                speedDialPosition2 = s_overheatDialFill[idx];
                hook_call_original(swrSprite_Draw, arg0, tex, mat, a4, a5, a6, a7, a8, a9, a10, a11,
                                   a12, a13, a14, a15, a16, a17, a18);
                swrSpriteTexture_dial_gradient_rgb2 = savedTex;
                speedDialPosition2 = savedFill;
                return;
            }
        }
    }
    hook_call_original(swrSprite_Draw, arg0, tex, mat, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13,
                       a14, a15, a16, a17, a18);
}

// Splitscreen opponent-marker fix: the floating racer-position number over opponents shows on P1's
// half but not P2's. swrPlayerHUD_RenderDistanceText runs once per viewport with a secondaryPass flag
// (false for the first/primary viewport = P1, true for the rest = P2) and gates each marker on an
// occlusion depth test: draw only if projectedDepth < player_sprite_depth_values[i]. But
// swrPlayerHUD_SampleOcclusion only samples occlusion for the PRIMARY viewport's projected marker
// positions (player_sprite_pixel_pos_x/y) -- never the secondary set (_x2/_y2). So on the secondary
// pass the depth array reflects P1's view (or the -1000 default for racers off P1's screen) and P2's
// markers systematically fail the test. The occlusion test is already effectively disabled on modern
// 32-bit displays anyway (the sampler only handles 8/16-bit -- see swrPlayerHUD.h), so for the
// secondary pass raise the depth values out of the way: the markers then draw unconditionally,
// matching P1. Gated on numLocalPlayers >= 2; primary pass and single-player are untouched.
typedef void(__cdecl *swrPlayerHUD_RenderDistanceText_t)(void *viewport, bool secondaryPass);

void __cdecl swrPlayerHUD_RenderDistanceText_delta(void *viewport, bool secondaryPass) {
    if (numLocalPlayers >= 2 && secondaryPass) {
        float saved[20];
        for (int i = 0; i < 20; i++) {
            saved[i] = player_sprite_depth_values[i];
            player_sprite_depth_values[i] = 1e9f;
        }
        hook_call_original((swrPlayerHUD_RenderDistanceText_t) swrPlayerHUD_RenderDistanceText_ADDR,
                           viewport, secondaryPass);
        for (int i = 0; i < 20; i++)
            player_sprite_depth_values[i] = saved[i];
        return;
    }
    hook_call_original((swrPlayerHUD_RenderDistanceText_t) swrPlayerHUD_RenderDistanceText_ADDR,
                       viewport, secondaryPass);
}

// Splitscreen P2 boost. The classic SWE1R pump boost -- nose down + throttle to CHARGE, then hit the
// boost button to FIRE the blue-flame speed surge -- runs through swrRace_BoostCharge (0x0046bd20),
// called every frame by the per-player swrRace_UpdatePlayerControl. Its charge state machine lives on
// the pod (player+0x210, already per-pod), but every input it reads is a main-device global written
// from P1's device by swrControl_ProcessInputs:
//   * CHARGE reads swrRace_ThrustInput / swrRace_ThrottleInput / swrRace_PitchInput.
//   * FIRE (state +0x210 == 2) reads swrRace_BoostInput (the dedicated boost button) -- the surge only
//     triggers while still pitched down AND the boost button is held.
// So P2 could neither charge nor fire from its own pad. For the 2nd local player, swap P2's own input
// into those four globals around the original call (the fire button comes from swrControl_player2BoostInput
// = XInput A), then restore so P1's boost/force-feedback path is untouched. Also zero the two
// main-device thrust/boost hold-time accumulators (DAT_00ec88a0[3]/[4]) for the duration: the separate
// flags1 "hold-throttle" afterburner keys off those, and leaving P1's values in would let P1's held
// throttle spuriously trigger P2's afterburner. These globals are read ONLY by the boost paths in the
// indexed (P2) control path -- P2's steering/pitch/thrust for normal driving come from the per-player
// arrays/bits -- so the swap is inert outside boost. Gated on numLocalPlayers >= 2.
typedef void(__cdecl *swrRace_UpdatePlayerControl_t)(swrRace *player);

// Per-player analog pitch array (0x00e98e80, stride 4), filled by updateInRaceInputBitsets from the raw
// input slots; index 1 is the 2nd local player (the same value that already tilts P2's nose).
static float *const kPlayerPitchArray = (float *) 0x00e98e80;
// Main-device per-action hold-time accumulators DAT_00ec88a0[3]/[4] (thrust / boost), read by the
// flags1 afterburner block; main-device only, so zero them while P2 is processed.
static float *const kHoldTimeThrust = (float *) 0x00ec88ac;
static float *const kHoldTimeBoost = (float *) 0x00ec88b0;

void __cdecl swrRace_UpdatePlayerControl_delta(swrRace *player) {
    if (numLocalPlayers < 2 || secondLocalPlayer == nullptr ||
        player->score_ptr != secondLocalPlayer) {
        hook_call_original((swrRace_UpdatePlayerControl_t) swrRace_UpdatePlayerControl_ADDR, player);
        return;
    }
    const bool accel = (inRaceLocalPlayerInputBitset3[1] & 0x100) != 0;// P2 accelerate bit

    const float savedThrust = swrRace_ThrustInput;
    const float savedThrottle = swrRace_ThrottleInput;
    const float savedPitch = swrRace_PitchInput;
    const float savedBoost = swrRace_BoostInput;
    const float savedHoldThrust = *kHoldTimeThrust;
    const float savedHoldBoost = *kHoldTimeBoost;

    // P2 has no analog throttle (button accelerate), so feed full thrust/throttle while held.
    swrRace_ThrustInput = accel ? 1.0f : 0.0f;
    swrRace_ThrottleInput = accel ? 1.0f : 0.0f;
    swrRace_PitchInput = kPlayerPitchArray[1];          // P2 analog pitch (charge)
    swrRace_BoostInput = swrControl_player2BoostInput;  // P2 boost button (fire)
    *kHoldTimeThrust = 0.0f;
    *kHoldTimeBoost = 0.0f;

    hook_call_original((swrRace_UpdatePlayerControl_t) swrRace_UpdatePlayerControl_ADDR, player);

    swrRace_ThrustInput = savedThrust;
    swrRace_ThrottleInput = savedThrottle;
    swrRace_PitchInput = savedPitch;
    swrRace_BoostInput = savedBoost;
    *kHoldTimeThrust = savedHoldThrust;
    *kHoldTimeBoost = savedHoldBoost;
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

    // Splitscreen P2 controller assignment. InitTrack assigns secondLocalPlayer, but the dropped
    // 2-player front-end never gives it a controller: swrObjHang_BuildRosterMultiplayer only sets the
    // single local player's control config (score+0xc, a stride-0x50 config-array entry whose +0x23
    // byte is the control type) and control index (score+0x10 low byte). Without them P2's pod reads
    // control index 0 / a null config and never uses the indexed input path. Hand P2 the next config
    // slot and control index 1 so swrRace_UpdatePlayerControl routes it through the indexed path and
    // reads raw input slot 1 (fed by swrControl_FeedPlayer2Input). Diagnostic log confirms the type.
    if (swrObjJdge_forceSplitscreen && numLocalPlayers >= 2 && firstLocalPlayer && secondLocalPlayer) {
        const uintptr_t p1cfg = *(uintptr_t *) ((char *) firstLocalPlayer + 0xc);
        if (p1cfg) {
            const uintptr_t p2cfg = p1cfg + 0x50;// next control-config slot (stride 0x50)
            *(uintptr_t *) ((char *) secondLocalPlayer + 0xc) = p2cfg;
            // Force the control type (config+0x23) to an indexed scheme (2, avoids a case-1 quirk) so
            // swrRace_UpdatePlayerControl routes P2 through the per-player FLOAT_ARRAY/bitset path
            // (control index 1 -> raw input slot 1) instead of the type-0 "main device" path that
            // reads the shared global -- which made P1's stick drive both pods.
            *(unsigned char *) (p2cfg + 0x23) = 2;
        }
        *((char *) secondLocalPlayer + 0x10) = 1;// control index -> input slot 1
        const uintptr_t p2cfg = *(uintptr_t *) ((char *) secondLocalPlayer + 0xc);
        fprintf(hook_log, "[splitscreen] P2 controller: cfg=0x%x type=%d idx=1\n", (unsigned) p2cfg,
                p2cfg ? *(signed char *) (p2cfg + 0x23) : -1);
        fflush(hook_log);
    }

    const int num_removed_nodes = fixup_invalid_node_ptrs(swrViewport_array[0].model_root_node);
    if (num_removed_nodes != 0)
    {
        fprintf(hook_log, "[swrObjJdge_InitTrack_delta] HACK: removed %d nodes with an invalid node type.\n", num_removed_nodes);
        fflush(hook_log);
    }
    return x;
}
