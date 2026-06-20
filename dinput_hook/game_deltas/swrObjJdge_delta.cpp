#include <macros.h>
#include <cstring>
#include <cstdio>
#include "swrObjJdge_delta.h"
#include "swrRace_delta.h"
#include "swrControl_delta.h"

extern "C" {
#include <Swr/swrObj.h>
#include <Swr/swrPlayerHUD.h>
#include <Swr/swrRace.h>
#include <Swr/swrText.h>
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
// = XInput A), then restore so P1's boost/force-feedback path is untouched. The timed START boost (hold
// accelerate so the engine charge lands in a window -> flags1 afterburner) keys off the main-device
// hold-time accumulators DAT_00ec88a0[3]/[4]; those are P1's, so we substitute P2's own accumulated
// accel/boost hold-times (tracked below) for the duration -- feeding 0 would deny P2 the start boost,
// feeding P1's would let P1's held throttle trigger it. These globals are read ONLY by the boost paths
// in the indexed (P2) control path -- P2's steering/pitch/thrust for normal driving come from the
// per-player arrays/bits -- so the swap is inert outside boost. Gated on numLocalPlayers >= 2.
typedef void(__cdecl *swrRace_UpdatePlayerControl_t)(swrRace *player);

// Per-player analog pitch array (0x00e98e80, stride 4), filled by updateInRaceInputBitsets from the raw
// input slots; index 1 is the 2nd local player (the same value that already tilts P2's nose).
static float *const kPlayerPitchArray = (float *) 0x00e98e80;
// Main-device per-action hold-time accumulators DAT_00ec88a0[3]/[4] (thrust / boost), read by the
// flags1 afterburner / timed-start-boost block; main-device only, so we feed P2's own accumulated
// hold-times (below) here while P2 is processed.
static float *const kHoldTimeThrust = (float *) 0x00ec88ac;
static float *const kHoldTimeBoost = (float *) 0x00ec88b0;
// P2's own accel / boost-button hold times, accumulated per tick the way swrControl_ProcessInputs does
// for the main device (+= dt while held, reset on release). The timed start boost needs these.
static float s_p2_accelHoldTime = 0.0f;
static float s_p2_boostHoldTime = 0.0f;

void __cdecl swrRace_UpdatePlayerControl_delta(swrRace *player) {
    if (numLocalPlayers < 2 || secondLocalPlayer == nullptr ||
        player->score_ptr != secondLocalPlayer) {
        hook_call_original((swrRace_UpdatePlayerControl_t) swrRace_UpdatePlayerControl_ADDR, player);
        return;
    }
    const bool accel = (inRaceLocalPlayerInputBitset3[1] & 0x100) != 0;// P2 accelerate bit
    const bool boostBtn = swrControl_player2BoostInput != 0.0f;        // P2 boost button

    // Accumulate P2's hold times (mirrors swrControl_ProcessInputs for the main device): += dt while
    // held, reset on release. Drives the timed start boost / afterburner below.
    s_p2_accelHoldTime = accel ? s_p2_accelHoldTime + (float) swrRace_deltaTimeSecs : 0.0f;
    s_p2_boostHoldTime = boostBtn ? s_p2_boostHoldTime + (float) swrRace_deltaTimeSecs : 0.0f;

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
    *kHoldTimeThrust = s_p2_accelHoldTime;// P2 accel hold time (timed start boost / afterburner)
    *kHoldTimeBoost = s_p2_boostHoldTime; // P2 boost-button hold time

    hook_call_original((swrRace_UpdatePlayerControl_t) swrRace_UpdatePlayerControl_ADDR, player);

    swrRace_ThrustInput = savedThrust;
    swrRace_ThrottleInput = savedThrottle;
    swrRace_PitchInput = savedPitch;
    swrRace_BoostInput = savedBoost;
    *kHoldTimeThrust = savedHoldThrust;
    *kHoldTimeBoost = savedHoldBoost;
}

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

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
static void reset_lap_tracking(swrScore *scores); // 100-lap support, defined below

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

    reset_lap_tracking(scores);
    const int num_removed_nodes = fixup_invalid_node_ptrs(swrViewport_array[0].model_root_node);
    if (num_removed_nodes != 0)
    {
        fprintf(hook_log, "[swrObjJdge_InitTrack_delta] HACK: removed %d nodes with an invalid node type.\n", num_removed_nodes);
        fflush(hook_log);
    }
    return x;
}

// --- 100-lap support -------------------------------------------------------------------------
// swrObjJdge_F2 (0x0045ea30) accumulates each frame's elapsed time into a fixed 5-element array
// swrScore::results_P1_Lap1..Lap5 (offsets 0x60..0x70), indexed *directly* by the current lap
// counter swrScore::results_P1_Lap (offset 0x78, read as an int). The vanilla menu caps laps at
// 5, so the index never exceeds 4. With more than 5 laps the index walks off the end of the
// array and corrupts the score struct -- total_time (0x74) at lap index 5, the lap counter
// itself (0x78) at lap index 6, then obj_test_ptr (0x84) at lap index 9 -> crash -- within a
// handful of laps. This is the real "hardcoded 5-lap" limit (the menu wrap is only cosmetic).
//
// Fix: de-index every access to that array inside F2 so it always uses the first slot
// (Lap1, [esi+0x60]). The lap counter (0x78) and total race time (0x74) are left untouched, so
// lap counting, the finish check (lap+1 == num_laps at judge+0x1c8) and the "n / N" HUD all work
// natively for any lap count. Per-lap split data is no longer kept in the score; instead
// swrObjJdge_F2_delta (below) reconstructs each lap's time from the running total at every lap
// boundary, the in-race "LAP TIME" reads are pointed at the live current/last-lap slots (the two
// swrRace_InRaceTimer sites in the table), and the on-track results screen is replaced with a
// best/worst/average summary (swrRace_InRaceEndStatistics_delta). Total time + lap counting are
// unaffected.
//
// Most sites are a 4-byte SIB-indexed memory operand ([esi + reg*4 + 0x60], plus one
// +num_laps*4+0x5c at the finish check). The de-indexed form is 3 bytes, padded with a NOP, so
// instruction boundaries are preserved and no trampoline is needed. We verify the original bytes
// before patching so a mismatched / already-patched / future binary is skipped, never corrupted.
void swrObjJdge_PatchLapTimeOverflow() {
    struct LapTimeSite {
        uint32_t address;
        uint8_t original[4];
        uint8_t patched[4];
    };

    static const LapTimeSite sites[] = {
        {0x0045ebc6, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045ebe4, {0xd9, 0x44, 0x86, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045ebee, {0x8d, 0x4c, 0x86, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]
        {0x0045ec49, {0xd9, 0x44, 0x96, 0x5c}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60] (was +num_laps*4+0x5c)
        {0x0045ed5f, {0x89, 0x5c, 0x86, 0x60}, {0x89, 0x5e, 0x60, 0x90}}, // mov [esi+0x60],ebx
        {0x0045eda8, {0x8d, 0x44, 0x8e, 0x60}, {0x8d, 0x46, 0x60, 0x90}}, // lea eax,[esi+0x60]
        {0x0045edb3, {0xd9, 0x44, 0x96, 0x60}, {0xd9, 0x46, 0x60, 0x90}}, // fld dword [esi+0x60]
        {0x0045edbd, {0x8d, 0x4c, 0x96, 0x60}, {0x8d, 0x4e, 0x60, 0x90}}, // lea ecx,[esi+0x60]

        // swrRace_InRaceTimer (0x00460950) in-race "LAP TIME" reads, indexed by current lap:
        // point the current-lap read at Lap1 (slot 0, where F2 now writes the live accumulator) and
        // the just-completed-lap read at Lap2 (slot 1, which swrObjJdge_F2_delta fills with the last
        // lap's time) so the readout ticks and the lap-complete flash shows the real last-lap time
        // instead of 00.000 / out-of-bounds garbage.
        {0x00460aec, {0xd9, 0x44, 0x85, 0x60}, {0xd9, 0x45, 0x60, 0x90}}, // fld [ebp+0x60] (current lap)
        {0x00460af6, {0xd9, 0x44, 0x85, 0x5c}, {0xd9, 0x45, 0x64, 0x90}}, // fld [ebp+0x64] (last lap)
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const LapTimeSite &site: sites) {
        uint8_t *code = (uint8_t *) site.address;
        if (std::memcmp(code, site.original, 4) != 0) {
            if (std::memcmp(code, site.patched, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchLapTimeOverflow] unexpected bytes at %p; aborting patch. "
                    ">5 laps will corrupt memory / crash.\n",
                    (void *) code);
            fflush(hook_log);
            return;
        }

        DWORD old_protect = 0;
        VirtualProtect(code, 4, PAGE_EXECUTE_READWRITE, &old_protect);
        std::memcpy(code, site.patched, 4);
        VirtualProtect(code, 4, old_protect, &old_protect);
        patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchLapTimeOverflow] de-indexed %d/%d lap-time sites; >5 laps now safe.\n",
            patched, total);
    fflush(hook_log);
}

// --- 1hr+ race-time support ------------------------------------------------------------------
// swrObjJdge_F2 caps the running race time (and each lap slot) at 3000.0s == 50:00 every frame:
//   if (total >= 3000.0f) total = 3000.0f;   // at 0x0045ed94 (total) and 0x0045edc8 (lap slot)
// using a shared threshold constant 3000.0f at 0x004ad264 (referenced only by these two compares).
// So the in-game timer pins at 50:00.000 and a longer race shows ~50:00.0xx. Raise the threshold
// and both clamp values to 24h so the time keeps accumulating; the time formatter
// (swrText_CreateTimeEntryPrecise) already prints minutes unbounded (MM:SS.mmm, e.g. 72:34.567),
// so every total-time readout (in-race timer, results summary, hangar results) follows.
void swrObjJdge_PatchRaceTimeCap() {
    const float kCap = 86400.0f; // 24h; effectively no cap for any real race, keeps ms precision
    uint8_t cap_bytes[4];
    std::memcpy(cap_bytes, &kCap, 4);

    static const uint8_t old_3000[4] = {0x00, 0x80, 0x3b, 0x45}; // 3000.0f

    struct CapSite {
        uint32_t address;
        bool executable; // .text immediate vs .rdata constant
    };
    static const CapSite sites[] = {
        {0x004ad264, false}, // shared threshold constant (.rdata), used by both fcom compares
        {0x0045ed97, true},  // total_time clamp immediate: mov [esi+0x74], 3000.0f
        {0x0045edca, true},  // lap-slot clamp immediate:  mov [ecx], 3000.0f
    };

    int patched = 0;
    const int total = (int) (sizeof(sites) / sizeof(sites[0]));
    for (const CapSite &site: sites) {
        uint8_t *p = (uint8_t *) site.address;
        if (std::memcmp(p, old_3000, 4) != 0) {
            if (std::memcmp(p, cap_bytes, 4) == 0)
                continue; // already patched
            fprintf(hook_log,
                    "[swrObjJdge_PatchRaceTimeCap] unexpected bytes at %p; skipping (timer stays "
                    "capped at 50:00).\n",
                    (void *) p);
            fflush(hook_log);
            return;
        }

        DWORD old_protect = 0;
        VirtualProtect(p, 4, PAGE_EXECUTE_READWRITE, &old_protect);
        std::memcpy(p, cap_bytes, 4);
        VirtualProtect(p, 4, old_protect, &old_protect);
        patched++;
    }

    fprintf(hook_log,
            "[swrObjJdge_PatchRaceTimeCap] raised race-time cap %d/%d sites (50:00 -> 24h).\n",
            patched, total);
    fflush(hook_log);
}

// --- hours in time displays ------------------------------------------------------------------
// The stock time formatters (swrText_CreateTimeEntry @0x00450670 -> centiseconds, and
// swrText_CreateTimeEntryPrecise @0x00450760 -> milliseconds) split the time only into
// minutes:seconds.fraction, with the minutes field unbounded -- so a 1h12m race renders as
// "72:34.567". Reimplement both to break out an hours field once the time reaches an hour
// ("1:12:34.567"). Under one hour the output is byte-for-byte the vanilla layout, so lap times,
// records and short totals are unchanged. The time arrives as the 3rd argument, a float passed as
// its raw bits (callers pass *(int*)&seconds); screenText is the leading ~format-code prefix.
// Formats a time (seconds) into out as H:MM:SS.frac (>=1h), M:SS.frac (>=1m) or SS.frac, with
// frac_digits of a frac_scale-th fraction (100 = centiseconds, 1000 = milliseconds). The hours
// field only appears past an hour; under an hour the layout matches stock exactly.
static void format_time_str(float t, int frac_scale, int frac_digits, char *out, int out_size) {
    if (t < 0.0f)
        t = 0.0f;
    int total_sec = (int) t;
    int frac = (int) ((t - (float) total_sec) * (float) frac_scale);
    if (frac >= frac_scale) { // guard against float edge cases, matching the stock carry
        frac -= frac_scale;
        total_sec++;
    }
    const int h = total_sec / 3600;
    const int m = (total_sec / 60) % 60;
    const int s = total_sec % 60;
    if (h > 0)
        snprintf(out, out_size, "%d:%02d:%02d.%0*d", h, m, s, frac_digits, frac);
    else if (m > 0)
        snprintf(out, out_size, "%d:%02d.%0*d", m, s, frac_digits, frac);
    else
        snprintf(out, out_size, "%02d.%0*d", s, frac_digits, frac);
}

static void format_time_with_hours(int x, int y, int time_bits, int r, int g, int b, int a,
                                   char *screenText, int frac_scale, int frac_digits) {
    float t;
    std::memcpy(&t, &time_bits, sizeof(t));
    char tstr[32];
    format_time_str(t, frac_scale, frac_digits, tstr, sizeof(tstr));
    char body[96];
    snprintf(body, sizeof(body), "%s%s", screenText ? screenText : "", tstr);
    swrText_CreateTextEntry1(x, y, r, g, b, a, body);
}

void swrText_CreateTimeEntry_delta(int x, int y, int unused, int r, int g, int b, int a,
                                   char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 100, 2); // centiseconds
}

void swrText_CreateTimeEntryPrecise_delta(int x, int y, int unused, int r, int g, int b, int a,
                                          char *screenText) {
    format_time_with_hours(x, y, unused, r, g, b, a, screenText, 1000, 3); // milliseconds
}

// --- 100-lap lap-time tracking + summary -----------------------------------------------------
// Because the de-index collapses the score's 5-slot per-lap array, we reconstruct each lap's time
// from the racer's running total_time (swrScore+0x74) at every lap boundary. This needs no per-lap
// storage in the score -- only a running best / worst (+ their lap numbers) per racer, plus the
// last completed lap time (mirrored into the score's Lap2 slot so the patched in-race readout can
// show it). swrScore field offsets:
#define SCORE_STRIDE     0x88
#define SCORE_POSITION   0x5c // short
#define SCORE_LAP1       0x60 // float, slot 0 (F2's live current-lap accumulator after de-index)
#define SCORE_LAP2       0x64 // float, slot 1 (we mirror the last completed lap time here)
#define SCORE_TOTAL_TIME 0x74 // float
#define SCORE_CUR_LAP    0x78 // int, completed-lap count for this racer
#define JDGE_NUM_RACERS  0x1ac
#define JDGE_NUM_LAPS    0x1c8

#define LAP_RACER_MAX 24
// The vanilla on-track results screen has exactly 5 per-lap rows (the score's 5-slot per-lap
// array). g_lapTimes only feeds that screen, and only on the <=5-lap path, so it needs no more
// than these 5 slots -- a >5-lap race uses the best/worst/avg summary instead and never reads it.
#define VANILLA_RESULTS_LAPS 5

static const char *g_lapScores = nullptr; // == DAT_00e28960 (scores base), captured at InitTrack
static float g_bestLap[LAP_RACER_MAX];
static int g_bestLapNum[LAP_RACER_MAX];
static float g_worstLap[LAP_RACER_MAX];
static int g_worstLapNum[LAP_RACER_MAX];
static float g_lastLap[LAP_RACER_MAX];
static float g_prevTotal[LAP_RACER_MAX];
static int g_prevLap[LAP_RACER_MAX];
static bool g_lapFinished[LAP_RACER_MAX];
// Per-lap times for the first VANILLA_RESULTS_LAPS laps, kept so the <=5-lap vanilla results screen
// (which reads the 5-slot per-lap array the de-index collapsed) can be refilled with real times.
static float g_lapTimes[LAP_RACER_MAX][VANILLA_RESULTS_LAPS];

static void reset_lap_tracking(swrScore *scores) {
    g_lapScores = (const char *) scores;
    for (int i = 0; i < LAP_RACER_MAX; i++) {
        g_bestLap[i] = 1.0e9f;
        g_bestLapNum[i] = 0;
        g_worstLap[i] = 0.0f;
        g_worstLapNum[i] = 0;
        g_lastLap[i] = 0.0f;
        g_prevTotal[i] = 0.0f;
        g_prevLap[i] = 0;
        g_lapFinished[i] = false;
        for (int j = 0; j < VANILLA_RESULTS_LAPS; j++)
            g_lapTimes[i][j] = 0.0f;
    }
}

// Wraps swrObjJdge_F2: runs the (de-indexed, crash-safe) original, then reconstructs per-lap times
// from each racer's total_time so we can report best / worst / average for any lap count.
void swrObjJdge_F2_delta(swrObjJdge *jdge) {
    hook_call_original(swrObjJdge_F2, jdge);

    if (!g_lapScores)
        return;

    int numRacers = *(int *) ((char *) jdge + JDGE_NUM_RACERS);
    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    if (numRacers > LAP_RACER_MAX)
        numRacers = LAP_RACER_MAX;

    for (int r = 0; r < numRacers; r++) {
        char *sc = (char *) g_lapScores + r * SCORE_STRIDE;
        const int lap = *(int *) (sc + SCORE_CUR_LAP);
        const float total = *(float *) (sc + SCORE_TOTAL_TIME);

        if (lap > g_prevLap[r]) {
            const float lapTime = total - g_prevTotal[r];
            const int completedIdx = g_prevLap[r]; // 0-based index of the lap that just finished
            const int lapNum = completedIdx + 1;   // 1-based number for display
            if (lapTime > 0.0f) {
                if (completedIdx < VANILLA_RESULTS_LAPS)
                    g_lapTimes[r][completedIdx] = lapTime; // for the <=5 vanilla results refill
                g_lastLap[r] = lapTime;
                if (lapTime < g_bestLap[r]) {
                    g_bestLap[r] = lapTime;
                    g_bestLapNum[r] = lapNum;
                }
                if (lapTime > g_worstLap[r]) {
                    g_worstLap[r] = lapTime;
                    g_worstLapNum[r] = lapNum;
                }
            }
            g_prevTotal[r] = total;
            g_prevLap[r] = lap;
        }

        if (!g_lapFinished[r] && lap < numLaps) {
            // Mirror the last completed lap time into slot 1 so the patched in-race "LAP TIME"
            // flash (which now reads slot 1) shows it instead of garbage.
            *(float *) (sc + SCORE_LAP2) = g_lastLap[r];
        } else if (!g_lapFinished[r] && numLaps > 0 && lap >= numLaps) {
            // On finish, overwrite the de-indexed lap slots so the records save in
            // swrRace_ResultsMenu (min over Lap1..Lap_n) records the real best lap rather than the
            // de-indexed 0.0; the sentinel in Lap2 makes its min loop stop after Lap1.
            g_lapFinished[r] = true;
            if (g_bestLapNum[r] > 0) {
                *(float *) (sc + SCORE_LAP1) = g_bestLap[r];
                *(float *) (sc + SCORE_LAP2) = -1.0f;
            }
        }
    }
}

// On-track end-of-race results. For <=5 laps the score's 5 per-lap slots fit, so refill them from
// the reconstructed lap times (the de-index dropped per-lap storage) and defer to the original
// screen -- it looks exactly like vanilla. For >5 laps a per-lap list can't fit (the vanilla layout
// stacks one row per lap off the top of the screen), so show a compact best/worst/average/total
// summary in the same left-label / time-column style.
void swrRace_InRaceEndStatistics_delta(void *jdge, void *score) {
    if (!g_lapScores) {
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    const int numLaps = *(int *) ((char *) jdge + JDGE_NUM_LAPS);
    const int r = (int) (((char *) score - g_lapScores) / SCORE_STRIDE);

    if (numLaps <= 5) {
        if (r >= 0 && r < LAP_RACER_MAX) {
            for (int i = 0; i < numLaps && i < VANILLA_RESULTS_LAPS; i++)
                *(float *) ((char *) score + SCORE_LAP1 + i * 4) = g_lapTimes[r][i];
        }
        hook_call_original(swrRace_InRaceEndStatistics, jdge, score);
        return;
    }

    // >5 laps: hide the results-screen sprites the vanilla screen would lay out, then draw the
    // summary. These are UI sprites, not racers: the original swrRace_InRaceEndStatistics
    // (0x00462320) single-player branch hides sprite IDs 0..0x12 (loop `while (i < 0x13)`) -- the
    // per-lap row sprites it would otherwise show. We mirror that exact range so none show through
    // our summary. (The vanilla 2-player splitscreen branches instead clear 0xf..0x12 / 0x13..0x16;
    // the >5-lap summary path only runs single-player.) Times are formatted here (hour-aware) and
    // drawn left-aligned so they sit in a clean column instead of right-aligning over the labels.
    const short kResultsScreenSprites = 0x13; // == original single-player sprite-hide loop bound
    for (short i = 0; i < kResultsScreenSprites; i++)
        swrSprite_SetVisible(i, 0);

    const float total = *(float *) ((char *) score + SCORE_TOTAL_TIME);
    const int pos = *(short *) ((char *) score + SCORE_POSITION);
    char buf[96];
    char tstr[32];

    swrText_CreateTextEntry1(0xa0, 0x14, -1, -1, -1, -1, swrText_Translate((char *) "~cResults"));

    const int label_x = 0x2d; // 45
    const int time_x = 0x82;  // 130
    const int lapn_x = 0xd2;  // 210
    int y = 0x48;             // 72

    if (r >= 0 && r < LAP_RACER_MAX && g_bestLapNum[r] > 0) {
        const float avg = (numLaps > 0) ? total / (float) numLaps : 0.0f;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sBest");
        format_time_str(g_bestLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_bestLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sWorst");
        format_time_str(g_worstLap[r], 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        snprintf(buf, sizeof(buf), "~f1~sLap %d", g_worstLapNum[r]);
        swrText_CreateTextEntry1(lapn_x, y, -1, -1, -1, -1, buf);
        y += 0xe;

        swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sAverage");
        format_time_str(avg, 1000, 3, tstr, sizeof(tstr));
        snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
        swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
        y += 0xe;
    }

    swrText_CreateTextEntry1(label_x, y, -1, -1, 0, -1, (char *) "~f4~sTotal");
    format_time_str(total, 1000, 3, tstr, sizeof(tstr));
    snprintf(buf, sizeof(buf), "~f1~s%s", tstr);
    swrText_CreateTextEntry1(time_x, y, -1, -1, -1, -1, buf);
    y += 0x16;

    snprintf(buf, sizeof(buf), "~cFinished %d laps - position %d", numLaps, pos);
    swrText_CreateTextEntry1(0xa0, y, -1, -1, -1, -1, buf);
}
