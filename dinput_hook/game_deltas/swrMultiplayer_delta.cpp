#include "swrMultiplayer_delta.h"

#include <windows.h>
#include <cstring>
#include <filesystem>

extern "C" {
#include <macros.h>
#include <Dss/sithMulti.h>
#include <Dss/sithMessage.h>
#include <Win95/stdComm.h>
#include <Swr/swrUI.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrEvent.h>
#include <Swr/swrMultiplayer.h>
#include <Swr/swrAssetBuffer.h>
#include <globals.h>

extern FILE *hook_log;
}

#include "../hook_helper.h"
#include "../config.h"
#include "../imgui_utils.h" // imgui_state.mp_allow_upgrades (the debug-menu toggle)

// DirectPlay send flags (the project's custom DirectX types omit them).
#ifndef DPSEND_ASYNC
#define DPSEND_ASYNC 0x00000200
#endif
#ifndef DPSEND_NOCOMPLETE
#define DPSEND_NOCOMPLETE 0x00000400
#endif

// ===========================================================================================
// Multiplayer netcode stability.
//
// (1) Async send (mp_async_send): the synchronous IDirectPlay4::Send (stdComm_Send -> vtable+0x68)
//     blocks the GAME THREAD for tens of ms per call under packet loss (it waits on DirectPlay's
//     retransmit/ACK cycle). At the ~31 Hz state-broadcast rate that stall blows the frame budget,
//     so the whole lobby stutters whenever any peer's link is lossy. We reissue the send via SendEx
//     (vtable+0xC4) with DPSEND_ASYNC, so DirectPlay's own worker thread absorbs the wait and the
//     game thread returns immediately. The caller's reliability flag is preserved (guaranteed stays
//     guaranteed); DPSEND_NOCOMPLETE skips the send-completion message we would otherwise drain.
//
// (2) PumpPackets per-frame cap (mp_packet_cap): swrMultiplayer_PumpPackets drains the ENTIRE
//     DirectPlay receive queue each frame (loops sithMulti_HandleIncomingPacket until empty). A
//     bursty/laggy peer can make the receiver process the whole backlog in one frame and hitch
//     everyone; we bound packets processed per pump (overflow stays queued in DirectPlay -- deferred,
//     not dropped).
//
// Tunable via SW_RACER_RE.ini [settings]:
//   mp_async_send  (default 1, 0 = original blocking Send)
//   mp_packet_cap  (default 32, 0 = unlimited / original behaviour)
// ===========================================================================================

static int g_mp_async_send = 1;
static int g_mp_packet_cap = 32;

// Packets processed in the current pump (one PumpPackets drain; ends when the queue reports empty).
static int g_mp_pump_count = 0;

static void load_mp_settings_once() {
    static bool loaded = false;
    if (loaded)
        return;
    loaded = true;

    g_mp_async_send = config::get_int("settings", "mp_async_send", 1);
    g_mp_packet_cap = config::get_int("settings", "mp_packet_cap", 32);

    fprintf(hook_log, "[swrMultiplayer_delta] mp_async_send=%d mp_packet_cap=%d\n", g_mp_async_send,
            g_mp_packet_cap);
    fflush(hook_log);
}

int sithMulti_HandleIncomingPacket_delta(DPID dpid) {
    load_mp_settings_once();

    if (g_mp_packet_cap > 0 && g_mp_pump_count >= g_mp_packet_cap) {
        // Per-pump cap reached: defer the rest of the queue to the next pump. Returning != 1 ends
        // the pump loop (same as an empty queue); the counter resets so the next pump starts fresh.
        g_mp_pump_count = 0;
        return 0;
    }

    const int result = hook_call_original(sithMulti_HandleIncomingPacket, dpid);

    if (result == 1)
        g_mp_pump_count++;
    else
        g_mp_pump_count = 0;  // queue drained / session ended

    return result;
}

// --- 5+ laps in multiplayer ------------------------------------------------------------------
// The MP race-setup lobby (swrUI_Menu_MpRaceSetup) clamps the host's lap stepper to 1..5: it bumps
// the count by 1 and stops at 5. Everything downstream already supports more -- multiplayer_laps is
// an int sent full-width over the wire (swrMultiplayer_BroadcastRaceSettings / _ApplyLobbyState copy
// it verbatim, no re-clamp), and the race funnels it through the same swrObjHang_StartRace ->
// hang->numLaps (signed char) -> judge->num_laps -> swrObjJdge_F2 path as single-player, which
// swrObjJdge_PatchLapTimeOverflow already made crash-safe for any lap count. So the lobby stepper
// was the only thing still capping multiplayer at 5 laps.
//
// Give it the same feel as the free-play lap selector (tracks_delta.c): fine +/-1 up to 5, then
// jump by 5, wrapping 125 -> 1 forward and 1 -> 125 back. 125 is the shared single-player ceiling
// (hang->numLaps is a signed char, so larger would overflow). We intercept just the laps number
// field's increment / decrement messages and defer every other message to the original handler.
//
// The laps control is the swrUI_NewNumberField with element id 0x8b (swrMultiplayer_BuildRaceSetupUI).
// Its +/- buttons post msg 0x7d1 (increment) / 0x7d0 (decrement) to this parent page handler with
// the element id in param_3 and the widget in param_4.
//
// swrUI_Menu_MpRaceSetup is not reimplemented in src, so it is hooked by address (registered with
// swrUI_Menu_MpRaceSetup_ADDR in init_renderer_hooks) and the original is called back through the
// same _ADDR cast, the way swrRace_AnimateDisplayPod_delta does. The three game helpers it calls are
// likewise reached through their named _ADDR function pointers.
typedef int(swrUI_Menu_MpRaceSetup_t)(swrUI_unk *self, unsigned int msg, void *element,
                                      swrUI_unk *widget);
typedef int(swrUI_GetNumberValue_t)(swrUI_unk *ui);
typedef void(swrUI_SetNumberValue_t)(swrUI_unk *ui, int value);
typedef void(swrMultiplayer_BroadcastRaceSettings_t)(void);

static const unsigned int MP_MSG_NUMBERFIELD_INC = 0x7d1;
static const unsigned int MP_MSG_NUMBERFIELD_DEC = 0x7d0;
static const int MP_LAPS_FIELD_ID = 0x8b;
static const int MP_LAPS_MIN = 1;
static const int MP_LAPS_MAX = 125;

int swrUI_Menu_MpRaceSetup_delta(swrUI_unk *self, unsigned int msg, void *element,
                                 swrUI_unk *widget) {
    const bool is_inc = (msg == MP_MSG_NUMBERFIELD_INC);
    const bool is_dec = (msg == MP_MSG_NUMBERFIELD_DEC);
    if ((is_inc || is_dec) && element == (void *) MP_LAPS_FIELD_ID) {
        int laps = ((swrUI_GetNumberValue_t *) swrUI_GetNumberValue_ADDR)(widget);
        if (is_inc) {
            laps += (laps < 5) ? 1 : 5;
            if (laps > MP_LAPS_MAX)
                laps = MP_LAPS_MIN; // wrap forward
        } else {
            laps -= (laps <= 5) ? 1 : 5;
            if (laps < MP_LAPS_MIN)
                laps = MP_LAPS_MAX; // wrap backward
        }
        ((swrUI_SetNumberValue_t *) swrUI_SetNumberValue_ADDR)(widget, laps);
        multiplayer_laps = laps;
        // host -> all: track/laps/racers (msg 0x3a)
        ((swrMultiplayer_BroadcastRaceSettings_t *) swrMultiplayer_BroadcastRaceSettings_ADDR)();
        return 0;
    }

    return hook_call_original((swrUI_Menu_MpRaceSetup_t *) swrUI_Menu_MpRaceSetup_ADDR, self, msg,
                              element, widget);
}

// --- multiplayer pod upgrades --------------------------------------------------------------
// In single-player, swrObjHang_BuildRosterSinglePlayer layers the active profile's seven upgrades
// (traction/turning/acceleration/top-speed/air-brake/cooling/repair) onto each local racer's pod via
// swrRace_ApplyUpgradesToStats. The multiplayer builder, swrObjHang_BuildRosterMultiplayer, skips
// that step entirely -- it copies the pod's raw swrRacer_PodHandlingData base stats and never calls
// ApplyUpgradesToStats -- so every multiplayer race runs on stock pods.
//
// Multiplayer also has no pilot-profile step (you do not pick a saved profile before entering MP), so
// there is no profile to source upgrades from -- the single-player upgrade globals are empty/stale in
// MP. Instead the player sets their own upgrade levels in the menu (imgui_state.mp_upgrade_levels,
// 0..5 per category), and when the host allows upgrades we apply those to the LOCAL player's 'Locl'
// score entry after the vanilla roster is built. Remote pods are transform-replayed from the network,
// so their local stats never feed our simulation; only the pod we actually drive needs upgrading, and
// because each machine upgrades its own pod, every player races with their own chosen upgrades.
typedef void *(swrObjHang_BuildRosterMultiplayer_t)(swrObjHang *hang, int *out);

static const int SCORE_IDENTIFIER_LOCAL = 0x4c6f636c; // 'Locl' -- the local player's score entry
// Part condition fed to every upgrade category. The game stores condition as a byte where 0xFF is a
// brand-new / fully-repaired part and 0 is worn out (swrRace_UpdatePartsHealth measures wear as
// 0xFF - health and full repair writes 0xFF to every slot). swrRace_CalculateUpgradedStat scales the
// boost by this condition, so 0xFF yields the full upgrade benefit -- a maxed part at its stat cap.
static const char MP_UPGRADE_HEALTH = (char) 0xFF;

void *swrObjHang_BuildRosterMultiplayer_delta(swrObjHang *hang, int *out) {
    void *result = hook_call_original(
        (swrObjHang_BuildRosterMultiplayer_t *) swrObjHang_BuildRosterMultiplayer_ADDR, hang, out);

    if (!imgui_state.mp_allow_upgrades || multiplayer_enabled == 0)
        return result;
    // The original no-ops when out is null (a measuring/query call, no roster built), so there is
    // nothing to upgrade then.
    if (out == nullptr)
        return result;
    if (playerNumber < 0 || playerNumber >= 20)
        return result;

    swrScore *score = &swrScores[playerNumber];
    if (score->identifier != SCORE_IDENTIFIER_LOCAL)
        return result;

    // Build the per-category level + health byte arrays ApplyUpgradesToStats expects (category order
    // 0..6, the same order as imgui_state.mp_upgrade_levels). Levels are clamped 0..5; level 0 is a
    // no-op inside CalculateUpgradedStat (stock part).
    char levels[7];
    char healths[7];
    for (int i = 0; i < 7; i++) {
        int level = imgui_state.mp_upgrade_levels[i];
        levels[i] = (char) ((level < 0) ? 0 : (level > 5) ? 5 : level);
        healths[i] = MP_UPGRADE_HEALTH;
    }

    // score->podStats already holds the pod's raw base stats (the builder just copied them in), so
    // pass it as both the active and the base buffer: ApplyUpgradesToStats first copies base->active
    // (a harmless self-copy here) and then layers the chosen upgrade categories on top.
    swrRace_ApplyUpgradesToStats(&score->podStats, &score->podStats, levels, healths);
    return result;
}

// Crash fixes for a player dropping out of a session. The originals are unimplemented stubs in
// src, so they are hooked by address and called back through their _ADDR casts.
//
// (1) swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent trusts the wire player_index: it
//     rejects only negatives, then hands swrScores[player_index].obj_test_ptr to
//     swrRace_TriggerHandler / swrObjTrig_HandleCrashHitTrigger, which dereference it. Once a
//     player has left, the slot is out of bounds or dangling and EVERY remaining peer crashes.
//     Validated against the roster bounds and the live 'Test' list; dropping the event matches
//     vanilla's own no-op for a NULL slot pointer.
//
// (2) stdComm_UpdatePlayers and stdComm_GetSessionSettings call through stdComm_pDirectPlay with
//     no NULL check, and the MP race-setup page polls both on a 500 ms timer -- so a teardown
//     while the menu is up dereferences NULL. Fail the calls instead (GetSessionSettings' only
//     caller, swrMultiplayer_GetSessionName, already maps failure to a NULL name).
//
// (5) Trigger-index desync. The wire event carries an INDEX into
//     swrObjTrig_TriggerDescriptionArray, which is APPEND-ONLY for the process lifetime: nothing
//     resets swrObjTrig_NumTriggerDescriptions, so every track load (single-player included)
//     appends after the previous track. Sender and receiver each map over their OWN accumulated
//     array, so indices agree only between peers with identical load histories since boot. A peer
//     that rejoined, joined a host mid-session, or practiced offline resolves the index to a stale
//     description in freed arena memory and crashes on its garbage affected_node.
//       a. Reset the registry in swrObjTrig_LoadAndInitializeTriggerModels -- the one place all
//          registration flows through, called exactly once per track load -- so wire indices are
//          positions in the current track's deterministic registration order.
//       b. On the receiver, require the description and its affected_node to lie inside the
//          allocated slice of the model asset arena; descriptions are parsed in place from model
//          data, so anything outside is stale by construction.
typedef void(swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_t)(int trigger_index,
                                                                        int player_index);
typedef int(stdComm_UpdatePlayers_t)(unsigned int sessionNum);
typedef int(stdComm_GetSessionSettings_t)(void *unused, StdCommSessionSettings *pSettings);
typedef void(swrObjTrig_LoadAndInitializeTriggerModels_t)(int planet_id, int a2,
                                                          swrModel_NodeTransformed *a3);

// assetBuffer is the arena base (malloc'd once at boot by swrScene_InitWorld, never moved) and
// swrAssetBuffer_GetBuffer() is the live bump top.
static bool mp_in_model_arena(const void *p) {
    return (const char *) p >= assetBuffer && (const char *) p < swrAssetBuffer_GetBuffer();
}

// Fix (5a): reset the trigger-description registry on every track load.
void swrObjTrig_LoadAndInitializeTriggerModels_delta(int planet_id, int a2,
                                                     swrModel_NodeTransformed *a3) {
    swrObjTrig_NumTriggerDescriptions = 0;
    memset(&swrObjTrig_TriggerDescriptionArray, 0, sizeof(swrObjTrig_TriggerDescriptionArray));
    hook_call_original((swrObjTrig_LoadAndInitializeTriggerModels_t
                            *) swrObjTrig_LoadAndInitializeTriggerModels_ADDR,
                       planet_id, a2, a3);
}

void swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_delta(int trigger_index,
                                                                   int player_index) {
    // Negative indices are vanilla's "no pod attached" case (handled as a no-op downstream),
    // but anything past the roster reads out of bounds.
    if (player_index >= (int) std::size(swrScores)) {
        fprintf(hook_log,
                "[swrMultiplayer_delta] dropped trigger event %d: player_index %d out of range\n",
                trigger_index, player_index);
        fflush(hook_log);
        return;
    }

    // Fix (5b). A NULL desc is vanilla's own no-op case, so it passes through.
    swrModel_TriggerDescription *desc = swrObjTrig_GetTriggerDescription(trigger_index);
    if (desc != NULL &&
        (!mp_in_model_arena(desc) ||
         (desc->affected_node != NULL && !mp_in_model_arena(desc->affected_node)))) {
        fprintf(hook_log,
                "[swrMultiplayer_delta] dropped trigger event %d: description %p / node %p not in "
                "the loaded track (stale index?)\n",
                trigger_index, (void *) desc, (void *) desc->affected_node);
        fflush(hook_log);
        return;
    }

    if (player_index >= 0) {
        swrRace *pod = swrScores[player_index].obj_test_ptr;
        if (pod != NULL) {
            // The slot pointer survives the pod. The pool keeps freed entities in place (count is
            // the pool size), so a pointer match is not liveness -- the freed flag must also be
            // clear, the same test swrEvent_GetEvent uses.
            bool alive = false;
            const int count = swrEvent_GetEventCount('Test');
            for (int i = 0; i < count; i++) {
                swrObj *obj = (swrObj *) swrEvent_GetItem('Test', i);
                if ((swrRace *) obj == pod) {
                    alive = (obj->flags & swrObj_FLAG_FREED) == 0;
                    break;
                }
            }
            if (!alive) {
                fprintf(hook_log,
                        "[swrMultiplayer_delta] dropped trigger event %d: player %d's pod is "
                        "gone (player left?)\n",
                        trigger_index, player_index);
                fflush(hook_log);
                return;
            }
        }
    }

    hook_call_original(
        (swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_t
             *) swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_ADDR,
        trigger_index, player_index);
}

// Follow-ups for a MIDDLE player leaving. When the departure leaves a hole with higher slots still
// occupied, the host sends the highest-indexed player a 'rejn' event; that client silently rejoins
// and swrMultiplayer_ApplyPlayerJoin assigns it the vacated slot. Two things go stale around that
// relocation. These four are declaration-only in src, so they are reached through their _ADDR casts.
//
// (3) Picks live per-slot in multiplayer_racer1_id[20], and the host's copy is authoritative
//     (clients report with msg 0x33, the host re-broadcasts the array in the 0x3a lobby state).
//     The relocated player never re-sends its pick, so it inherits the leaver's pod everywhere.
//     Captured before the rejoin tears the session down and re-sent through RacerPick once the new
//     slot lands (the host's reply reaches swrMultiplayer_SetLocalPlayer with the new playerNumber).
//
// (4) swrMultiplayer_PopulateRacerList builds one row per slot 0..activeCount-1, so a vacated
//     middle slot keeps the departed player's row while the last ACTIVE player falls off the end.
//     Rebuilt over all slots that are active, retired, or finished. Separately, a player lost to a
//     crash (DirectPlay DESTROYPLAYER -> sithMulti_ProcessPlayerLost) never gets the retired flag a
//     graceful 'quit' sets, so their row keeps ticking as a live racer under AI takeover -- flagged
//     retired when the drop happens during a race. Both flag arrays are zeroed by
//     BroadcastRaceReset/ApplyRaceReset, so the widened predicate cannot leak rows into the next race.
typedef void(swrMultiplayer_JoinGame_t)(swrUI_unk *page);
typedef void(swrMultiplayer_SetLocalPlayer_t)(int playerIndex);
typedef void(sithMulti_ProcessPlayerLost_t)(DPID idPlayer);
typedef unsigned int(swrMultiplayer_IsPlayerActive_t)(int slot);
typedef void(swrUI_RefreshListSelection_t)(swrUI_unk *list);
typedef swrUI_unk *(swrUI_CreateRaceResultRow_t)(int id);
typedef swrUI_unk *(swrUI_AddListElement_t)(swrUI_unk *list, swrUI_unk *element);

// Pick captured when a 'rejn'-triggered rejoin starts, re-announced once the new slot is assigned.
static bool g_rejoin_pick_pending = false;
static int g_rejoin_pick = 0;

void swrMultiplayer_JoinGame_delta(swrUI_unk *page) {
    // multiplayer_rejoinPending is only ever set by the 'rejn' event handler; the original resets
    // it on entry, so read it first. playerNumber still holds our OLD slot here.
    if (multiplayer_rejoinPending != 0 && multiplayer_enabled != 0 && playerNumber >= 0 &&
        playerNumber < 20) {
        g_rejoin_pick = (&multiplayer_racer1_id)[playerNumber];
        g_rejoin_pick_pending = true;
    }

    hook_call_original((swrMultiplayer_JoinGame_t *) swrMultiplayer_JoinGame_ADDR, page);

    // A failed (re)join shuts multiplayer down entirely; drop the pending pick with it.
    if (multiplayer_enabled == 0)
        g_rejoin_pick_pending = false;
}

void swrMultiplayer_SetLocalPlayer_delta(int playerIndex) {
    hook_call_original((swrMultiplayer_SetLocalPlayer_t *) swrMultiplayer_SetLocalPlayer_ADDR,
                       playerIndex);

    if (g_rejoin_pick_pending && multiplayer_enabled != 0) {
        g_rejoin_pick_pending = false;
        // playerNumber is now the vacated slot; RacerPick writes the local array and reports the
        // pick to the host (msg 0x33), whose next 0x3a lobby broadcast propagates it to everyone.
        swrMultiplayer_RacerPick(g_rejoin_pick);
        fprintf(hook_log, "[swrMultiplayer_delta] rejoined as player %d, re-announced pod pick %d\n",
                playerNumber, g_rejoin_pick);
        fflush(hook_log);
    }
}

void sithMulti_ProcessPlayerLost_delta(DPID idPlayer) {
    // Resolve the slot before the original zeroes the player's DPID.
    const int slot = sithMulti_GetPlayerNum(idPlayer);

    hook_call_original((sithMulti_ProcessPlayerLost_t *) sithMulti_ProcessPlayerLost_ADDR,
                       idPlayer);

    // The judge entity only exists while a race runs, so lobby departures are unaffected.
    if (slot >= 0 && slot < (int) std::size(multiplayer_aPlayerQuit) &&
        swrEvent_GetItem('Jdge', 0) != NULL) {
        multiplayer_aPlayerQuit[slot] = 1;
    }
}

void swrMultiplayer_PopulateRacerList_delta(void) {
    // The MP racer-list / race-results list (its own page; the lobby uses a different list).
    static const int MP_RACER_LIST_ID = 0x30d42;
    // Byte offset of the row's player-slot ref inside swrUI_unk::unk560 (widget +0x56c).
    static const int SWRUI_RACE_RESULT_ROW_SLOT_OFFSET = 0xc;

    swrUI_unk *list = swrUI_GetById(NULL, MP_RACER_LIST_ID);
    ((swrUI_RefreshListSelection_t *) swrUI_RefreshListSelection_ADDR)(list);

    for (int slot = 0; slot < (int) std::size(multiplayer_aPlayerQuit); slot++) {
        // Row per participating slot -- connected, retired mid-race, or finished -- rather than
        // vanilla's 0..activeCount-1.
        if (((swrMultiplayer_IsPlayerActive_t *) swrMultiplayer_IsPlayerActive_ADDR)(slot) == 0 &&
            multiplayer_aPlayerQuit[slot] == 0 && multiplayer_aPlayerFinished[slot] == 0)
            continue;

        swrUI_unk *element = ((swrUI_CreateRaceResultRow_t *) swrUI_CreateRaceResultRow_ADDR)(slot);
        if (element == NULL)
            continue;
        // Read back by swrUI_DrawRaceResultRow. Vanilla writes it straight into the widget's class
        // payload at +0x56c (MOV dword ptr [EAX+0x56c],ESI at 0x420cf3): a struct offset, NOT an
        // indirection through the int at +0x538.
        *(int *) &element->unk560[SWRUI_RACE_RESULT_ROW_SLOT_OFFSET] = slot; // 0x560 + 0xc = 0x56c
        ((swrUI_AddListElement_t *) swrUI_AddListElement_ADDR)(list, element);
    }
}

// GetActivePlayerCount returns how many slots are ACTIVE, but its callers use it as a LOOP BOUND
// OVER SLOT INDICES: swrObjHang_StartRace stores it as hang->num_players and
// swrObjHang_BuildRosterMultiplayer walks 0..num_players-1, emitting the local 'Locl' entry only
// when the index equals playerNumber. That identity holds only while the active slots are
// contiguous -- with 0, 1 and 3 occupied the count is 3 and the player at slot 3 gets no local pod
// at all (camera at the world origin, never spawns, Escape goes straight to results).
//
// Returning one past the highest active slot is identical whenever the slots are contiguous. A
// vacated slot inside the range already emits the AI entry, vanilla's behaviour for a mid-race drop.
int swrMultiplayer_GetActivePlayerCount_delta(void) {
    const int scanned = sithPlayer_g_numPlayers < (int) std::size(swrScores)
                            ? sithPlayer_g_numPlayers
                            : (int) std::size(swrScores);
    int highest_active = -1;
    int active_count = 0;
    for (int slot = 0; slot < scanned; slot++) {
        if (((swrMultiplayer_IsPlayerActive_t *) swrMultiplayer_IsPlayerActive_ADDR)(slot) != 0) {
            highest_active = slot;
            active_count++;
        }
    }

    const int bound = highest_active + 1;
    // The lobby polls this every frame through swrMultiplayer_UpdateStartButtonState, so log only
    // on a change of shape -- otherwise one stale slot buries the log.
    static int last_count = -1;
    static int last_highest = -1;
    if (bound != active_count && (active_count != last_count || highest_active != last_highest)) {
        fprintf(hook_log,
                "[swrMultiplayer_delta] slot gap: %d active but highest slot %d (local slot %d) -"
                " widening roster bound to %d\n",
                active_count, highest_active, playerNumber, bound);
        fflush(hook_log);
    }
    last_count = active_count;
    last_highest = highest_active;
    return bound;
}

// Hardening: every per-slot handler indexes the parallel 20-entry globals (swrScores[] and
// siblings) by a wire-supplied slot with no bounds check -- the same out-of-bounds access that
// crashed the trigger handler. Dropping the message is faithful: the handlers return 1
// ("consumed") on their normal paths and a bogus slot has no valid effect.
//
// message+0x28 is the first payload int (swrMultiplayer_SendEvent stamps playerNumber there), so a
// value outside [0, 20) means the packet is bogus regardless of type. message+0x2c is the event
// magic and message+0x30 the first event payload word.
typedef int(swrMultiplayer_ApplyEvent_t)(void *message);
typedef int(swrMultiplayer_ApplyPlayerName_t)(void *message);
typedef int(swrMultiplayer_ApplyRacerPick_t)(void *message);

static bool mp_slot_in_range(int slot) {
    return slot >= 0 && slot < (int) std::size(swrScores);
}

static int mp_msg_int(void *message, int byte_offset) {
    return *(const int *) ((const char *) message + byte_offset);
}

// Wire layout of a multiplayer message, as written by the senders.
static const int MP_MSG_SENDER_SLOT = 0x28; // first payload int; SendEvent stamps playerNumber
static const int MP_MSG_EVENT_MAGIC = 0x2c; // four-character sub-event tag
static const int MP_MSG_PAYLOAD0 = 0x30;    // first event payload word

int swrMultiplayer_ApplyEvent_delta(void *message) {
    // Sub-events keyed on the sender's own slot ('fini','plap','taun','quit') index the per-slot
    // arrays by message+0x28 directly.
    const int sender_slot = mp_msg_int(message, MP_MSG_SENDER_SLOT);
    if (!mp_slot_in_range(sender_slot)) {
        fprintf(hook_log, "[swrMultiplayer_delta] dropped event: sender slot %d out of range\n",
                sender_slot);
        fflush(hook_log);
        return 1;
    }

    // Sub-events keyed on a payload slot read swrScores[payload]. 'Sprk' hands the pod pointer to
    // swrRace_SetupScrapeSpray, which dereferences it unconditionally -- the exact analog of the
    // trigger crash. 'hell'/'lost' NULL-check the pod but still fault on the fetch itself.
    const int SUBEVENT_SPRK = 0x5370726b; // 'Sprk'
    const int SUBEVENT_HELL = 0x68656c6c; // 'hell'
    const int SUBEVENT_LOST = 0x6c6f7374; // 'lost'
    const int magic = mp_msg_int(message, MP_MSG_EVENT_MAGIC);
    if (magic == SUBEVENT_SPRK || magic == SUBEVENT_HELL || magic == SUBEVENT_LOST) {
        const int pod_slot = mp_msg_int(message, MP_MSG_PAYLOAD0);
        const bool bad = !mp_slot_in_range(pod_slot) ||
                         (magic == SUBEVENT_SPRK && swrScores[pod_slot].obj_test_ptr == NULL);
        if (bad) {
            fprintf(hook_log,
                    "[swrMultiplayer_delta] dropped event %.4s: pod slot %d gone (player left?)\n",
                    (const char *) &magic, pod_slot);
            fflush(hook_log);
            return 1;
        }
    }

    // 'fini' is the only sub-event indexing swrScoresPtr (the dynamically allocated score array)
    // and it dereferences the base unconditionally, so a straggler landing after teardown faults on
    // NULL -- observed as a read at 0x228 == NULL + slot 4 * 0x88 + 8. Both writes it would make
    // are cleared by the race-reset broadcast anyway.
    const int SUBEVENT_FINI = 0x66696e69; // 'fini'
    if (magic == SUBEVENT_FINI && swrScoresPtr == NULL) {
        fprintf(hook_log,
                "[swrMultiplayer_delta] dropped event fini from slot %d: no active score array\n",
                sender_slot);
        fflush(hook_log);
        return 1;
    }

    return hook_call_original((swrMultiplayer_ApplyEvent_t *) swrMultiplayer_ApplyEvent_ADDR,
                              message);
}

int swrMultiplayer_ApplyPlayerName_delta(void *message) {
    // Writes swrMultiplayer_playerNames + slot*0x58 with no bounds check.
    const int slot = mp_msg_int(message, MP_MSG_SENDER_SLOT);
    if (!mp_slot_in_range(slot)) {
        fprintf(hook_log, "[swrMultiplayer_delta] dropped player-name: slot %d out of range\n",
                slot);
        fflush(hook_log);
        return 1;
    }
    return hook_call_original((swrMultiplayer_ApplyPlayerName_t *) swrMultiplayer_ApplyPlayerName_ADDR,
                              message);
}

int swrMultiplayer_ApplyRacerPick_delta(void *message) {
    // Writes multiplayer_racer1_id[slot] and swrRace_UnlockDataBase[slot*0x50] unchecked.
    const int slot = mp_msg_int(message, MP_MSG_SENDER_SLOT);
    if (!mp_slot_in_range(slot)) {
        fprintf(hook_log, "[swrMultiplayer_delta] dropped racer-pick: slot %d out of range\n", slot);
        fflush(hook_log);
        return 1;
    }
    return hook_call_original((swrMultiplayer_ApplyRacerPick_t *) swrMultiplayer_ApplyRacerPick_ADDR,
                              message);
}

int stdComm_UpdatePlayers_delta(unsigned int sessionNum) {
    if (stdComm_pDirectPlay == NULL) {
        // The original wipes the player-info table then repopulates it from EnumPlayers.
        stdComm_numPlayers = 0;
        return E_FAIL;
    }
    return hook_call_original((stdComm_UpdatePlayers_t *) stdComm_UpdatePlayers_ADDR, sessionNum);
}

int stdComm_GetSessionSettings_delta(void *unused, StdCommSessionSettings *pSettings) {
    if (stdComm_pDirectPlay == NULL)
        return E_FAIL;
    return hook_call_original((stdComm_GetSessionSettings_t *) stdComm_GetSessionSettings_ADDR,
                              unused, pSettings);
}

int stdComm_Send_delta(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags) {
    load_mp_settings_once();

    if (g_mp_async_send) {
        // stdComm_pDirectPlay is the IDirectPlay4* (globals.h). Cast to void* and index the vtable
        // manually so this C++ TU does not depend on the C-style lpVtbl member.
        void *const dp = (void *) stdComm_pDirectPlay;
        if (dp != nullptr) {
            // Reissue asynchronously: DirectPlay's worker thread (not the game thread) absorbs the
            // retransmit/ACK wait that otherwise blocks Send for tens of ms per call under loss.
            // IDirectPlay4::SendEx is vtable offset 0xC4 (index 49) -- verified against
            // IDirectPlay4Vtbl (Send=0x68, GetGroupOwner=0xbc, SetGroupOwner=0xc0, SendEx=0xc4).
            typedef HRESULT(__stdcall * SendEx_t)(void *, DPID, DPID, DWORD, LPVOID, DWORD, DWORD,
                                                  DWORD, LPVOID, DWORD *);
            void **const vtbl = *(void ***) dp;
            const SendEx_t pSendEx = (SendEx_t) vtbl[0xC4 / 4];
            const DWORD ex_flags = dwFlags | DPSEND_ASYNC | DPSEND_NOCOMPLETE;
            pSendEx(dp, idFrom, idTo, ex_flags, lpData, dwDataSize, 0, 0, nullptr, nullptr);
            // The message is queued; report success (callers treat a non-zero HRESULT as failure).
            return 0;
        }
    }

    return hook_call_original(stdComm_Send, idFrom, idTo, lpData, dwDataSize, dwFlags);
}
