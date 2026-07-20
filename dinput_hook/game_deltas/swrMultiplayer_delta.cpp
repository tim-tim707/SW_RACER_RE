#include "swrMultiplayer_delta.h"

#include <windows.h>
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
#include <globals.h>

extern FILE *hook_log;
}

#include "../hook_helper.h"
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

    wchar_t module_path[1024];
    GetModuleFileNameW(nullptr, module_path, (DWORD) std::size(module_path));
    const std::wstring ini =
        (std::filesystem::path(module_path).parent_path() / "SW_RACER_RE.ini").wstring();
    g_mp_async_send = (int) GetPrivateProfileIntW(L"settings", L"mp_async_send", 1, ini.c_str());
    g_mp_packet_cap = (int) GetPrivateProfileIntW(L"settings", L"mp_packet_cap", 32, ini.c_str());

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

// --- crash fixes: player leaving a session -----------------------------------------------------
// Triage of a 4-7 player session (2026-07): every crash dump collected fell on one of two
// unguarded paths, both reached when a player drops out of the session.
//
// (1) Mid-race: swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent trusts the player_index
//     that arrives in a remote trigger event. It only rejects negative values, then reads
//     swrScores[player_index].obj_test_ptr and hands it to swrRace_TriggerHandler ->
//     swrObjTrig_HandleCrashHitTrigger, which dereference it. Once a player has left (or the
//     index is desynced) the slot is out of bounds or holds a dangling pod pointer, and every
//     remaining peer that receives the event crashes. Validate the index against the roster
//     bounds and the pointer against the live 'Test' entity list, and drop the event otherwise
//     (same net effect as vanilla's own no-op when the slot pointer is NULL: the trigger FX
//     just doesn't play for a pod that no longer exists).
//
// (2) Menus: stdComm_UpdatePlayers and stdComm_GetSessionSettings call through
//     stdComm_pDirectPlay with no NULL check. The MP race-setup page polls both on its 500 ms
//     refresh timer (player-list refresh and session name), so when the DirectPlay object is
//     torn down while the menu is still up -- typically after the host or the other peers
//     crashed out -- the next poll dereferences NULL. Fail the call instead: UpdatePlayers
//     reports an empty player list, GetSessionSettings returns E_FAIL (its only caller,
//     swrMultiplayer_GetSessionName, already maps failure to a NULL name).
//
// All three originals are unimplemented stubs in src, so they are hooked by address and called
// back through their _ADDR casts, the same way swrObjHang_BuildRosterMultiplayer_delta does.
typedef void(swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent_t)(int trigger_index,
                                                                        int player_index);
typedef int(stdComm_UpdatePlayers_t)(unsigned int sessionNum);
typedef int(stdComm_GetSessionSettings_t)(void *unused, StdCommSessionSettings *pSettings);

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

    if (player_index >= 0) {
        swrRace *pod = swrScores[player_index].obj_test_ptr;
        if (pod != NULL) {
            // The slot pointer survives the pod itself: verify it still names a live 'Test'
            // entity before the trigger handlers dereference it. The pool keeps freed entities
            // in place (count is the pool size), so a pointer match alone isn't liveness --
            // the freed flag must be clear too, the same test swrEvent_GetEvent uses.
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

// --- follow-up fixes: a middle player leaving shifts state -------------------------------------
// When a departing player leaves a hole in the slot table (players at higher indices remain), the
// host asks the HIGHEST-indexed player to fill it: it sends them a 'rejn' event, and that client
// silently re-joins the session (swrMultiplayer_JoinGame via the race-setup timer) and is assigned
// the vacated slot by swrMultiplayer_ApplyPlayerJoin. Two things go stale around that relocation:
//
// (3) Pod-pick inheritance: picks live per-slot in multiplayer_racer1_id[20]. The host's copy is
//     authoritative -- clients report their own pick with msg 0x33 (swrMultiplayer_RacerPick) and
//     the host re-broadcasts the whole array in the 0x3a lobby state. The relocated player never
//     re-sends its pick after landing in the vacated slot, so it inherits the leaver's pod on
//     every machine. Capture the pick before the rejoin tears the session down, and re-send it
//     through the canonical RacerPick path once the new slot assignment lands (the host's reply
//     reaches swrMultiplayer_SetLocalPlayer with the new playerNumber).
//
// (4) Results/racer-list after a mid-race drop: swrMultiplayer_PopulateRacerList builds one row
//     per slot 0..activeCount-1, so with a middle slot vacated the departed player keeps a row
//     while the last ACTIVE player falls off the end ("missing player"). Rebuild over all slots
//     that are active, retired, or finished instead. Also, a player lost to a crash/disconnect
//     (DirectPlay DESTROYPLAYER -> sithMulti_ProcessPlayerLost) never gets the retired flag a
//     graceful 'quit' sets, so their row keeps ticking as a live racer (the pod continues under
//     AI takeover); flag them retired when the drop happens during a race. Both flag arrays are
//     zeroed by BroadcastRaceReset/ApplyRaceReset on the way back to the lobby, so the widened
//     row predicate cannot leak stale rows into the next race.
typedef void(swrMultiplayer_JoinGame_t)(swrUI_unk *page);
typedef void(swrMultiplayer_SetLocalPlayer_t)(int playerIndex);
typedef void(sithMulti_ProcessPlayerLost_t)(DPID idPlayer);
// These four have no src reimpl (declaration only), so they are reached through their _ADDR
// casts -- calling them by name would not link.
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

    // Mid-race drop: give the leaver the same retired flag a graceful 'quit' would have set, so
    // the results row shows "Retired" instead of a live lap/time forever. The judge entity only
    // exists while a race is running, so lobby departures are unaffected.
    if (slot >= 0 && slot < (int) std::size(multiplayer_aPlayerQuit) &&
        swrEvent_GetItem('Jdge', 0) != NULL) {
        multiplayer_aPlayerQuit[slot] = 1;
    }
}

void swrMultiplayer_PopulateRacerList_delta(void) {
    // The MP racer-list / race-results list (its own page; the lobby uses a different list).
    static const int MP_RACER_LIST_ID = 0x30d42;

    swrUI_unk *list = swrUI_GetById(NULL, MP_RACER_LIST_ID);
    ((swrUI_RefreshListSelection_t *) swrUI_RefreshListSelection_ADDR)(list);

    for (int slot = 0; slot < (int) std::size(multiplayer_aPlayerQuit); slot++) {
        // Vanilla creates rows for slots 0..activeCount-1, which drops the highest occupied slot
        // once a middle slot is vacated. Row per participating slot instead: still connected,
        // retired mid-race, or already finished.
        if (((swrMultiplayer_IsPlayerActive_t *) swrMultiplayer_IsPlayerActive_ADDR)(slot) == 0 &&
            multiplayer_aPlayerQuit[slot] == 0 && multiplayer_aPlayerFinished[slot] == 0)
            continue;

        swrUI_unk *element = ((swrUI_CreateRaceResultRow_t *) swrUI_CreateRaceResultRow_ADDR)(slot);
        if (element == NULL)
            continue;
        *(int *) (element->unk538 + 0x34) = slot; // the row's player-slot ref (read by DrawRaceResultRow)
        ((swrUI_AddListElement_t *) swrUI_AddListElement_ADDR)(list, element);
    }
}

int stdComm_UpdatePlayers_delta(unsigned int sessionNum) {
    if (stdComm_pDirectPlay == NULL) {
        // The original starts by wiping the player-info table, then the EnumPlayers callback
        // repopulates it; with no DirectPlay object left, just report an empty lobby.
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
