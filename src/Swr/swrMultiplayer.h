#ifndef SWRMULTIPLAYER_H
#define SWRMULTIPLAYER_H

#include "types.h"

#define swrMultiplayer_SetInMultiplayer_ADDR (0x00412640)

#define swrMultiplayer_IsMultiplayerEnabled_ADDR (0x0041d6b0)
#define swrMultiplayer_IsHost_ADDR (0x0041d6c0)

#define swrMultiplayer_InRace_ADDR (0x0041da00)
#define swrMultiplayer_RacerPick_ADDR (0x0041dc30)

// netplay event/state senders (DirectPlay + sithMessage)
#define swrMultiplayer_InitPlayerStatus_ADDR (0x0041d3b0)
#define swrMultiplayer_SetPlayerStatusBit_ADDR (0x0041d4e0)
#define swrMultiplayer_SendPodHello_ADDR (0x0041d8d0)
#define swrMultiplayer_PublishPodState_ADDR (0x0041d930)
#define swrMultiplayer_SendEvent_ADDR (0x0041df10)
#define swrMultiplayer_BroadcastRaceReset_ADDR (0x0041e660)
#define swrMultiplayer_ApplyPlayerStates_ADDR (0x0041d6f0)
#define swrMultiplayer_BroadcastRoster_ADDR (0x0041dd50)
#define swrMultiplayer_SetRosterEntry_ADDR (0x0041de50)
#define swrMultiplayer_BroadcastPlayerState_ADDR (0x0041e5a0)
#define swrMultiplayer_UpdateReadyState_ADDR (0x0041e700)
#define swrMultiplayer_AddChatMessage_ADDR (0x0041e800)
#define swrMultiplayer_BuildCreateGameUI_ADDR (0x0041eb80)
#define swrMultiplayer_SendJoinResponse_ADDR (0x0041d060)
#define swrMultiplayer_SendChatMessage_ADDR (0x0041d0c0)
#define swrMultiplayer_DropPlayer_ADDR (0x0041d270)
#define swrMultiplayer_SendPlayerQuit_ADDR (0x0041d2a0)
#define swrMultiplayer_GetPlayerDpid_ADDR (0x0041d380)
#define swrMultiplayer_SendReadyFlag_ADDR (0x0041d420)
#define swrMultiplayer_PollPlayerStatus_ADDR (0x0041d640)
#define swrMultiplayer_ClearPlayerStatus_ADDR (0x0041d690)
#define swrMultiplayer_ClearStateBuffer_ADDR (0x0041d6d0)
#define swrMultiplayer_RegisterHandler_ADDR (0x0041b750)
#define swrMultiplayer_RegisterHandlers_ADDR (0x0041ba00)
#define swrMultiplayer_OnChatReceived_ADDR (0x0041c130)

// netplay receive handlers (registered in the subtype -> handler table)
#define swrMultiplayer_ApplyReadyState_ADDR (0x0041d600)
#define swrMultiplayer_ApplyRoster_ADDR (0x0041de60)
#define swrMultiplayer_ApplyEvent_ADDR (0x0041e260)
#define swrMultiplayer_ApplyRaceReset_ADDR (0x0041e6c0)
#define swrMultiplayer_VerifyPlayerList_ADDR (0x00404a70)
#define swrMultiplayer_ApplyPlayerLeave_ADDR (0x0041bba0)
#define swrMultiplayer_ApplyLobbyState_ADDR (0x0041c330)
#define swrMultiplayer_ApplyLobbyRefresh_ADDR (0x0041c3e0)
#define swrMultiplayer_ApplyMenuEvent_ADDR (0x0041c490)
#define swrMultiplayer_ApplyPlayerName_ADDR (0x0041cb90)
#define swrMultiplayer_ApplyPlayerList_ADDR (0x0041ccd0)
#define swrMultiplayer_ApplyPlayerJoin_ADDR (0x0041ce60)
#define swrMultiplayer_HandleNoOp_ADDR (0x0041d0b0)
#define swrMultiplayer_ReplyPing_ADDR (0x0041d1d0)
#define swrMultiplayer_ApplyPingReply_ADDR (0x0041d200)
#define swrMultiplayer_ApplyPlayerQuit_ADDR (0x0041d2f0)
#define swrMultiplayer_ApplyReadyFlag_ADDR (0x0041d540)
#define swrMultiplayer_ApplyReadyMask_ADDR (0x0041d5b0)
#define swrMultiplayer_ApplyRacerPick_ADDR (0x0041dca0)
#define swrMultiplayer_ApplyAllRacerPicks_ADDR (0x0041dce0)
#define swrMultiplayer_ApplyRosterRequest_ADDR (0x0041dd20)
#define swrMultiplayer_ApplyStateRequest_ADDR (0x0041e590)
#define swrMultiplayer_ApplyRaceSettings_ADDR (0x0041e620)

#define swrMultiplayer_Initialize_ADDR (0x00420830)
#define swrMultiplayer_Shutdown_ADDR (0x004208c0)

#define swrMultiplayer_SetLastGame_ADDR (0x00420c20)

#define swrMultiplayer_SetSessionDesc_ADDR (0x00486e60)

// Per-frame: drain and dispatch all queued incoming network packets
// (sithMulti_HandleIncomingPacket loop). Called from swrMain2_GuiAdvance.
#define swrMultiplayer_PumpPackets_ADDR (0x0041b7f0)

// Multiplayer menu UI: the host/join/race-setup screen builders + their helpers.
#define swrMultiplayer_GetSessionName_ADDR (0x0041bd10)
#define swrMultiplayer_SetRacerListDisplay_ADDR (0x0041bd90)
#define swrMultiplayer_ResetRaceSettings_ADDR (0x0041c260)
#define swrMultiplayer_BroadcastRaceSettings_ADDR (0x0041c2a0)
#define swrMultiplayer_SendRacerSelection_ADDR (0x0041c390)
#define swrMultiplayer_CreateSession_ADDR (0x0041c5c0)
#define swrMultiplayer_FreeRacerSlot_ADDR (0x0041e7c0)
#define swrMultiplayer_IsAvailable_ADDR (0x0041e9d0)
#define swrMultiplayer_BuildSessionTypeUI_ADDR (0x0041ea20)
#define swrMultiplayer_BuildJoinGameUI_ADDR (0x0041f0e0)
#define swrMultiplayer_BuildRaceSetupUI_ADDR (0x0041f940)
#define swrMultiplayer_BuildRacerListUI_ADDR (0x00420600)
#define swrMultiplayer_ValidateGameFields_ADDR (0x00420730)
#define swrMultiplayer_FillLastPlayerName_ADDR (0x00420a90)
#define swrMultiplayer_FillDefaultGameName_ADDR (0x00420b80)
#define swrMultiplayer_PopulateRacerList_ADDR (0x00420cc0)
#define swrMultiplayer_JoinGame_ADDR (0x00420d90)
#define swrMultiplayer_GetActivePlayerCount_ADDR (0x00420f90)

void swrMultiplayer_SetInMultiplayer(int bInMultiplayer);

int swrMultiplayer_IsMultiplayerEnabled(void);
int swrMultiplayer_IsHost(void);

void swrMultiplayer_InRace(void);

void swrMultiplayer_RacerPick(int a);

// netplay event/state senders (DirectPlay + sithMessage):
// Serializes and broadcasts a 4-char game event ('fini','quit','taun','trig','hell','rejn','prxy',...).
void swrMultiplayer_SendEvent(int to, unsigned int flags, int eventMagic, int a4, float a5, float a6, double a7, void* a8, void* a9, int a10);
// Snapshots a pod's transform/speed/lap into the per-player netplay arrays.
void swrMultiplayer_PublishPodState(swrRace* player);
// Marks a pod as remote/proxy and broadcasts a 'hell'o announcement for it.
void swrMultiplayer_SendPodHello(swrRace* player);
// Initializes a per-player status slot and announces it.
void swrMultiplayer_InitPlayerStatus(int slot);
// Sets a per-player ready/status bit (and broadcasts the change).
void swrMultiplayer_SetPlayerStatusBit(int slot, int value);
// Clears all per-player finish/quit flags and broadcasts a race-reset message.
void swrMultiplayer_BroadcastRaceReset(void);
// Applies a received full-state sync: writes remote pods' transforms/speed/lap into per-player arrays.
int swrMultiplayer_ApplyPlayerStates(int message);
// Broadcasts the player roster + per-player vehicle picks (host).
void swrMultiplayer_BroadcastRoster(int param_1, void* roster);
// Sets an entry in the per-player roster array.
void swrMultiplayer_SetRosterEntry(int index, int value);
// Broadcasts the local player's state snapshot.
void swrMultiplayer_BroadcastPlayerState(void);
// Detects when all players are ready and broadcasts the ready state.
void swrMultiplayer_UpdateReadyState(int slot);
// Adds a chat/session string to the on-screen message log (with a display TTL).
void swrMultiplayer_AddChatMessage(char* text);
// Builds the "Create A Game" multiplayer dialog (name/game/password fields).
int swrMultiplayer_BuildCreateGameUI(void);

// Sends a subtype-0x24 join-response code (result + value) to one player.
void swrMultiplayer_SendJoinResponse(int result, int value, DPID to);
// Broadcasts a chat string (subtype 2) to all players.
void swrMultiplayer_SendChatMessage(char* text, int param2, int param3);
// Drops a player: resolves its DPID, sends a quit, and sithMulti_RemovePlayer.
void swrMultiplayer_DropPlayer(unsigned int playerNum);
// Sends a subtype-0x2a player-quit message to a player (host).
void swrMultiplayer_SendPlayerQuit(DPID player);
// Returns the DPID of the roster player at playerNum, or -1.
DPID swrMultiplayer_GetPlayerDpid(unsigned int playerNum);
// Sets/clears the local player's ready bit and sends it (subtype 0x2d) to the host.
void swrMultiplayer_SendReadyFlag(int player, int ready);
// Pumps packets and polls a player's status slot (returns 0 while still waiting).
int swrMultiplayer_PollPlayerStatus(int player);
// Zeroes a player's status slot (status/ready/extra).
void swrMultiplayer_ClearPlayerStatus(int player);
// Zeroes the per-player network state buffer (DAT_00e29bc0).
void swrMultiplayer_ClearStateBuffer(void);

// Receive side: RegisterHandlers wires the sithMessage subtype -> handler table
// (DAT_004e9d18[subtype]). Complete subtype -> handler map (all named below):
//   0x17 ApplyEvent      0x20 ApplyPlayerList   0x21 ApplyPlayerName
//   0x22 ApplyPlayerJoin 0x24/0x2f HandleNoOp   0x26 ReplyPing
//   0x27 ApplyPingReply  0x28 ApplyPlayerLeave  0x29 VerifyPlayerList
//   0x2a ApplyPlayerQuit 0x2c ApplyReadyMask    0x2d ApplyReadyFlag
//   0x2e ApplyReadyState 0x32 ApplyPlayerStates 0x33 ApplyRacerPick
//   0x34 ApplyAllRacerPicks 0x35 ApplyRosterRequest 0x36 ApplyRoster
//   0x37 ApplyStateRequest  0x38 ApplyRaceSettings  0x39 ApplyRaceReset
//   0x3a ApplyLobbyState    0x3b ApplyLobbyRefresh  0x3c/0x3d ApplyMenuEvent
void swrMultiplayer_RegisterHandler(int subtype, void* handler);
void swrMultiplayer_RegisterHandlers(void);
// Receive handler for an incoming chat message: logs it and appends to the chat UI list.
void swrMultiplayer_OnChatReceived(char* text);

// Receive handler (subtype 0x17): applies an incoming game event - the SendEvent counterpart.
// Dispatches ctrl/Sprk/hell/fini/plap/lost/quit/prxy/rejn/taun/trig/flam to the addressed racer
// (scrape spray, finish/quit flags, lap toast, taunt SFX via swrSound_PlaySfxThrottled, triggers).
int swrMultiplayer_ApplyEvent(void* message);
// Receive handler (subtype 0x2e): records a remote player's ready flag into its status slot.
int swrMultiplayer_ApplyReadyState(void* message);
// Receive handler (subtype 0x36): copies the broadcast roster (count + per-player arrays) locally.
int swrMultiplayer_ApplyRoster(void* message);
// Receive handler (subtype 0x39): clears all per-player finish/quit flags on race reset.
int swrMultiplayer_ApplyRaceReset(void);

// --- session / player-table handlers ---
// 0x20: rebuilds the local player table (count, names, flags, DPIDs) from a full session sync.
int swrMultiplayer_ApplyPlayerList(void* message);
// 0x21: stores one player's display name.
int swrMultiplayer_ApplyPlayerName(void* message);
// 0x22: handles a player joining (find/add to the roster, assign slot, ack to sender).
int swrMultiplayer_ApplyPlayerJoin(void* message);
// 0x29: verifies a received player-id list against the local session and sets the synced flag.
int swrMultiplayer_VerifyPlayerList(void* message);
// 0x28: removes a player from a session group bitfield, freeing the slot when it empties.
int swrMultiplayer_ApplyPlayerLeave(void* message);
// 0x2a: handles a player quit - closes the game on host quit, else removes that player.
int swrMultiplayer_ApplyPlayerQuit(void* message);
// 0x24/0x2f: no-op handler (acknowledges without acting).
int swrMultiplayer_HandleNoOp(void);
// --- ping / latency ---
// 0x26: ping request - echoes back as subtype 0x27.
int swrMultiplayer_ReplyPing(void* message);
// 0x27: ping reply - folds the round-trip time into the per-player smoothed latency.
int swrMultiplayer_ApplyPingReply(void* message);
// --- ready / lobby handshake ---
// 0x2d: sets/clears a player's ready bit in the ready mask, then re-evaluates ready state.
int swrMultiplayer_ApplyReadyFlag(void* message);
// 0x2c: reads a player's ready mask and applies the local player's bit.
int swrMultiplayer_ApplyReadyMask(void* message);
// --- racer picks / roster ---
// 0x33: applies one player's racer/character pick into the profile + roster tables.
int swrMultiplayer_ApplyRacerPick(void* message);
// 0x34: applies the full set of all players' racer picks.
int swrMultiplayer_ApplyAllRacerPicks(void* message);
// 0x35: roster request - host re-broadcasts the roster.
int swrMultiplayer_ApplyRosterRequest(void);
// 0x37: player-state request - responds by broadcasting the local player state.
int swrMultiplayer_ApplyStateRequest(void);
// 0x38: applies a 5-field host broadcast (race/session settings).
int swrMultiplayer_ApplyRaceSettings(void* message);
// 0x3a: applies a full lobby-state block into the pick/roster region + posts a UI event.
int swrMultiplayer_ApplyLobbyState(void* message);
// 0x3b: lobby refresh request - re-broadcasts the local lobby state.
int swrMultiplayer_ApplyLobbyRefresh(void);
// 0x3c/0x3d: posts a menu/lobby UI event (or resets the lobby on 0x3c).
int swrMultiplayer_ApplyMenuEvent(void* message);

int swrMultiplayer_Initialize(void);
void swrMultiplayer_Shutdown(void);

void swrMultiplayer_SetLastGame(char* str);

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)

unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2);

// Drain and dispatch all queued incoming network packets; returns the count handled.
int swrMultiplayer_PumpPackets(void);

// Multiplayer menu UI: host/join/race-setup screen builders + their helpers.
int swrMultiplayer_IsAvailable(void);                               // can a session start? gates the MP menu entry
unsigned int swrMultiplayer_CreateSession(wchar_t* a1, wchar_t* a2, wchar_t* a3, char* a4, int a5);
char* swrMultiplayer_GetSessionName(void);
void swrMultiplayer_SetRacerListDisplay(int enabled, int x, int y); // toggle racer-list overlay + free slot cache
void swrMultiplayer_FreeRacerSlot(int slot);
void swrMultiplayer_ResetRaceSettings(void);                        // reset racer ids + track (Boonta) / laps (3)
void swrMultiplayer_BroadcastRaceSettings(void);                    // host -> all: track/laps/racers (msg 0x3a)
void swrMultiplayer_SendRacerSelection(void);                       // client -> server: racer pick (msg 0x3b)
int swrMultiplayer_GetActivePlayerCount(void);
void swrMultiplayer_PopulateRacerList(void);                        // fill racer list with connected players
void swrMultiplayer_JoinGame(swrUI_unk* page);                      // connect to the entered game
int swrMultiplayer_ValidateGameFields(swrUI_unk* page, int id1, int id2, int id3); // fields non-empty -> enable OK
void swrMultiplayer_FillLastPlayerName(swrUI_unk* field);
void swrMultiplayer_FillDefaultGameName(swrUI_unk* field);
// Screen builders (each registers its swrUI_Menu_Mp* page proc):
int swrMultiplayer_BuildSessionTypeUI(void);   // window 0x186a5: Host / Join root
int swrMultiplayer_BuildJoinGameUI(void);      // window 0x186ab
int swrMultiplayer_BuildRaceSetupUI(void);     // window 0x186b8
int swrMultiplayer_BuildRacerListUI(void);     // window 0x30d41

#endif // SWRMULTIPLAYER_H
