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
#define swrMultiplayer_RegisterHandler_ADDR (0x0041b750)
#define swrMultiplayer_RegisterHandlers_ADDR (0x0041ba00)
#define swrMultiplayer_OnChatReceived_ADDR (0x0041c130)

// netplay receive handlers (registered in the subtype -> handler table)
#define swrMultiplayer_ApplyReadyState_ADDR (0x0041d600)
#define swrMultiplayer_ApplyRoster_ADDR (0x0041de60)
#define swrMultiplayer_ApplyEvent_ADDR (0x0041e260)
#define swrMultiplayer_ApplyRaceReset_ADDR (0x0041e6c0)

#define swrMultiplayer_Initialize_ADDR (0x0042830)
#define swrMultiplayer_Shutdown_ADDR (0x004208c0)

#define swrMultiplayer_SetLastGame_ADDR (0x00420c20)

#define swrMultiplayer_SetSessionDesc_ADDR (0x00486e60)

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

// Receive side: RegisterHandlers wires the sithMessage subtype -> handler table
// (DAT_004e9d18[subtype]). Several handlers are still undefined functions and need
// a Ghidra Create Function pass before naming; known subtype -> address map
// (named ones below have their own _ADDR define):
//   0x17 -> swrMultiplayer_ApplyEvent (0x41e260; SendEvent counterpart)
//   0x20 -> 0x41ccd0   0x21 -> 0x41cb90   0x22 -> 0x41ce60
//   0x24/0x2f -> 0x41d0b0   0x26 -> 0x41d1d0   0x27 -> 0x41d200
//   0x28 -> 0x41bba0   0x29 -> 0x404a70   0x2a -> 0x41d2f0
//   0x2c -> 0x41d5b0   0x2d -> 0x41d540   0x2e -> swrMultiplayer_ApplyReadyState
//   0x32 -> ApplyPlayerStates   0x33 -> 0x41dca0   0x34 -> 0x41dce0
//   0x35 -> 0x41dd20   0x36 -> swrMultiplayer_ApplyRoster   0x37 -> 0x41e590
//   0x38 -> 0x41e620   0x39 -> swrMultiplayer_ApplyRaceReset   0x3a -> 0x41c330
//   0x3b -> 0x41c3e0   0x3c/0x3d -> 0x41c490
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

int swrMultiplayer_Initialize(void);
void swrMultiplayer_Shutdown(void);

void swrMultiplayer_SetLastGame(char* str);

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)

unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2);

#endif // SWRMULTIPLAYER_H
