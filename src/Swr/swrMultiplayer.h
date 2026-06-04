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

int swrMultiplayer_Initialize(void);
void swrMultiplayer_Shutdown(void);

void swrMultiplayer_SetLastGame(char* str);

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)

unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2);

#endif // SWRMULTIPLAYER_H
