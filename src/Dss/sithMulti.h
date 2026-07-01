#ifndef SITHMULTI_H
#define SITHMULTI_H

#include "types.h"

// TODO: Match real addresses
// #define sithMulti_RemovePlayer_ADDR (0x0041cae0)
// #define sithMulti_ProcessQuit_ADDR (0x0041d2f0)
// #define sithMulti_GetPlayerNum_ADDR (0x0041d350)

#define sithMulti_InitializeConnection_ADDR (0x00404760)

#define sithMulti_HandleIncomingPacket_ADDR (0x00404880)
#define sithMulti_JoinSessionAndCreatePlayer_ADDR (0x00404960)

#define sithMulti_CreatePlayerFromConfig_ADDR (0x00404a20)

#define sithMulti_RunCallback_ADDR (0x0041b8f0)
#define sithMulti_ResetCallbackState_ADDR (0x0041b920)
#define sithMulti_DefaultCallback_ADDR (0x0041b940)
#define sithMulti_ClearMessageField_Maybe_ADDR (0x0041b950)
#define swrMultiplayer_SendPlayerLeave_Maybe_ADDR (0x0041b960)
#define sithMulti_TrackMessagePair_Maybe_ADDR (0x0041b9a0)

#define sithMulti_CloseGame_ADDR (0x0041c570)

void sithMulti_InitializeConnection(int connectionIndex);

int sithMulti_HandleIncomingPacket(DPID dpid);
HRESULT sithMulti_JoinSessionAndCreatePlayer(int sessionId, wchar_t* playerName, wchar_t* password);

HRESULT sithMulti_CreatePlayerFromConfig(int param_1);

int sithMulti_RunCallback(tSithMessage* message);

// Resets the multiplayer message and callback bookkeeping buffers (best guess).
void sithMulti_ResetCallbackState(void);

// A default message handler that simply returns one (best guess).
unsigned int sithMulti_DefaultCallback(tSithMessage* message);

// Clears a single field of a message struct (best guess).
void sithMulti_ClearMessageField_Maybe(int message);

// Sends a player-leave message to one DirectPlay peer (best guess).
void swrMultiplayer_SendPlayerLeave_Maybe(DPID to, unsigned short value);

// Tracks a message pair in a 128-entry table, appending if unseen and reporting whether it was already present (best guess).
unsigned int sithMulti_TrackMessagePair_Maybe(int a, int b);

void sithMulti_CloseGame(void);

#endif // SITHMULTI_H
