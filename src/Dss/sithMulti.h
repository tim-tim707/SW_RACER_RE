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

#define sithMulti_CloseGame_ADDR (0x0041c570)

void sithMulti_InitializeConnection(int connectionIndex);

int sithMulti_HandleIncomingPacket(DPID dpid);
HRESULT sithMulti_JoinSessionAndCreatePlayer(int sessionId, wchar_t* playerName, wchar_t* password);

HRESULT sithMulti_CreatePlayerFromConfig(int param_1);

int sithMulti_RunCallback(tSithMessage* message);

void sithMulti_CloseGame(void);

#endif // SITHMULTI_H
