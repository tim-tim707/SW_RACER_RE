#ifndef STDCOMM_H
#define STDCOMM_H

#include "types.h"

#define stdComm_Startup_ADDR (0x004207e0)
#define stdComm_Shutdown_ADDR (0x00420810)

#define stdComm_InitializeConnection_ADDR (0x00486bc0)

#define stdComm_GetNumConnections_ADDR (0x00486c00)

#define stdComm_GetNumSessionSettings_ADDR (0x00486c50)
#define stdComm_Send_ADDR (0x00486ca0)
#define stdComm_Receive_ADDR (0x00486cd0)

#define stdComm_GetSessionSettings_ADDR (0x00486f50)
#define stdComm_JoinSession_ADDR (0x004870d0)

#define stdComm_Close_ADDR (0x00487180)
#define stdComm_UpdatePlayers_ADDR (0x004871b0)
#define stdComm_EnumSessions_ADDR (0x00487230)
#define stdComm_CreatePlayer_ADDR (0x004872e0)
#define stdComm_DestroyPlayer_ADDR (0x00487320)
#define stdComm_GetNumPlayers_ADDR (0x00487340)
#define stdComm_GetPlayerId_ADDR (0x00487350)

#define stdComm_EnumPlayersCallback_ADDR (0x004874a0)
#define stdComm_ProcessSystemMessage_ADDR (0x00487550)
#define stdComm_SessionToSettings_ADDR (0x004876d0)

int stdComm_Startup(void);
int stdComm_Shutdown(void);

int stdComm_InitializeConnection(int connectionIndex);

int stdComm_GetNumConnections(void);

int stdComm_GetNumSessionSettings(void);
int stdComm_Send(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags);
int stdComm_Receive(DPID* pSender, void* pData, unsigned int* pLength);

int stdComm_GetSessionSettings(void* unused, StdCommSessionSettings* pSettings);
HRESULT stdComm_JoinSession(int sessionIndex, wchar_t* password);

void stdComm_Close(void);
int stdComm_UpdatePlayers(unsigned int sessionNum);
void stdComm_EnumSessions(int one, wchar_t* password);
DPID stdComm_CreatePlayer(wchar_t* const pPlayerName);
void stdComm_DestroyPlayer(DPID playerId);
int stdComm_GetNumPlayers(void);
DPID stdComm_GetPlayerId(int index);

BOOL stdComm_EnumPlayersCallback(DPID playerId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);
int stdComm_ProcessSystemMessage(LPDPMSG_GENERIC pMessage, DPID* pSender);
void stdComm_SessionToSettings(LPDPSESSIONDESC2 pSession, StdCommSessionSettings* pSettings);

#endif // STDCOMM_H
