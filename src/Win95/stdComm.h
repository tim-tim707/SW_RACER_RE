#ifndef STDCOMM_H
#define STDCOMM_H

#include "types.h"

#define stdComm_Send_ADDR (0x00486ca0)
#define stdComm_Receive_ADDR (0x00486cd0)

#define stdComm_UpdatePlayers_ADDR (0x004871b0)

#define stdComm_CreatePlayer_ADDR (0x004872e0)
#define stdComm_DestroyPlayer_ADDR (0x00487320)

#define stdComm_EnumPlayersCallback_ADDR (0x004874a0)
#define stdComm_ProcessSystemMessage_ADDR (0x00487550)
#define stdComm_SessionToSettings_ADDR (0x004876d0)

int stdComm_Send(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags);
int stdComm_Receive(DPID* pSender, void* pData, unsigned int* pLength);

int stdComm_UpdatePlayers(unsigned int sessionNum);

DPID stdComm_CreatePlayer(wchar_t* const pPlayerName);
void stdComm_DestroyPlayer(DPID playerId);

BOOL stdComm_EnumPlayersCallback(DPID playerId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext);
int stdComm_ProcessSystemMessage(LPDPMSG_GENERIC pMessage, DPID* pSender);
void stdComm_SessionToSettings(LPDPSESSIONDESC2 pSession, StdCommSessionSettings* pSettings);

#endif // STDCOMM_H
