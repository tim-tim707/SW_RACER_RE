#include "stdComm.h"

// 0x00486ca0
int stdComm_Send(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags)
{
    HANG("TODO");
}

// 0x00486cd0
int stdComm_Receive(DPID* pSender, void* pData, unsigned int* pLength)
{
    HANG("TODO");
}

// 0x00486f50
int stdComm_GetSessionSettings(void* unused, StdCommSessionSettings* pSettings)
{
    HANG("TODO");
}

// 0x004871b0
int stdComm_UpdatePlayers(unsigned int sessionNum)
{
    HANG("TODO");
}

// 0x004872e0
DPID stdComm_CreatePlayer(wchar_t* const pPlayerName)
{
    HANG("TODO");
}

// 0x00487320
void stdComm_DestroyPlayer(DPID playerId)
{
    HANG("TODO");
}

// 0x004874a0
BOOL stdComm_EnumPlayersCallback(DPID playerId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    HANG("TODO");
}

// 0x00487550
int stdComm_ProcessSystemMessage(LPDPMSG_GENERIC pMessage, DPID* pSender)
{
    HANG("TODO");
}

// 0x004876d0
void stdComm_SessionToSettings(LPDPSESSIONDESC2 pSession, StdCommSessionSettings* pSettings)
{
    HANG("TODO");
}
