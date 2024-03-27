#include "stdComm.h"

#include "DirectX.h"
#include "globals.h"

#include <macros.h>

// 0x004207e0
int stdComm_Startup(void)
{
    int res;

    if (stdComm_bInitted == 0)
    {
        res = DirectPlay_Startup();
        if (res != 0)
        {
            return 0;
        }
        stdComm_bInitted = 1;
    }
    return 1;
}

// 0x00420810
int stdComm_Shutdown(void)
{
    if (stdComm_bInitted != 0)
    {
        DirectPlay_Destroy();
        stdComm_bInitted = 0;
    }
    return 1;
}

// 0x00486bc0
int stdComm_InitializeConnection(int connectionIndex)
{
    unsigned int tmp;

    if (stdComm_pDirectPlay == NULL)
    {
        return -0x7788ff06;
    }
    tmp = (*stdComm_pDirectPlay->lpVtbl->InitializeConnection)(stdComm_pDirectPlay, stdComm_Connections[connectionIndex].lpConnection, 0);
    return tmp & ((-1 < (int)tmp) - 1);
}

// 0x00486c00
int stdComm_GetNumConnections(void)
{
    return stdComm_numConnections;
}

// 0x00486c10
int stdComm_GetConnection(unsigned int connectionIndex, StdCommConnection* connection_out)
{
    int i;
    StdCommConnection* connection;

    if ((unsigned int)stdComm_numConnections < connectionIndex)
    {
        return 1;
    }
    connection = stdComm_Connections + connectionIndex;
    for (i = 0x46; i != 0; i = i + -1)
    {
        *(uint32_t*)connection_out->name = *(uint32_t*)connection->name;
        connection = (StdCommConnection*)(connection->name + 2);
        connection_out = (StdCommConnection*)(connection_out->name + 2);
    }
    return connectionIndex * 0x23; // ?. Unused result
}

// 0x00486c50
int stdComm_GetNumSessionSettings(void)
{
    return stdComm_numSessionSettings;
}

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

// 0x004870d0
HRESULT stdComm_JoinSession(int sessionIndex, wchar_t* password)
{
    HANG("TODO");
}

// 0x00487180
void stdComm_Close(void)
{
    if (stdComm_bGameActive != 0)
    {
        (*stdComm_pDirectPlay->lpVtbl->Close)(stdComm_pDirectPlay);
    }
    stdComm_bGameActive = 0;
    stdComm_bIsServer = 0;
}

// 0x004871b0
int stdComm_UpdatePlayers(unsigned int sessionNum)
{
    HANG("TODO");
}

// 0x00487230
void stdComm_EnumSessions(int one, wchar_t* password)
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

// 0x00487340
int stdComm_GetNumPlayers(void)
{
    return stdComm_numPlayers;
}

// 0x00487350
DPID stdComm_GetPlayerId(int index)
{
    return stdComm_aPlayerInfos[index].id;
}

// 0x00487450
int stdComm_EnumSessionsCallback(LPCDPSESSIONDESC2 lpThisSD, LPDWORD lpdwTimeOut, DWORD dwFlags, LPVOID lpContext)
{
    int iVar1;

    if ((dwFlags & 1) != 0)
    {
        return 0;
    }
    HANG("TODO"); // StdCommSessionSettings_0x005117e8 size and alignment
    return 1;
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
