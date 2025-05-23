#include "sithMulti.h"

#include "globals.h"

#include <macros.h>
#include <Win95/stdComm.h>

// 0x00404760
void sithMulti_InitializeConnection(int connectionIndex)
{
    int res;

    res = stdComm_InitializeConnection(connectionIndex);
    if (res == -0x7788ff06)
    {
        sprintf(unknownError_buffer, "Not_available.\n%s", std_output_buffer);
        return;
    }
    if (res != 0)
    {
        sprintf(unknownError_buffer, "Did_not_connect.\n_%s", std_output_buffer);
    }
}

// 0x00404880
int sithMulti_HandleIncomingPacket(DPID dpid)
{
    HANG("TODO");
    return 0;
}

// 0x00404960
HRESULT sithMulti_JoinSessionAndCreatePlayer(int sessionId, wchar_t* playerName, wchar_t* password)
{
    HANG("TODO");
    return 0;
}

// 0x00404a20
HRESULT sithMulti_CreatePlayerFromConfig(int param_1)
{
    HANG("TODO");
    return 0;
}

// 0x00404a20

// 0x0041b8f0
int sithMulti_RunCallback(tSithMessage* message)
{
    int res;

    if (((true) && ((unsigned short)message->callbackId < 100)) && (swrCallback_multiplayer[message->callbackId] != NULL))
    {
        res = (*swrCallback_multiplayer[message->callbackId])(message);
        return res;
    }
    return 1;
}

// 0x0041c570
void sithMulti_CloseGame(void)
{
    HANG("TODO");
}
