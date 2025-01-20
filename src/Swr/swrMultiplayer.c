#include "swrMultiplayer.h"

#include "globals.h"
#include "macros.h"

#include <Platform/wuRegistry.h>
#include <Win95/stdComm.h>
#include <Dss/sithMulti.h>

// 0x00412640
void swrMultiplayer_SetInMultiplayer(int bInMultiplayer)
{
    multiplayer_in_mp = bInMultiplayer;
}

// 0x0041d6b0
int swrMultiplayer_IsMultiplayerEnabled(void)
{
    return multiplayer_enabled;
}

// 0x0041da00
void swrMultiplayer_InRace(void)
{
    HANG("TODO");
}

// 0x0041dc30
void swrMultiplayer_RacerPick(int a)
{
    HANG("TODO");
}

// 0x0042830
int swrMultiplayer_Initialize(void)
{
    unsigned int numSessions;
    int guid_size;
    unsigned int connectionIndex;
    GUID* guid;
    GUID* ipx_guid;
    bool bFound;
    StdCommConnection connection;

    if (swrMulti_Initialized == 0)
    {
        numSessions = stdComm_GetNumSessionSettings();
        connectionIndex = 0;
        if (numSessions != 0)
        {
            do
            {
                stdComm_GetConnection(connectionIndex, &connection);
                guid_size = 0x10;
                bFound = true;
                guid = &connection.guid;
                ipx_guid = &IPX_GUID;
                do
                {
                    if (guid_size == 0)
                        break;
                    guid_size = guid_size + -1;
                    bFound = *(char*)guid == *(char*)ipx_guid;
                    guid = (GUID*)&guid->Data1;
                    ipx_guid = (GUID*)&ipx_guid->Data1;
                } while (bFound);
                if (bFound)
                {
                    stdComm_IPX_connectionIndex = connectionIndex;
                    sithMulti_InitializeConnection(connectionIndex);
                    swrMulti_Initialized = 1;
                    return 1;
                }
                connectionIndex = connectionIndex + 1;
                if (numSessions <= connectionIndex)
                {
                    return 0;
                }
            } while (true);
        }
    }
    return 0;
}

// 0x004208c0
void swrMultiplayer_Shutdown(void)
{
    if (swrMulti_Initialized != 0)
    {
        sithMulti_CloseGame();
        stdComm_Shutdown();
        swrMulti_Initialized = 0;
    }
}

// 0x00420c20
void swrMultiplayer_SetLastGame(char* str)
{
    wuRegistry_SetString("Last Game", str);
}

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)
// 0x00486e60
unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2)
{
    HANG("TODO");
    return 0;
}
