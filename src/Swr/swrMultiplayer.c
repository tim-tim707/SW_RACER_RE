#include "swrMultiplayer.h"

#include "globals.h"
#include "macros.h"

#include <General/stdString.h>
#include <Platform/wuRegistry.h>
#include <Win95/stdComm.h>
#include <Dss/sithMulti.h>
#include <Swr/swrEvent.h>

// Stride in wchar_t between consecutive players in the swrMultiplayer_playerNames table;
// 0x58 wchar_t == the 0xb0 sizeof(SithPlayer) that table is a view into.
#define swrMultiplayer_PLAYER_NAME_STRIDE 0x58

// Slots in sithPlayer_g_aPlayers; the bound swrMultiplayer_ClearPlayerSlot enforces.
#define swrMultiplayer_MAX_PLAYERS 20

// 0x00412640
void swrMultiplayer_SetInMultiplayer(int bInMultiplayer)
{
    multiplayer_in_mp = bInMultiplayer;
}

// 0x0041bcc0
wchar_t* swrMultiplayer_GetPlayerName(int playerIndex)
{
    return swrMultiplayer_playerNames + playerIndex * swrMultiplayer_PLAYER_NAME_STRIDE;
}

// 0x0041bce0
char* swrMultiplayer_GetPlayerNameAscii(int playerIndex)
{
    stdString_WcharToChar(swrMultiplayer_asciiNameBuffer, swrMultiplayer_playerNames + playerIndex * swrMultiplayer_PLAYER_NAME_STRIDE, 0x20);
    return swrMultiplayer_asciiNameBuffer;
}

// 0x0041bd50
void swrMultiplayer_SetNetworkTick(int value)
{
    swrMultiplayer_networkTick = value;
}

// 0x0041c4d0
int swrMultiplayer_GetRacerId(int playerIndex)
{
    return (&multiplayer_racer1_id)[playerIndex];
}

// 0x0041d3b0
void swrMultiplayer_InitPlayerStatus(int slot)
{
    HANG("TODO");
}

// 0x0041d4e0
void swrMultiplayer_SetPlayerStatusBit(int slot, int value)
{
    HANG("TODO");
}

// 0x0041d640
int swrMultiplayer_PollPlayerStatus(int player)
{
    HANG("TODO");
}

// 0x0041d6b0
int swrMultiplayer_IsMultiplayerEnabled(void)
{
    return multiplayer_enabled;
}

// 0x0041d6c0
int swrMultiplayer_IsHost(void)
{
    return multiplayer_isHost;
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

// 0x0041df10
void swrMultiplayer_SendEvent(int to, unsigned int flags, int eventMagic, int a4, float a5, float a6, double a7, void* a8, void* a9, int a10)
{
    HANG("TODO");
}

// 0x0041d380
DPID swrMultiplayer_GetPlayerDpid(unsigned int playerNum)
{
    if (playerNum < sithPlayer_g_numPlayers)
        return sithPlayer_g_aPlayers[playerNum].playerNetId;
    return -1;
}

// 0x00420f70
int swrMultiplayer_IsPlayerActive(int playerIndex)
{
    return sithPlayer_g_aPlayers[playerIndex].flags & SITH_PLAYER_JOINEDGAME;
}

// 0x00420f90
int swrMultiplayer_GetActivePlayerCount(void)
{
    int count = 0;
    for (unsigned int i = 0; i < sithPlayer_g_numPlayers; i++) {
        if ((sithPlayer_g_aPlayers[i].flags & SITH_PLAYER_JOINEDGAME) != 0)
            count++;
    }
    return count;
}

// 0x00420fc0
int swrMultiplayer_NotifyHangarPlayerChange(void)
{
    swrObjHang* hang = swrEvent_FindObjectById(0x48616e67, 0); // 'Hang'
    if (hang != NULL) {
        hang->num_local_players = 1;
        hang->num_network_players = sithPlayer_g_numPlayers;
    }
    return 1;
}

// 0x00421020
int swrMultiplayer_RegisterPlayer(int playerIndex, DPID idPlayer)
{
    sithPlayer_g_aPlayers[playerIndex].playerNetId = idPlayer;
    sithPlayer_g_aPlayers[playerIndex].flags |= SITH_PLAYER_JOINEDGAME | SITH_PLAYER_UNKNOWN_04;
    sithPlayer_g_aPlayers[playerIndex].msecLastCommTime = 0;
    sithPlayer_g_numPlayers++;
    swrMultiplayer_NotifyHangarPlayerChange();
    return 1;
}

// 0x004210e0
void swrMultiplayer_ClearPlayerSlot(unsigned int playerIndex)
{
    if (playerIndex >= swrMultiplayer_MAX_PLAYERS)
        return;

    sithPlayer_g_aPlayers[playerIndex].playerNetId = 0;
    sithPlayer_g_aPlayers[playerIndex].awName[0] = L'\0';
    sithPlayer_g_aPlayers[playerIndex].unk44[0] = L'\0';
    sithPlayer_g_aPlayers[playerIndex].flags &= ~(SITH_PLAYER_JOINEDGAME | SITH_PLAYER_UNKNOWN_04);
}
