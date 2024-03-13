#include "sithMessage.h"
#include "globals.h"

#include <macros.h>
#include <Win95/stdComm.h>

// 0x004047b0
int sithMessage_NetWrite(tSithMessage* pMsg, DPID idTo)
{
    HANG("TODO");
}

// 0x004049e0
void sithMessage_CloseGame(void)
{
    if (sithMessage_g_localPlayerId != 0)
    {
        stdComm_DestroyPlayer(sithMessage_g_localPlayerId);
    }
    stdComm_Close();
    multiplayer_enabled = 0;
    sithMessage_g_localPlayerId = 0;
    playerNumber = 0;
}

// 0x0041b760
int sithMessage_SendMessage(tSithMessage* pMessage, DPID idTo, unsigned int outstream, unsigned int dwDPFlags)
{
    HANG("TODO");
}

// 0x0041c780
void sithMulti_ProcessPlayerLost(DPID idPlayer)
{
    HANG("TODO");
}

// 0x0041cae0
void sithMulti_RemovePlayer(unsigned int playerNum)
{
    HANG("TODO");
}

// 0x0041d350
int sithMulti_GetPlayerNum(DPID idPlayer)
{
    HANG("TODO");
}

// 0x00420ff0
void sithPlayer_HidePlayer(unsigned int playerNum)
{
    HANG("TODO");
}
