#include "sithMessage.h"
#include "globals.h"

#include <macros.h>
#include <Win95/stdComm.h>
#include <Dss/sithMulti.h>
#include <swr.h>

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
    unsigned int streams;
    int result = 1;

    streams = outstream & sithMessage_g_outputstream;
    if (streams == 0)
        return 1;
    pMessage->idFrom = playerNumber;
    if (streams & sithMessage_STREAM_NET) {
        if (dwDPFlags == 0) {
            pMessage->sequenceId = 0;
        } else {
            if (sithMessage_g_nextSequenceId == 0)
                sithMessage_g_nextSequenceId = 1;
            pMessage->sequenceId = sithMessage_g_nextSequenceId;
            sithMessage_g_nextSequenceId++;
            pMessage->idTo = idTo;
            sithMulti_ClearMessageField_Maybe(pMessage);
            // faithful: unk14 was just cleared, so every send goes out unsequenced
            if (pMessage->unk14 == 0)
                pMessage->sequenceId = 0;
        }
        result = sithMessage_NetWrite(pMessage, idTo);
    }
    if (streams & sithMessage_STREAM_NOOP)
        swr_noop2();
    return result;
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
    unsigned int i = 0;
    if (sithPlayer_g_numPlayers != 0) {
        SithPlayer* player = sithPlayer_g_aPlayers;
        do {
            if (idPlayer == player->playerNetId)
                return i;
            i++;
            player++;
        } while (i < sithPlayer_g_numPlayers);
    }
    return -1;
}

// 0x00420ff0
void sithPlayer_HidePlayer(unsigned int playerNum)
{
    sithPlayer_g_aPlayers[playerNum].playerNetId = 0;
    sithPlayer_g_aPlayers[playerNum].flags &= ~SITH_PLAYER_JOINEDGAME;
}
