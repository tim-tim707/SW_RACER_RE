#include "sithMessage.h"
#include "globals.h"

#include <macros.h>
#include <Win95/stdComm.h>
#include <Dss/sithMulti.h>
#include <swr.h>
#include <engine_config.h>
#include <stdPlatform.h>
#include <Swr/swrMultiplayer.h>
#include <Swr/swrText.h>
#include <Swr/swrUI.h>

#include <stdio.h>

// 0x004047b0
int sithMessage_NetWrite(tSithMessage* pMsg, DPID idTo)
{
    DWORD size;
    unsigned int i;
    SithPlayer* player;

    // callbackId + sequenceId ride ahead of the payload
    size = pMsg->dataSize + 4;
    if (idTo == (DPID)-1) {
        for (i = 0; i < sithPlayer_g_numPlayers; i++) {
            player = &sithPlayer_g_aPlayers[i];
            if ((player->flags & SITH_PLAYER_JOINEDGAME) != 0 && player->playerNetId != (DPID)sithMessage_g_localPlayerId) {
                stdComm_Send(sithMessage_g_localPlayerId, player->playerNetId, &pMsg->callbackId, size, 0);
                sithMessage_totalNetSent++;
                sithMessage_totalSentDataSize += size;
            }
        }
        return 1;
    }
    if (stdComm_Send(sithMessage_g_localPlayerId, idTo, &pMsg->callbackId, size, 0) < 0)
        return 0;
    sithMessage_totalNetSent++;
    sithMessage_totalSentDataSize += size;
    return 1;
}

// 0x004049e0
void sithMessage_CloseGame(void)
{
    if (sithMessage_g_localPlayerId != 0)
    {
        stdComm_DestroyPlayer(sithMessage_g_localPlayerId);
    }
    stdComm_Close();
    swrMultiplayer_enabled = 0;
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
            sithMulti_ClearAckMask(pMessage);
            // faithful: ackMask was just cleared, so every send goes out unsequenced
            if (pMessage->ackMask == 0)
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
    char text[1024];
    int playerNum;

    if (swrMultiplayer_joinLocked != 0 && idPlayer == swrMultiplayer_reservedDpid)
        stdPlatform_noop(1);

    playerNum = sithMulti_GetPlayerNum(idPlayer);
    if (playerNum < 0)
        return;

    sithMulti_RemovePlayer(playerNum);
    if (swrMultiplayer_proxyPlayer != -1) {
        swrMultiplayer_TakeOverPodAsAi(playerNum);
    } else {
        swrMultiplayer_SendEvent(SITH_MESSAGE_TO_ALL, sithMessage_SEND_GUARANTEED, 'lost', playerNum);
    }

    if (swrMultiplayer_lowestLostSlot >= playerNum)
        swrMultiplayer_lowestLostSlot = playerNum;

    if (swrMultiplayer_isHost != 0 && swrMultiplayer_aRejoinRequested[playerNum] == 0) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0423/%s has left the game."), swrMultiplayer_GetPlayerNameAscii(playerNum));
        swrMultiplayer_PostChatMessage(text);
        swrMultiplayer_SendRejoin(playerNum);
        swrUI_BroadcastToWindows(swrMultiplayer_UIEVENT_PLAYER_LEFT, playerNum);
    }
    swrMultiplayer_aRejoinRequested[playerNum] = 0;
}

// 0x0041cae0
void sithMulti_RemovePlayer(unsigned int playerNum)
{
    if (sithPlayer_g_aPlayers[playerNum].playerNetId == sithMulti_g_serverId)
        sithMulti_g_serverId = 0;
    sithPlayer_HidePlayer(playerNum);
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
