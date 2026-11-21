#include "sithMulti.h"

#include "globals.h"

#include <macros.h>
#include <Win95/stdComm.h>
#include <Dss/sithMessage.h>
#include <Swr/swrMultiplayer.h>

#include <engine_config.h>
#include <types_enums.h>

#include <string.h>

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
int sithMulti_HandleIncomingPacket(tSithMessage* pMsg)
{
    DPID idFrom;
    unsigned int size;
    int res;

    size = STDCOMM_RECV_MAX_SIZE;
    if (swrMultiplayer_enabled == 0)
        return 0;
    res = stdComm_Receive(&idFrom, &pMsg->callbackId, &size);
    if (res == STDCOMM_RECV_NONE)
        return 0;

    sithMessage_totalNetReceived++;
    if (res == STDCOMM_RECV_DATA) {
        sithMessage_totalReceivedDataSize += size;
        pMsg->dataSize = size - 4;
        pMsg->idFrom = idFrom;
        return 1;
    }
    if (res == STDCOMM_RECV_PLAYER_LEFT) {
        sithMulti_ProcessPlayerLost(idFrom);
    } else if (res == STDCOMM_RECV_PLAYER_JOINED) {
        if (swrMultiplayer_isHost != 0)
            swrMultiplayer_SendPlayerList(idFrom, 1);
    } else if (res == STDCOMM_RECV_BECAME_HOST) {
        swrMultiplayer_isHost = 1;
        sithMulti_g_serverId = sithMessage_g_localPlayerId;
        swrMultiplayer_BecomeHost(sithMessage_g_localPlayerId);
    }
    return 0;
}

// 0x00404960
HRESULT sithMulti_JoinSessionAndCreatePlayer(int sessionId, wchar_t* playerName, wchar_t* password)
{
    HRESULT res;

    res = stdComm_JoinSession(sessionId, password);
    if (res != 0)
        return res;

    swrMultiplayer_enabled = 1;
    sithMulti_playerListVerified = 0;
    sithMessage_g_localPlayerId = stdComm_CreatePlayer(playerName);
    if (sithMessage_g_localPlayerId == 0) {
        if (swrMultiplayer_enabled != 0) {
            stdComm_Close();
            swrMultiplayer_enabled = 0;
        }
        return E_FAIL;
    }
    wcsncpy(swrMultiplayer_localPlayerName, playerName, 31);
    swrMultiplayer_localPlayerName[31] = 0;
    return 0;
}

// 0x00404a20
HRESULT sithMulti_CreatePlayerFromConfig(StdCommSessionSettings* pSettings)
{
    HRESULT res;

    res = stdComm_HostSession(pSettings);
    if (res != 0)
        return res;

    sithMessage_g_localPlayerId = stdComm_CreatePlayer(pSettings->aPlayerName);
    if (sithMessage_g_localPlayerId == 0) {
        stdComm_Close();
        return E_FAIL;
    }
    swrMultiplayer_enabled = 1;
    return 0;
}

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
    swrMultiplayer_SetRacerListDisplay(0, 0, 0);
    swrMultiplayer_inSession = 0;
    swrMultiplayer_isHost = 0;
    sithMessage_g_outputstream &= ~sithMessage_STREAM_NET;
    sithMessage_g_inputstream &= ~sithMessage_STREAM_NET;
    sithMessage_CloseGame();
}

// 0x0041b950
void sithMulti_ClearAckMask(tSithMessage* message)
{
    message->ackMask = 0;
}

// 0x0041b920
void sithMulti_ResetCallbackState(void)
{
    memset(sithMulti_aPendingMessages, 0, sizeof(sithMulti_aPendingMessages));
    sithMulti_numPendingMessages = 0;
}

// 0x0041b940
unsigned int sithMulti_DefaultCallback(tSithMessage* message)
{
    return 1;
}

// 0x0041b960
void swrMultiplayer_SendAck(DPID to, unsigned short value)
{
    swrMultiplayer_ackMessage.sequenceId = 0;
    *(unsigned short*)swrMultiplayer_ackMessage.data = value;
    swrMultiplayer_ackMessage.idTo = to;
    swrMultiplayer_ackMessage.callbackId = swrMultiplayer_MSG_ACK;
    swrMultiplayer_ackMessage.dataSize = sizeof(unsigned short);
    sithMessage_NetWrite(&swrMultiplayer_ackMessage, to);
}

// 0x0041b9a0
unsigned int sithMulti_IsDuplicateMessage(DPID idFrom, unsigned int sequenceId)
{
    swrMultiplayer_SeenMessage* seen;

    for (seen = swrMultiplayer_aSeenMessages; seen < swrMultiplayer_aSeenMessages + SWR_MP_SEEN_MESSAGE_COUNT; seen++) {
        if (seen->idFrom == idFrom && seen->sequenceId == sequenceId)
            return 1;
    }
    swrMultiplayer_aSeenMessages[swrMultiplayer_seenMessageNext].idFrom = idFrom;
    swrMultiplayer_aSeenMessages[swrMultiplayer_seenMessageNext].sequenceId = sequenceId;
    swrMultiplayer_seenMessageNext++;
    if (swrMultiplayer_seenMessageNext >= SWR_MP_SEEN_MESSAGE_COUNT)
        swrMultiplayer_seenMessageNext = 0;
    return 0;
}
