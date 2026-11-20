#include "swrMultiplayer.h"

#include "globals.h"
#include "macros.h"

#include <General/stdString.h>
#include <Platform/wuRegistry.h>
#include <Win95/stdComm.h>
#include <Dss/sithMessage.h>
#include <Dss/sithMulti.h>
#include <Swr/swrEvent.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrSound.h>
#include <Swr/swrText.h>
#include <Swr/swrUI.h>
#include <engine_config.h>
#include <Primitives/rdMatrix.h>
#include <stdPlatform.h>

#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

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

// 0x00404a70
int swrMultiplayer_VerifyPlayerList(void* message)
{
    BYTE* cursor = ((tSithMessage*)message)->data;
    unsigned int count;
    unsigned int k;
    unsigned int i;
    DPID id;

    if (multiplayer_isHost != 0 || sithMulti_playerListVerified != 0)
        return 1;

    stdComm_UpdatePlayers(0);
    count = *cursor++;
    sithPlayer_g_numPlayers = count;
    for (k = 0; k < count; k++) {
        id = *(DPID*)cursor;
        cursor += sizeof(DPID);
        for (i = 0; i < (unsigned int)sithPlayer_g_numPlayers; i++) {
            if (stdComm_GetPlayerId(i) == id)
                break;
        }
        if (i == (unsigned int)sithPlayer_g_numPlayers)
            return 1;
    }
    sithMulti_playerListVerified = 1;
    return 1;
}

// 0x0041b700
int swrMultiplayer_InitMessaging(void)
{
    if (swrMultiplayer_messagingInitialized != 0)
        return 0;
    memset(swrCallback_multiplayer, 0, sizeof(swrCallback_multiplayer));
    memset(swrMultiplayer_aSeenMessages, 0, sizeof(swrMultiplayer_aSeenMessages));
    swrMultiplayer_seenMessageNext = 0;
    sithMessage_g_nextSequenceId = 1;
    swrMultiplayer_RegisterHandlers();
    swrMultiplayer_messagingInitialized = 1;
    return 1;
}

// 0x0041bc20
char* swrMultiplayer_FormatTimeString_Maybe(float seconds)
{
    double total;
    double rem;
    int minutes;
    int secs;
    int hundredths;

    total = seconds * (double)0.016666668f;
    minutes = (int)total;
    rem = (total - minutes) * 60.0f;
    secs = (int)rem;
    hundredths = (int)((rem - secs - -0.005f) * 100.0f);
    if (hundredths == 100) {
        hundredths = 0;
        secs++;
        // faithful: seconds are not wrapped back to 0 when they carry into the minutes
        if (secs == 60)
            minutes++;
    }
    if (minutes != 0) {
        sprintf(time_buffer, "%d:%.2d.%.2d", minutes, secs, hundredths);
        return time_buffer;
    }
    sprintf(time_buffer, "%.2d.%.2d", secs, hundredths);
    return time_buffer;
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

// 0x0041bd10
char* swrMultiplayer_GetSessionName(void)
{
    StdCommSessionSettings settings;

    if (stdComm_GetSessionSettings(&settings) != 0)
        return NULL;
    stdString_WcharToChar(swrMultiplayer_sessionName, settings.aSessionName, 64);
    return swrMultiplayer_sessionName;
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

// 0x0041c4f0
int swrMultiplayer_ResetSession(void)
{
    sithMessage_g_outputstream |= sithMessage_STREAM_NET;
    memset(swrMultiplayer_aRejoinRequested, 0, sizeof(swrMultiplayer_aRejoinRequested));
    swrMultiplayer_quitState = 0;
    sithMessage_g_inputstream |= sithMessage_STREAM_NET;
    swrMultiplayer_sessionResetUnk = 0;
    swrMultiplayer_joinLocked = 0;
    sithMulti_ResetCallbackState();
    swrObjHang_someState = swrObjHang_STATE_LEGAL;
    swrMultiplayer_hangSyncUnk1 = 0;
    swrMultiplayer_hangSyncUnk2 = 0;
    g_LoadTrackModel = 0;
    swrMultiplayer_hangSyncUnk4 = 0;
    swrMultiplayer_ResetRacerListState_Maybe();
    swrMultiplayer_proxyPlayer = -1;
    return 1;
}

// 0x0041c5c0
unsigned int swrMultiplayer_CreateSession(wchar_t* playerName, wchar_t* sessionName, wchar_t* password, char* sessionSuffix, int user3)
{
    StdCommSessionSettings settings;
    unsigned int res;
    int i;

    for (i = 0; i < SWR_MAX_RACERS; i++)
        swrMultiplayer_ClearPlayerSlot(i);

    memset(&settings, 0, sizeof(settings));
    wcsncpy(settings.aPlayerName, playerName, 31);
    settings.aPlayerName[31] = 0;
    wcsncpy(settings.aSessionName, sessionName, 31);
    settings.aSessionName[31] = 0;
    strncpy(settings.aSomething, sessionSuffix, 31);
    settings.aSomething[31] = 0;
    wcsncpy(settings.aPassword, password, 31);
    settings.aPassword[31] = 0;
    settings.user3 = user3;
    settings.maxPlayers = SWR_MAX_RACERS;
    // rand() / RAND_MAX scaled to 2^32, rounded by FISTP (overflows to INT_MIN above 2^31)
    swrMultiplayer_sessionSeed = (int)lrintf((float)rand() * 3.0518509e-05f * 4294967296.0f);
    settings.user2 = 1;
    settings.user1 = swrMultiplayer_sessionSeed;

    if (multiplayer_enabled != 0) {
        res = swrMultiplayer_SetSessionDesc(&settings);
        if (res != 0) {
            stdComm_Close();
            return res;
        }
    } else {
        res = sithMulti_CreatePlayerFromConfig(&settings);
        if (res != 0)
            return res;
    }

    multiplayer_isHost = 1;
    multiplayer_inSession = 1;
    sithMulti_g_serverUnk = 0;
    sithMulti_g_serverId = sithMessage_g_localPlayerId;
    stdComm_UpdatePlayers(0);
    sithPlayer_g_numPlayers = 0;
    swrMultiplayer_RegisterPlayer(0, sithMessage_g_localPlayerId);
    playerNumber = 0;
    wcsncpy(sithPlayer_g_aPlayers[0].awName, playerName, 31);
    sithPlayer_g_aPlayers[0].awName[31] = 0;
    wcsncpy(swrMultiplayer_localPlayerName, playerName, 31);
    swrMultiplayer_localPlayerName[31] = 0;
    return 0;
}

// 0x0041d3b0
void swrMultiplayer_InitPlayerStatus(int slot)
{
    swrMultiplayer_ReadyStatus* status;
    int* payload;

    if (multiplayer_enabled == 0)
        return;
    status = &swrMultiplayer_aReadyStatus[slot];
    status->state = swrMultiplayer_READY_IDLE;
    status->readyMask = 0;
    status->sent = 0;
    status->state = swrMultiplayer_READY_WAITING;
    if (multiplayer_isHost != 0) {
        payload = (int*)swrMultiplayer_message.data;
        payload[0] = slot;
        swrMultiplayer_message.length = 0;
        swrMultiplayer_message.callbackId = swrMultiplayer_MSG_READY_MASK;
        swrMultiplayer_message.dataSize = 4;
        sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
    }
}

// 0x0041d4e0
void swrMultiplayer_SetPlayerStatusBit(int slot, int value)
{
    swrMultiplayer_ReadyStatus* status;

    if (multiplayer_enabled == 0)
        return;
    status = &swrMultiplayer_aReadyStatus[slot];
    if (status->state == swrMultiplayer_READY_IDLE)
        return;
    if (status->sent == 0 || ((status->readyMask >> playerNumber) & 1) != (unsigned int)(value != 0)) {
        status->sent = 1;
        swrMultiplayer_SendReadyFlag(slot, value != 0);
    }
}

// 0x0041d640
int swrMultiplayer_PollPlayerStatus(int player)
{
    if (multiplayer_enabled != 0) {
        swrMultiplayer_PumpPackets();
        swrMultiplayer_UpdateReadyState(player);
        if (swrMultiplayer_aReadyStatus[player].state != swrMultiplayer_READY_IDLE) {
            if (swrMultiplayer_aReadyStatus[player].state != swrMultiplayer_READY_ALL)
                return 0;
            swrMultiplayer_ClearPlayerStatus(player);
        }
    }
    return 1;
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
    swrScore* score;
    rdMatrix44* transform;
    int* record;
    int numRacers;
    int slot;
    int col;
    int row;
    int lap;

    numRacers = 0;
    for (slot = 0; slot < SWR_MAX_RACERS; slot++) {
        if (swrScores[slot].identifier == 'Locl' || swrScores[slot].identifier == 'AAII')
            numRacers++;
    }
    if (numRacers == 0)
        return;

    ((int*)swrMultiplayer_message.data)[0] = numRacers;
    record = (int*)swrMultiplayer_message.data + 1;
    for (slot = 0; slot < SWR_MAX_RACERS; slot++) {
        score = &swrScores[slot];
        if (score->identifier != 'Locl' && score->identifier != 'AAII')
            continue;

        transform = &swrMultiplayer_aLocalPodTransform[slot];
        record[0] = slot;
        // the packet carries the matrix column by column
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++)
                ((float*)record)[1 + col * 4 + row] = (&transform->vA.x)[row * 4 + col];
        }
        ((float*)record)[17] = swrMultiplayer_aRemoteSpeed[slot];
        ((float*)record)[18] = swrMultiplayer_aRemoteLapComp[slot];
        ((float*)record)[19] = swrMultiplayer_aRemoteLapCompMax[slot];
        record[20] = swrMultiplayer_aRemoteLap[slot];
        record[21] = (short)score->results_P1_Position;
        lap = score->results_P1_Lap;
        record[22] = lap;
        ((float*)record)[23] = (&score->results_P1_Lap1)[lap];
        ((float*)record)[24] = score->results_P1_total_time;
        record[25] = score->identifier;
        record[26] = score->obj_test_ptr->flags0 & swrObjTest_FLAG0_REMOTE_SYNCED;
        record[27] = score->obj_test_ptr->flags1 & swrObjTest_FLAG1_REMOTE_PUBLISHED;
        if (swrMultiplayer_aPodStatus[slot][0] != SWR_MP_POD_STATUS_PARKED) {
            swrMultiplayer_aPodStatus[slot][0] = record[21];
            swrMultiplayer_aPodStatus[slot][1] = record[22];
            swrMultiplayer_aPodStatus[slot][2] = record[23];
            swrMultiplayer_aPodStatus[slot][3] = record[24];
        }
        record += SWR_MP_POD_STATE_RECORD_INTS;
    }
    swrMultiplayer_message.dataSize = (char*)record - (char*)swrMultiplayer_message.data;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_PLAYER_STATES;
    sithMessage_SendMessage(&swrMultiplayer_message, (DPID)-1, sithMessage_STREAM_NET, 0);
}

// 0x0041dc30
void swrMultiplayer_RacerPick(int a)
{
    int* payload = (int*)swrMultiplayer_message.data;

    payload[0] = playerNumber;
    payload[1] = a;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_RACER_PICK;
    swrMultiplayer_message.dataSize = 8;
    sithMessage_SendMessage(&swrMultiplayer_message, sithMulti_g_serverId, sithMessage_STREAM_NET, 0);
    (&multiplayer_racer1_id)[playerNumber] = a;
    swrUI_BroadcastToWindows(swrMultiplayer_MSG_RACER_PICK, (int)swrMultiplayer_message.data);
}

// 0x0041e5a0
void swrMultiplayer_BroadcastPlayerState(void)
{
    int* payload = (int*)swrMultiplayer_message.data;

    if (multiplayer_enabled == 0)
        return;
    payload[0] = swrObjHang_someState;
    payload[1] = swrMultiplayer_hangSyncUnk1;
    payload[2] = swrMultiplayer_hangSyncUnk2;
    payload[3] = g_LoadTrackModel;
    payload[4] = swrMultiplayer_hangSyncUnk4;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_RACE_SETTINGS;
    swrMultiplayer_message.dataSize = 0x14;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, 0);
}

// 0x0041e660
void swrMultiplayer_BroadcastRaceReset(void)
{
    if (multiplayer_enabled == 0)
        return;
    memset(multiplayer_aPlayerQuit, 0, sizeof(multiplayer_aPlayerQuit));
    memset(multiplayer_aPlayerFinished, 0, sizeof(multiplayer_aPlayerFinished));
    swrMultiplayer_ignoreEvents = 0;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_RACE_RESET;
    swrMultiplayer_message.dataSize = 0;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, 0);
}

// 0x00420830
int swrMultiplayer_Initialize(void)
{
    unsigned int numConnections;
    unsigned int connectionIndex;
    StdCommConnection connection;

    if (swrMulti_Initialized == 0) {
        numConnections = stdComm_GetNumConnections();
        for (connectionIndex = 0; connectionIndex < numConnections; connectionIndex++) {
            stdComm_GetConnection(connectionIndex, &connection);
            if (memcmp(&connection.guid, &IPX_GUID, sizeof(GUID)) == 0) {
                stdComm_IPX_connectionIndex = connectionIndex;
                sithMulti_InitializeConnection(connectionIndex);
                swrMulti_Initialized = 1;
                return 1;
            }
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

// 0x00420990
void swrMultiplayer_UpdateRacerSelectUI(swrUI_unk* page, swrUI_unk* list)
{
    swrUI_unk* selected;
    swrUI_unk* element;
    int slot;
    char podName[1024];

    if (list == NULL || page == NULL)
        return;
    selected = swrUI_GetSelectedItem(list);
    if (selected == NULL)
        return;
    slot = selected->id;
    if (slot == playerNumber) {
        swrUI_EnableElement(swrUI_GetById(page, SWR_UI_ID_MP_PODRACER));
        swrUI_DisableElement(swrUI_GetById(page, SWR_UI_ID_MP_BOOT));
    } else {
        swrUI_DisableElement(swrUI_GetById(page, SWR_UI_ID_MP_PODRACER));
        element = swrUI_GetById(page, SWR_UI_ID_MP_BOOT);
        if (multiplayer_track_change_permission != 0 && multiplayer_race_button_toggle[slot] != 0)
            swrUI_EnableElement(element);
        else
            swrUI_DisableElement(element);
    }
    element = swrUI_GetById(page, SWR_UI_ID_MP_RACER_NAME);
    if (element != NULL) {
        swrText_FormatPodName(swrMultiplayer_GetRacerId(slot), podName, sizeof(podName));
        swrUI_RunCallbacksScreenText(element, podName, 0);
    }
}

// 0x00420a90
void swrMultiplayer_FillLastPlayerName(swrUI_unk* field)
{
    char computerName[256];
    char name[256];
    DWORD size;

    memset(computerName, 0, sizeof(computerName));
    size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    wuRegistry_GetString("Last Player", name, sizeof(name), computerName);
    swrUI_RunCallbacksScreenText(field, name, 0);
}

// 0x00420b00
void swrMultiplayer_SaveLastPlayerName(swrUI_unk* field)
{
    char name[256];
    DWORD size;

    memset(name, 0, sizeof(name));
    size = sizeof(name);
    if (field == NULL) {
        memset(name, 0, sizeof(name));
        GetComputerNameA(name, &size);
    } else {
        swrUI_GetAllocatedString(field, name, sizeof(name));
    }
    wuRegistry_SetString("Last Player", name);
}

// 0x00420b80
void swrMultiplayer_FillDefaultGameName(swrUI_unk* field)
{
    char name[256];
    char defaultName[256];
    DWORD size;

    memset(name, 0, sizeof(name));
    size = sizeof(name);
    GetComputerNameA(name, &size);
    sprintf(defaultName, swrText_Translate("/MONDOTEXT_H_0426/%s's Game"), name);
    memset(name, 0, sizeof(name));
    wuRegistry_GetString("Last Game", name, sizeof(name), defaultName);
    swrUI_RunCallbacksScreenText(field, name, 0);
}

// 0x00420c20
void swrMultiplayer_SetLastGame(char* str)
{
    wuRegistry_SetString("Last Game", str);
}

// Looks like
//----- (004C2EB0) --------------------------------------------------------
// 0x00486e60
unsigned int swrMultiplayer_SetSessionDesc(StdCommSessionSettings* pSettings)
{
    DWORD size;
    LPDPSESSIONDESC2 desc;
    HRESULT res;
    wchar_t sessionName[128];

    res = IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, NULL, &size);
    if (res != DPERR_BUFFERTOOSMALL)
        return res;
    // faithful: desc is never freed
    desc = (LPDPSESSIONDESC2)(*stdPlatform_hostServices_ptr->alloc)(size);
    res = IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, desc, &size);
    if (res < 0)
        return res;

    desc->dwMaxPlayers = pSettings->maxPlayers;
    _snwprintf(sessionName, 128, L"%s:%S", pSettings->aSessionName, pSettings->aSomething);
    desc->lpszSessionName = sessionName;
    if (wcslen(pSettings->aPassword) != 0)
        desc->lpszPassword = pSettings->aPassword;
    desc->dwUser1 = pSettings->user1;
    desc->dwUser3 = pSettings->user2;
    desc->dwUser4 = pSettings->user3;
    desc->dwFlags |= DPSESSION_OPTIMIZELATENCY | DPSESSION_NOPRESERVEORDER | DPSESSION_DIRECTPLAYPROTOCOL | DPSESSION_NODATAMESSAGES | DPSESSION_KEEPALIVE | DPSESSION_MIGRATEHOST;
    res = IDirectPlayX_SetSessionDesc(stdComm_pDirectPlay, desc, 0);
    return res < 0 ? res : 0;
}

// 0x0041dd50
void swrMultiplayer_BroadcastRoster(int hang, void* roster)
{
    int* begin = (int*)roster;
    int* payload;
    int i;

    if (multiplayer_enabled == 0)
        return;
    g_objHang1 = (swrObjHang*)hang;
    // ApplyRosterRequest passes swrMultiplayer_raceBegin itself (self-copy, rep movsd in the EXE)
    for (i = 0; i < 10; i++)
        swrMultiplayer_raceBegin[i] = begin[i];
    swrMultiplayer_raceBeginValid = 1;
    payload = (int*)swrMultiplayer_message.data;
    for (i = 2; i < 10; i++)
        *payload++ = begin[i];
    // begin[2] = numRacers
    for (i = 0; i < begin[2]; i++)
        *payload++ = (&((swrObjHang*)hang)->vehiclePlayer)[i];
    for (i = 0; i < begin[2]; i++)
        *payload++ = swrMultiplayer_rosterIdentifiers[i];
    swrMultiplayer_message.dataSize = (char*)payload - (char*)swrMultiplayer_message.data;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_ROSTER;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, 0);
}

// 0x0041de50
void swrMultiplayer_SetRosterEntry(int index, int value)
{
    swrMultiplayer_rosterIdentifiers[index] = value;
}

// Variadic: each event pushes its own payload (floats arrive promoted to double).
// 0x0041df10
void swrMultiplayer_SendEvent(DPID to, unsigned int flags, int eventMagic, ...)
{
    char text[1024];
    va_list args;
    int* payload;
    int* end;
    rdVector3* vec;
    int count;
    int i;

    if (multiplayer_enabled == 0)
        return;

    payload = (int*)swrMultiplayer_message.data;
    payload[0] = playerNumber;
    payload[1] = eventMagic;
    end = &payload[2];
    va_start(args, eventMagic);
    switch (eventMagic) {
    case 'Sprk':
        payload[2] = va_arg(args, int);
        *(float*)&payload[3] = (float)va_arg(args, double);
        *(float*)&payload[4] = (float)va_arg(args, double);
        vec = va_arg(args, rdVector3*);
        *(rdVector3*)&payload[5] = *vec;
        vec = va_arg(args, rdVector3*);
        *(rdVector3*)&payload[8] = *vec;
        payload[11] = va_arg(args, int);
        end = &payload[12];
        break;
    case 'ctrl':
    case 'rejn':
        break;
    case 'fini':
        multiplayer_aPlayerFinished[playerNumber] = 1;
        break;
    case 'flam':
    case 'hell':
    case 'lost':
        payload[2] = va_arg(args, int);
        end = &payload[3];
        break;
    case 'plap':
        payload[2] = va_arg(args, int);
        *(float*)&payload[3] = (float)va_arg(args, double);
        end = &payload[4];
        break;
    case 'prxy':
        count = 0;
        for (i = 0; i < SWR_MAX_RACERS; i++) {
            if (swrScores[i].identifier == 'AAII' || swrScores[i].identifier == 'Locl')
                count++;
        }
        payload[2] = count;
        end = &payload[3];
        for (i = 0; i < SWR_MAX_RACERS; i++) {
            if (swrScores[i].identifier == 'AAII' || swrScores[i].identifier == 'Locl')
                *end++ = i;
        }
        break;
    case 'quit':
        multiplayer_aPlayerQuit[playerNumber] = 1;
        swrMultiplayer_aPodStatus[playerNumber][0] = SWR_MP_POD_STATUS_PARKED;
        swrMultiplayer_aPodStatus[playerNumber][1] = 0;
        swrMultiplayer_aPodStatus[playerNumber][2] = 0;
        swrMultiplayer_aPodStatus[playerNumber][3] = 0;
        break;
    case 'taun':
        payload[2] = va_arg(args, int);
        payload[3] = va_arg(args, int);
        payload[4] = va_arg(args, int);
        end = &payload[5];
        break;
    case 'trig':
        payload[2] = va_arg(args, int);
        payload[3] = va_arg(args, int);
        end = &payload[4];
        break;
    default:
        va_end(args);
        return;
    }
    va_end(args);

    swrMultiplayer_message.dataSize = (BYTE*)end - swrMultiplayer_message.data;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_EVENT;
    sithMessage_SendMessage(&swrMultiplayer_message, to, sithMessage_STREAM_NET, flags);

    if (eventMagic == 'quit') {
        if (multiplayer_isHost != 0 || swrMultiplayer_proxyPlayer == playerNumber)
            swrMultiplayer_SendProxy();
        multiplayer_aPlayerQuit[playerNumber] = 1;
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0500/%s has left the race."), swrMultiplayer_GetPlayerNameAscii(playerNumber));
        swrMultiplayer_PostChatMessage(text);
    }
}

// 0x0041d380
DPID swrMultiplayer_GetPlayerDpid(unsigned int playerNum)
{
    if (playerNum < sithPlayer_g_numPlayers)
        return sithPlayer_g_aPlayers[playerNum].playerNetId;
    return -1;
}

// 0x00420c40
void swrMultiplayer_SetRaceButtonToggle(swrUI_unk* page, int* pair)
{
    // pair[0] = player slot, pair[1] = ready flag
    multiplayer_race_button_toggle[pair[0]] = pair[1];
    swrMultiplayer_UpdateStartButtonState(page);
}

// 0x00420c60
void swrMultiplayer_UpdateStartButtonState(swrUI_unk* page)
{
    int ready = 0;
    swrUI_unk* button;

    // Scans every slot, not just sithPlayer_g_numPlayers
    for (int i = 0; i < swrMultiplayer_MAX_PLAYERS; i++) {
        if ((sithPlayer_g_aPlayers[i].flags & SITH_PLAYER_JOINEDGAME) != 0 && multiplayer_race_button_toggle[i] != 0)
            ready++;
    }
    button = swrUI_GetById(page, swrUI_WINDOW_MP_RACE_BUTTON);
    if (ready == swrMultiplayer_GetActivePlayerCount()) {
        swrUI_EnableElement(button);
        return;
    }
    swrUI_DisableElement(button);
}

// 0x00420cc0
void swrMultiplayer_PopulateRacerList(void)
{
    unsigned int count;
    unsigned int slot;
    swrUI_unk* list;
    swrUI_unk* row;

    count = swrMultiplayer_GetActivePlayerCount();
    list = swrUI_GetById(NULL, SWR_UI_ID_MP_RESULTS_LIST);
    swrUI_RefreshListSelection(list);
    for (slot = 0; slot < count; slot++) {
        row = swrUI_CreateRaceResultRow(slot);
        row->result_player_slot = slot;
        swrUI_AddListElement(list, row);
    }
}

// 0x00420d10
void swrMultiplayer_UpdatePlayerListItems(void)
{
    swrUI_unk* list;
    swrUI_unk* row;
    int slot;

    list = swrUI_GetById(NULL, SWR_UI_ID_MP_RESULTS_LIST);
    for (row = list->next; row != NULL; row = row->next2) {
        slot = row->result_player_slot;
        if (multiplayer_aPlayerQuit[slot] == 0) {
            // raw dword copies: slots 2/3 hold float times in an int array
            row->result_lap = swrMultiplayer_aPodStatus[slot][1];
            row->result_current_time = *(float*)&swrMultiplayer_aPodStatus[slot][2];
            row->result_total_time = *(float*)&swrMultiplayer_aPodStatus[slot][3];
            row->sort_key = swrMultiplayer_aPodStatus[slot][0] - 1;
        } else {
            row->sort_key = SWR_UI_RACE_RESULT_RETIRED;
        }
    }
    swrUI_SortListItems(list);
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
    sithPlayer_g_aPlayers[playerIndex].pingMs = 0;
    sithPlayer_g_numPlayers++;
    swrMultiplayer_NotifyHangarPlayerChange();
    return 1;
}

// 0x00421070
void swrMultiplayer_SetLocalPlayer(int playerIndex)
{
    SithPlayer* player;

    playerNumber = playerIndex;
    sithPlayer_g_localPlayer = &sithPlayer_g_aPlayers[playerIndex];
    player = sithPlayer_g_localPlayer;
    wcsncpy(player->awName, swrMultiplayer_localPlayerName, ARRAYSIZE(player->awName) - 1);
    player->awName[ARRAYSIZE(player->awName) - 1] = 0;
    wcsncpy(player->unk44, swrMultiplayer_localPlayerUnk44, ARRAYSIZE(player->unk44) - 1);
    player->unk44[ARRAYSIZE(player->unk44) - 1] = 0;
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

// 0x0041bd60
void swrMultiplayer_ResetRacerListState_Maybe(void)
{
    memset(swrMultiplayer_chatLineTimeLeftMs, 0, sizeof(swrMultiplayer_chatLineTimeLeftMs));
    memset(swrMultiplayer_chatLineState, 0, sizeof(swrMultiplayer_chatLineState));
    memset(swrMultiplayer_chatLines, 0, sizeof(swrMultiplayer_chatLines));
}

// 0x0041bd90
void swrMultiplayer_SetRacerListDisplay(int enabled, int x, int y)
{
    int i;

    swrMultiplayer_chatX = x;
    swrMultiplayer_chatY = y;
    swrMultiplayer_chatEnabled = enabled;
    for (i = 0; i < SWR_MP_CHAT_LINE_COUNT; i++) {
        swrMultiplayer_FreeRacerSlot(i);
    }
}

// 0x0041bdd0
void swrMultiplayer_OpenChatInput(void)
{
    if (swrMultiplayer_chatEnabled == 0) {
        return;
    }

    swrMultiplayer_TickRacerListOverlay();
    swrMultiplayer_chatCaret = SWR_MP_CHAT_INPUT_PREFIX_LEN;
    memset(swrMultiplayer_chatInput, 0, sizeof(swrMultiplayer_chatInput));
    memcpy(swrMultiplayer_chatInput, "~F0]", SWR_MP_CHAT_INPUT_PREFIX_LEN);
    swrUI_SetCaretActive(1);
    swrUI_SetCaretRect(swrMultiplayer_chatX, swrMultiplayer_chatY, 1, 7);
    swrMultiplayer_chatSavedUiInputActive = swrControl_uiInputActive;
    swrControl_uiInputActive = 1;
    swrMultiplayer_chatSkipNextKey = 1;
    swrMultiplayer_chatInputOpen = 1;
    swrConfig_keyboard_enabled = 0;
}

// 0x0041be80
void swrMultiplayer_HandleChatKey(int key)
{
    char message[1024];
    int width;

    if (swrMultiplayer_chatEnabled == 0 || swrMultiplayer_chatInputOpen == 0) {
        return;
    }
    if (swrMultiplayer_chatSkipNextKey != 0) {
        swrMultiplayer_chatSkipNextKey = 0;
        return;
    }

    // One switch serves both virtual-key and character codes, so '#', '$', '%', '\'' and '.'
    // collide with End/Home/Left/Right/Delete and can't be typed.
    switch (key) {
    case VK_BACK:
        if ((unsigned int)swrMultiplayer_chatCaret > SWR_MP_CHAT_INPUT_PREFIX_LEN) {
            memmove(&swrMultiplayer_chatInput[swrMultiplayer_chatCaret - 1], &swrMultiplayer_chatInput[swrMultiplayer_chatCaret], SWR_MP_CHAT_INPUT_SIZE - swrMultiplayer_chatCaret);
            swrMultiplayer_chatCaret--;
            swrMultiplayer_chatInput[SWR_MP_CHAT_INPUT_SIZE - 1] = '\0';
        }
        break;
    case VK_RETURN:
        swrUI_SetCaretActive(0);
        swrMultiplayer_chatInputOpen = 0;
        swrConfig_keyboard_enabled = 1;
        swrControl_uiInputActive = swrMultiplayer_chatSavedUiInputActive;
        sprintf(message, swrText_Translate("/MONDOTEXT_H_0393/%s says '%s'"), swrMultiplayer_GetPlayerNameAscii(playerNumber), &swrMultiplayer_chatInput[SWR_MP_CHAT_INPUT_PREFIX_LEN]);
        swrMultiplayer_PostChatMessage(message);
        break;
    case VK_ESCAPE:
        swrUI_SetCaretActive(0);
        swrControl_uiInputActive = swrMultiplayer_chatSavedUiInputActive;
        swrMultiplayer_chatInputOpen = 0;
        swrConfig_keyboard_enabled = 1;
        break;
    case VK_END:
        swrMultiplayer_chatCaret = strlen(swrMultiplayer_chatInput);
        break;
    case VK_HOME:
        // Faithful: lands before the "~F0]" prefix.
        swrMultiplayer_chatCaret = 0;
        break;
    case VK_LEFT:
        if (swrMultiplayer_chatCaret != 0) {
            swrMultiplayer_chatCaret--;
        }
        break;
    case VK_RIGHT:
        if ((unsigned int)swrMultiplayer_chatCaret < strlen(swrMultiplayer_chatInput)) {
            swrMultiplayer_chatCaret++;
        }
        break;
    case VK_DELETE:
        break;
    default:
        if (isalnum(key) || key == ' ') {
            if ((unsigned int)swrMultiplayer_chatCaret < SWR_MP_CHAT_INPUT_SIZE && (key != ' ' || swrMultiplayer_chatCaret != 0)) {
                memmove(&swrMultiplayer_chatInput[swrMultiplayer_chatCaret + 1], &swrMultiplayer_chatInput[swrMultiplayer_chatCaret], (SWR_MP_CHAT_INPUT_SIZE - 1) - swrMultiplayer_chatCaret);
                swrMultiplayer_chatInput[swrMultiplayer_chatCaret] = (char)key;
                swrMultiplayer_chatCaret++;
            }
        }
        break;
    }

    width = swrUI_GetSubstringWidth(&swrMultiplayer_chatInput[SWR_MP_CHAT_INPUT_PREFIX_LEN], 0, 0, swrMultiplayer_chatCaret - SWR_MP_CHAT_INPUT_PREFIX_LEN);
    swrUI_SetCaretRect(width + 5 + swrMultiplayer_chatX, swrMultiplayer_chatInputY, 1, 7);
}

// 0x0041c130
void swrMultiplayer_OnChatReceived(char* text)
{
    swrUI_unk* list;
    unsigned int count;

    swrMultiplayer_TickRacerListOverlay();
    swrMultiplayer_AddChatMessage(text);
    list = swrUI_GetById(NULL, SWR_UI_ID_MP_CHAT_LIST);
    swrUI_DrawWrappedText(list, text, 0);
    count = swrUI_CountSelectableItems(list);
    if (count > SWR_MP_CHAT_VISIBLE_LINES) {
        // +0x10 of the list state: first visible row
        *(unsigned int*)(list->unk4f4 + 0x10) = count - SWR_MP_CHAT_VISIBLE_LINES;
        swrUI_RefreshListLayout(list);
    }
}

// 0x0041c190
void swrMultiplayer_PostChatMessage(char* text)
{
    if (text != NULL && text[0] != '\0') {
        swrMultiplayer_SendChatMessage(text, -1, playerNumber);
        swrMultiplayer_OnChatReceived(text);
    }
}

// 0x0041c260
void swrMultiplayer_ResetRaceSettings(void)
{
    int i;

    for (i = 0; i < SWR_MAX_RACERS; i++)
        (&multiplayer_racer1_id)[i] = i;
    multiplayer_track_select = swrRace_TRACK_BOONTA_TRAINING_COURSE;
    multiplayer_numAiRacers = 0;
    multiplayer_laps = 3;
    multiplayer_raceSettingsUnk = 10000;
}

// 0x0041c760
void swrMultiplayer_ClearHostState(void)
{
    multiplayer_inSession = 1;
    sithMulti_g_serverId = 0;
    multiplayer_isHost = 0;
}

// 0x0041c870
void swrMultiplayer_SendRejoin(unsigned int playerNum)
{
    int target;
    int i;

    if (playerNum < sithPlayer_g_numPlayers - 1) {
        swrMultiplayer_rejoinSlot = SWR_MP_NO_SLOT;
        target = SWR_MP_NO_SLOT;
        for (i = 0; i < swrMultiplayer_MAX_PLAYERS; i++) {
            if (swrMultiplayer_IsPlayerActive(i) != 0)
                target = i;
        }
        if (target != SWR_MP_NO_SLOT) {
            swrMultiplayer_aRejoinRequested[target] = 1;
            swrMultiplayer_SendEvent(swrMultiplayer_GetPlayerDpid(target), sithMessage_SEND_GUARANTEED, 'rejn');
        }
    }
}

// 0x0041c8e0
void swrMultiplayer_SendProxy(void)
{
    int i;

    // no break: every eligible player gets the event and the last one keeps the proxy role
    for (i = 0; i < swrMultiplayer_MAX_PLAYERS; i++) {
        if (swrMultiplayer_IsPlayerActive(i) != 0 && i != playerNumber && multiplayer_aPlayerQuit[i] == 0) {
            swrMultiplayer_proxyPlayer = i;
            swrMultiplayer_SendEvent(swrMultiplayer_GetPlayerDpid(i), sithMessage_SEND_GUARANTEED, 'prxy');
            swrMultiplayer_MarkAllPodsRemote_Maybe();
        }
    }
}

// 0x0041c940
void swrMultiplayer_MarkAllPodsRemote_Maybe(void)
{
    int i;
    swrRace* pod;

    for (i = 0; i < swrMultiplayer_MAX_PLAYERS; i++) {
        pod = swrScores[i].obj_test_ptr;
        if (pod != NULL && (pod->flags0 & swrObjTest_FLAG0_AI) != 0) {
            pod->flags0 = (pod->flags0 & ~swrObjTest_FLAG0_AI) | swrObjTest_FLAG0_REMOTE;
            pod->score_ptr->identifier = 'REMO';
            swrMultiplayer_rosterIdentifiers[i] = 'REMO';
        }
    }
}

// 0x0041c990
void swrMultiplayer_MarkPodLocal_Maybe(int playerIndex)
{
    swrRace* pod;

    if (multiplayer_isHost != 0 || swrMultiplayer_proxyPlayer != -1) {
        pod = swrScores[playerIndex].obj_test_ptr;
        if (pod != NULL) {
            pod->flags0 = (pod->flags0 & ~swrObjTest_FLAG0_REMOTE) | swrObjTest_FLAG0_AI;
            pod->score_ptr->identifier = 'AAII';
            swrMultiplayer_rosterIdentifiers[playerIndex] = 'AAII';
        }
    }
}

// 0x0041ca50
void swrMultiplayer_BecomeHost(DPID newHost)
{
    char text[1024];
    int playerNum;

    multiplayer_track_change_permission = 1;
    multiplayer_isHost = 1;
    swrMultiplayer_SendEvent(SITH_MESSAGE_TO_ALL, sithMessage_SEND_GUARANTEED, 'ctrl');
    playerNum = sithMulti_GetPlayerNum(newHost);
    sprintf(text, swrText_Translate("/MONDOTEXT_H_0425/%s is now the host."), swrMultiplayer_GetPlayerNameAscii(playerNum));
    swrMultiplayer_PostChatMessage(text);
    swrMultiplayer_BroadcastRaceSettings();
    swrUI_BroadcastToWindows(0x40, playerNum);
}

// 0x0041cb20
void swrMultiplayer_SendPlayerName(DPID playerId, int playerIndex, DPID to)
{
    swrMultiplayer_NameRecord* record = (swrMultiplayer_NameRecord*)swrMultiplayer_message.data;

    record->playerIndex = playerIndex;
    record->playerId = playerId;
    wcsncpy(record->name, sithPlayer_g_aPlayers[playerIndex].awName, SWR_MP_WIRE_NAME_LEN);
    record->name[SWR_MP_WIRE_NAME_LEN] = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_PLAYER_NAME;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.dataSize = sizeof(swrMultiplayer_NameRecord);
    sithMessage_SendMessage(&swrMultiplayer_message, to, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
}

// 0x0041cb90
int swrMultiplayer_ApplyPlayerName(void* message)
{
    swrMultiplayer_NameRecord* record = (swrMultiplayer_NameRecord*)((tSithMessage*)message)->data;
    SithPlayer* player = &sithPlayer_g_aPlayers[record->playerIndex];

    wcsncpy(player->awName, record->name, SWR_MP_WIRE_NAME_LEN);
    player->awName[SWR_MP_WIRE_NAME_LEN] = 0;
    return 1;
}

// 0x0041cbd0
void swrMultiplayer_SendPlayerList(DPID to, unsigned int reliable)
{
    char text[SWR_MP_WIRE_NAME_LEN + 1];
    BYTE* cursor = swrMultiplayer_message.data;
    SithPlayer* player;
    unsigned int i;

    *(DPID*)cursor = sithMulti_g_serverId;
    cursor += sizeof(DPID);
    *(short*)cursor = (short)sithPlayer_g_numPlayers;
    cursor += sizeof(short);
    for (i = 0; i < (unsigned int)sithPlayer_g_numPlayers; i++) {
        player = &sithPlayer_g_aPlayers[i];
        *(int*)cursor = player->flags;
        cursor += sizeof(int);
        if ((player->flags & SITH_PLAYER_UNKNOWN_04) == 0)
            continue;
        stdString_WcharToChar(text, player->awName, SWR_MP_WIRE_NAME_LEN);
        text[SWR_MP_WIRE_NAME_LEN] = 0;
        strncpy((char*)cursor, text, SWR_MP_WIRE_NAME_LEN);
        cursor[SWR_MP_WIRE_NAME_LEN] = 0;
        cursor += SWR_MP_WIRE_NAME_LEN + 1;
        stdString_WcharToChar(text, player->unk44, SWR_MP_WIRE_NAME_LEN);
        text[SWR_MP_WIRE_NAME_LEN] = 0;
        strncpy((char*)cursor, text, SWR_MP_WIRE_NAME_LEN);
        cursor[SWR_MP_WIRE_NAME_LEN] = 0;
        cursor += SWR_MP_WIRE_NAME_LEN + 1;
        *(DPID*)cursor = player->playerNetId;
        cursor += sizeof(DPID);
        *(int*)cursor = player->unk8c;
        cursor += sizeof(int);
    }
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_PLAYER_LIST;
    swrMultiplayer_message.dataSize = cursor - swrMultiplayer_message.data;
    sithMessage_SendMessage(&swrMultiplayer_message, to, sithMessage_STREAM_NET, reliable);
}

// 0x0041ccd0
int swrMultiplayer_ApplyPlayerList(void* message)
{
    char text[SWR_MP_WIRE_NAME_LEN + 1];
    BYTE* cursor = ((tSithMessage*)message)->data;
    SithPlayer* player;
    unsigned int i;
    int count;

    // faithful: zeroed, then overwritten from the payload
    sithMulti_g_serverId = 0;
    sithMulti_g_serverUnk = 0;
    sithMulti_g_serverId = *(DPID*)cursor;
    cursor += sizeof(DPID);
    count = *(short*)cursor;
    cursor += sizeof(short);
    if (count != sithPlayer_g_numPlayers) {
        sithPlayer_g_numPlayers = count;
        swrMultiplayer_NotifyHangarPlayerChange();
    }
    for (i = 0; i < (unsigned int)sithPlayer_g_numPlayers; i++) {
        player = &sithPlayer_g_aPlayers[i];
        player->flags = *(int*)cursor;
        cursor += sizeof(int);
        if ((player->flags & SITH_PLAYER_UNKNOWN_04) == 0)
            continue;
        strncpy(text, (char*)cursor, SWR_MP_WIRE_NAME_LEN);
        text[SWR_MP_WIRE_NAME_LEN] = 0;
        cursor += SWR_MP_WIRE_NAME_LEN + 1;
        stdString_CharToWchar(player->awName, text, SWR_MP_WIRE_NAME_LEN);
        player->awName[SWR_MP_WIRE_NAME_LEN] = 0;
        strncpy(text, (char*)cursor, SWR_MP_WIRE_NAME_LEN);
        text[SWR_MP_WIRE_NAME_LEN] = 0;
        cursor += SWR_MP_WIRE_NAME_LEN + 1;
        stdString_CharToWchar(player->unk44, text, SWR_MP_WIRE_NAME_LEN);
        player->unk44[SWR_MP_WIRE_NAME_LEN] = 0;
        player->playerNetId = *(DPID*)cursor;
        cursor += sizeof(DPID);
        player->unk8c = *(int*)cursor;
        cursor += sizeof(int);
        if (player->playerNetId == sithMessage_g_localPlayerId)
            swrMultiplayer_SetLocalPlayer(i);
    }
    return 1;
}

// 0x0041cde0
void swrMultiplayer_SendPlayerJoin(DPID to)
{
    swrMultiplayer_JoinRecord* record = (swrMultiplayer_JoinRecord*)swrMultiplayer_message.data;

    wcsncpy(record->name, swrMultiplayer_localPlayerName, SWR_MP_WIRE_NAME_LEN);
    record->name[SWR_MP_WIRE_NAME_LEN] = 0;
    wcsncpy(record->unk44, swrMultiplayer_localPlayerUnk44, ARRAYSIZE(record->unk44) - 1);
    record->unk44[ARRAYSIZE(record->unk44) - 1] = 0;
    record->unk8c = swrMultiplayer_localPlayerUnk8c;
    swrMultiplayer_message.dataSize = sizeof(swrMultiplayer_JoinRecord);
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_PLAYER_JOIN;
    sithMessage_SendMessage(&swrMultiplayer_message, to, sithMessage_STREAM_NET, 0);
}

// 0x0041ce60
int swrMultiplayer_ApplyPlayerJoin(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    swrMultiplayer_JoinRecord* record = (swrMultiplayer_JoinRecord*)msg->data;
    DPID from = msg->idFrom;
    SithPlayer* player;
    unsigned int i;

    if (sithMessage_g_localPlayerId != sithMulti_g_serverId || from == 0)
        return 1;

    // already in the table: just resend its name
    for (i = 0; i < (unsigned int)swrMultiplayer_maxPlayers; i++) {
        if (sithPlayer_g_aPlayers[i].playerNetId == from)
            break;
    }
    if (i < (unsigned int)swrMultiplayer_maxPlayers) {
        swrMultiplayer_SendPlayerName(from, i, from);
        return 1;
    }

    // response values are float bit patterns: 0x3f000000 = 0.5f, 0x3e800000 = 0.25f
    if (swrMultiplayer_joinLocked != 0) {
        if (swrMultiplayer_reservedDpid != from) {
            swrMultiplayer_SendJoinResponse(1, 0, from);
            return 1;
        }
        swrMultiplayer_SendJoinResponse(0, 0x3f000000, from);
        return 1;
    }

    for (i = 0; i < (unsigned int)swrMultiplayer_maxPlayers; i++) {
        if ((sithPlayer_g_aPlayers[i].flags & SITH_PLAYER_PLACED) != 0 || sithPlayer_g_aPlayers[i].playerNetId == 0)
            break;
    }
    if (i == (unsigned int)swrMultiplayer_maxPlayers) {
        swrMultiplayer_SendJoinResponse(5, 0, from);
        return 1;
    }
    swrMultiplayer_joiningSlot = i;

    stdComm_UpdatePlayers(0);
    for (i = 0; i < (unsigned int)stdComm_GetNumPlayers(); i++) {
        if (stdComm_GetPlayerId(i) == from)
            break;
    }
    if (i == (unsigned int)stdComm_GetNumPlayers())
        return 1;

    stdPlatform_noop(from);
    swrMultiplayer_ClearPlayerSlot(swrMultiplayer_joiningSlot);
    player = &sithPlayer_g_aPlayers[swrMultiplayer_joiningSlot];
    wcsncpy(player->awName, record->name, SWR_MP_WIRE_NAME_LEN);
    player->awName[SWR_MP_WIRE_NAME_LEN] = 0;
    wcsncpy(player->unk44, record->unk44, ARRAYSIZE(player->unk44) - 1);
    player->unk44[ARRAYSIZE(player->unk44) - 1] = 0;
    player->unk8c = record->unk8c;
    swrMultiplayer_SendJoinResponse(0, 0x3e800000, from);
    player->playerNetId = from;
    swrMultiplayer_RegisterPlayer(swrMultiplayer_joiningSlot, from);
    // faithful: the slot index is passed as the destination DPID
    for (i = 0; i < (unsigned int)sithPlayer_g_numPlayers; i++)
        swrMultiplayer_SendPlayerList(i, 0);
    swrMultiplayer_OnPlayerJoined(from);
    return 1;
}

// 0x0041c9e0
void swrMultiplayer_OnPlayerJoined(DPID player)
{
    char text[1024];
    int playerNum;

    playerNum = sithMulti_GetPlayerNum(player);
    if (multiplayer_isHost != 0) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0424/%s has joined the game."), swrMultiplayer_GetPlayerNameAscii(playerNum));
        swrMultiplayer_PostChatMessage(text);
    }
    swrMultiplayer_aRejoinRequested[playerNum] = 0;
    swrUI_BroadcastToWindows(0x3f, playerNum);
}

// 0x0041d0c0
void swrMultiplayer_SendChatMessage(char* text, int target, int sender)
{
    int* payload = (int*)swrMultiplayer_message.data;
    unsigned int length;

    if (multiplayer_enabled == 0 || text == NULL)
        return;

    length = strlen(text) + 1;
    if (length >= SWR_MP_CHAT_TEXT_MAX)
        length = SWR_MP_CHAT_TEXT_MAX;
    payload[0] = target;
    payload[1] = sender;
    payload[2] = length;
    strncpy((char*)&payload[3], text, length - 1);
    ((char*)&payload[3])[length - 1] = '\0';
    swrMultiplayer_message.dataSize = 3 * sizeof(int) + length;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_CHAT;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
}

// 0x0041e260
int swrMultiplayer_ApplyEvent(void* message)
{
    char text[256];
    int* payload = (int*)((tSithMessage*)message)->data;
    int sender;
    int eventMagic;
    int* args;
    rdVector3 sparkPos;
    rdVector3 sparkDir;
    swrRace* pod;
    int count;
    int i;

    if (swrMultiplayer_ignoreEvents != 0)
        return 1;

    sender = payload[0];
    eventMagic = payload[1];
    args = &payload[2];
    // faithful: no 'flam' case, so remote flame attacks fall into default and the tail spawn below never runs
    switch (eventMagic) {
    case 'Sprk':
        if (swrMultiplayer_networkTick != 0) {
            sparkPos = *(rdVector3*)&args[3];
            sparkDir = *(rdVector3*)&args[6];
            swrRace_SetupScrapeSpray(swrScores[args[0]].obj_test_ptr, *(float*)&args[1], *(float*)&args[2], &sparkPos, &sparkDir, args[9]);
        }
        break;
    case 'ctrl':
        swrMultiplayer_proxyPlayer = -1;
        swrMultiplayer_MarkAllPodsRemote_Maybe();
        break;
    case 'fini':
        swrScoresPtr[sender].flag |= swrScore_FLAG_FINISHED;
        multiplayer_aPlayerFinished[sender] = 1;
        break;
    case 'hell':
        pod = swrScores[args[0]].obj_test_ptr;
        if (pod != NULL)
            pod->flags1 |= swrObjTest_FLAG1_ON_LAVA;
        swrMultiplayer_aPodStatus[args[0]][0] = SWR_MP_POD_STATUS_PARKED;
        swrMultiplayer_aPodStatus[args[0]][1] = 0;
        swrMultiplayer_aPodStatus[args[0]][2] = 0;
        swrMultiplayer_aPodStatus[args[0]][3] = 0;
        break;
    case 'lost':
        swrMultiplayer_MarkPodLocal_Maybe(args[0]);
        break;
    case 'plap':
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0511/~s%s completed lap %d in %s"), swrMultiplayer_GetPlayerNameAscii(sender), args[0], swrMultiplayer_FormatTimeString_Maybe(*(float*)&args[1]));
        swrMultiplayer_PostChatMessage(text);
        break;
    case 'prxy':
        swrMultiplayer_proxyPlayer = playerNumber;
        count = args[0];
        for (i = 0; i < count; i++)
            swrMultiplayer_MarkPodLocal_Maybe(args[1 + i]);
        break;
    case 'quit':
        multiplayer_aPlayerQuit[sender] = 1;
        swrMultiplayer_aPodStatus[sender][0] = SWR_MP_POD_STATUS_PARKED;
        swrMultiplayer_aPodStatus[sender][1] = 0;
        swrMultiplayer_aPodStatus[sender][2] = 0;
        swrMultiplayer_aPodStatus[sender][3] = 0;
        if (multiplayer_isHost != 0)
            swrMultiplayer_MarkPodLocal_Maybe(sender);
        break;
    case 'rejn':
        swrUI_BroadcastToWindows(0x41, 0);
        multiplayer_rejoinPending = 1;
        break;
    case 'taun':
        swrSound_PlaySfxThrottled(args[0], args[1], args[2], (rdVector3*)&((rdMatrix44*)((char*)&swrMultiplayer_remotePodTransform + sender * sizeof(swrRace)))->vD);
        break;
    case 'trig':
        swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent(args[0], args[1]);
        break;
    default:
        return 0;
    }

    if (swrMultiplayer_ignoreEvents == 0 && eventMagic == 'flam')
        swrRace_SpawnFlameAttackByIndex(args[0]);
    return 1;
}

// 0x0041d6d0
void swrMultiplayer_ClearStateBuffer(void)
{
    memset(swrScores, 0, sizeof(swrScores));
}

// 0x0041e7c0
void swrMultiplayer_FreeRacerSlot(int slot)
{
    if (swrMultiplayer_chatLines[slot] != NULL) {
        free(swrMultiplayer_chatLines[slot]);
        swrMultiplayer_chatLines[slot] = NULL;
        swrMultiplayer_chatLineState[slot] = 0;
        swrMultiplayer_chatLineTimeLeftMs[slot] = 0;
    }
}

// 0x0041e800
void swrMultiplayer_AddChatMessage(char* text)
{
    int slot;
    size_t len;

    for (slot = 0; swrMultiplayer_chatLines[slot] != NULL; slot++) {
        if (slot + 1 >= SWR_MP_CHAT_LINE_COUNT) {
            return;
        }
    }
    len = strlen(text) + 1;
    swrMultiplayer_chatLines[slot] = malloc(len);
    memcpy(swrMultiplayer_chatLines[slot], text, len);
    swrMultiplayer_chatLineState[slot] = 0;
    swrMultiplayer_chatLineTimeLeftMs[slot] = SWR_MP_CHAT_LINE_LIFETIME_MS;
    swrMultiplayer_chatLastTickMs = timeGetTime();
}

// 0x0041e880
void swrMultiplayer_TickRacerListOverlay(void)
{
    unsigned int now;
    unsigned int elapsed;
    unsigned int step;
    int i;
    int j;

    now = timeGetTime();
    elapsed = now - swrMultiplayer_chatLastTickMs;
    for (i = 0; i < SWR_MP_CHAT_LINE_COUNT; i++) {
        if (swrMultiplayer_chatLines[i] != NULL) {
            step = swrMultiplayer_chatLineTimeLeftMs[i];
            if (elapsed <= step) {
                step = elapsed;
            }
            swrMultiplayer_chatLineTimeLeftMs[i] -= step;
            if (swrMultiplayer_chatLineTimeLeftMs[i] == 0) {
                swrMultiplayer_FreeRacerSlot(i);
            }
        }
    }

    // Compact the lines upward. Faithful: only the text pointers move; the timers stay in their slots.
    for (i = 0; i < SWR_MP_CHAT_LINE_COUNT; i++) {
        if (swrMultiplayer_chatLines[i] == NULL) {
            for (j = i + 1; j < SWR_MP_CHAT_LINE_COUNT; j++) {
                if (swrMultiplayer_chatLines[j] != NULL) {
                    swrMultiplayer_chatLines[i] = swrMultiplayer_chatLines[j];
                    swrMultiplayer_chatLines[j] = NULL;
                    break;
                }
            }
        }
    }
    swrMultiplayer_chatLastTickMs = now;
}

// 0x0041e9b0
void swrMultiplayer_BuildAllMenuScreens(void)
{
    swrMultiplayer_BuildSessionTypeUI();
    swrMultiplayer_BuildCreateGameUI();
    swrMultiplayer_BuildJoinGameUI();
    swrMultiplayer_BuildRaceSetupUI();
    swrMultiplayer_BuildRacerListUI();
}

// 0x0041ea20
int swrMultiplayer_BuildSessionTypeUI(void)
{
    swrUI_unk* page;

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_MP_START, (swrUI_unk_F2*)swrUI_Menu_MpSessionType);
    // faithful: reports success even when the window could not be created
    if (page != NULL) {
        swrUI_NewButton(page, SWR_UI_ID_MP_HOST_BUTTON, 6, swrText_Translate("/MONDOTEXT_H_0395/~sHost Multiplayer Race"), 0x96, 0x96, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_MP_JOIN_BUTTON, 6, swrText_Translate("/MONDOTEXT_H_0396/~sJoin Multiplayer Race"), 0x96, 0xbe, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1a4, 2);
    }
    return 1;
}

// Label at labelY with a centered 16-char text entry under it, left edges aligned.
static swrUI_unk* swrMultiplayer_AddLabeledEntry(swrUI_unk* page, char* labelKey, int labelY, int entryId, int entryTop)
{
    swrUI_unk* label;
    swrUI_unk* entry;
    int rect[4];

    label = swrUI_NewLabel(page, 0, 6, swrText_Translate(labelKey), 0xdc, labelY, 0, 0);
    rect[0] = 0;
    rect[1] = entryTop;
    rect[2] = 299;
    rect[3] = entryTop + 0x27;
    entry = swrUI_NewTextEntry(page, entryId, rect, 0, 0, 0);
    swrUI_CenterElement(entry, 1, 0);
    swrUI_SetMaxLength(entry, 0x10);
    swrUI_AlignElementTo(label, entry, 1);
    return entry;
}

// 0x0041eb80
int swrMultiplayer_BuildCreateGameUI(void)
{
    swrUI_unk* page;
    int rect[4];

    rect[0] = 0x78;
    rect[1] = 0x5a;
    rect[2] = 0x207;
    rect[3] = 0x185;
    page = swrUI_NewWindow(NULL, rect, swrUI_WINDOW_MP_CREATE_GAME, (swrUI_unk_F2*)swrUI_Menu_MpCreateGame);
    if (page == NULL)
        return 0;
    swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0398/~sCreate A Game"), 0x15e, 0x3c, 0, 0);
    swrMultiplayer_FillLastPlayerName(swrMultiplayer_AddLabeledEntry(page, "/MONDOTEXT_H_0399/~sEnter your name", 0x82, SWR_UI_ID_MP_CREATE_PLAYER_NAME, 0x9b));
    swrMultiplayer_AddLabeledEntry(page, "/MONDOTEXT_H_0400/~sEnter the game name", 0xd2, SWR_UI_ID_MP_CREATE_GAME_NAME, 0xeb);
    swrMultiplayer_AddLabeledEntry(page, "/MONDOTEXT_H_0401/~sEnter a password", 0x122, SWR_UI_ID_MP_CREATE_PASSWORD, 0x13b);
    swrUI_AddNavButton(page, 3, 0, 0x1ae, 2);
    swrUI_DisableElement(swrUI_AddOkButton(page, 0x208, 0x17c));
    return 1;
}

// 0x0041f0e0
int swrMultiplayer_BuildJoinGameUI(void)
{
    swrUI_unk* page;
    swrUI_unk* label;
    swrUI_unk* list;
    int rect[4];

    rect[0] = 0x78;
    rect[1] = 0x5a;
    rect[2] = 0x207;
    rect[3] = 0x185;
    page = swrUI_NewWindow(NULL, rect, swrUI_WINDOW_MP_JOIN_GAME, (swrUI_unk_F2*)swrUI_Menu_MpJoinGame);
    if (page == NULL)
        return 0;
    swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0402/~sJoin A Game"), 400, 0x28, 0, 0);
    swrMultiplayer_FillLastPlayerName(swrMultiplayer_AddLabeledEntry(page, "/MONDOTEXT_H_0399/~sEnter your name", 0x78, SWR_UI_ID_MP_JOIN_PLAYER_NAME, 0x91));
    swrMultiplayer_AddLabeledEntry(page, "/MONDOTEXT_H_0401/~sEnter a password", 200, SWR_UI_ID_MP_JOIN_PASSWORD, 0xe1);

    label = swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0403/~sChoose a game to join"), 0xdc, 0x118, 0, 0);
    rect[0] = 0;
    rect[1] = 0x131;
    rect[2] = 299;
    rect[3] = 0x1a8;
    list = swrUI_NewList(page, SWR_UI_ID_MP_GAME_LIST, rect, 0, 0, 0);
    swrUI_CenterElement(list, 1, 0);
    swrUI_AlignElementTo(label, list, 1);

    swrUI_AddNavButton(page, 3, 0, 0x1a4, 2);
    swrUI_DisableElement(swrUI_AddOkButton(page, 0x208, 0x17c));
    return 1;
}

// 0x0041f940
int swrMultiplayer_BuildRaceSetupUI(void)
{
    swrUI_unk* page;
    swrUI_unk* element;
    int rect[4];

    swrMultiplayer_ResetRaceSettings();
    rect[0] = 0x82;
    rect[1] = 0x73;
    rect[2] = 0x26b;
    rect[3] = 0x1cb;
    page = swrUI_NewWindow(NULL, rect, swrUI_WINDOW_MP_RACE_SETUP, (swrUI_unk_F2*)swrUI_Menu_MpRaceSetup);
    if (page == NULL)
        return 0;

    rect[0] = 0x78;
    rect[1] = 0x73;
    rect[2] = 0x141;
    rect[3] = 0x11c;
    swrUI_NewList(page, SWR_UI_ID_MP_PLAYER_LIST, rect, 0, 0, 0);

    swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0411/~sRacer"), 0x138, 0x7d, 0, 0);
    swrUI_NewLabel(page, SWR_UI_ID_MP_RACER_NAME, 0, wuRegistry_lpClass, 0x172, 0x82, 0, 0);
    swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0412/~sTrack"), 0x138, 0x96, 0, 0);
    swrUI_NewLabel(page, SWR_UI_ID_MP_TRACK_NAME, 0, wuRegistry_lpClass, 0x172, 0x9b, 0, 0);
    swrUI_NewLabel(page, 0, 6, swrText_Translate("/MONDOTEXT_H_0414/~sLaps"), 0x138, 0xb9, 0, 0);
    element = swrUI_NewNumberField(page, SWR_UI_ID_MP_LAPS, 0x172, 0xaf, 200, swrUI_SLIDER_SHOW_NUMBER, 0);
    swrUI_SetNumberValue(element, multiplayer_laps);
    // 0x40004 kept literal: the 0x40000 bit is unconfirmed on 3-patch boxes
    swrUI_New3PatchBox(page, SWR_UI_ID_MP_SETUP_TAB, 6, NULL, 0x14a, 0x32, 0xdc, swrUI_3PATCH_LARGE_TAB, 0, 0x40004, 0);

    rect[0] = 0x8c;
    rect[1] = 0x131;
    rect[2] = 599;
    rect[3] = 0x1a8;
    swrUI_NewList(page, SWR_UI_ID_MP_CHAT_LIST, rect, 0, swrUI_LIST_NO_SELECTION_FRAME, 0);

    swrUI_NewButton(page, SWR_UI_ID_MP_RETIRE, 6, swrText_Translate("/MONDOTEXT_H_0416/~sRetire"), 0, 0x18b, 0x8c, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, swrUI_WINDOW_MP_RACE_BUTTON, 6, swrText_Translate("/MONDOTEXT_H_0417/~sRace"), 0, 0x1ae, 0x8c, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);

    rect[0] = 0x8c;
    rect[1] = 0x1ae;
    rect[2] = 599;
    rect[3] = 0x1d5;
    element = swrUI_NewTextEntry(page, SWR_UI_ID_MP_CHAT_ENTRY, rect, 0, swrUI_TEXT_ENTRY_CLEAR_ON_COMMIT, 0);
    swrUI_SetMaxLength(element, 0x32);

    swrUI_NewButton(page, SWR_UI_ID_MP_PODRACER, 6, swrText_Translate("/MONDOTEXT_H_0418/~sPodracer"), 0, 0x73, 0x8c, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, SWR_UI_ID_MP_TRACKS, 6, swrText_Translate("/MONDOTEXT_H_0419/~sTracks"), 0, 0x91, 0x8c, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, SWR_UI_ID_MP_BOOT, 6, swrText_Translate("/MONDOTEXT_H_0421/~sBoot"), 0, 0xaf, 0x8c, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    return 1;
}

// 0x00420600
int swrMultiplayer_BuildRacerListUI(void)
{
    swrUI_unk* page;
    swrUI_unk* list;
    int rect[4];

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_MP_RACER_LIST, (swrUI_unk_F2*)swrUI_Menu_MpRacerList);
    if (page == NULL)
        return 0;
    rect[0] = 0x32;
    rect[1] = 0x96;
    rect[2] = 0x24e;
    rect[3] = 0x17c;
    list = swrUI_NewList(page, SWR_UI_ID_MP_RESULTS_LIST, rect, -1, swrUI_LIST_NO_SELECTION_FRAME, 0);
    list->row_spacing = 0;
    swrUI_NewButton(page, SWR_UI_ID_BACK_BUTTON, 6, swrText_Translate("/MONDOTEXT_H_0510/~sReturn to lobby"), 0xdc, 0x1a4, 200, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    return 1;
}

// 0x0041e9d0
int swrMultiplayer_IsAvailable(void)
{
    unsigned int failed;

    // probe: open a throwaway session and tear it down again
    if (stdComm_Startup() == 0)
        return 0;
    if (swrMultiplayer_Initialize() == 0)
        return 0;
    failed = swrMultiplayer_CreateSession((wchar_t*)wuRegistry_lpClass, (wchar_t*)wuRegistry_lpClass, (wchar_t*)wuRegistry_lpClass, wuRegistry_lpClass, 0xb4);
    swrMultiplayer_Shutdown();
    stdComm_Shutdown();
    return failed == 0;
}

// 0x0041e920
void swrMultiplayer_RenderRacerListOverlay(void)
{
    char line[1024];
    int x;
    int y;
    int i;

    x = swrMultiplayer_chatX;
    y = swrMultiplayer_chatY;
    for (i = 0; i < SWR_MP_CHAT_LINE_COUNT; i++) {
        if (swrMultiplayer_chatLines[i] != NULL) {
            sprintf(line, "~F0%s", swrMultiplayer_chatLines[i]);
            swrText_CreateTextEntry1(x, y, -1, -1, -1, -1, line);
            y += SWR_MP_CHAT_LINE_SPACING;
        }
    }
    if (swrMultiplayer_chatInputOpen != 0) {
        swrText_CreateTextEntry1(x, y, -1, -1, -1, -1, swrMultiplayer_chatInput);
        swrMultiplayer_chatInputY = y;
    }
}

// 0x00420730
int swrMultiplayer_ValidateGameFields(swrUI_unk* page, int id1, int id2, int id3)
{
    int ids[3];
    swrUI_unk* field;
    int i;

    ids[0] = id1;
    ids[1] = id2;
    ids[2] = id3;
    for (i = 0; i < 3; i++) {
        if (ids[i] != 0) {
            field = swrUI_GetById(page, ids[i]);
            if (field != NULL && (field->str_allocated == NULL || field->str_allocated[0] == '\0')) {
                return 0;
            }
        }
    }
    return 1;
}

// 0x0041d8d0
void swrMultiplayer_SendPodHello(swrRace* player)
{
    int slot;

    if (player == NULL)
        return;

    // ON_LAVA doubles as the 'hello sent' marker (swrMultiplayer_PublishPodState)
    player->flags1 |= swrObjTest_FLAG1_ON_LAVA;
    slot = *(int*)&player->score_ptr->time_unk;
    swrMultiplayer_SendEvent(SITH_MESSAGE_TO_ALL, sithMessage_SEND_GUARANTEED, 'hell', slot);
    swrMultiplayer_aPodStatus[slot][0] = SWR_MP_POD_STATUS_PARKED;
    swrMultiplayer_aPodStatus[slot][1] = 0;
    swrMultiplayer_aPodStatus[slot][2] = 0;
    swrMultiplayer_aPodStatus[slot][3] = 0;
}

// 0x0041d930
void swrMultiplayer_PublishPodState(swrRace* player)
{
    int slot = *(int*)&player->score_ptr->time_unk;

    // AI pod not yet joined: parked below the track. SendPodHello sets the ON_LAVA bit as its 'sent' marker
    if ((player->flags0 & swrObjTest_FLAG0_AI) && (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0) {
        if ((player->flags1 & swrObjTest_FLAG1_ON_LAVA) == 0)
            swrMultiplayer_SendPodHello(player);
        player->transform.vD.x = swrMultiplayer_aLocalPodTransform[slot].vD.x;
        player->transform.vD.y = swrMultiplayer_aLocalPodTransform[slot].vD.y;
        swrMultiplayer_aLocalPodTransform[slot].vD.z = SWR_MP_PARKED_POD_Z;
        player->transform.vD.z = SWR_MP_PARKED_POD_Z;
        swrMultiplayer_aPodStatus[slot][0] = SWR_MP_POD_STATUS_PARKED;
        swrMultiplayer_aPodStatus[slot][1] = 0;
        swrMultiplayer_aPodStatus[slot][2] = 0;
        swrMultiplayer_aPodStatus[slot][3] = 0;
        return;
    }
    rdMatrix_Copy44(&swrMultiplayer_aLocalPodTransform[slot], &player->transform);
    swrMultiplayer_aRemoteSpeed[slot] = player->speedValue;
    swrMultiplayer_aRemoteLapComp[slot] = player->lapComp;
    swrMultiplayer_aRemoteLapCompMax[slot] = player->lapCompMax;
    swrMultiplayer_aRemoteLap[slot] = player->score_ptr->results_P1_Lap;
}

// 0x0041b750
void swrMultiplayer_RegisterHandler(int subtype, void* handler)
{
    swrCallback_multiplayer[subtype] = (tSithCallback*)handler;
}

// 0x0041ba00
void swrMultiplayer_RegisterHandlers(void)
{
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_JOIN, swrMultiplayer_ApplyPlayerJoin);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_NAME, swrMultiplayer_ApplyPlayerName);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_LIST, swrMultiplayer_ApplyPlayerList);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_CHAT, swrMultiplayer_ApplyChat);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PING, swrMultiplayer_ReplyPing);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PING_REPLY, swrMultiplayer_ApplyPingReply);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_VERIFY_PLAYER_LIST, swrMultiplayer_VerifyPlayerList);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_LEAVE, swrMultiplayer_ApplyPlayerLeave);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_QUIT, swrMultiplayer_ApplyPlayerQuit);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_JOIN_RESPONSE, swrMultiplayer_HandleNoOp);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_READY_MASK, swrMultiplayer_ApplyReadyMask);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_READY_FLAG, swrMultiplayer_ApplyReadyFlag);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_READY_STATE, swrMultiplayer_ApplyReadyState);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_PLAYER_STATES, swrMultiplayer_ApplyPlayerStates);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_NOOP, swrMultiplayer_HandleNoOp);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_RACER_PICK, swrMultiplayer_ApplyRacerPick);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_ALL_RACER_PICKS, swrMultiplayer_ApplyAllRacerPicks);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_ROSTER_REQUEST, swrMultiplayer_ApplyRosterRequest);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_ROSTER, swrMultiplayer_ApplyRoster);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_EVENT, swrMultiplayer_ApplyEvent);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_STATE_REQUEST, swrMultiplayer_ApplyStateRequest);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_RACE_SETTINGS, swrMultiplayer_ApplyRaceSettings);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_RACE_RESET, swrMultiplayer_ApplyRaceReset);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_LOBBY_STATE, swrMultiplayer_ApplyLobbyState);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_LOBBY_REFRESH, swrMultiplayer_ApplyLobbyRefresh);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_MENU_RESET, swrMultiplayer_ApplyMenuEvent);
    swrMultiplayer_RegisterHandler(swrMultiplayer_MSG_MENU_EVENT, swrMultiplayer_ApplyMenuEvent);
}

// 0x0041b7f0
int swrMultiplayer_PumpPackets(void)
{
    unsigned short type;
    int numReceived;

    numReceived = 0;
    if (swrMultiplayer_IsMultiplayerEnabled() == 0)
        return 0;
    if (sithMessage_g_inputstream == 0)
        return 0;

    swrMultiplayer_pumpStop = 0;
    do {
        if (sithMulti_HandleIncomingPacket(&swrMultiplayer_message) != 1)
            break;
        numReceived++;
        if (swrMultiplayer_message.idFrom == 0) {
            sithMulti_DefaultCallback(&swrMultiplayer_message);
            continue;
        }
        type = swrMultiplayer_message.callbackId;
        if (sithMulti_GetPlayerNum(swrMultiplayer_message.idFrom) < 0 && type != swrMultiplayer_MSG_PLAYER_NAME && type != swrMultiplayer_MSG_PLAYER_JOIN && type != swrMultiplayer_MSG_PLAYER_LEAVE && type != swrMultiplayer_MSG_PLAYER_LIST) {
            // unknown sender outside the join handshake
            if (multiplayer_isHost != 0)
                swrMultiplayer_SendPlayerQuit(swrMultiplayer_message.idFrom);
            continue;
        }
        if (swrMultiplayer_message.sequenceId != 0) {
            swrMultiplayer_SendPlayerLeave_Maybe(swrMultiplayer_message.idFrom, swrMultiplayer_message.sequenceId);
            if (sithMulti_TrackMessagePair_Maybe(swrMultiplayer_message.idFrom, swrMultiplayer_message.sequenceId) != 0)
                continue;
        }
        sithMulti_RunCallback(&swrMultiplayer_message);
    } while (swrMultiplayer_pumpStop == 0);
    swr_noop2();
    return numReceived;
}

// 0x0041c3f0
void swrMultiplayer_SendMenuEvent(int value)
{
    int* payload;

    if (multiplayer_enabled == 0)
        return;
    payload = (int*)swrMultiplayer_message.data;
    payload[0] = playerNumber;
    payload[1] = value;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_MENU_EVENT;
    swrMultiplayer_message.dataSize = 8;
    sithMessage_SendMessage(&swrMultiplayer_message, sithMulti_g_serverId, sithMessage_STREAM_NET, 0);
    swrMultiplayer_menuEvent = value;
}

// 0x0041c450
void swrMultiplayer_BroadcastMenuReset(void)
{
    if (multiplayer_enabled == 0)
        return;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_MENU_RESET;
    swrMultiplayer_message.dataSize = 0;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, 0);
}

// 0x0041c490
int swrMultiplayer_ApplyMenuEvent(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;

    if (msg->callbackId == swrMultiplayer_MSG_MENU_RESET) {
        swrMultiplayer_SendMenuEvent(swrMultiplayer_menuEvent);
        return 1;
    }
    swrUI_BroadcastToWindows(msg->callbackId, (int)msg->data);
    return 1;
}

// 0x0041d060
void swrMultiplayer_SendJoinResponse(int result, int value, DPID to)
{
    int* payload = (int*)swrMultiplayer_message.data;

    payload[0] = result;
    payload[1] = value;
    swrMultiplayer_message.dataSize = 8;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_JOIN_RESPONSE;
    sithMessage_SendMessage(&swrMultiplayer_message, to, sithMessage_STREAM_NET, 0);
}

// 0x0041d0b0
int swrMultiplayer_HandleNoOp(void)
{
    return 1;
}

// 0x0041d1d0
int swrMultiplayer_ReplyPing(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;

    msg->callbackId = swrMultiplayer_MSG_PING_REPLY;
    // faithful: sends the shared buffer, which is the received ping (PumpPackets receives into it)
    sithMessage_SendMessage(&swrMultiplayer_message, msg->idFrom, sithMessage_STREAM_NET, 0);
    return 1;
}

// 0x0041d2a0
void swrMultiplayer_SendPlayerQuit(DPID player)
{
    if (multiplayer_isHost == 0)
        return;
    ((DPID*)swrMultiplayer_message.data)[0] = player;
    swrMultiplayer_message.dataSize = 4;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_PLAYER_QUIT;
    sithMessage_SendMessage(&swrMultiplayer_message, player, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
}

// 0x0041d420
void swrMultiplayer_SendReadyFlag(int player, int ready)
{
    swrMultiplayer_ReadyStatus* status;
    int* payload;
    int localPlayer = playerNumber;

    if (multiplayer_enabled == 0)
        return;
    status = &swrMultiplayer_aReadyStatus[player];
    if (status->state == swrMultiplayer_READY_IDLE)
        return;
    if (ready == 0) {
        status->readyMask &= ~(1u << playerNumber);
    } else {
        status->readyMask |= 1u << playerNumber;
    }
    if (multiplayer_isHost == 0) {
        payload = (int*)swrMultiplayer_message.data;
        payload[0] = player;
        payload[1] = localPlayer;
        payload[2] = ready;
        swrMultiplayer_message.length = 0;
        swrMultiplayer_message.callbackId = swrMultiplayer_MSG_READY_FLAG;
        swrMultiplayer_message.dataSize = 0xc;
        sithMessage_SendMessage(&swrMultiplayer_message, sithMulti_g_serverId, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
    }
    swrMultiplayer_UpdateReadyState(player);
}

// 0x0041d540
int swrMultiplayer_ApplyReadyFlag(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;
    swrMultiplayer_ReadyStatus* status;
    int slot;

    if (multiplayer_enabled == 0)
        return 1;
    slot = payload[0];
    status = &swrMultiplayer_aReadyStatus[slot];
    if (status->state != swrMultiplayer_READY_IDLE) {
        if (payload[2] == 0) {
            status->readyMask &= ~(1u << payload[1]);
        } else {
            status->readyMask |= 1u << payload[1];
        }
        swrMultiplayer_UpdateReadyState(slot);
    }
    return 1;
}

// 0x0041d5b0
int swrMultiplayer_ApplyReadyMask(void* message)
{
    int slot = ((int*)((tSithMessage*)message)->data)[0];

    if (multiplayer_enabled != 0 && swrMultiplayer_aReadyStatus[slot].state != swrMultiplayer_READY_IDLE)
        swrMultiplayer_SendReadyFlag(slot, (swrMultiplayer_aReadyStatus[slot].readyMask >> playerNumber) & 1);
    return 1;
}

// 0x0041d600
int swrMultiplayer_ApplyReadyState(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;

    if (multiplayer_enabled != 0) {
        // faithful: payload[1] (the sender's all-ready flag) is ignored
        swrMultiplayer_aReadyStatus[payload[0]].state = swrMultiplayer_READY_ALL;
        swrMultiplayer_aReadyStatus[payload[0]].readyMask = payload[2];
    }
    return 1;
}

// 0x0041d690
void swrMultiplayer_ClearPlayerStatus(int player)
{
    swrMultiplayer_aReadyStatus[player].state = swrMultiplayer_READY_IDLE;
    swrMultiplayer_aReadyStatus[player].readyMask = 0;
    swrMultiplayer_aReadyStatus[player].sent = 0;
}

// 0x0041dca0
int swrMultiplayer_ApplyRacerPick(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;
    int slot;
    int pick;

    if (multiplayer_enabled != 0) {
        slot = payload[0];
        pick = payload[1];
        (&multiplayer_racer1_id)[slot] = pick;
        swrRace_aProfiles[slot].pilotId = (uint8_t)pick;
        swrUI_BroadcastToWindows(swrMultiplayer_MSG_RACER_PICK, (int)payload);
    }
    return 1;
}

// 0x0041e6c0
int swrMultiplayer_ApplyRaceReset(void)
{
    memset(multiplayer_aPlayerQuit, 0, sizeof(multiplayer_aPlayerQuit));
    memset(multiplayer_aPlayerFinished, 0, sizeof(multiplayer_aPlayerFinished));
    swrMultiplayer_ignoreEvents = 0;
    swrMultiplayer_SendMenuEvent(0);
    swrObjHang_EnterMultiplayerMenu_Maybe();
    return 1;
}

// 0x0041e700
void swrMultiplayer_UpdateReadyState(int slot)
{
    swrMultiplayer_ReadyStatus* status = &swrMultiplayer_aReadyStatus[slot];
    int* payload;
    int allReady = 1;
    int prevState;
    unsigned int i;

    for (i = 0; i < swrMultiplayer_MAX_PLAYERS; i++) {
        if (swrMultiplayer_IsPlayerActive(i) != 0 && (status->readyMask & (1u << i)) == 0)
            allReady = 0;
    }
    prevState = status->state;
    if (allReady)
        status->state = swrMultiplayer_READY_ALL;
    if (status->state != prevState && multiplayer_isHost != 0) {
        payload = (int*)swrMultiplayer_message.data;
        payload[2] = status->readyMask;
        payload[1] = status->state == swrMultiplayer_READY_ALL;
        payload[0] = slot;
        swrMultiplayer_message.length = 0;
        swrMultiplayer_message.callbackId = swrMultiplayer_MSG_READY_STATE;
        swrMultiplayer_message.dataSize = 0xc;
        sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, sithMessage_SEND_GUARANTEED);
    }
}

// 0x0041d6f0
int swrMultiplayer_ApplyPlayerStates(int message)
{
    int* payload = (int*)((tSithMessage*)message)->data;
    float* record;
    rdMatrix44* transform;
    int count;
    int slot;
    int col;
    int row;

    if (multiplayer_enabled == 0)
        return 1;
    count = *payload++;
    while (count > 0) {
        record = (float*)payload;
        slot = payload[0];
        transform = (rdMatrix44*)((char*)&swrMultiplayer_remotePodTransform + slot * sizeof(swrRace));
        // the packet carries the matrix column by column
        for (col = 0; col < 4; col++) {
            for (row = 0; row < 4; row++)
                (&transform->vA.x)[row * 4 + col] = record[1 + col * 4 + row];
        }
        swrMultiplayer_aRemoteSpeed[slot] = record[17];
        swrMultiplayer_aRemoteLapComp[slot] = record[18];
        swrMultiplayer_aRemoteLapCompMax[slot] = record[19];
        swrMultiplayer_aRemoteLap[slot] = payload[20];
        swrMultiplayer_aRemoteFlags0[slot] = payload[26];
        swrMultiplayer_aRemoteFlags1[slot] = payload[27];
        if (payload[25] == 'AAII') {
            swrMultiplayer_aPodStatus[slot][0] = SWR_MP_POD_STATUS_PARKED;
            swrMultiplayer_aPodStatus[slot][1] = 0;
            swrMultiplayer_aPodStatus[slot][2] = 0;
            swrMultiplayer_aPodStatus[slot][3] = 0;
        } else {
            swrMultiplayer_aPodStatus[slot][0] = payload[21];
            swrMultiplayer_aPodStatus[slot][1] = payload[22];
            swrMultiplayer_aPodStatus[slot][2] = payload[23];
            swrMultiplayer_aPodStatus[slot][3] = payload[24];
        }
        swrMultiplayer_aRemoteStateTime[slot] = timeGetTime();
        payload += SWR_MP_POD_STATE_RECORD_INTS;
        count--;
    }
    return 1;
}

// 0x0041de60
int swrMultiplayer_ApplyRoster(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;
    int numRacers = payload[0];
    int i;

    // payload = swrMultiplayer_raceBegin[2..9], then per racer the pilot id, then the identifier
    for (i = 0; i < 8; i++)
        swrMultiplayer_raceBegin[2 + i] = payload[i];
    payload += 8;
    for (i = 0; i < numRacers; i++)
        swrMultiplayer_rosterPilots[i] = *payload++;
    for (i = 0; i < numRacers; i++)
        swrMultiplayer_rosterIdentifiers[i] = *payload++;
    swrMultiplayer_rosterUnk = 0;
    return 1;
}

// 0x0041dce0
int swrMultiplayer_ApplyAllRacerPicks(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;
    int i;

    if (multiplayer_enabled == 0)
        return 1;
    for (i = sithPlayer_g_numPlayers; i > 0; i--) {
        swrRace_aProfiles[payload[0]].pilotId = (uint8_t)payload[1];
        payload += 2;
    }
    return 1;
}

// 0x0041dd20
int swrMultiplayer_ApplyRosterRequest(void)
{
    if (swrMultiplayer_raceBeginValid != 0)
        swrMultiplayer_BroadcastRoster((int)g_objHang1, swrMultiplayer_raceBegin);
    return 1;
}

// 0x0041e590
int swrMultiplayer_ApplyStateRequest(void)
{
    swrMultiplayer_BroadcastPlayerState();
    return 1;
}

// 0x0041e620
int swrMultiplayer_ApplyRaceSettings(void* message)
{
    int* payload = (int*)((tSithMessage*)message)->data;

    swrObjHang_someState = payload[0];
    swrMultiplayer_hangSyncUnk1 = payload[1];
    swrMultiplayer_hangSyncUnk2 = payload[2];
    g_LoadTrackModel = payload[3];
    swrMultiplayer_hangSyncUnk4 = payload[4];
    return 1;
}

// 0x0041c2a0
void swrMultiplayer_BroadcastRaceSettings(void)
{
    int* payload = (int*)swrMultiplayer_message.data;

    if (multiplayer_enabled == 0)
        return;
    memcpy(payload, &multiplayer_racer1_id, swrMultiplayer_MAX_PLAYERS * sizeof(int));
    payload[20] = multiplayer_track_select;
    payload[21] = multiplayer_numAiRacers;
    payload[22] = multiplayer_laps;
    payload[23] = multiplayer_raceSettingsUnk;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_LOBBY_STATE;
    swrMultiplayer_message.dataSize = 0x60;
    sithMessage_SendMessage(&swrMultiplayer_message, SITH_MESSAGE_TO_ALL, sithMessage_STREAM_NET, 0);
    swrUI_BroadcastToWindows(swrMultiplayer_MSG_LOBBY_STATE, (int)payload);
}

// 0x0041c390
void swrMultiplayer_SendRacerSelection(void)
{
    if (multiplayer_enabled == 0)
        return;
    ((int*)swrMultiplayer_message.data)[0] = playerNumber;
    swrMultiplayer_message.length = 0;
    swrMultiplayer_message.callbackId = swrMultiplayer_MSG_LOBBY_REFRESH;
    swrMultiplayer_message.dataSize = 4;
    sithMessage_SendMessage(&swrMultiplayer_message, sithMulti_g_serverId, sithMessage_STREAM_NET, 0);
}

// 0x0041c330
int swrMultiplayer_ApplyLobbyState(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    int* payload = (int*)msg->data;

    memcpy(&multiplayer_racer1_id, payload, swrMultiplayer_MAX_PLAYERS * sizeof(int));
    multiplayer_track_select = payload[20];
    multiplayer_numAiRacers = payload[21];
    multiplayer_laps = payload[22];
    multiplayer_raceSettingsUnk = payload[23];
    swrUI_BroadcastToWindows(msg->callbackId, (int)msg->data);
    return 1;
}

// 0x0041c3e0
int swrMultiplayer_ApplyLobbyRefresh(void)
{
    swrMultiplayer_BroadcastRaceSettings();
    return 1;
}

// 0x0041d200
int swrMultiplayer_ApplyPingReply(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    unsigned int i;
    unsigned int rtt;

    if (*(unsigned int*)msg->data != swrMultiplayer_pingSentTime)
        return 1;
    for (i = 0; i < (unsigned int)sithPlayer_g_numPlayers; i++) {
        if (sithPlayer_g_aPlayers[i].playerNetId == msg->idFrom)
            break;
    }
    if (i >= (unsigned int)sithPlayer_g_numPlayers)
        return 1;
    rtt = timeGetTime() - swrMultiplayer_pingSentTime;
    if (sithPlayer_g_aPlayers[i].pingMs != 0)
        rtt = (rtt + sithPlayer_g_aPlayers[i].pingMs) >> 1;
    sithPlayer_g_aPlayers[i].pingMs = rtt;
    return 1;
}

// 0x0041d2f0
int swrMultiplayer_ApplyPlayerQuit(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    DPID player = *(DPID*)msg->data;
    int playerNum;

    if (msg->idFrom != sithMulti_g_serverId)
        return 0;
    if (player == sithMessage_g_localPlayerId) {
        sithMessage_CloseGame();
        if (swrMultiplayer_quitState != 2) {
            swrUI_BroadcastToWindows(swrMultiplayer_MSG_PLAYER_QUIT, 0);
            return 1;
        }
    } else {
        playerNum = sithMulti_GetPlayerNum(player);
        if (playerNum >= 0)
            sithMulti_RemovePlayer(playerNum);
    }
    return 1;
}

// 0x0041d270
void swrMultiplayer_DropPlayer(unsigned int playerNum)
{
    swrMultiplayer_SendPlayerQuit(swrMultiplayer_GetPlayerDpid(playerNum));
    sithMulti_RemovePlayer(playerNum);
}

// 0x0041d160
int swrMultiplayer_ApplyChat(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    unsigned int length = *(unsigned int*)(msg->data + 8);
    char text[SWR_MP_CHAT_TEXT_MAX + 4];

    if (length >= SWR_MP_CHAT_TEXT_MAX)
        length = SWR_MP_CHAT_TEXT_MAX;
    strncpy(text, (char*)msg->data + 0xc, length - 1);
    text[length - 1] = '\0';
    // faithful: also clears the byte two past the terminator
    text[length + 1] = '\0';
    swrUI_BroadcastToWindows(msg->callbackId, (int)text);
    swrMultiplayer_OnChatReceived(text);
    return 1;
}

// 0x0041bba0
int swrMultiplayer_ApplyPlayerLeave(void* message)
{
    tSithMessage* msg = (tSithMessage*)message;
    int sequenceId = *(short*)msg->data;
    int playerNum = sithMulti_GetPlayerNum(msg->idFrom);
    unsigned int ackMask;
    int i;

    for (i = 0; i < SITH_MULTI_MAX_PENDING_MESSAGES; i++) {
        if (sithMulti_aPendingMessages[i].sequenceId == sequenceId)
            break;
    }
    if (i == SITH_MULTI_MAX_PENDING_MESSAGES)
        return 1;
    ackMask = (unsigned int)sithMulti_aPendingMessages[i].unk14 & ~(1u << (playerNum & 0x1f)); // faithful: x86 masks the shift count
    sithMulti_aPendingMessages[i].unk14 = ackMask;
    if (ackMask == 0) {
        memset(&sithMulti_aPendingMessages[i], 0, sizeof(tSithMessage));
        sithMulti_numPendingMessages--;
    }
    return 1;
}
