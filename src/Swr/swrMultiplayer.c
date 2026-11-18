#include "swrMultiplayer.h"

#include "globals.h"
#include "macros.h"

#include <General/stdString.h>
#include <Platform/wuRegistry.h>
#include <Win95/stdComm.h>
#include <Dss/sithMulti.h>
#include <Swr/swrEvent.h>
#include <Swr/swrText.h>
#include <Swr/swrUI.h>
#include <engine_config.h>
#include <Primitives/rdMatrix.h>

#include <ctype.h>
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

// 0x0041b700
int swrMultiplayer_InitMessaging(void)
{
    HANG("TODO");
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
    HANG("TODO");
}

// 0x0041c5c0
unsigned int swrMultiplayer_CreateSession(wchar_t* a1, wchar_t* a2, wchar_t* a3, char* a4, int a5)
{
    HANG("TODO");
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

// 0x0041e5a0
void swrMultiplayer_BroadcastPlayerState(void)
{
    HANG("TODO");
}

// 0x0041e660
void swrMultiplayer_BroadcastRaceReset(void)
{
    HANG("TODO");
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
// int __cdecl stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)
// 0x00486e60
unsigned int swrMultiplayer_SetSessionDesc(int unused, void* param_2)
{
    HANG("TODO");
    return 0;
}

// 0x0041dd50
void swrMultiplayer_BroadcastRoster(int hang, void* roster)
{
    HANG("TODO");
}

// 0x0041de50
void swrMultiplayer_SetRosterEntry(int index, int value)
{
    swrMultiplayer_rosterIdentifiers[index] = value;
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
    HANG("TODO");
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

// 0x0041d0c0
void swrMultiplayer_SendChatMessage(char* text, int param2, int param3)
{
    HANG("TODO");
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
    HANG("TODO");
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
