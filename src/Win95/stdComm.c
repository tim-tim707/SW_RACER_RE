#include "stdComm.h"

#include "DirectX.h"
#include "globals.h"

#include "Window.h"
#include "General/stdString.h"

#include <engine_config.h>
#include <macros.h>
#include <types_enums.h>
#include <string.h>
#include <wchar.h>

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

// 0x00486c60
int stdComm_GetSessionSettingsByIndex(unsigned int index, StdCommSessionSettings* pSettings)
{
    // faithful: off-by-one bound (index == count is accepted)
    if ((unsigned int)stdComm_numSessionSettings < index)
        return 1;
    *pSettings = stdCommSessionSettings[index];
    return 0;
}

// 0x00486ca0
int stdComm_Send(DPID idFrom, DPID idTo, LPVOID lpData, DWORD dwDataSize, DWORD dwFlags)
{
    return IDirectPlayX_Send(stdComm_pDirectPlay, idFrom, idTo, dwFlags, lpData, dwDataSize);
}

// 0x00486cd0
int stdComm_Receive(DPID* pSender, void* pData, unsigned int* pLength)
{
    DPID idTo;
    HRESULT res;
    int msgResult;

    // faithful: *pLength is not reset between reads, so a system message shrinks the next buffer
    res = IDirectPlayX_Receive(stdComm_pDirectPlay, pSender, &idTo, DPRECEIVE_ALL, pData, (LPDWORD)pLength);
    while (res >= 0) {
        if (*pSender != DPID_SYSMSG)
            return 0;
        msgResult = stdComm_ProcessSystemMessage((LPDPMSG_GENERIC)pData, pSender);
        if (msgResult != STDCOMM_RECV_NONE)
            return msgResult;
        res = IDirectPlayX_Receive(stdComm_pDirectPlay, pSender, &idTo, DPRECEIVE_ALL, pData, (LPDWORD)pLength);
    }
    return res == DPERR_NOMESSAGES ? STDCOMM_RECV_NONE : STDCOMM_RECV_ERROR;
}

// 0x00486d40
HRESULT stdComm_HostSession(StdCommSessionSettings* pSettings)
{
    DPSESSIONDESC2 desc;
    wchar_t sessionName[128];
    HRESULT res;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DPSESSIONDESC2);
    desc.dwFlags |= DPSESSION_OPTIMIZELATENCY | DPSESSION_NOPRESERVEORDER | DPSESSION_DIRECTPLAYPROTOCOL | DPSESSION_NODATAMESSAGES | DPSESSION_KEEPALIVE | DPSESSION_JOINDISABLED | DPSESSION_MIGRATEHOST;
    desc.guidApplication = *Window_GetGUID();
    desc.dwMaxPlayers = pSettings->maxPlayers;
    _snwprintf(sessionName, 128, L"%s:%S", pSettings->aSessionName, pSettings->aSomething);
    desc.lpszSessionName = sessionName;
    if (wcslen(pSettings->aPassword) != 0)
        desc.lpszPassword = pSettings->aPassword;
    desc.dwUser3 = pSettings->user2;
    desc.dwUser4 = pSettings->user3;
    desc.dwUser1 = pSettings->user1;
    res = IDirectPlayX_Open(stdComm_pDirectPlay, &desc, DPOPEN_CREATE);
    if (res < 0) {
        IDirectPlayX_Close(stdComm_pDirectPlay);
        stdComm_bIsServer = 0;
        stdComm_bGameActive = 0;
        return res;
    }
    stdComm_bIsServer = 1;
    stdComm_bGameActive = 1;
    return 0;
}

// 0x00486f50
int stdComm_GetSessionSettings(StdCommSessionSettings* pSettings)
{
    DWORD size;
    LPDPSESSIONDESC2 desc;
    HRESULT res;

    res = IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, NULL, &size);
    if (res == DPERR_BUFFERTOOSMALL) {
        desc = (LPDPSESSIONDESC2)(*stdPlatform_hostServices_ptr->alloc)(size);
        res = IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, desc, &size);
        if (res >= 0) {
            stdComm_SessionToSettings(desc, pSettings);
            (*stdPlatform_hostServices_ptr->free)(desc);
        }
    }
    return res;
}

// 0x00486fc0
int stdComm_SetSessionOpenState(char* nameSuffix, DWORD maxPlayers, int bOpen)
{
    DWORD size;
    LPDPSESSIONDESC2 desc;
    wchar_t sessionName[128];
    wchar_t* colon;
    int failed = 0;

    if (IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, NULL, &size) != DPERR_BUFFERTOOSMALL) {
        // faithful: frees the size value as a pointer
        desc = (LPDPSESSIONDESC2)(uintptr_t)size;
        failed = 1;
    } else {
        desc = (LPDPSESSIONDESC2)(*stdPlatform_hostServices_ptr->alloc)(size);
        if (desc == NULL || IDirectPlayX_GetSessionDesc(stdComm_pDirectPlay, desc, &size) < 0) {
            failed = 1;
        } else {
            if (bOpen) {
                desc->dwFlags &= ~DPSESSION_JOINDISABLED;
            } else {
                desc->dwFlags |= DPSESSION_JOINDISABLED;
            }
            wcsncpy(sessionName, desc->lpszSessionName, 127);
            sessionName[127] = L'\0';
            colon = wcsrchr(sessionName, L':');
            if (colon == NULL) {
                failed = 1;
            } else {
                _snwprintf(colon + 1, 32, L"%S", nameSuffix);
                desc->lpszSessionName = sessionName;
                desc->dwMaxPlayers = maxPlayers;
                if (IDirectPlayX_SetSessionDesc(stdComm_pDirectPlay, desc, 0) < 0)
                    failed = 1;
            }
        }
    }
    (*stdPlatform_hostServices_ptr->free)(desc);
    return failed;
}

// 0x004870d0
HRESULT stdComm_JoinSession(int sessionIndex, wchar_t* password)
{
    DPSESSIONDESC2 desc;
    HRESULT res;

    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DPSESSIONDESC2);
    desc.guidInstance = stdCommSessionSettings[sessionIndex].guid;
    if (password != NULL && wcslen(password) != 0)
        desc.lpszPassword = password;
    res = IDirectPlayX_Open(stdComm_pDirectPlay, &desc, DPOPEN_JOIN);
    if (res < 0) {
        IDirectPlayX_Close(stdComm_pDirectPlay);
        return res;
    }
    stdComm_bIsServer = 0;
    stdComm_bGameActive = 1;
    return 0;
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
    stdComm_numPlayers = 0;
    memset(stdComm_aPlayerInfos, 0, sizeof(stdComm_aPlayerInfos));
    if (stdComm_bGameActive)
        return IDirectPlayX_EnumPlayers(stdComm_pDirectPlay, NULL, stdComm_EnumPlayersCallback, NULL, 0);
    if (sessionNum < (unsigned int)stdComm_numSessionSettings)
        return IDirectPlayX_EnumPlayers(stdComm_pDirectPlay, &stdCommSessionSettings[sessionNum].guid, stdComm_EnumPlayersCallback, NULL, DPENUMPLAYERS_SESSION);
    return DPERR_GENERIC;
}

// 0x00487230
void stdComm_EnumSessions(int one, wchar_t* password)
{
    DPSESSIONDESC2 desc;
    DWORD flags;

    flags = DPENUMSESSIONS_PASSWORDREQUIRED | DPENUMSESSIONS_AVAILABLE;
    if (one)
        flags = DPENUMSESSIONS_ASYNC | DPENUMSESSIONS_PASSWORDREQUIRED | DPENUMSESSIONS_AVAILABLE;
    stdComm_numSessionSettings = 0;
    memset(stdCommSessionSettings, 0, sizeof(stdCommSessionSettings));
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DPSESSIONDESC2);
    desc.guidApplication = *Window_GetGUID();
    if (password != NULL && wcslen(password) != 0)
        desc.lpszPassword = password;
    IDirectPlayX_EnumSessions(stdComm_pDirectPlay, &desc, 0, stdComm_EnumSessionsCallback, Window_GetHWND(), flags);
}

// 0x004872e0
DPID stdComm_CreatePlayer(wchar_t* const pPlayerName)
{
    DPID id;
    DPNAME name;

    name.dwFlags = 0;
    name.lpszLongName = NULL;
    name.lpszShortName = pPlayerName;
    name.dwSize = sizeof(DPNAME);
    IDirectPlayX_CreatePlayer(stdComm_pDirectPlay, &id, &name, NULL, NULL, 0, 0);
    return id;
}

// 0x00487320
void stdComm_DestroyPlayer(DPID playerId)
{
    IDirectPlayX_DestroyPlayer(stdComm_pDirectPlay, playerId);
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
BOOL __stdcall stdComm_EnumSessionsCallback(LPCDPSESSIONDESC2 lpThisSD, LPDWORD lpdwTimeOut, DWORD dwFlags, LPVOID lpContext)
{
    if (dwFlags & DPESC_TIMEDOUT)
        return FALSE;
    if ((unsigned int)stdComm_numSessionSettings < STDCOMM_MAX_SESSIONS)
        stdComm_SessionToSettings((LPDPSESSIONDESC2)lpThisSD, &stdCommSessionSettings[stdComm_numSessionSettings++]);
    return TRUE;
}

// 0x004874a0
BOOL __stdcall stdComm_EnumPlayersCallback(DPID playerId, DWORD dwPlayerType, LPCDPNAME lpName, DWORD dwFlags, LPVOID lpContext)
{
    StdCommPlayerInfo* info;
    char nameAscii[1024];

    if (dwPlayerType == DPPLAYERTYPE_PLAYER && (unsigned int)stdComm_numPlayers < STDCOMM_MAX_PLAYERS) {
        info = &stdComm_aPlayerInfos[stdComm_numPlayers];
        memset(info, 0, sizeof(*info));
        if (lpName->lpszShortName != NULL) {
            wcsncpy(info->aName, lpName->lpszShortName, 19);
            stdComm_aPlayerInfos[stdComm_numPlayers].aName[19] = L'\0';
        }
        // faithful: converted and discarded
        stdString_WcharToChar(nameAscii, lpName->lpszShortName, sizeof(nameAscii));
        stdComm_aPlayerInfos[stdComm_numPlayers].id = playerId;
        stdComm_numPlayers++;
    }
    return TRUE;
}

// 0x00487550
int stdComm_ProcessSystemMessage(LPDPMSG_GENERIC pMessage, DPID* pSender)
{
    switch (pMessage->dwType) {
    case DPSYS_CREATEPLAYERORGROUP:
        *pSender = ((LPDPMSG_CREATEPLAYERORGROUP)pMessage)->dpId;
        return ((LPDPMSG_CREATEPLAYERORGROUP)pMessage)->dwPlayerType == DPPLAYERTYPE_PLAYER ? STDCOMM_RECV_PLAYER_JOINED : STDCOMM_RECV_NONE;
    case DPSYS_DESTROYPLAYERORGROUP:
        *pSender = ((LPDPMSG_DESTROYPLAYERORGROUP)pMessage)->dpId;
        return STDCOMM_RECV_PLAYER_LEFT;
    case DPSYS_SESSIONLOST:
        return STDCOMM_RECV_SESSION_LOST;
    case DPSYS_HOST:
        stdComm_bIsServer = 1;
        return STDCOMM_RECV_BECAME_HOST;
    default:
        return STDCOMM_RECV_NONE;
    }
}

// 0x004876d0
void stdComm_SessionToSettings(LPDPSESSIONDESC2 pSession, StdCommSessionSettings* pSettings)
{
    wchar_t sessionName[128];
    wchar_t* token;
    wchar_t* tokenState;

    wcsncpy(sessionName, pSession->lpszSessionName, 127);
    sessionName[127] = L'\0';
    token = wcstok(sessionName, L":\n", &tokenState);
    if (token != NULL) {
        wcsncpy(pSettings->aSessionName, token, 31);
        pSettings->aSessionName[31] = L'\0';
    }
    token = wcstok(NULL, L"\n", &tokenState);
    if (token != NULL) {
        stdString_WcharToChar(pSettings->aSomething, token, 31);
        pSettings->aSomething[31] = '\0';
    }
    pSettings->guid = pSession->guidInstance;
    pSettings->maxPlayers = pSession->dwMaxPlayers;
    pSettings->numCurrentPlayers = pSession->dwCurrentPlayers;
    pSettings->user1 = pSession->dwUser1;
    pSettings->user2 = pSession->dwUser3;
    pSettings->user3 = pSession->dwUser4;
}
