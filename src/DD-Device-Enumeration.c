//----- (00487D20) --------------------------------------------------------
signed int sub_487D20()
{
    if (dword_52D438 != 0)
    {
        return 1;
    }

    memset(&dword_EC8CA0, 0, 0xE0u);
    memset(&dword_EC8DA0, 0, 0xE0u);
    memset(&dword_529578, 0, 0x80u);
    dword_52D438 = 1;
    dword_52D444 = 0;
    if (DirectDrawEnumerateA(Callback, 0))
    {
        return 0;
    }
    dword_52951C = 640;
    dword_529520 = 480;
    return 1;
}

//----- (00488D70) --------------------------------------------------------
BOOL __stdcall Callback(GUID *lpGUID, LPSTR a2, LPSTR a3, LPVOID a4)
{
    int v4; // esi
    DWORD *v5; // edx
    DWORD v6; // eax
    _DWORD *v7; // edx
    struct IDirectDrawVtbl *v9; // edi
    int v10; // eax
    int v11; // ecx
    struct IDirectDrawVtbl *v12; // edi
    int v13; // eax
    LPDIRECTDRAW lpDD; // [esp+24h] [ebp-4h]

    lpDD = 0;

    // Don't allow more than 16 devices
    if ((unsigned int)dword_52D444 >= 0x10)
    {
        return 0;
    }

    struct
    {
        char name[128]; // 0
        char description[128]; // 128
        uint32_t hasGUID; // 256
        uint32_t unk260; // 260
        uint32_t hasNoGUID; // 264
        uint32_t unk268; // 268
        uint32_t unk272; // 272
        uint32_t unk276; // 276
        DDCAPS dd_caps; // 280
        GUID guid; // 660
    } *v4 = 676 * dword_52D444 + 5417464;

    // Copy GUID
    if (lpGUID)
    {
        v5 = &v4->guid;
        *v5 = lpGUID->Data1;
        v5[1] = *(_DWORD *)&lpGUID->Data2;
        v5[2] = *(_DWORD *)lpGUID->Data4;
        v6 = *(_DWORD *)&lpGUID->Data4[4];
        *(_DWORD *)(v4 + 264) = 0;
        v5[3] = v6;
    }
    else
    {
        v7 = &v4->guid;
        *v7 = 0;
        v7[1] = 0;
        v7[2] = 0;
        v7[3] = 0;
        *(_DWORD *)(v4 + 264) = 1;
    }

    // Copy name
    strncpy((char *)(v4 + 128), a2, 0x7Fu);
    *(_BYTE *)(v4 + 255) = 0;

    // Copy description
    strncpy((char *)v4, a3, 0x7Fu);
    *(_BYTE *)(v4 + 127) = 0;

    // Mark wether there was a GUID
    if (lpGUID)
    {
        *(_DWORD *)(v4 + 256) = 1;
    }
    else
    {
        *(_DWORD *)(v4 + 256) = 0;
    }

    if (DirectDrawCreate(lpGUID, &lpDD, 0))
    {
        MessageBoxA(0, aDirectdrawFail, Caption, 0);
        return 1;
    }

    v9 = lpDD->lpVtbl;
    v10 = get_hwnd();
    if (v9->SetCooperativeLevel(lpDD, (HWND)v10, 17))
        return 0;
    memset((void *)(v4 + 280), 0, 0x17Cu);
    *(_DWORD *)(v4 + 280) = 380;
    if (lpDD->lpVtbl->GetCaps(lpDD, (LPDDCAPS)(v4 + 280), 0))
    {
        lpDD->lpVtbl->Release(lpDD);
        return 1;
    }
    *(_DWORD *)(v4 + 268) = *(_DWORD *)(v4 + 288) & 0x80000 ? 0 : 1;
    *(_DWORD *)(v4 + 260) = *(_BYTE *)(v4 + 284) & 1 ? 1 : 0;
    v11 = *(_DWORD *)(v4 + 344);
    *(_DWORD *)(v4 + 272) = *(_DWORD *)(v4 + 340);
    *(_DWORD *)(v4 + 276) = v11;
    v12 = lpDD->lpVtbl;
    v13 = get_hwnd();
    if (v12->SetCooperativeLevel(lpDD, (HWND)v13, 8))
        return 0;
    lpDD->lpVtbl->Release(lpDD);
    if (*(_DWORD *)(v4 + 260) == 1)
        ++dword_52D444;
    return 1;
}
