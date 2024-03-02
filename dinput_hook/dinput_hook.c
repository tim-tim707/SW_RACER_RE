//
// Created by tly on 05.09.2021.
//

#include <windows.h>

#include <psapi.h>
#include <stdio.h>
#include <ddraw.h>

HRESULT (WINAPI * DirectInputCreateA_orig)(HINSTANCE hinst, DWORD dwVersion, LPVOID *ppDI, LPUNKNOWN punkOuter) = NULL;

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPVOID *ppDI, LPUNKNOWN punkOuter) {
    if (!DirectInputCreateA_orig) {
        // find original
        wchar_t buff[1024];
        UINT L = GetSystemDirectoryW(buff, sizeof(buff));
        memcpy(buff + L, L"\\dinput.dll", sizeof(L"\\dinput.dll"));
        HMODULE mod = LoadLibraryW(buff);
        DirectInputCreateA_orig = GetProcAddress(mod, "DirectInputCreateA");
        if (!DirectInputCreateA_orig) {
            MessageBoxA(NULL, "Could not find original DirectInputCreateA function", "Error",
                        MB_OK);
            abort();
        }

        // MessageBoxA(NULL, "Test", "Test", MB_OK);

        // MODULEINFO info;
        // GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info));
        // DWORD old_protect;
        // VirtualProtect(info.lpBaseOfDll, info.SizeOfImage, PAGE_EXECUTE_READWRITE, &old_protect);
    }

    return DirectInputCreateA_orig(hinst, dwVersion, ppDI, punkOuter);
}

// TODO tries to fix windowed mode problems...

HRESULT (WINAPI *DirectDrawCreatePtr)(GUID* guid, LPDIRECTDRAW* dd, IUnknown* unk) = &DirectDrawCreate;

HRESULT(WINAPI* DDSetCooperativeLevelOrig)(IDirectDraw* This, HWND hWnd, DWORD dwFlags) = NULL;
HRESULT WINAPI DDSetCooperativeLevelHook(IDirectDraw* This, HWND hWnd, DWORD dwFlags)
{
    return DDSetCooperativeLevelOrig(This, hWnd, DDSCL_NORMAL);
}

HRESULT(WINAPI* DD4SetCooperativeLevelOrig)(IDirectDraw4* This, HWND hWnd, DWORD dwFlags) = NULL;
HRESULT WINAPI DD4SetCooperativeLevelHook(IDirectDraw4* This, HWND hWnd, DWORD dwFlags)
{
    return DD4SetCooperativeLevelOrig(This, hWnd, DDSCL_NORMAL);
}

extern FILE* hook_log;

HRESULT WINAPI DirectDrawCreateHook(GUID* guid, LPDIRECTDRAW* dd, IUnknown* unk)
{
    const auto res = DirectDrawCreatePtr(guid, dd, unk);
    if (!SUCCEEDED(res))
        return res;

    fprintf(hook_log, "[DirectDrawCreateHook] IDirectDraw vtable is %p\n", (*dd)->lpVtbl);
    fflush(hook_log);

    if (DDSetCooperativeLevelOrig == NULL)
    {
        DWORD* vtable_entry = &(*dd)->lpVtbl->SetCooperativeLevel;
        DWORD old_protect = 0;
        if (!VirtualProtect(vtable_entry, sizeof(*vtable_entry), PAGE_EXECUTE_READWRITE, &old_protect))
            abort();

        DDSetCooperativeLevelOrig = *vtable_entry;
        *vtable_entry = DDSetCooperativeLevelHook;
    }

    IDirectDraw4* dd4;
    if (SUCCEEDED(IDirectDraw_QueryInterface(*dd, &IID_IDirectDraw4, (void**)&dd4)))
    {
        fprintf(hook_log, "[DirectDrawCreateHook] IDirectDraw4 vtable is %p\n", dd4->lpVtbl);
        fflush(hook_log);

        if (DD4SetCooperativeLevelOrig == NULL)
        {
            DWORD* vtable_entry = &dd4->lpVtbl->SetCooperativeLevel;
            DWORD old_protect = 0;
            if (!VirtualProtect(vtable_entry, sizeof(*vtable_entry), PAGE_EXECUTE_READWRITE, &old_protect))
                abort();

            DD4SetCooperativeLevelOrig = *vtable_entry;
            *vtable_entry = DD4SetCooperativeLevelHook;
        }
        IDirectDraw4_Release(dd4);
    }
    return res;
}