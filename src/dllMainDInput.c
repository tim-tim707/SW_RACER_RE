#include <windows.h>

#include <ddraw.h>

#include <stdio.h>

#include "hook.h"

FILE* hook_log = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook_dinput.log", "wb");

    fprintf(hook_log, "[DInput DllMain]\n");
    fflush(hook_log);

    hook_init(hook_log);

    return TRUE;
}

HRESULT(WINAPI* DirectInputCreateA_orig)(HINSTANCE hinst, DWORD dwVersion, LPVOID* ppDI, LPUNKNOWN punkOuter) = NULL;

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion, LPVOID* ppDI, LPUNKNOWN punkOuter)
{
    if (!DirectInputCreateA_orig)
    {
        // find original
        wchar_t buff[1024];
        UINT L = GetSystemDirectoryW(buff, sizeof(buff));
        memcpy(buff + L, L"\\dinput.dll", sizeof(L"\\dinput.dll"));
        HMODULE mod = LoadLibraryW(buff);
        DirectInputCreateA_orig = (HRESULT(WINAPI*)(HINSTANCE, DWORD, LPVOID*, LPUNKNOWN))GetProcAddress(mod, "DirectInputCreateA");
        if (!DirectInputCreateA_orig)
        {
            MessageBoxA(NULL, "Could not find original DirectInputCreateA function", "Error", MB_OK);
            abort();
        }
    }

    return DirectInputCreateA_orig(hinst, dwVersion, ppDI, punkOuter);
}
