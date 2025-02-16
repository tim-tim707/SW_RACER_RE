//
// Created by tly on 05.09.2021.
//

#include <windows.h>

#include <psapi.h>
#include <stdio.h>
#include <ddraw.h>

void init_hooks();
void init_renderer_hooks();

extern FILE *hook_log;

HRESULT(WINAPI *DirectInputCreateA_orig)(HINSTANCE hinst, DWORD dwVersion, LPVOID *ppDI,
                                         LPUNKNOWN punkOuter) = NULL;

#if _MSC_VER
#pragma comment(linker, "/EXPORT:DirectInputCreateA=_DirectInputCreateA@16")
#endif

__declspec(dllexport) HRESULT WINAPI DirectInputCreateA(HINSTANCE hinst, DWORD dwVersion,
                                                        LPVOID *ppDI, LPUNKNOWN punkOuter) {
    if (!DirectInputCreateA_orig) {
        // find original
        wchar_t buff[1024];
        UINT L = GetSystemDirectoryW(buff, sizeof(buff));
        memcpy(buff + L, L"\\dinput.dll", sizeof(L"\\dinput.dll"));
        HMODULE mod = LoadLibraryW(buff);
        DirectInputCreateA_orig = (HRESULT(WINAPI *)(
            HINSTANCE, DWORD, LPVOID *, LPUNKNOWN)) GetProcAddress(mod, "DirectInputCreateA");
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
