#include <stdio.h>

#include <windows.h>
#include "hook.h"
#include <stdint.h>
#include <stdbool.h>

// The swr_reimpl.dll entry point

#ifdef WIN32

HWND g_ConsoleWindow = NULL;

bool CreateConsoleWindow()
{
    // Allocate a new console for the calling process
    if (!AllocConsole())
        return false;

    // Get the newly created console window handle
    g_ConsoleWindow = GetConsoleWindow();
    if (g_ConsoleWindow == NULL)
        return false;

    // Redirect standard input, output, and error streams to the console
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

    SetConsoleTitleA("SWR CE Debug Console");

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        printf("Star Wars Episode 1 Racer Community Edition loading\n");
        if (!CreateConsoleWindow())
        {
            printf("swr_reimpl dll console exists\n");
        }
        hook_init();
        break;

    case DLL_PROCESS_DETACH:
        printf("swr_reimpl unloading\n");
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}

#else // !WIN32
#error "This dll must be compiled for Windows 32bits, x86. The WIN32 environment variable must be set."
#endif // WIN32
