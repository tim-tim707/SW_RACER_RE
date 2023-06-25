// DLL main with hook for my_f

// g++ -o swr_reimpl.dll hook.c main.cpp -s -shared

#include <stdio.h>

#include "addresses.h"
#include "hook.h"
#include "types.h"

#define SWR_VEC3F_ADD_ADDR (0x0042f830)
#define SWR_MAIN_ADDR (0x004238D0)
// #define SWR_MAIN_ADDR (0x0049CD40)

#ifdef WIN32

HWND g_ConsoleWindow = nullptr;

int Window_Main(uint32_t hInstance, uint32_t hPrevInstance, char *lpCmdLine, int nShowCmd)
{
    printf("%p %p %S %d\n", (void *)hInstance, (void *)hPrevInstance, (LPWSTR)lpCmdLine, nShowCmd);

    printf("Entering reimpl main which should be the same as the original\nHanging now...\n");

    while (1)
    {
    }

    return 0;
}

u8 *g_SWR_BASE_ADDR = NULL;
u8 *g_SWR_TEXT_ADDR = NULL;
u8 *g_SWR_DATA_ADDR = NULL;

void hook_init()
{
    g_SWR_BASE_ADDR = (u8 *)GetModuleHandleA(NULL);
    g_SWR_TEXT_ADDR = g_SWR_BASE_ADDR + (u32_ptr)SWR_TEXT_OFFSET;
    g_SWR_DATA_ADDR = g_SWR_BASE_ADDR + (u32_ptr)SWR_DATA_OFFSET;

    // u32 MY_FUN = 0x40151C; // tester my_fun
    // u32 MY_FUN = 0x401526; // window wWinMain
    u32 MY_FUN = SWR_MAIN_ADDR;
    u8 *MY_FUN_ADDR = g_SWR_BASE_ADDR + (MY_FUN - SWR_BASE_ADDR_);
    u8 *swr_main = (u8 *)MY_FUN_ADDR;
    printf("bytes at %p:\n", swr_main);
    for (int i = 0; i < 20; i++)
    {
        printf("%02hhx ", swr_main[i]);
    }
    printf("\n");
    hook_function(MY_FUN, (u8 *)Window_Main);
    printf("bytes:\n");
    for (int i = 0; i < 20; i++)
    {
        printf("%02hhx ", swr_main[i]);
    }
    printf("\n");
}

bool CreateConsoleWindow()
{
    // Allocate a new console for the calling process
    if (!AllocConsole())
        return false;

    // Get the newly created console window handle
    g_ConsoleWindow = GetConsoleWindow();
    if (g_ConsoleWindow == nullptr)
        return false;

    // Redirect standard input, output, and error streams to the console
    freopen_s((FILE **)stdin, "CONIN$", "r", stdin);
    freopen_s((FILE **)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE **)stderr, "CONOUT$", "w", stderr);

    // Set the console window title
    SetConsoleTitleA("Debug Console");

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!CreateConsoleWindow())
        {
            printf("swr_reimpl dll console exists\n");
        }
        printf("swr_reimpl dll loaded successfully\n");
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

#else
#error "This dll must be compiled for Windows 32bits, x86. The WIN32 environment variable must be set."
#endif // WIN32
