// DLL main with hook for my_f

// gcc -c -o hook.o hook.c && g++ -c -o main.o main.cpp && g++ -o swr_reimpl.dll hook.o main.o -s -shared

#include "hook.h"
#include <stdio.h>
#include "types.h"

#include <Windows.h>

extern "C"
{
    __declspec(dllexport) void hook_init_win(uint32_t hInstance, uint32_t hPrevInstance, char *lpCmdLine, int nShowCmd);
};

// #define TEXT_ADDR (0x5C1000)
// #define DATA_ADDR (0x5C9000)

// int other_f(int a) {
//     printf("hook called with value %d\n", a);
//     return 42;
// }

// void do_hooks() {
//     hook_function(my_f_ADDR, other_f);
// }

#ifdef WIN32

HWND g_ConsoleWindow = nullptr;

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
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

    // Set the console window title
    SetConsoleTitleA("Debug Console");

    return true;
}

int Window_Main(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd) {
    printf("Entering reimpl main which should be the same as the original\n");

    // printf("Dll Window main: Value 3 * 2 is %d\n", my_f(3)); // if the hook succeeded, should be 42 instead of 6
    return 0;
}

// void hook_init(void)
// {
//     do_hooks();
// }

void hook_init_win(uint32_t hInstance, uint32_t hPrevInstance, char* lpCmdLine, int nShowCmd)
{
    printf("%p %p %s %d\n", (void*)hInstance, (void*)hPrevInstance, lpCmdLine, nShowCmd);
    printf("hook_init_win called successfully\n");

    printf("hook_init_win hanging now...");
    while(1) {}

    // DWORD old;

    // VirtualProtect((void*)TEXT_ADDR, DATA_ADDR - TEXT_ADDR, PAGE_EXECUTE_READWRITE, &old);

    // hook_init();

    // VirtualProtect((void*)TEXT_ADDR, DATA_ADDR - TEXT_ADDR, old, NULL);

    // Window_Main(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!CreateConsoleWindow()) {
            printf("swr_reimpl dll console exists\n");
        }
        printf("swr_reimpl dll loaded successfully\n");
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
