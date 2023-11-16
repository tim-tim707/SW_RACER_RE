#include <stdio.h>

#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef WIN32

HWND g_ConsoleWindow = NULL;

bool CreateConsoleWindow()
{
    if (!AllocConsole())
        return false;

    g_ConsoleWindow = GetConsoleWindow();
    if (g_ConsoleWindow == NULL)
        return false;

    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);

    SetConsoleTitleA("SWR CE Debug Console");
    char NPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, NPath);
    printf("DLL Loaded at %s\n", NPath);
    printf("PID is %d\n", GetCurrentProcessId());
    printf("Waiting for input...\n");
    getchar();

    return true;
}

void PrintMemory(unsigned char* at, size_t nbBytes)
{
    for (size_t i = 0; i < nbBytes; i++)
    {
        printf("%02x ", *at);
        at += 1;
    }
    printf("\n");
}

void WriteBytes(unsigned char* at, unsigned char* code, size_t nbBytes)
{
    for (size_t i = 0; i < nbBytes; i++)
    {
        *at = *code;
        at += 1;
        code += 1;
    }
}

int applyPatches(void)
{
    printf("applying Patches...\n");

    DWORD old;
    VirtualProtect((void*)0x00401000, 0x00ece000 - 0x00401000, PAGE_EXECUTE_READWRITE, &old);

    PrintMemory((unsigned char*)0x0042aa0a, 20);
    unsigned char debug1[] = { 0x01 };
    WriteBytes((unsigned char*)0x0042aa0b, debug1, sizeof(debug1));
    PrintMemory((unsigned char*)0x0042aa0a, 20);
    // uint8_t* g_SWR_BASE_ADDR = (uint8_t*)GetModuleHandleA(NULL);
    // uint32_t enable_debug_menu = 0x004d79dc;
    // uint8_t* patched_address = g_SWR_BASE_ADDR + (enable_debug_menu - 0x00400000);
    // *(unsigned int*)patched_address = (unsigned int)0;

    // printf("patched address is %p\n", patched_address);

    VirtualProtect((void*)0x00401000, 0x00ece000 - 0x00401000, old, NULL);

    printf("Press any key to continue\n");
    getchar();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        if (!CreateConsoleWindow())
        {
            printf("swr_reimpl dll console exists\n");
        }
        applyPatches();
        break;
    }

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
