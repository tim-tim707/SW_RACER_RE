#include <stdio.h>

#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdbool.h>

#include "config.h"

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
    printf("PID is %ld\n", GetCurrentProcessId());
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
    printf("Writting...\n <<<<\n");
    PrintMemory(at, nbBytes);
    for (size_t i = 0; i < nbBytes; i++)
    {
        *at = *code;
        at += 1;
        code += 1;
    }
    printf(">>>>\n");
    PrintMemory(at - nbBytes, nbBytes);
    printf("Written %u code bytes from %p to %p\n", nbBytes, at - nbBytes, at);
}

#define SWR_SECTION_TEXT_BEGIN (0x00401000)
#define SWR_SECTION_RSRC_BEGIN (0x00ece000)

#define NOP (0x90)

#define CHANGEWINDOWFLAG_ADDR (0x0049cf7e)
#define ASSETBUFFERMALLOCSIZE_ADDR (0x00449042)

int applyPatches(LoaderConfig* config)
{
    printf("Applying Patches...\n");

    DWORD old;
    VirtualProtect((void*)SWR_SECTION_TEXT_BEGIN, SWR_SECTION_RSRC_BEGIN - SWR_SECTION_TEXT_BEGIN, PAGE_EXECUTE_READWRITE, &old);

    // PrintMemory((unsigned char*)0x0042aa0a, 20);
    // unsigned char debug1[] = { 0x06 };
    // WriteBytes((unsigned char*)0x0042aa0b, debug1, sizeof(debug1));
    // PrintMemory((unsigned char*)0x0042aa0a, 20);
    // memmove((void*)0x0049cf8b + 8, (void*)0x0049cf8b, 0x0049cfc5 - 0x0049cf8b);
    // memset((void*)0x0049cf8b, NOP, 8); // always nop !
    WriteBytes((unsigned char*)ASSETBUFFERMALLOCSIZE_ADDR, (unsigned char*)(&config->assetBufferByteSize), 4);

    if (config->changeWindowFlags)
    {
        unsigned char code[] = { 0x68, 0x00, 0x00, 0x04, 0x90 }; // PUSH imm32 WS_SIZEBOX | WS_VISIBLE | WS_POPUP
        WriteBytes((unsigned char*)CHANGEWINDOWFLAG_ADDR, code, sizeof(code));
    }

    VirtualProtect((void*)SWR_SECTION_TEXT_BEGIN, SWR_SECTION_RSRC_BEGIN - SWR_SECTION_TEXT_BEGIN, old, NULL);

    printf("Patching done. Press any key to continue to the game\n");
    getchar();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        if (!CreateConsoleWindow())
        {
            printf("swr_reimpl dll console exists\n");
        }
        LoaderConfig config;
        parseConfig(&config);
        printConfig(&config);
        applyPatches(&config);
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
