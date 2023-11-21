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
    if (g_config.developperMode)
    {
        printf("Waiting for input...\n");
        getchar();
    }

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
    if (g_config.developperMode)
    {
        printf("Writting...\n <<<<\n");
        PrintMemory(at, nbBytes);
    }
    for (size_t i = 0; i < nbBytes; i++)
    {
        *at = *code;
        at += 1;
        code += 1;
    }
    if (g_config.developperMode)
    {
        printf(">>>>\n");
        PrintMemory(at - nbBytes, nbBytes);
        printf("Written %u code bytes from %p to %p\n", nbBytes, at - nbBytes, at);
    }
}

#define SWR_SECTION_TEXT_BEGIN (0x00401000)
#define SWR_SECTION_RSRC_BEGIN (0x00ece000)

#define NOP (0x90)

void patchAssetBuffer()
{
    unsigned char* ASSETBUFFERMALLOCSIZE_ADDR = (unsigned char*)0x00449042;
    unsigned char* ASSETBUFFERENDOFFSET_ADDR = (unsigned char*)0x0044904d;
    WriteBytes(ASSETBUFFERMALLOCSIZE_ADDR, (unsigned char*)(&g_config.assetBufferByteSize), 4);
    WriteBytes(ASSETBUFFERENDOFFSET_ADDR, (unsigned char*)(&g_config.assetBufferByteSize), 4);
}

void patchWindowFlag()
{
    unsigned char* CHANGEWINDOWFLAG_ADDR = (unsigned char*)0x0049cf7e;
    if (g_config.changeWindowFlags)
    {
        unsigned char pushNewFlags[] = { 0x68, 0x00, 0x00, 0x04, 0x90 }; // PUSH imm32 WS_SIZEBOX | WS_VISIBLE | WS_POPUP
        WriteBytes(CHANGEWINDOWFLAG_ADDR, pushNewFlags, sizeof(pushNewFlags));
    }
}

void patchFOV()
{
    unsigned char* CAMERAFOVCHANGE_ADDR = (unsigned char*)0x004832ee;
    unsigned char* CAMERAFOVCHANGEF1_ADDR = (unsigned char*)0x0048349e;
    unsigned char* CAMERAFOVCHANGEF2_ADDR = (unsigned char*)0x004834a7;

    // make room for FOV change. + 8 bytes, hitting into nops without issues
    memmove((void*)(CAMERAFOVCHANGE_ADDR + 8), (void*)CAMERAFOVCHANGE_ADDR, 0x1ba);
    memset((void*)CAMERAFOVCHANGE_ADDR, NOP, 14); // we remove the original instruction as well and put it in our shellcode instead

    // MOV ECX, config->cameraFOV
    // MOV [ESI + 0x44], ECX
    // MOV ECX, 0x3f800000 // Put back the original value for the rest of the function
    unsigned char cameraFOVPatch[13] = { 0xB9, NOP, NOP, NOP, NOP, 0x89, 0x4E, 0x44, 0xB9, 0x00, 0x00, 0x80, 0x3F };
    memmove(&(cameraFOVPatch[1]), (void*)(&g_config.cameraFOV), 4);
    WriteBytes(CAMERAFOVCHANGE_ADDR, cameraFOVPatch, sizeof(cameraFOVPatch));

    // Need to patch the two rel16 function call. These two writes both do -8 on the relative call
    unsigned char cameraFOVF1 = 0x3e;
    WriteBytes(CAMERAFOVCHANGEF1_ADDR, &cameraFOVF1, 1);
    unsigned char cameraFOVF2 = 0x65;
    WriteBytes(CAMERAFOVCHANGEF2_ADDR, &cameraFOVF2, 1);
}

void patchSkipRaceCutscene()
{
    unsigned char* SKIPRACECUTSCENE_ADDR = (unsigned char*)0x0045753d;
    if (g_config.skipRaceCutscene == false)
        return;
    unsigned char nops[5] = { NOP, NOP, NOP, NOP, NOP };
    WriteBytes(SKIPRACECUTSCENE_ADDR, nops, sizeof(nops));
}

void patchSkipIntroCamera()
{
    if (g_config.skipIntroCamera == false)
        return;
    unsigned char* SKIPINTROCAMERA_ADDR = (unsigned char*)0x0045e2d5;
    unsigned char float_zero[4] = { 0, 0, 0, 0 };
    WriteBytes(SKIPINTROCAMERA_ADDR, float_zero, sizeof(float_zero));
}

int applyPatches()
{
    if (g_config.developperMode)
        printf("Applying Patches...\n");

    DWORD old;
    VirtualProtect((void*)SWR_SECTION_TEXT_BEGIN, SWR_SECTION_RSRC_BEGIN - SWR_SECTION_TEXT_BEGIN, PAGE_EXECUTE_READWRITE, &old);

    patchAssetBuffer();
    // patchWindowFlag(); // TODO: investigate
    patchFOV();
    patchSkipRaceCutscene();
    patchSkipIntroCamera();

    VirtualProtect((void*)SWR_SECTION_TEXT_BEGIN, SWR_SECTION_RSRC_BEGIN - SWR_SECTION_TEXT_BEGIN, old, NULL);

    if (g_config.developperMode)
    {
        printf("Patching done. Press any key to continue to the game\n");
        getchar();
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        parseConfig();
        printConfig();
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
