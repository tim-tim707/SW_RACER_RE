//
// Created by tly on 27.02.2024.
//
#include <fstream>
#include <windows.h>

#include "renderer_hook.h"
#include "hook_helper.h"

FILE *hook_log = nullptr;

// https://github.com/lcsig/API-Hooking
DWORD_PTR hookIAT(const char *libName, const char *API_Name, LPVOID newFun) {
    DWORD_PTR imageBase = (DWORD_PTR) GetModuleHandleA(0);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER) imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS) (imageBase + dosHeaders->e_lfanew);
    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor =
        (PIMAGE_IMPORT_DESCRIPTOR) (imageBase +
                                    optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                        .VirtualAddress);

    DWORD oldProtect;
    PIMAGE_IMPORT_BY_NAME functionName;
    PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
    /*
	Initially FirstThunk is the same as OriginalFirstThunk
	The OriginalFirstThunk is array of names ---> Uses the AddressOfData element of the IMAGE_THUNK_DATA structure to point to IMAGE_IMPORT_BY_NAME structure that contains the Name element, function name.
	The FirstThunk is array of addresses -------> Uses the Function element of the IMAGE_THUNK_DATA structure, which points to the address of the imported function.

	When the executable is loaded, the loader goes through the OriginalFirstThunk array and finds all imported function names the executable is using.
	Then it calculates the addresses of the functions and populates the FirstThunk array so that real functions can be accessed.
	As a result, we need to change the real loaded addresses which are found in FirstThunk not in OriginalFirstThunk
	*/

    LoadLibraryA(libName);
    while (importDescriptor->Name) {

        if (strnicmp(libName, (LPCSTR) (imageBase + importDescriptor->Name), strlen(libName)) !=
            0) {
            importDescriptor++;
            continue;
        }

        originalFirstThunk = (PIMAGE_THUNK_DATA) (imageBase + importDescriptor->OriginalFirstThunk);
        firstThunk = (PIMAGE_THUNK_DATA) (imageBase + importDescriptor->FirstThunk);

        while (originalFirstThunk->u1.AddressOfData) {
            functionName =
                (PIMAGE_IMPORT_BY_NAME) (imageBase + originalFirstThunk->u1.AddressOfData);

            if (strcmp(functionName->Name, API_Name) == 0) {
                VirtualProtect((LPVOID) (&firstThunk->u1.Function), sizeof(DWORD_PTR),
                               PAGE_READWRITE, &oldProtect);
                firstThunk->u1.Function = (DWORD_PTR) newFun;
                VirtualProtect((LPVOID) (&firstThunk->u1.Function), sizeof(DWORD_PTR), oldProtect,
                               &oldProtect);

                return (DWORD_PTR) GetProcAddress(LoadLibraryA(libName), API_Name);
            }

            originalFirstThunk++;
            firstThunk++;
        }
    }

    return (DWORD_PTR) nullptr;
}

typedef HICON(WINAPI *NewLoadIconA)(HINSTANCE hInstance, LPCSTR lpIconName);
NewLoadIconA ReCall;

HICON __stdcall LoadIconHook(HINSTANCE hInstance, LPCSTR lpIconName) {
    // Main is ready. Patch the hooks and the function we are in to return properly
    fprintf(hook_log, "LoadIcon Hook called\n");
    fflush(hook_log);

    init_renderer_hooks();
    init_hooks();

    // nop Window_CreateMainWindow from 0x0049cede to 0x0049cfb8 included, will return peacefully
    DWORD oldProtect;
    uint32_t addr = 0x0049cede;
    uint32_t size = 0x0049cfb9 - addr;
    VirtualProtect((LPVOID) addr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memset((LPVOID) addr, 0x90 /* NOP */, size);
    VirtualProtect((LPVOID) addr, size, oldProtect, &oldProtect);

    // in Window_Main, call Window_Main again, that will be hooked to Window_Main_delta and early return
    uint32_t call_address = 0x0049cd60;
    uint8_t call_code[] = {
        0x8b, 0x44, 0x24, 0x4c, 0x50,// MOV + Push window_name
        0x8b, 0x74, 0x24, 0x4c, 0x56,// MOV + Push nCmdShow
        0x8b, 0x4c, 0x24, 0x4c, 0x51,// MOV + Push pCmdLine
        0x8b, 0x44, 0x24, 0x4c, 0x50,// MOV + Push hPrevInstance
        0x8b, 0x44, 0x24, 0x4c, 0x50,// MOV + Push hInstance
        0x8b, 0x44, 0x24, 0x4c, 0x50,// MOV + Push Return Address
        0xeb, 0xc0,                  // JMP Window_Main, rel16 just above ourselves
        // I do a ret here but the stack is completely busted at this point. Need to do some stack cleanup
        0xc3,// RET
    };
    VirtualProtect((LPVOID) call_address, sizeof(call_code), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((LPVOID) call_address, call_code, sizeof(call_code));
    VirtualProtect((LPVOID) call_address, sizeof(call_code), oldProtect, &oldProtect);

    return nullptr;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook.log", "wb");

    fprintf(hook_log, "[DllMain]\n");
    fflush(hook_log);

    // GOG Version works like Steam Version
    // Steam Version gets initialized with dinput_hook.c: LoadIconA patched to DirectInputCreateA
    // Hook the Import Address Table LoadIconA at 0x004ac23c (untouched by Steam) to run patching code and redirect in Window_Main_delta directly.
    ReCall = (NewLoadIconA) hookIAT("User32", "LoadIconA", (LPVOID) LoadIconHook);

    return TRUE;
}
