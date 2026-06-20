//
// Created by tly on 27.02.2024.
//
#include <fstream>
#include <windows.h>

#include "./game_deltas/tracks_delta.h"
#include "renderer_hook.h"
#include "hook_helper.h"
#include "custom_tracks.h"

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

// Toggle the "AI full LOD" feature (debug-menu option ai_full_lod). Three .text patches are
// applied together when enabled and reverted to the stock bytes when disabled. They take
// effect on the next race load.
//
// 1) swrObjJdge_SpawnRacers @0x0046654d: JNZ 0x46655a -> NOP. Makes every racer (not just the
//    local "Locl" human) load the full pod model + pilot instead of the low-detail "bot" model,
//    so AI render at full detail with no whole-model LOD pop-in.
// 2) swrRace_PoddAnimateVariousThings @0x004723ce: JG 0x472704 -> NOP. Always build the four
//    cockpit/engine connector quads regardless of camera distance (otherwise far pods drop them
//    and look like a bare cockpit "on the floor").
// 3) swrRace_PoddAnimateVariousThings @0x00472577: JG 0x472740 -> NOP. Always build the finer
//    energy-binder detail regardless of distance.
//
// Verified on the OpenGL renderer: full-detail AI with connectors intact, no cockpit detachment,
// no >6-pod crash. Costs some (largely renderer-bound) FPS. NOTE: distant AI still follow the
// track spline (vanilla AI LOD) and can show a slight "tiptoe"; a clean fix for that is tracked
// separately and intentionally out of scope here.
extern "C" void set_ai_full_lod(bool on) {
    struct Patch {
        uint32_t addr;
        uint8_t len;
        uint8_t original[6];// stock bytes (from Ghidra; the Steam EXE .text is encrypted on disk)
    };
    static const Patch patches[] = {
        {0x0046654d, 2, {0x75, 0x0b}},                        // JNZ 0x0046655a
        {0x004723ce, 6, {0x0f, 0x8f, 0x30, 0x03, 0x00, 0x00}},// JG 0x00472704
        {0x00472577, 6, {0x0f, 0x8f, 0xc3, 0x01, 0x00, 0x00}},// JG 0x00472740
    };
    for (const Patch &p: patches) {
        uint8_t bytes[6];
        for (uint8_t i = 0; i < p.len; i++)
            bytes[i] = on ? 0x90 /* NOP */ : p.original[i];
        DWORD oldProtect;
        VirtualProtect((LPVOID) p.addr, p.len, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((LPVOID) p.addr, bytes, p.len);
        VirtualProtect((LPVOID) p.addr, p.len, oldProtect, &oldProtect);
    }
}

HICON __stdcall LoadIconHook(HINSTANCE hInstance, LPCSTR lpIconName) {
    // Main is ready. Patch the hooks and the function we are in to return properly
    fprintf(hook_log, "LoadIcon Hook called\n");
    fflush(hook_log);

    init_renderer_hooks();
    init_hooks();
    init_customTracks();

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
        // I do a ret here but the stack is completely busted at this point. Need to do some stack cleanup, about 0x40 ?
        0xc3,// RET
    };
    VirtualProtect((LPVOID) call_address, sizeof(call_code), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((LPVOID) call_address, call_code, sizeof(call_code));
    VirtualProtect((LPVOID) call_address, sizeof(call_code), oldProtect, &oldProtect);

    // Splitscreen MAlt-engine fix. swrObjJdge_SpawnRacers (0x004663e0) picks a pod "model class"
    // for each local-human racer: (numLocalPlayers > 1) ? 2 : 1. Class 1 loads the main _pod model
    // AND the separate _alt model (which holds the high-detail engines for most racers), linking
    // them via swrModel_FixupAltNodePointers. Class 2 -- chosen in splitscreen -- loads ONLY the
    // _pod model and skips the _alt load + fixup, so racers whose engines live in _alt (Sebulba et
    // al.; Teemto/Anakin instead keep engines in _pod and are unaffected) render with no engines or
    // cockpit in split. NOP the `SETG AL` at 0x00466554 (0F 9F C0 -> 90 90 90): EAX stays 0 from the
    // preceding XOR EAX,EAX, so the following INC makes the class always 1, loading + linking the
    // _alt model in splitscreen too. Single-player is already class 1, so it is unaffected; an
    // out-of-asset-memory _alt load still falls back gracefully via lowMemoryRacerCount.
    uint32_t spawn_class_setg_addr = 0x00466554;
    VirtualProtect((LPVOID) spawn_class_setg_addr, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    memset((LPVOID) spawn_class_setg_addr, 0x90 /* NOP */, 3);
    VirtualProtect((LPVOID) spawn_class_setg_addr, 3, oldProtect, &oldProtect);

    // Splitscreen P2 forward-thrust fix. In swrRace_UpdatePlayerControl (0x0046bec0) the in-race
    // "indexed" control path (control types 1-7, used by the 2nd local player) decodes every input
    // per-player from the raw input slots EXCEPT forward thrust: at 0x0046bfbf it reads the single
    // global swrRace_ThrustInput (0x00ec884c, written only by swrControl_ProcessInputs from the main
    // device) into local_48 -- the flag that drives gravityMultiplier = 1.0 (full forward). So the
    // 2nd player's accelerate never reaches the engine; only the main device can. The per-player
    // accelerate bit IS already decoded (inRaceLocalPlayerInputBitset3[idx] & 0x100, folded in from
    // raw slot+0x11), and at 0x0046bfbf register EDI still holds that bitset word. Redirect local_48
    // to read the per-player accelerate bit instead of the global:
    //     FLD [0x00ec884c]; CALL __ftol; MOV [ESP+0x28],EAX      (D9 05 .. ; E8 .. ; 89 44 24 28)
    //  -> MOV EAX,EDI; AND EAX,0x100; MOV [ESP+0x28],EAX; NOP*4  (same 15 bytes, FPU stack balanced)
    // Only local human players reach UpdatePlayerControl (swrRace_CalcTargetTurnRate routes AI/remote
    // to the autopilot path), and only the 2nd local player uses an indexed control type, so this is
    // inert for the main player, AI, and single-player. Pairs with swrControl_FeedPlayer2Input, which
    // feeds the 2nd gamepad into raw slot 1.
    uint32_t thrust_input_addr = 0x0046bfbf;
    uint8_t thrust_code[] = {
        0x8b, 0xc7,                   // MOV EAX,EDI         (EDI = inRaceLocalPlayerInputBitset3[idx])
        0x25, 0x00, 0x01, 0x00, 0x00, // AND EAX,0x100       (accelerate bit)
        0x89, 0x44, 0x24, 0x28,       // MOV [ESP+0x28],EAX  (local_48)
        0x90, 0x90, 0x90, 0x90,       // NOP padding to match the original 15-byte sequence
    };
    VirtualProtect((LPVOID) thrust_input_addr, sizeof(thrust_code), PAGE_EXECUTE_READWRITE,
                   &oldProtect);
    memcpy((LPVOID) thrust_input_addr, thrust_code, sizeof(thrust_code));
    VirtualProtect((LPVOID) thrust_input_addr, sizeof(thrust_code), oldProtect, &oldProtect);

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
