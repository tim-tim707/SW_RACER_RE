//
// Created by tly on 27.02.2024.
//
#include <fstream>
#include <windows.h>
#include <cstdio>
#include <cstring>

#include "./game_deltas/tracks_delta.h"
#include "renderer_hook.h"
#include "hook_helper.h"
#include "custom_tracks.h"

FILE *hook_log = nullptr;

// DIAGNOSTIC (remove before any PR): on an unhandled crash, log the faulting address +
// module and a scan of on-stack return addresses (module+offset) to hook.log, so a CTD on
// a tester's machine is actionable from the log alone.
static void crash_log_addr(void *addr) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR) addr, &mod) &&
        mod) {
        char full[MAX_PATH] = {0};
        GetModuleFileNameA(mod, full, MAX_PATH);
        const char *name = strrchr(full, '\\');
        name = name ? name + 1 : full;
        fprintf(hook_log, "    %p  %s+0x%lx\n", addr, name,
                (unsigned long) ((UINT_PTR) addr - (UINT_PTR) mod));
    } else {
        fprintf(hook_log, "    %p  (no module)\n", addr);
    }
}

static bool crash_addr_is_code(void *addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi))
        return false;
    if (mbi.State != MEM_COMMIT)
        return false;
    const DWORD p = mbi.Protect & 0xff;
    return p == PAGE_EXECUTE || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
           p == PAGE_EXECUTE_WRITECOPY;
}

static void crash_dump(EXCEPTION_POINTERS *ep, const char *tag) {
    if (!hook_log)
        return;
    const EXCEPTION_RECORD *er = ep->ExceptionRecord;
    fprintf(hook_log, "\n*** [%s] EXCEPTION code=0x%08lx addr=%p ***\n", tag,
            er->ExceptionCode, er->ExceptionAddress);
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        fprintf(hook_log, "    access %s at %p\n",
                er->ExceptionInformation[0] ? "write" : "read",
                (void *) er->ExceptionInformation[1]);
    }
    fprintf(hook_log, "  faulting instruction:\n");
    crash_log_addr(er->ExceptionAddress);

    fprintf(hook_log, "  on-stack code addresses:\n");
    UINT_PTR *sp = (UINT_PTR *) ep->ContextRecord->Esp;
    int logged = 0;
    for (int i = 0; i < 8192 && logged < 64; i++) {
        if (IsBadReadPtr(&sp[i], sizeof(UINT_PTR)))
            break;
        const UINT_PTR val = sp[i];
        if (val > 0x10000 && crash_addr_is_code((void *) val)) {
            crash_log_addr((void *) val);
            logged++;
        }
    }
    fprintf(hook_log, "*** [%s] end report ***\n", tag);
    fflush(hook_log);
}

static bool crash_is_fatal(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            return true;
        default:
            return false;
    }
}

static LONG WINAPI crash_veh(EXCEPTION_POINTERS *ep) {
    static int reports = 0;
    if (crash_is_fatal(ep->ExceptionRecord->ExceptionCode) && reports < 8) {
        reports++;
        crash_dump(ep, "VEH");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG WINAPI crash_uef(EXCEPTION_POINTERS *ep) {
    crash_dump(ep, "UEF");
    return EXCEPTION_CONTINUE_SEARCH;
}

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

    return nullptr;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook.log", "wb");
    setvbuf(hook_log, nullptr, _IONBF, 0);// DIAGNOSTIC: unbuffered so the log survives a crash

    // DIAGNOSTIC: capture an unhandled crash (faulting addr + stack) into hook.log.
    AddVectoredExceptionHandler(1, crash_veh);
    SetUnhandledExceptionFilter(crash_uef);

    fprintf(hook_log, "[DllMain]\n");
    fflush(hook_log);

    // GOG Version works like Steam Version
    // Steam Version gets initialized with dinput_hook.c: LoadIconA patched to DirectInputCreateA
    // Hook the Import Address Table LoadIconA at 0x004ac23c (untouched by Steam) to run patching code and redirect in Window_Main_delta directly.
    ReCall = (NewLoadIconA) hookIAT("User32", "LoadIconA", (LPVOID) LoadIconHook);

    return TRUE;
}
