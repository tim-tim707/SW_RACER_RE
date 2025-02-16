//
// Created by tly on 27.02.2024.
//
#include <fstream>
#include <windows.h>

#include "renderer_hook.h"
#include "hook_helper.h"

FILE *hook_log = nullptr;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook.log", "wb");

    fprintf(hook_log, "[DllMain]\n");
    fflush(hook_log);

    // GOG Version
    if (0) {
        init_renderer_hooks();
        init_hooks();
    }

    // Steam Version gets initialized with dinput_hook.c: DirectInputCreateA, which is late but we can't do much about it

    return TRUE;
}
