//
// Created by tly on 27.02.2024.
//
#include <fstream>
#include <thread>
#include <windows.h>

#include "globals.h"

#include "gltf_utils.h"
#include "renderer_hook.h"

#include "hook_helper.h"


FILE *hook_log = nullptr;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    hook_log = fopen("hook.log", "wb");

    fprintf(hook_log, "[DllMain]\n");
    fflush(hook_log);

    init_renderer_hooks();
    init_hooks();

    return TRUE;
}
