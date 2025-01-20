#include "main_delta.h"

#include <windows.h>
#include <stdint.h>

#include "./Window_delta.h"
#include "macros.h"

// 0x004238d0
int __stdcall WinMain_delta(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine,
                            int nCmdShow) {
    // TODO: have a cast of address for sub functions instead of a hook
    Window_Main_delta(hInstance, hPrevInstance, pCmdLine, nCmdShow,
                      "Episode I Racer: Community Edition");

    return 0;
}
