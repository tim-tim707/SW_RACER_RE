#include "main.h"

#include <windows.h>
#include <stdint.h>

#include "./Win95/Window.h"
#include "macros.h"

// 0x004238d0
int __stdcall WinMain_delta(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine,
                            int nCmdShow) {
    // TODO: have a cast of address for sub functions instead of a hook
    Window_Main(hInstance, hPrevInstance, pCmdLine, nCmdShow, "Episode I Racer: Community Edition");

    return 0;
}
