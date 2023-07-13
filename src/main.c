#include "main.h"

#include "./Win95/Window.h"
#include <windows.h>
#include "macros.h"
#include <stdint.h>

// 0x004238d0
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow)
{
    Window_Main(hInstance, hPrevInstance, pCmdLine, nCmdShow, "Episode I Racer: Community Edition");

    return 0;
}
