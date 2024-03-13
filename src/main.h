#ifndef MAIN_H
#define MAIN_H

#include <windows.h>
#include <stdint.h>

#define WinMain_ADDR (0x004238d0)

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow);

#endif // MAIN_H
