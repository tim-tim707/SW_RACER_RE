#ifndef MAIN_H
#define MAIN_H

#include <windows.h>
#include <stdint.h>

int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int32_t nShowCmd);
WPARAM swr_main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int32_t nCmdShow, LPCSTR window_name);

#endif // MAIN_H
