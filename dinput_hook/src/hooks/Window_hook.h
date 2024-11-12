#pragma once

#include "types.h"

#include <Windows.h>
#include <commctrl.h>

void Window_SetActivated_hook(HWND hwnd, WPARAM activated);
int Window_SmushPlayCallback_hook(const SmushImage *image);
int Window_Main_hook(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow,
                     const char *window_name);
