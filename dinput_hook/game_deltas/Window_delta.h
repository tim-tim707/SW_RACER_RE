#pragma once

#include <windows.h>

#include "types.h"

void Window_SetActivated_delta(HWND hwnd, WPARAM activated);
void Window_Resize_delta(HWND hwnd, WPARAM edgeOfWindow, struct tagRECT *dragRectangle);

int Window_SmushPlayCallback_delta(const SmushImage *image_info);

int Window_Main_delta(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow,
                      const char *window_name);

int Window_CreateMainWindow_delta(HINSTANCE hInstance, int unused, const char *window_name,
                                  int unused2, LPCSTR unused3);
