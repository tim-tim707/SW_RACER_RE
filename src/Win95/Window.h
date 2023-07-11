#ifndef WINDOW_H
#define WINDOW_H

#include <windows.h>

#define Window_msg_default_handler_ADDR (0x00423900)

#define Window_set_msg_handler_ADDR (0x0049ce90)
#define Window_Main_ADDR (0x0049cea0)
#define Window_msg_main_handler_ADDR (0x0049cfd0)

LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr);

void Window_set_msg_handler(Window_MSGHANDLER proc);
int Window_Main(HINSTANCE hInstance, int unused, char* lpCmdLine, int nShowCmd, LPCSTR lpWindowName);
LRESULT Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif // WINDOW_H
