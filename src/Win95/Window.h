#ifndef WINDOW_H
#define WINDOW_H

#include <windows.h>
#include "types.h"

#define Window_msg_default_handler_ADDR (0x00423900)

#define Window_SetHWND_ADDR (0x0048c770)
#define Window_GetHWND_ADDR (0x0048c780)
#define Window_SetHINSTANCE_ADDR (0x0048c790)
#define Window_SetUUID_ADDR (0x0048c7b0)

#define Window_Main_ADDR (0x0049cd40)
#define Window_SetWindowPos_ADDR (0x0049ce60)
#define Window_set_msg_handler_ADDR (0x0049ce90)
#define Window_CreateMainWindow_ADDR (0x0049cea0)
#define Window_msg_main_handler_ADDR (0x0049cfd0)

LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr);
void Window_SetHWND(HWND hwnd);
HWND Window_GetHWND(void);
void Window_SetHINSTANCE(HINSTANCE hInstance);
void Window_SetUUID(uint32_t* uuid); // uuid[4]

int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, const char* window_name);
BOOL Window_SetWindowPos(int cx, int cy);

void Window_set_msg_handler(Window_MSGHANDLER_ptr proc);
int Window_CreateMainWindow(HINSTANCE hInstance, int unused, const char* window_name, int unused2, LPCSTR unused3);
LRESULT __attribute__((__stdcall__)) Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif // WINDOW_H
