#ifndef WINDOW_H
#define WINDOW_H

#include <windows.h>

#include "types.h"

#define Window_msg_default_handler_ADDR (0x00423900)

#define Window_ActivateApp_ADDR (0x00423aa0)
#define Window_Activate_ADDR (0x00423ac0)

#define Window_SetActivated_ADDR (0x00423ae0)
#define Window_Resize_ADDR (0x00423b90)
#define Window_ResizeExit_ADDR (0x00423c80)
#define Window_SetWindowed_ADDR (0x004246c0)

#define Window_DisplaySettingsBox_ADDR (0x004246d0)

#define Window_DisplaySettingsCallback_ADDR (0x00424700)

#define Window_SmushPlayCallback_ADDR (0x00425070)
#define Window_PlayCinematic_ADDR (0x004252a0)
#define Window_CDCheck_ADDR (0x00425500)

#define Window_DisplaySettingsMoveWindow_ADDR (0x00425820)

#define Window_SetHWND_ADDR (0x0048c770)
#define Window_GetHWND_ADDR (0x0048c780)
#define Window_SetHINSTANCE_ADDR (0x0048c790)
#define Window_GetHINSTANCE_ADDR (0x0048c7a0)
#define Window_SetGUID_ADDR (0x0048c7b0)
#define Window_GetGUID_ADDR (0x0048c7e0)

#define Window_Main_ADDR (0x0049cd40)
#define Window_SetWindowPos_ADDR (0x0049ce60)
#define Window_set_msg_handler_ADDR (0x0049ce90)
#define Window_CreateMainWindow_ADDR (0x0049cea0)
#define Window_msg_main_handler_ADDR (0x0049cfd0)

LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr);
void Window_ActivateApp(HWND hwnd, WPARAM activated, LPARAM unused);
void Window_Activate(HWND hwnd, int active, LPARAM unused, WPARAM unused2);

void Window_SetActivated(HWND hwnd, WPARAM activated);
void Window_Resize(HWND hwnd, WPARAM edgeOfWindow, struct tagRECT* dragRectangle);
void Window_ResizeExit(HWND unused);
void Window_SetWindowed(int windowed);

void Window_DisplaySettingsBox(HWND hwnd, swrMainDisplaySettings* displaySettings);

int Window_DisplaySettingsCallback(HWND dialogBoxHwnd, unsigned int message, WPARAM infos, LPARAM displaySettings);

int Window_SmushPlayCallback(void* image_info);
int Window_PlayCinematic(char** znmFile);
int Window_CDCheck(void);

int Window_DisplaySettingsMoveWindow(HWND dialogBoxHwnd);

void Window_SetHWND(HWND hwnd);
HWND Window_GetHWND(void);
void Window_SetHINSTANCE(HINSTANCE hInstance);
HINSTANCE Window_GetHINSTANCE(void);
void Window_SetGUID(GUID* guid);
GUID* Window_GetGUID(void);

int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, const char* window_name);
BOOL Window_SetWindowPos(int cx, int cy);

void Window_set_msg_handler(Window_MSGHANDLER proc);
int Window_CreateMainWindow(HINSTANCE hInstance, int unused, const char* window_name, int unused2, LPCSTR unused3);
LRESULT __stdcall Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

#endif // WINDOW_H
