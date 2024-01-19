#include "Window.h"

#include <Windows.h>
#include <commctrl.h>

#include "globals.h"

#include "../Main/Main.h"
#include "../Main/swrMain.h"
#include "stdPlatform.h"

// 0x00423900
LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr)
{
    // TODO
    return 0;
}

// 0x00423ae0
void Window_SetActivated(HWND hwnd, WPARAM activated)
{
    if (activated != 0)
    {
        if (Window_Active == 0)
        {
            if ((swrMainDisplaySettings_g.RegFullScreen == 0) && (swrMainDisplaySettings_g.RegDevMode == 0))
            {
                ShowWindow(hwnd, 3);
            }
            swrDisplay_SetWindowPos();
            stdDisplay_Refresh(1);
            std3D_ClearCacheList();
            swrDisplay_SetWindowPos();
        }
        swrMain_GuiAdvanceFunction = (void*)swrMain_GuiAdvance;
        Window_Active = 1;
        swrGui_Stop(0);
        stdControl_SetActivation(activated);
        return;
    }
    swrMain_GuiAdvanceFunction = stdPlatform_noop;
    stdDisplay_Refresh(0);
    Window_Active = 0;
    swrGui_Stop(1);
    stdControl_SetActivation(0);
}

// 0x00423b90
void Window_Resize(HWND hwnd, WPARAM edgeOfWindow, tagRECT* dragRectangle)
{
    int height;
    int width;
    tagRECT windowRect;
    tagRECT clientRect;

    GetWindowRect(hwnd, &windowRect);
    GetClientRect(hwnd, &clientRect);
    clientRect.right = (windowRect.right - windowRect.left) - clientRect.right;
    clientRect.bottom = (windowRect.bottom - windowRect.top) - clientRect.bottom;
    switch (edgeOfWindow)
    {
    case 1:
    case 2:
        width = (dragRectangle->right - clientRect.right) - dragRectangle->left;
        hwnd = (HWND)((int)(width + (width >> 0x1f & 3U)) >> 2);
        break;
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
        hwnd = (HWND)(((dragRectangle->bottom - dragRectangle->top) - clientRect.bottom) / 3);
    }
    Windows_windowWidth = (int)hwnd * 3;
    Windows_windowHeight = (int)hwnd * 4;
    width = Windows_windowWidth;
    if (Windows_windowWidth < 0x50)
    {
        width = 0x50;
    }
    height = Windows_windowHeight;
    if (Windows_windowHeight < 0x3c)
    {
        height = 0x3c;
    }
    dragRectangle->bottom = dragRectangle->top + width + clientRect.bottom;
    dragRectangle->right = dragRectangle->left + height + clientRect.right;
    Windows_WinProc_res = 1;
}

// 0x00423c80
void Window_ResizeExit(HWND unused)
{
    int set;

    set = swrDisplay_SetWindowPos();
    if (set == 0)
    {
        swrDisplay_Resize(&swrMainDisplaySettings_g, Windows_windowWidth, Windows_windowHeight);
    }
}

// 0x0048c770
void Window_SetHWND(HWND hwnd)
{
    Window_hWnd = hwnd;
}

// 0x0048c780
HWND Window_GetHWND(void)
{
    return Window_hWnd;
}

// 0x0048c790
void Window_SetHINSTANCE(HINSTANCE hInstance)
{
    Window_hinstance = hInstance;
}

// 0x0048c7a0
HINSTANCE Window_GETHINSTANCE(void)
{
    return Window_hinstance;
}

// 0x0048c7b0
void Window_SetGUID(GUID* guid)
{
    // copy guid
    ((uint32_t*)&Window_GUID)[0] = ((uint32_t*)guid)[0];
    ((uint32_t*)&Window_GUID)[1] = ((uint32_t*)guid)[1];
    ((uint32_t*)&Window_GUID)[2] = ((uint32_t*)guid)[2];
    ((uint32_t*)&Window_GUID)[3] = ((uint32_t*)guid)[3];
}

// 0x0048c7e0
GUID* Window_GetGUID(void)
{
    return &Window_GUID;
}

// 0x0049cd40
int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, const char* window_name)
{
    int iVar1;
    int iVar2;
    BOOL msg_res;
    LPCSTR unaff_ESI;
    int unaff_EDI;
    tagMSG msg;

    g_nCmdShow = nCmdShow;
    Window_CreateMainWindow(hInstance, nCmdShow, window_name, 0, NULL);
    Window_SetHWND(g_hWnd);
    Window_SetHINSTANCE(hInstance);
    GUID win_guid = {
        Window_UUID[0],
        Window_UUID[1],
        Window_UUID[2],
        Window_UUID[3],
    };

    Window_SetGUID(&win_guid);
    InitCommonControls();
    iVar1 = GetSystemMetrics(0x20);
    Window_border_width = iVar1 << 1;
    iVar1 = GetSystemMetrics(0x20);
    iVar2 = GetSystemMetrics(0xf);
    Window_border_height = iVar2 + iVar1 * 2;
    iVar1 = Main_Startup((char*)pCmdLine);
    if (iVar1 == 0)
    {
        return 0;
    }
    do
    {
        while (msg_res = PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE), msg_res == 0)
        {
            swrMain_GuiAdvance();
        }
        do
        {
            msg_res = GetMessageA(&msg, NULL, 0, 0);
            if (msg_res == -1)
            {
                return -1;
            }
            if (msg_res == 0)
            {
                return msg.wParam;
            }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
            msg_res = PeekMessageA(&msg, NULL, 0, 0, 0);
        } while (msg_res != 0);
    } while (true);
}

// 0x0049ce60
BOOL Window_SetWindowPos(int width, int height)
{
    return SetWindowPos(g_hWnd, NULL, 0, 0, width + Window_border_width, height + Window_border_height, SWP_NOMOVE | SWP_NOZORDER);
}

// 0x0049ce90
void Window_set_msg_handler(Window_MSGHANDLER_ptr handler)
{
    g_WndProc = handler;
}

// 0x0049cea0
int Window_CreateMainWindow(HINSTANCE hInstance, int unused, const char* window_name, int unused2, LPCSTR unused3)
{
    ATOM register_class_res;
    HWND hWnd;
    int nHeight;
    int nWidth;
    HMENU hMenu;
    LPVOID lpParam;
    WNDCLASSEXA wndClass;

    wndClass.cbSize = 0x30;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = "wKernelJones3D";
    wndClass.lpszMenuName = NULL;
    wndClass.lpfnWndProc = Window_msg_main_handler;
    // FROM LRESULT (*)(HWND, UINT, WPARAM, LPARAM)
    // TO WNDPROC
    // aka
    // long int (*)(HWND__*, unsigned int, unsigned int, long int)
    // long int (__attribute__((stdcall)) *)(HWND__*, unsigned int, unsigned int, long int)
    wndClass.style = 0;
    wndClass.hIcon = LoadIconA(hInstance, "APPICON");
    if (wndClass.hIcon == NULL)
    {
        wndClass.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hIconSm = LoadIconA(hInstance, "APPICON");
    if (wndClass.hIconSm == NULL)
    {
        wndClass.hIconSm = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = (HBRUSH)GetStockObject(4);
    register_class_res = RegisterClassExA(&wndClass);
    if (register_class_res == 0)
    {
        return 0;
    }
    hWnd = FindWindowA("wKernelJones3D", window_name);
    if (hWnd != NULL)
    {
        exit(-1);
    }
    lpParam = NULL;
    hMenu = NULL;
    hWnd = NULL;
    nHeight = GetSystemMetrics(1);
    nWidth = GetSystemMetrics(0);
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", window_name, 0x90000000, 0, 0, nWidth, nHeight, hWnd, hMenu, hInstance, lpParam);
    if (g_hWnd == NULL)
    {
        return 0;
    }
    ShowWindow(g_hWnd, 1);
    UpdateWindow(g_hWnd);
    return 1;
}

// 0x0049cfd0
LRESULT __attribute__((__stdcall__)) Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    LPARAM lParam_;
    WPARAM wParam_;
    UINT uMsg_;
    int window_proc_res;

    lParam_ = lParam;
    wParam_ = wParam;
    uMsg_ = uMsg;
    if (uMsg == 2)
    {
        Main_Shutdown();
        PostQuitMessage(0);
    }
    else if (g_WndProc != NULL)
    {
        window_proc_res = (*g_WndProc)(hWnd, uMsg, wParam, lParam, &uMsg);
        if (window_proc_res != 0)
        {
            return uMsg;
        }
        goto end;
    }
    lParam_ = lParam;
    wParam_ = wParam;
    if (false) // original compilation artifact
    {
        return 1;
    }
end:
    return DefWindowProcA(hWnd, uMsg_, wParam_, lParam_);
}
