#include "Window.h"

#include "globals.h"

// 0x00423900
LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr)
{
    // TODO
    return 0;
}

// 0x0049ce90
void Window_set_msg_handler(Window_MSGHANDLER handler)
{
    g_WndProc = handler;
}

// 0x0049cea0
int Window_Main(HINSTANCE hInstance, int unused, char* lpCmdLine, int nShowCmd, LPCSTR lpWindowName)
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
    hWnd = FindWindowA("wKernelJones3D", lpCmdLine);
    if (hWnd != NULL)
    {
        stdlib__exit_0(-1);
    }
    lpParam = NULL;
    hMenu = NULL;
    hWnd = NULL;
    nHeight = GetSystemMetrics(1);
    nWidth = GetSystemMetrics(0);
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", lpCmdLine, 0x90000000, 0, 0, nWidth, nHeight, hWnd, hMenu, hInstance, lpParam);
    if (g_hWnd == NULL)
    {
        return 0;
    }
    ShowWindow(g_hWnd, 1);
    UpdateWindow(g_hWnd);
    return 1;
}

// 0x0049cfd0
LRESULT Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
        FUN_004240d0();
        PostQuitMessage(0);
    }
    else if (g_WndProc != NULL)
    {
        window_proc_res = g_WndProc(hWnd, uMsg, wParam, lParam, &uMsg);
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
