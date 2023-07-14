#include "Window.h"

#include "globals.h"
#include <windows.h>

// 0x00423900
LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr)
{
    // TODO
    return 0;
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

// 0x0048c7b0
void Window_SetUUID(uint32_t* uuid) // uuid[4]
{
    Window_UUID_0 = uuid[0];
    Window_UUID_1 = uuid[1];
    Window_UUID_2 = uuid[2];
    Window_UUID_3 = uuid[3];
}

// 0x0049cd40
int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, char* window_name)
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
    Window_SetUUID(Window_UUID);
    InitCommonControls();
    iVar1 = GetSystemMetrics(0x20);
    Window_width = iVar1 << 1;
    iVar1 = GetSystemMetrics(0x20);
    iVar2 = GetSystemMetrics(0xf);
    Window_height = iVar2 + iVar1 * 2;
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
BOOL Window_SetWindowPos(int cx, int cy)
{
    return SetWindowPos(g_hWnd, NULL, 0, 0, cx + Window_width, cy + Window_height, SWP_NOMOVE | SWP_NOZORDER);
}

// 0x0049ce90
void Window_set_msg_handler(Window_MSGHANDLER_ptr handler)
{
    g_WndProc = handler;
}

// 0x0049cea0
int Window_CreateMainWindow(HINSTANCE hInstance, int unused, char* lpCmdLine, int unused2, LPCSTR unused3)
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
