#include "Window.h"

#include <Windows.h>
#include <commctrl.h>

#include "globals.h"
#include "stdDisplay.h"

#include "stdPlatform.h"

#include <macros.h>
#include <Gui/swrGui.h>
#include <Main/swrControl.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Swr/swrDisplay.h>
#include <Win95/Window.h>
#include <Main/swrMain.h>
#include <Main/swrMain2.h>
#include <Swr/swrUI.h>

#if GLFW_BACKEND
#include <glad/glad.h>
#include <GLFW/glfw3.h>

const static int glfw_key_to_dik[] = {
    [GLFW_KEY_SPACE] = DIK_SPACE,
    [GLFW_KEY_APOSTROPHE] = DIK_APOSTROPHE,
    [GLFW_KEY_COMMA] = DIK_COMMA,
    [GLFW_KEY_MINUS] = DIK_MINUS,
    [GLFW_KEY_PERIOD] = DIK_PERIOD,
    [GLFW_KEY_SLASH] = DIK_SLASH,
    [GLFW_KEY_0] = DIK_0,
    [GLFW_KEY_1] = DIK_1,
    [GLFW_KEY_2] = DIK_2,
    [GLFW_KEY_3] = DIK_3,
    [GLFW_KEY_4] = DIK_4,
    [GLFW_KEY_5] = DIK_5,
    [GLFW_KEY_6] = DIK_6,
    [GLFW_KEY_7] = DIK_7,
    [GLFW_KEY_8] = DIK_8,
    [GLFW_KEY_9] = DIK_9,
    [GLFW_KEY_SEMICOLON] = DIK_SEMICOLON,
    [GLFW_KEY_EQUAL] = DIK_EQUALS,
    [GLFW_KEY_A] = DIK_A,
    [GLFW_KEY_B] = DIK_B,
    [GLFW_KEY_C] = DIK_C,
    [GLFW_KEY_D] = DIK_D,
    [GLFW_KEY_E] = DIK_E,
    [GLFW_KEY_F] = DIK_F,
    [GLFW_KEY_G] = DIK_G,
    [GLFW_KEY_H] = DIK_H,
    [GLFW_KEY_I] = DIK_I,
    [GLFW_KEY_J] = DIK_J,
    [GLFW_KEY_K] = DIK_K,
    [GLFW_KEY_L] = DIK_L,
    [GLFW_KEY_M] = DIK_M,
    [GLFW_KEY_N] = DIK_N,
    [GLFW_KEY_O] = DIK_O,
    [GLFW_KEY_P] = DIK_P,
    [GLFW_KEY_Q] = DIK_Q,
    [GLFW_KEY_R] = DIK_R,
    [GLFW_KEY_S] = DIK_S,
    [GLFW_KEY_T] = DIK_T,
    [GLFW_KEY_U] = DIK_U,
    [GLFW_KEY_V] = DIK_V,
    [GLFW_KEY_W] = DIK_W,
    [GLFW_KEY_X] = DIK_X,
    [GLFW_KEY_Y] = DIK_Y,
    [GLFW_KEY_Z] = DIK_Z,
    [GLFW_KEY_LEFT_BRACKET] = DIK_LBRACKET,
    [GLFW_KEY_BACKSLASH] = DIK_BACKSLASH,
    [GLFW_KEY_RIGHT_BRACKET] = DIK_RBRACKET,
    [GLFW_KEY_GRAVE_ACCENT] = DIK_GRAVE,
    [GLFW_KEY_ESCAPE] = DIK_ESCAPE,
    [GLFW_KEY_ENTER] = DIK_RETURN,
    [GLFW_KEY_TAB] = DIK_TAB,
    [GLFW_KEY_BACKSPACE] = DIK_BACKSPACE,
    [GLFW_KEY_INSERT] = DIK_INSERT,
    [GLFW_KEY_DELETE] = DIK_DELETE,
    [GLFW_KEY_RIGHT] = DIK_RIGHT,
    [GLFW_KEY_LEFT] = DIK_LEFT,
    [GLFW_KEY_DOWN] = DIK_DOWN,
    [GLFW_KEY_UP] = DIK_UP,
    [GLFW_KEY_PAGE_UP] = DIK_PGUP,
    [GLFW_KEY_PAGE_DOWN] = DIK_PGDN,
    [GLFW_KEY_HOME] = DIK_HOME,
    [GLFW_KEY_END] = DIK_END,
    [GLFW_KEY_CAPS_LOCK] = DIK_CAPSLOCK,
    [GLFW_KEY_SCROLL_LOCK] = DIK_SCROLL,
    [GLFW_KEY_NUM_LOCK] = DIK_NUMLOCK,
    [GLFW_KEY_PAUSE] = DIK_PAUSE,
    [GLFW_KEY_F1] = DIK_F1,
    [GLFW_KEY_F2] = DIK_F2,
    [GLFW_KEY_F3] = DIK_F3,
    [GLFW_KEY_F4] = DIK_F4,
    [GLFW_KEY_F5] = DIK_F5,
    [GLFW_KEY_F6] = DIK_F6,
    [GLFW_KEY_F7] = DIK_F7,
    [GLFW_KEY_F8] = DIK_F8,
    [GLFW_KEY_F9] = DIK_F9,
    [GLFW_KEY_F10] = DIK_F10,
    [GLFW_KEY_F11] = DIK_F11,
    [GLFW_KEY_F12] = DIK_F12,
    [GLFW_KEY_F13] = DIK_F13,
    [GLFW_KEY_F14] = DIK_F14,
    [GLFW_KEY_F15] = DIK_F15,
    [GLFW_KEY_KP_0] = DIK_NUMPAD0,
    [GLFW_KEY_KP_1] = DIK_NUMPAD1,
    [GLFW_KEY_KP_2] = DIK_NUMPAD2,
    [GLFW_KEY_KP_3] = DIK_NUMPAD3,
    [GLFW_KEY_KP_4] = DIK_NUMPAD4,
    [GLFW_KEY_KP_5] = DIK_NUMPAD5,
    [GLFW_KEY_KP_6] = DIK_NUMPAD6,
    [GLFW_KEY_KP_7] = DIK_NUMPAD7,
    [GLFW_KEY_KP_8] = DIK_NUMPAD8,
    [GLFW_KEY_KP_9] = DIK_NUMPAD9,
    [GLFW_KEY_KP_DECIMAL] = DIK_NUMPADCOMMA,
    [GLFW_KEY_KP_DIVIDE] = DIK_NUMPADSLASH,
    [GLFW_KEY_KP_MULTIPLY] = DIK_NUMPADSTAR,
    [GLFW_KEY_KP_SUBTRACT] = DIK_NUMPADMINUS,
    [GLFW_KEY_KP_ADD] = DIK_NUMPADPLUS,
    [GLFW_KEY_KP_ENTER] = DIK_NUMPADENTER,
    [GLFW_KEY_KP_EQUAL] = DIK_NUMPADEQUALS,
    [GLFW_KEY_LEFT_SHIFT] = DIK_LSHIFT,
    [GLFW_KEY_LEFT_CONTROL] = DIK_LCONTROL,
    [GLFW_KEY_LEFT_ALT] = DIK_LALT,
    [GLFW_KEY_LEFT_SUPER] = DIK_LWIN,
    [GLFW_KEY_RIGHT_SHIFT] = DIK_RSHIFT,
    [GLFW_KEY_RIGHT_CONTROL] = DIK_RCONTROL,
    [GLFW_KEY_RIGHT_ALT] = DIK_RALT,
    [GLFW_KEY_RIGHT_SUPER] = DIK_RWIN,
    [GLFW_KEY_MENU] = DIK_RMENU,
};

static int prev_window_x = 0;
static int prev_window_y = 0;
static int prev_window_width = 0;
static int prev_window_height = 0;

static void key_callback(GLFWwindow* window, int key, int scancode, int action, int mods)
{
    if (key == GLFW_KEY_ENTER && action == GLFW_PRESS && mods & GLFW_MOD_ALT)
    {
        bool fullscreen = glfwGetWindowMonitor(window);
        if (!fullscreen)
        {
            glfwGetWindowPos(window, &prev_window_x, &prev_window_y);
            glfwGetWindowSize(window, &prev_window_width, &prev_window_height);
            GLFWmonitor* monitor = glfwGetPrimaryMonitor();
            const GLFWvidmode* mode = glfwGetVideoMode(monitor);
            glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height, mode->refreshRate);
        }
        else
        {
            glfwSetWindowMonitor(window, NULL, prev_window_x, prev_window_y, prev_window_width, prev_window_height, 0);
        }
        return;
    }

    if (key >= ARRAYSIZE(glfw_key_to_dik))
        return;

    int dik_key = glfw_key_to_dik[key];
    if (dik_key == 0)
        return;

    const bool pressed = action != GLFW_RELEASE;

    stdControl_aKeyInfos[dik_key] = pressed;
    stdControl_g_aKeyPressCounter[dik_key] += pressed;

    UINT vk = MapVirtualKeyA(dik_key, MAPVK_VSC_TO_VK);
    if (vk == 0)
    {
        // TODO hack: for some reason the arrow keys return 0 on MapVirtualKeyA...
        switch (key)
        {
        case GLFW_KEY_DOWN:
            vk = VK_DOWN;
            break;
        case GLFW_KEY_UP:
            vk = VK_UP;
            break;
        case GLFW_KEY_LEFT:
            vk = VK_LEFT;
            break;
        case GLFW_KEY_RIGHT:
            vk = VK_RIGHT;
            break;
        }
    }

    // Window_AddKeyEvent(vk, 0, pressed); <-- not actually used by the game
    swrUI_HandleKeyEvent(vk, pressed);
}

static void mouse_button_callback(GLFWwindow* window, int button, int action, int mods)
{
    const bool pressed = action != GLFW_RELEASE;
    stdControl_aKeyInfos[512 + button] = pressed;
    stdControl_g_aKeyPressCounter[512 + button] += pressed;
}

#endif

// 0x004080C0 HOOK
void Window_AddKeyEvent(WPARAM virtual_key_code, USHORT flags, uint8_t pressed)
{
    if (!enableWindowInput)
        return;

    EnterCriticalSection(&WindowsInputCritSection);
    if (WindowsInputStackSize < 64u)
    {
        WindowsInputStack[WindowsInputStackSize++] = (WindowsInputItem){
            .virtualKeyCode = virtual_key_code,
            .keystrokeMessageFlags = flags,
            .keydown = pressed,
        };
    }
    LeaveCriticalSection(&WindowsInputCritSection);
}

// 0x00423900
LRESULT Window_msg_default_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT* uMsg_ptr)
{
    // TODO
    return 0;
}

// 0x00423aa0 HOOK
void Window_ActivateApp(HWND hwnd, WPARAM activated, LPARAM unused)
{
    Window_SetActivated(hwnd, activated);
}

// 0x00423ac0 HOOK
void Window_Activate(HWND hwnd, int active, LPARAM unused, WPARAM unused2)
{
    Window_SetActivated(hwnd, (unsigned int)(active != 0));
}

// 0x00423ae0 HOOK
void Window_SetActivated(HWND hwnd, WPARAM activated)
{
    if (activated != 0)
    {
        if (Window_Active == 0)
        {
#if !GLFW_BACKEND
            if ((swrMainDisplaySettings_g.RegFullScreen == 0) && (swrMainDisplaySettings_g.RegDevMode == 0))
            {
                ShowWindow(hwnd, 3);
            }
#endif
            swrDisplay_SetWindowSize();
            stdDisplay_Refresh(1);
            std3D_ClearCacheList();
            swrDisplay_SetWindowSize();
        }
        swrMain_GuiAdvanceFunction = (void*)swrMain2_GuiAdvance;
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

// 0x00423b90 HOOK
void Window_Resize(HWND hwnd, WPARAM edgeOfWindow, struct tagRECT* dragRectangle)
{
#if WINDOWED_MODE_FIXES
    Windows_WinProc_res = 1;
    return;
#endif

    int height;
    int width;
    struct tagRECT windowRect;
    struct tagRECT clientRect;

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

// 0x00423c80 HOOK
void Window_ResizeExit(HWND unused)
{
    int set;

    set = swrDisplay_SetWindowSize();
    if (set == 0)
    {
        swrDisplay_Resize(&swrMainDisplaySettings_g, Windows_windowWidth, Windows_windowHeight);
    }
}

// 0x004246c0 HOOK
void Window_SetWindowed(int windowed)
{
    swrMainDisplay_windowed = windowed;
}

// 0x004246d0
void Window_DisplaySettingsBox(HWND hwnd, swrMainDisplaySettings* displaySettings)
{
    HANG("TODO");
    // HINSTANCE hInstance;

    // hInstance = (HINSTANCE)GetWindowLongA(hwnd, -6);
    // DialogBoxParamA(hInstance, (LPCSTR)0x65, hwnd, FUN_00424700, (LPARAM)displaySettings);
}

// 0x00424700
int Window_DisplaySettingsCallback(HWND dialogBoxHwnd, unsigned int message, WPARAM infos, LPARAM displaySettings)
{
    HANG("TODO");
}

// 0x00425070 HOOK
int Window_SmushPlayCallback(const SmushImage* image)
{
#if GLFW_BACKEND
    swrControl_ProcessInputs();

    glMatrixMode(GL_PROJECTION);
    glPushMatrix();
    glLoadIdentity();

    int w, h;
    glfwGetFramebufferSize(glfwGetCurrentContext(), &w, &h);

    glViewport(0, 0, w, h);
    glOrtho(0, w, 0, h, 0, 1);
    glClear(GL_COLOR_BUFFER_BIT);

    float video_scale = w / (float)image->width;

    glRasterPos2f(w * 0.5 - 0.5 * video_scale * image->width, h * 0.5 + 0.5 * video_scale * image->height);
    glPixelZoom(video_scale, -video_scale);

    glDrawPixels(image->width, image->height, GL_RGB, GL_UNSIGNED_SHORT_5_6_5, image->data);
    glPopMatrix();
    glMatrixMode(GL_MODELVIEW);

    stdDisplay_Update();

    return stdControl_ReadKey(DIK_ESCAPE, 0) || stdControl_ReadKey(DIK_RETURN, 0) || glfwWindowShouldClose(glfwGetCurrentContext());
#else
    HANG("TODO");
#endif
}

// 0x00425500
int Window_CDCheck(void)
{
    HANG("TODO");
}

// 0x004252a0
int Window_PlayCinematic(char** znmFile)
{
    HANG("TODO");
}

// 0x00425820
int Window_DisplaySettingsMoveWindow(HWND dialogBoxHwnd)
{
    HWND hWnd;
    int iVar1;
    int iVar2;
    struct tagRECT window_rect;
    struct tagRECT desktop_window;
    struct tagRECT client_rect;
    struct tagRECT* desktop_window_ref;

    GetWindowRect(dialogBoxHwnd, &window_rect);
    GetClientRect(dialogBoxHwnd, &client_rect);
    iVar1 = window_rect.right - window_rect.left;
    desktop_window_ref = &desktop_window;
    iVar2 = window_rect.bottom - window_rect.top;
    hWnd = GetDesktopWindow();
    GetWindowRect(hWnd, desktop_window_ref);
    window_rect.top = (((desktop_window.bottom - window_rect.bottom) - window_rect.top) - desktop_window.top) / 2;
    window_rect.left = (((desktop_window.right - window_rect.right) - window_rect.left) - desktop_window.left) / 2;
    window_rect.bottom = iVar2 + window_rect.top;
    window_rect.right = iVar1 + window_rect.left;
    MoveWindow(dialogBoxHwnd, window_rect.left, window_rect.top, window_rect.right - window_rect.left, window_rect.bottom - window_rect.top, 1);
    return 1;
}

// 0x0048c770 HOOK
void Window_SetHWND(HWND hwnd)
{
    Window_hWnd = hwnd;
}

// 0x0048c780 HOOK
HWND Window_GetHWND(void)
{
    return Window_hWnd;
}

// 0x0048c790 HOOK
void Window_SetHINSTANCE(HINSTANCE hInstance)
{
    Window_hinstance = hInstance;
}

// 0x0048c7a0 HOOK
HINSTANCE Window_GetHINSTANCE(void)
{
    return Window_hinstance;
}

// 0x0048c7b0 HOOK
void Window_SetGUID(GUID* guid)
{
    // copy guid
    ((uint32_t*)&Window_GUID)[0] = ((uint32_t*)guid)[0];
    ((uint32_t*)&Window_GUID)[1] = ((uint32_t*)guid)[1];
    ((uint32_t*)&Window_GUID)[2] = ((uint32_t*)guid)[2];
    ((uint32_t*)&Window_GUID)[3] = ((uint32_t*)guid)[3];
}

// 0x0048c7e0 HOOK
GUID* Window_GetGUID(void)
{
    return &Window_GUID;
}

// 0x0049cd40 HOOK
int Window_Main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow, const char* window_name)
{
#if GLFW_BACKEND
    InitCommonControls();
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID*)Window_UUID);

    glfwInit();
    GLFWwindow* window = glfwCreateWindow(640, 480, window_name, NULL, NULL);
    if (!window)
        abort();

    glfwMaximizeWindow(window);
    glfwMakeContextCurrent(window);
    glfwSetKeyCallback(window, key_callback);
    glfwSetMouseButtonCallback(window, mouse_button_callback);

    Main_Startup((char*)pCmdLine);

    while (!glfwWindowShouldClose(window))
    {
        swrMain2_GuiAdvance();
    }
#else
    int iVar1;
    int iVar2;
    BOOL msg_res;
    LPCSTR unaff_ESI;
    int unaff_EDI;
    struct tagMSG msg;

    g_nCmdShow = nCmdShow;
    Window_CreateMainWindow(hInstance, nCmdShow, window_name, 0, NULL);
    Window_SetHWND(g_hWnd);
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID*)Window_UUID);
    InitCommonControls();
    iVar1 = GetSystemMetrics(0x20);
    Window_border_width = iVar1 << 1;
    iVar1 = GetSystemMetrics(0x20);
    iVar2 = GetSystemMetrics(0xf);
    Window_border_height = iVar2 + iVar1 * 2;
    iVar1 = Main_Startup((char*)pCmdLine);
#if WINDOWED_MODE_FIXES
    ShowWindow(g_hWnd, SW_NORMAL);
#endif
    if (iVar1 == 0)
    {
        return 0;
    }
    do
    {
        while (msg_res = PeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE), msg_res == 0)
        {
            swrMain2_GuiAdvance();
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
#endif
}

// 0x0049ce60 HOOK
BOOL Window_SetWindowSize(int width, int height)
{
    return SetWindowPos(g_hWnd, NULL, 0, 0, width + Window_border_width, height + Window_border_height, SWP_NOMOVE | SWP_NOZORDER);
}

// 0x0049ce90 HOOK
void Window_set_msg_handler(Window_MSGHANDLER handler)
{
    g_WndProc = handler;
}

// 0x0049cea0 HOOK
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
#if WINDOWED_MODE_FIXES
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", window_name, WS_OVERLAPPEDWINDOW, 0, 0, CW_USEDEFAULT, CW_USEDEFAULT, hWnd, hMenu, hInstance, lpParam);
#else
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", window_name, WS_VISIBLE | WS_POPUP, 0, 0, nWidth, nHeight, hWnd, hMenu, hInstance, lpParam);
#endif
    if (g_hWnd == NULL)
    {
        return 0;
    }
    ShowWindow(g_hWnd, 1);
    UpdateWindow(g_hWnd);
    return 1;
}

// 0x0049cfd0 HOOK
LRESULT __stdcall Window_msg_main_handler(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
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
