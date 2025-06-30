#include "Window_delta.h"

#include <stdio.h>
#include <Windows.h>
#include <commctrl.h>

#include "globals.h"

#include "stdPlatform.h"

#include <macros.h>
#include <Gui/swrGui.h>
#include <Main/swrControl.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Swr/swrDisplay.h>
#include <Win95/stdDisplay.h>
#include <Win95/Window.h>
#include <Main/swrMain.h>
#include <Main/swrMain2.h>
#include <Swr/swrUI.h>

int stdDisplay_Update_Hook();

#include <glad/glad.h>
#include <GLFW/glfw3.h>
// Sound card
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>

extern char show_imgui;

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

static void key_callback(GLFWwindow *window, int key, int scancode, int action, int mods) {
    if (key == GLFW_KEY_ENTER && action == GLFW_PRESS && mods & GLFW_MOD_ALT) {
        bool fullscreen = glfwGetWindowMonitor(window);
        if (!fullscreen) {
            glfwGetWindowPos(window, &prev_window_x, &prev_window_y);
            glfwGetWindowSize(window, &prev_window_width, &prev_window_height);
            GLFWmonitor *monitor = glfwGetPrimaryMonitor();
            const GLFWvidmode *mode = glfwGetVideoMode(monitor);
            glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height,
                                 mode->refreshRate);
        } else {
            glfwSetWindowMonitor(window, NULL, prev_window_x, prev_window_y, prev_window_width,
                                 prev_window_height, 0);
        }
        return;
    }

    if (key >= ARRAYSIZE(glfw_key_to_dik))
        return;

    int dik_key = glfw_key_to_dik[key];
    if (dik_key == 0)
        return;

    // Toggle imgui with F3
    if (key == GLFW_KEY_F5 && action == GLFW_PRESS) {
        show_imgui ^= 1;
    }

    const bool pressed = action != GLFW_RELEASE;

#if ENABLE_GLFW_INPUT_HANDLING
    stdControl_aKeyInfos[dik_key] = pressed;
    stdControl_g_aKeyPressCounter[dik_key] += pressed;
#endif

    UINT vk = MapVirtualKeyA(dik_key, MAPVK_VSC_TO_VK);
    if (vk == 0) {
        // TODO hack: for some reason the arrow keys return 0 on MapVirtualKeyA...
        switch (key) {
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

static void mouse_button_callback(GLFWwindow *window, int button, int action, int mods) {
#if ENABLE_GLFW_INPUT_HANDLING
    const bool pressed = action != GLFW_RELEASE;
    stdControl_aKeyInfos[512 + button] = pressed;
    stdControl_g_aKeyPressCounter[512 + button] += pressed;
#endif
}

extern FILE *hook_log;

extern void renderer_drawSmushFrame(const SmushImage *image);

// 0x00423ae0
void Window_SetActivated_delta(HWND hwnd, WPARAM activated) {
    if (activated != 0) {
        if (Window_Active == 0) {
            swrDisplay_SetWindowSize();
            stdDisplay_Refresh(1);
            std3D_ClearCacheList();
            swrDisplay_SetWindowSize();
        }
        swrMain_GuiAdvanceFunction = (void *) swrMain2_GuiAdvance;
        Window_Active = 1;
        swrGui_Stop(0);
        stdControl_SetActivation(activated);
        return;
    }
    swrMain_GuiAdvanceFunction = (void *) stdPlatform_noop;
    stdDisplay_Refresh(0);
    Window_Active = 0;
    swrGui_Stop(1);
    stdControl_SetActivation(0);
}

// 0x00423b90
void Window_Resize_delta(HWND hwnd, WPARAM edgeOfWindow, struct tagRECT *dragRectangle) {
    Windows_WinProc_res = 1;
    return;
}

// 0x00425070
int Window_SmushPlayCallback_delta(const SmushImage *image) {
    swrControl_ProcessInputs();

    renderer_drawSmushFrame(image);

    stdDisplay_Update_Hook();

    return stdControl_ReadKey(DIK_ESCAPE, 0) || stdControl_ReadKey(DIK_RETURN, 0) ||
           glfwWindowShouldClose(glfwGetCurrentContext());
}


// Added
void GLAPIENTRY Window_glDebugMessageCallback(GLenum source, GLenum type, GLuint id,
                                              GLenum severity, GLsizei length,
                                              const GLchar *message, const void *userParam) {
    const char *source_str = "UNKNOWN";

    switch (source) {
        case GL_DEBUG_SOURCE_API:
            source_str = "API";
            break;

        case GL_DEBUG_SOURCE_WINDOW_SYSTEM:
            source_str = "WINDOW SYSTEM";
            break;

        case GL_DEBUG_SOURCE_SHADER_COMPILER:
            source_str = "SHADER COMPILER";
            break;

        case GL_DEBUG_SOURCE_THIRD_PARTY:
            source_str = "THIRD PARTY";
            break;

        case GL_DEBUG_SOURCE_APPLICATION:
            source_str = "APPLICATION";
            break;
    }

    const char *type_str = "UNKNOWN";
    switch (type) {
        case GL_DEBUG_TYPE_ERROR:
            type_str = "ERROR";
            break;
        case GL_DEBUG_TYPE_DEPRECATED_BEHAVIOR:
            type_str = "DEPRECATED_BEHAVIOR";
            break;
        case GL_DEBUG_TYPE_UNDEFINED_BEHAVIOR:
            type_str = "UNDEFINED_BEHAVIOR";
            break;
        case GL_DEBUG_TYPE_PORTABILITY:
            type_str = "PORTABILITY";
            break;
        case GL_DEBUG_TYPE_PERFORMANCE:
            type_str = "PERFORMANCE";
            break;
        case GL_DEBUG_TYPE_OTHER:
            type_str = "OTHER";
            break;
        case GL_DEBUG_TYPE_MARKER:
            type_str = "MARKER";
            break;
    }

    const char *severity_str = "UNKNOWN";
    switch (severity) {
        case GL_DEBUG_SEVERITY_LOW:
            severity_str = "LOW";
            break;
        case GL_DEBUG_SEVERITY_MEDIUM:
            severity_str = "MEDIUM";
            break;
        case GL_DEBUG_SEVERITY_HIGH:
            severity_str = "HIGH";
            break;
        case GL_DEBUG_SEVERITY_NOTIFICATION:
            severity_str = "NOTIFICATION";
            break;
    }

    // Filter out OTHER NOTIFICATION API
    if (type == GL_DEBUG_TYPE_OTHER && severity == GL_DEBUG_SEVERITY_NOTIFICATION &&
        source == GL_DEBUG_SOURCE_API) {
        return;
    }
    // Filter out debugGroupMarker NOTIFICATION API
    if (severity == GL_DEBUG_SEVERITY_NOTIFICATION && source == GL_DEBUG_SOURCE_APPLICATION) {
        return;
    }
    // Filter out PERFORMANCE MEDIUM API (usually shader recompilation)
    if (type == GL_DEBUG_TYPE_PERFORMANCE && severity == GL_DEBUG_SEVERITY_MEDIUM &&
        source == GL_DEBUG_SOURCE_API) {
        return;
    }

    fprintf(hook_log, "[OpenGL](%d, %s) %s (%s): %s\n", id, type_str, severity_str, source_str,
            message);
    fflush(hook_log);
}

// 0x0049cd40
int Window_Main_delta(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow,
                      const char *window_name) {
    InitCommonControls();
    Window_SetHINSTANCE(hInstance);
    Window_SetGUID((GUID *) Window_UUID);

    glfwInit();

    {// Core compatibility for RenderDocs
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 4);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 5);
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
        glfwWindowHint(GLFW_OPENGL_DEBUG_CONTEXT, GL_TRUE);// OpenGL debug callback
    }

    GLFWwindow *window = glfwCreateWindow(640, 480, window_name, NULL, NULL);
    if (!window) {
        fprintf(hook_log, "GLFW Window couldn't be created, aborting\n");
        fflush(hook_log);

        abort();
    }
    g_hWnd = glfwGetWin32Window(window);
    Window_SetHWND(g_hWnd);// Sound card isn't detected without this

    glfwMaximizeWindow(window);
    glfwMakeContextCurrent(window);
    glfwSetKeyCallback(window, key_callback);
    glfwSetMouseButtonCallback(window, mouse_button_callback);

    Main_Startup((char *) pCmdLine);

    // NEEDS to be AFTER Main_Startup !
    glEnable(GL_DEBUG_OUTPUT_SYNCHRONOUS);
    glDebugMessageCallback(Window_glDebugMessageCallback, 0);

    while (!glfwWindowShouldClose(window)) {
        swrMain2_GuiAdvance();
#if !ENABLE_GLFW_INPUT_HANDLING
        // if glfw input handling is enabled, glfwPollEvents is called in stdControl_ReadControls
        // instead. this is important for the timing of the input state.
        glfwPollEvents();
#endif
    }

    return 0;
}

// 0x0049cea0
int Window_CreateMainWindow_delta(HINSTANCE hInstance, int unused, const char *window_name,
                                  int unused2, LPCSTR unused3) {
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
    if (wndClass.hIcon == NULL) {
        wndClass.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hIconSm = LoadIconA(hInstance, "APPICON");
    if (wndClass.hIconSm == NULL) {
        wndClass.hIconSm = LoadIconA(NULL, IDI_APPLICATION);
    }
    wndClass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wndClass.cbClsExtra = 0;
    wndClass.cbWndExtra = 0;
    wndClass.hbrBackground = (HBRUSH) GetStockObject(4);
    register_class_res = RegisterClassExA(&wndClass);
    if (register_class_res == 0) {
        return 0;
    }
    hWnd = FindWindowA("wKernelJones3D", window_name);
    if (hWnd != NULL) {
        exit(-1);
    }
    lpParam = NULL;
    hMenu = NULL;
    hWnd = NULL;
    g_hWnd = CreateWindowExA(8, "wKernelJones3D", window_name, WS_OVERLAPPEDWINDOW, 0, 0,
                             CW_USEDEFAULT, CW_USEDEFAULT, hWnd, hMenu, hInstance, lpParam);
    if (g_hWnd == NULL) {
        return 0;
    }
    ShowWindow(g_hWnd, 1);
    UpdateWindow(g_hWnd);
    return 1;
}
