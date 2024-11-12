#include "Window_hook.h"

#include "globals.h"

#include "../utils/renderer_utils.h"

#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include <Windows.h>
#include <commctrl.h>

extern "C" {
#include <Gui/swrGui.h>
#include <Main/swrMain.h>
#include <Main/swrMain2.h>
#include <Platform/std3D.h>
#include <Platform/stdControl.h>
#include <Main/swrControl.h>
#include <Swr/swrDisplay.h>
#include <Swr/swrUI.h>
#include <Win95/stdDisplay.h>
#include <Win95/Window.h>
}

extern "C" FILE *hook_log;

extern int glfw_key_to_dik[349];

static void noop(){};

void Window_SetActivated_hook(HWND hwnd, WPARAM activated) {
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
    swrMain_GuiAdvanceFunction = (void *) noop;
    stdDisplay_Refresh(0);
    Window_Active = 0;
    swrGui_Stop(1);
    stdControl_SetActivation(0);
}

int Window_SmushPlayCallback_hook(const SmushImage *image) {
    swrControl_ProcessInputs();

    renderer_drawSmushFrame(image);

    stdDisplay_Update();

    return stdControl_ReadKey(DIK_ESCAPE, 0) || stdControl_ReadKey(DIK_RETURN, 0) ||
           glfwWindowShouldClose(glfwGetCurrentContext());
}

static int prev_window_x = 0;
static int prev_window_y = 0;
static int prev_window_width = 0;
static int prev_window_height = 0;

static void key_callback(GLFWwindow *window, int key, int scancode, int action, int mods) {
    init_glfw_key_to_dik();

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

    const bool pressed = action != GLFW_RELEASE;

    stdControl_aKeyInfos[dik_key] = pressed;
    stdControl_g_aKeyPressCounter[dik_key] += pressed;

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
    const bool pressed = action != GLFW_RELEASE;
    stdControl_aKeyInfos[512 + button] = pressed;
    stdControl_g_aKeyPressCounter[512 + button] += pressed;
}

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
    // Filter out PERFORMANCE MEDIUM API (usually shader recompilation)
    if (type == GL_DEBUG_TYPE_PERFORMANCE && severity == GL_DEBUG_SEVERITY_MEDIUM &&
        source == GL_DEBUG_SOURCE_API) {
        return;
    }

    fprintf(hook_log, "[OpenGL](%d, %s) %s (%s): %s\n", id, type_str, severity_str, source_str,
            message);
    fflush(hook_log);
}

int Window_Main_hook(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow,
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
    }

    return 0;
}
