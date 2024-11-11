#include "stdConsole.h"

#include "Window.h"
#include "globals.h"

#if GLFW_BACKEND
#include <GLFW/glfw3.h>
#endif

// 0x004082e0 HOOK
int stdConsole_GetCursorPos(int* out_x, int* out_y)
{
#if GLFW_BACKEND
    if (!out_x || !out_y)
        return 0;

    GLFWwindow* window = glfwGetCurrentContext();

    int w, h;
    glfwGetWindowSize(window, &w, &h);

    if (w == 0 || h == 0)
        return 0;

    double x, y;
    glfwGetCursorPos(window, &x, &y);

    *out_x = x * 640 / w;
    *out_y = y * 480 / h;
    return 1;
#else
    BOOL res;
    tagPOINT point;

    if ((out_x != NULL) && (out_y != NULL))
    {
        *out_x = 0;
        *out_y = 0;
        res = GetCursorPos(&point);
        if (res != 0)
        {
            if (screen_width == 0x200)
            {
                *out_x = point.x + (point.x >> 2);
                *out_y = point.y + (point.y >> 2);
                return 1;
            }
            *out_x = point.x;
            *out_y = point.y;
            return 1;
        }
    }
    return 0;
#endif
}

// 0x00408360 HOOK
void stdConsole_SetCursorPos(int X, int Y)
{
#if GLFW_BACKEND
    GLFWwindow* window = glfwGetCurrentContext();

    int w, h;
    glfwGetWindowSize(window, &w, &h);

    if (w == 0 || h == 0)
        return;

    glfwSetCursorPos(window, X * w / 640, Y * h / 480);
#else
    if (screen_width == 0x200)
    {
        SetCursorPos((X << 9) / 0x280, (Y * screen_height) / 0x1e0);
        return;
    }
    SetCursorPos(X, Y);
#endif
}

// 0x00484820 HOOK
int stdConsole_Printf(char* format, ...)
{
    va_list args;
    va_start(args, format);
    va_end(args);

    vsnprintf(std_output_buffer, sizeof(std_output_buffer), format, args);
    stdConsole_Puts(std_output_buffer, 7);

    return sizeof(std_output_buffer);
}

// 0x0048d160 HOOK
BOOL stdConsole_SetConsoleTextAttribute(WORD wAttributes)
{
    stdConsole_wAttributes = wAttributes;
    return SetConsoleTextAttribute(stdConsole_hConsoleOutput, wAttributes);
}

// 0x0048d180 HOOK
BOOL stdConsole_Puts(char* buffer, DWORD wAttributes)
{
    unsigned int buffer_len;
    if (stdConsole_wAttributes != (short)wAttributes)
    {
        stdConsole_SetConsoleTextAttribute(wAttributes);
    }

    buffer_len = strlen(buffer);
    return WriteConsoleA(stdConsole_hConsoleOutput, buffer, buffer_len, &wAttributes, NULL);
}
