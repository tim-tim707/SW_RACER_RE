#include "stdConsole_delta.h"

#include "../imgui_utils.h"

#include <imgui.h>
#include <imgui_stdlib.h>

extern "C" {
#include <Swr/swrSprite.h>
#include <Win95/Window.h>
}

#include "globals.h"

#include <GLFW/glfw3.h>

static POINT virtual_cursor_pos{-100, -100};

// 0x004082e0
int stdConsole_GetCursorPos_delta(int *out_x, int *out_y) {
    if (!out_x || !out_y)
        return 0;

    if (!imgui_initialized) {
        GLFWwindow *window = glfwGetCurrentContext();

        int w, h;
        glfwGetWindowSize(window, &w, &h);

        if (w == 0 || h == 0)
            return 0;

        double x, y;
        glfwGetCursorPos(window, &x, &y);

        *out_x = x * 640 / w;
        *out_y = y * 480 / h;
        return 1;
    }

    const auto &io = ImGui::GetIO();

    if (io.WantCaptureMouse) {
        // move mouse pos out of window
        virtual_cursor_pos = {-100, -100};
    } else {
        if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0) {
            // mouse moved, update virtual mouse position
            virtual_cursor_pos.x = (io.MousePos.x * 640) / io.DisplaySize.x;
            virtual_cursor_pos.y = (io.MousePos.y * 480) / io.DisplaySize.y;
        }
    }

    *out_x = virtual_cursor_pos.x;
    *out_y = virtual_cursor_pos.y;
    swrSprite_SetVisible(249, 0);
    return 1;
}

// 0x00408360
void stdConsole_SetCursorPos_delta(int X, int Y) {
    if (!imgui_initialized) {
        GLFWwindow *window = glfwGetCurrentContext();

        int w, h;
        glfwGetWindowSize(window, &w, &h);

        if (w == 0 || h == 0)
            return;

        glfwSetCursorPos(window, X * w / 640, Y * h / 480);
    }

    virtual_cursor_pos = POINT{X, Y};
}
