#include "stdConsole_delta.h"

#include "../imgui_utils.h"
#include "../ui_transform.h"

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

        if (ui_enabled()) {
            // Map window px -> framebuffer px (identity when they match), subtract the UI-centering
            // offset (so hit-tests align with the shifted visuals), then invert the uniform draw
            // scale so clicks land on the centered menu frames.
            float fb_x = (float) x * (float) swrDisplay_screenWidth / (float) w;
            float fb_y = (float) y * (float) swrDisplay_screenHeight / (float) h;
            fb_x -= ui_center_offset_px();
            UiVec2 d = ui_screen_to_design(UI_H_LEFT, UI_V_TOP, UiVec2{fb_x, fb_y});
            *out_x = (int) d.x;
            *out_y = (int) d.y;
        } else {
            *out_x = x * 640 / w;
            *out_y = y * 480 / h;
        }
        return 1;
    }

    const ImGuiIO &io = ImGui::GetIO();

    if (io.WantCaptureMouse) {
        // move mouse pos out of window
        virtual_cursor_pos = {-100, -100};
    } else {
        if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0) {
            // mouse moved, update virtual mouse position
            if (ui_enabled()) {
                // Map window px -> framebuffer px (identity when they match), subtract the
                // UI-centering offset (so hit-tests align with the shifted visuals), then invert the
                // uniform draw scale so clicks land on the centered menu frames.
                float fb_x = io.MousePos.x * (float) swrDisplay_screenWidth / io.DisplaySize.x;
                float fb_y = io.MousePos.y * (float) swrDisplay_screenHeight / io.DisplaySize.y;
                fb_x -= ui_center_offset_px();
                UiVec2 d = ui_screen_to_design(UI_H_LEFT, UI_V_TOP, UiVec2{fb_x, fb_y});
                virtual_cursor_pos.x = (LONG) d.x;
                virtual_cursor_pos.y = (LONG) d.y;
            } else {
                virtual_cursor_pos.x = (io.MousePos.x * 640) / io.DisplaySize.x;
                virtual_cursor_pos.y = (io.MousePos.y * 480) / io.DisplaySize.y;
            }
        }
    }

    *out_x = virtual_cursor_pos.x;
    *out_y = virtual_cursor_pos.y;
    // Force the game's software cursor sprite hidden so only the OS pointer shows -- unless the
    // player opted into the game cursor, in which case swrSprite_DisplayCursor draws it.
    if (!imgui_state.cursor_use_game_sprite)
        swrSprite_SetVisible(swrUISprite_d_cursor_rgb_0, 0);
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

        if (ui_enabled()) {
            // design -> framebuffer px, add the UI-centering offset (inverse of GetCursorPos), then
            // framebuffer -> window px (identity when they match).
            UiVec2 fb = ui_design_to_screen(UI_H_LEFT, UI_V_TOP, UiVec2{(float) X, (float) Y});
            fb.x += ui_center_offset_px();
            glfwSetCursorPos(window, fb.x * w / swrDisplay_screenWidth,
                             fb.y * h / swrDisplay_screenHeight);
        } else {
            glfwSetCursorPos(window, X * w / 640, Y * h / 480);
        }
    }

    virtual_cursor_pos = POINT{X, Y};
}
