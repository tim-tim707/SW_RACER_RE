#include "stdConsole_hook.h"

#include "../hook_helper.h"

#include <imgui.h>
#include <imgui_stdlib.h>

extern "C" {
#include <Swr/swrSprite.h>
#include <Win95/stdConsole.h>
}

extern bool imgui_initialized;

static POINT virtual_cursor_pos{-100, -100};

int stdConsole_GetCursorPos_Hook(int *out_x, int *out_y) {
    if (!out_x || !out_y)
        return 0;

    if (!imgui_initialized)
        return hook_call_original(stdConsole_GetCursorPos, out_x, out_y);

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

void stdConsole_SetCursorPos_Hook(int X, int Y) {
    if (!imgui_initialized)
        return hook_call_original(stdConsole_SetCursorPos, X, Y);

    virtual_cursor_pos = POINT{X, Y};
}
