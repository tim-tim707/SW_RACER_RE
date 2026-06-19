#pragma once

// Window display modes selectable from the debug menu dropdown (and Alt+Enter).
enum WindowMode {
    WINDOW_MODE_WINDOWED = 0,  // decorated, resizable window
    WINDOW_MODE_BORDERLESS = 1,// undecorated window filling the primary monitor
    WINDOW_MODE_FULLSCREEN = 2,// exclusive fullscreen on the primary monitor
};

#ifdef __cplusplus
extern "C" {
#endif

// Source of truth for the current window mode (one of WindowMode). Defined in Window_delta.c.
extern int g_window_mode;

// Applies `mode` to the GLFW window and updates g_window_mode. Safe to call once the
// GLFW window/context exists. Does not persist the choice (see save_window_mode_setting).
void set_window_mode(int mode);

// Persists the current window mode to SW_RACER_RE.ini. Implemented in imgui_utils.cpp.
void save_window_mode_setting(void);

#ifdef __cplusplus
}
#endif
