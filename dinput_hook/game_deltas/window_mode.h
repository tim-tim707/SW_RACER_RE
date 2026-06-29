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
// GLFW window/context exists. Does not persist the choice (see persist_settings_ini).
void set_window_mode(int mode);

// Persists the whole settings block to SW_RACER_RE.ini. C-callable from the window
// key callbacks (window mode, F5 overlay toggle). Implemented in imgui_utils.cpp.
void persist_settings_ini(void);

#ifdef __cplusplus
}
#endif
