#pragma once

// Panel-registry shell for the ImGui debug/overlay UI. Each subsystem registers
// its own panel (from its own delta file) instead of splicing into one giant
// function; the shell draws a toolbar (main menu bar) across the top of the game
// window, and each panel opens as its own closable window from its menu entry.
// Panels under the "Settings" menu instead share one tabbed Settings window.

// One registrable overlay panel, opened as a window from the toolbar. The body
// draws plain ImGui widgets; the shell owns the surrounding window. Keep
// instances static (the registry stores the pointer, not a copy).
struct DebugPanel {
    const char *category;// toolbar menu path, '/'-separated, e.g. "Debug/Inspect"
    const char *name;    // menu item + window title (must be unique)
    void (*draw)();      // window body: ImGui widgets
    bool dev_only;       // hidden while debug_ui_show_dev_panels is off (currently always on)
    bool open;           // window shown; session-only (windows are not reopened on launch)
};

// Whether dev_only panels (and dev-only extras inside panels) are shown. Always on
// for now: the Debug menu is visible to everyone, with no toggle.
extern bool debug_ui_show_dev_panels;

// Test runner: open every panel window (cycling the Settings tabs), dev-only ones
// included, so each panel body runs.
extern bool debug_ui_test_expand_all;

// Register a panel. Call once per panel at startup (registration order sets the
// order of items within a menu). The pointer must outlive the program (use a
// static DebugPanel).
void debug_ui_register(DebugPanel *panel);

// Register the shell's own built-in panels (overlay/ImGui tools). Call once at
// startup alongside the subsystem panels, before debug_ui_load_settings().
void debug_ui_register_builtin_shell_panels();

// Restore the overlay look (theme, opacity, font scale) from SW_RACER_RE.ini. Call
// once after all panels are registered.
void debug_ui_load_settings();

// Draw the toolbar and the open panel windows. Called once per frame from imgui_Update.
void debug_ui_render();
