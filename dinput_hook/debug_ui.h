#pragma once

// Panel-registry shell for the ImGui debug/overlay UI. Each subsystem registers
// its own panel (from its own delta file) instead of splicing into one giant
// function; the shell draws a menu bar that groups panels by category and opens
// each one in its own window. This is the fix for the merge-conflict generator
// that the old monolithic opengl_render_imgui() had become. See DEBUG_UI_ROADMAP.md.

// One registrable overlay panel. The body draws plain ImGui widgets; the shell
// wraps it in a Begin/End window and persists its open-state. Keep instances
// static (the registry stores the pointer, not a copy).
struct DebugPanel {
    const char *category;// menu grouping, e.g. "Render", "Inspect", "Tools"
    const char *name;    // window title + menu item (must be unique)
    void (*draw)();      // panel body: ImGui widgets, no Begin/End of its own
    bool dev_only;       // hidden from players (see developer-panels toggle)
    bool open;           // current visibility; restored from the ini at startup
    float default_w;     // first-use window width  (0 = let ImGui decide)
    float default_h;     // first-use window height (0 = let ImGui decide)
};

// Whether developer-only panels are shown. Defaults on in debug builds, off in
// release so players never see dev clutter. Toggled from the View menu.
extern bool debug_ui_show_dev_panels;

// Register a panel. Call once per panel at startup (registration order sets the
// menu order). The pointer must outlive the program (use a static DebugPanel).
void debug_ui_register(DebugPanel *panel);

// Restore panel open-state + the developer-panels toggle from SW_RACER_RE.ini.
// Call once after all panels are registered.
void debug_ui_load_settings();

// Draw the menu bar and every open panel. Called once per frame from imgui_Update.
void debug_ui_render();
