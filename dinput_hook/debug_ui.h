#pragma once

// Panel-registry shell for the ImGui debug/overlay UI. Each subsystem registers
// its own panel (from its own delta file) instead of splicing into one giant
// function; the shell draws a single window of collapsing-header sections,
// grouped by category. This is the fix for the merge-conflict generator that the
// old monolithic opengl_render_imgui() had become. See DEBUG_UI_ROADMAP.md.

// One registrable overlay panel, rendered as a collapsing-header section. The
// body draws plain ImGui widgets; the shell owns the surrounding window. Keep
// instances static (the registry stores the pointer, not a copy).
struct DebugPanel {
    const char *category;// section grouping, e.g. "Render", "Inspect", "Tools"
    const char *name;    // collapsing-header label (must be unique)
    void (*draw)();      // section body: ImGui widgets
    bool dev_only;       // hidden from players (see developer-panels toggle)
    bool open;           // section expanded; seeded from the ini, then user-driven
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
