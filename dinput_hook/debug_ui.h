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
    const char *keywords;// extra search terms (control labels / synonyms) the filter
                         // also matches, so a section surfaces by its contents and not
                         // just its header. Optional (null = match on name only).
    void (*draw)();      // section body: ImGui widgets
    bool dev_only;       // hidden from players (see developer-panels toggle)
    bool open;           // section expanded; seeded from the ini, then user-driven
};

// Whether developer-only panels are shown. Defaults on in debug builds, off in
// release so players never see dev clutter. Toggled from the overlay checkbox.
extern bool debug_ui_show_dev_panels;

// Register a panel. Call once per panel at startup (registration order sets the
// section order). The pointer must outlive the program (use a static DebugPanel).
void debug_ui_register(DebugPanel *panel);

// Register the shell's own built-in sections (overlay/ImGui tools). Call once at
// startup alongside the subsystem panels, before debug_ui_load_settings().
void debug_ui_register_builtin_shell_panels();

// Restore section expand-state + the developer-panels toggle from SW_RACER_RE.ini.
// Call once after all panels are registered.
void debug_ui_load_settings();

// Draw the overlay window and its sections. Called once per frame from imgui_Update.
void debug_ui_render();

// Open a URL in the user's default browser (ShellExecute). Shared by the overlay's
// link buttons (info header, mode-select community links).
void debug_ui_open_url(const char *url);
