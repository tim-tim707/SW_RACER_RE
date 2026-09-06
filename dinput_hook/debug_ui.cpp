#include "debug_ui.h"
#include "imgui_utils.h"
#include "config.h"
#include "mod_version.h"
#include "update_check.h"

#include <vector>
#include <string>
#include <cstring>

#include <windows.h>
#include <shellapi.h>
#include <imgui.h>

#include "build_id.h"// SWR_BUILD_* (generated at build time)

// show_imgui (the F5 overlay toggle) comes from imgui_utils.h.

bool debug_ui_show_dev_panels = false;

static std::vector<DebugPanel *> g_panels;

void debug_ui_register(DebugPanel *panel) {
    g_panels.push_back(panel);
}

void debug_ui_load_settings() {
    debug_ui_show_dev_panels =
        config::get_int("debug_ui", "show_dev_panels", debug_ui_show_dev_panels);
    for (DebugPanel *p: g_panels)
        p->open = config::get_int("debug_ui_panels", p->name, p->open);
}

static void save_settings() {
    config::set_bool("debug_ui", "show_dev_panels", debug_ui_show_dev_panels);
    for (DebugPanel *p: g_panels)
        config::set_bool("debug_ui_panels", p->name, p->open);
    config::save();
}

// Persist open-state whenever it changes from any source -- a section toggle, an
// expand/collapse-all, or the dev toggle. Comparing against last frame's snapshot
// is simpler than threading a dirty flag through every path.
static void save_if_state_changed() {
    static int prev_dev = -1;
    static std::vector<char> prev_open;

    bool changed = (int) debug_ui_show_dev_panels != prev_dev || prev_open.size() != g_panels.size();
    for (size_t i = 0; !changed && i < g_panels.size(); i++)
        changed = prev_open[i] != (char) g_panels[i]->open;
    if (!changed)
        return;

    prev_dev = debug_ui_show_dev_panels;
    prev_open.resize(g_panels.size());
    for (size_t i = 0; i < g_panels.size(); i++)
        prev_open[i] = (char) g_panels[i]->open;
    save_settings();
}

// A "(?)" label that shows a wrapped tooltip on hover (imgui_demo.cpp idiom).
static void help_marker(const char *desc) {
    ImGui::TextDisabled("(?)");
    if (ImGui::BeginItemTooltip()) {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

// Open a URL in the user's default browser.
void debug_ui_open_url(const char *url) {
    ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

// A section matches the filter by its header name OR its registered keywords, so typing a
// control name ("msaa", "vsync") surfaces the section holding it.
static bool panel_passes_filter(const ImGuiTextFilter &filter, const DebugPanel *p) {
    return filter.PassFilter(p->name) || (p->keywords && filter.PassFilter(p->keywords));
}

// Identity + community links banner at the top of the overlay.
static void draw_info_header() {
    ImGui::TextUnformatted(MOD_NAME);
    ImGui::SameLine();
    ImGui::TextDisabled(MOD_VERSION);
    ImGui::SameLine();
    ImGui::TextDisabled("| F5 to show / hide");
    ImGui::SameLine();
    help_marker("F5 shows / hides this overlay.\n"
                "Turn on 'Developer mode' (bottom) for the dev-only sections.\n"
                "Type in the filter to find a section by name.");

    if (ImGui::SmallButton("GitHub"))
        debug_ui_open_url(MOD_GITHUB_URL);
    ImGui::SameLine();
    if (ImGui::SmallButton("Discord"))
        debug_ui_open_url(MOD_DISCORD_URL);
    ImGui::SameLine();
    if (ImGui::SmallButton("Report an issue / feedback"))
        debug_ui_open_url(MOD_ISSUES_URL);

    // Filled asynchronously by the worker; absent unless a release newer than MOD_VERSION exists.
    std::string latest, url;
    if (update_check_get_result(&latest, &url)) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(120, 230, 140, 255));
        ImGui::Text("Update available: %s", latest.c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (ImGui::SmallButton("Download"))
            debug_ui_open_url(url.c_str());
    }

    // Same build stamp the crash reports carry, so a player can read it off the screen and
    // quote it without having to reproduce the crash first. Click to copy.
    static const char *build_text = SWR_BUILD_DIRTY
                                        ? (SWR_BUILD_BRANCH " @ " SWR_BUILD_COMMIT "-dirty")
                                        : (SWR_BUILD_BRANCH " @ " SWR_BUILD_COMMIT);
    ImGui::TextDisabled("build: %s", build_text);
    if (ImGui::IsItemClicked())
        ImGui::SetClipboardText(build_text);
    if (ImGui::BeginItemTooltip()) {
        ImGui::TextUnformatted("The build this dinput.dll was compiled from -- the same stamp");
        ImGui::TextUnformatted("written into crash reports. Click to copy.");
        ImGui::EndTooltip();
    }

    ImGui::Separator();
}

// Built-in shell section: ImGui-level conveniences (theme, opacity, the demo and
// metrics windows). These are overlay chrome, not a game subsystem, so they live
// in the shell rather than being registered from a delta file.
static bool g_show_imgui_demo = false;
static bool g_show_imgui_metrics = false;
static bool g_show_log = false;// floating hook.log window (toggled from the footer)

static void panel_overlay() {
    ImGui::TextUnformatted("Theme:");
    ImGui::SameLine();
    if (ImGui::SmallButton("Dark"))
        ImGui::StyleColorsDark();
    ImGui::SameLine();
    if (ImGui::SmallButton("Light"))
        ImGui::StyleColorsLight();
    ImGui::SameLine();
    if (ImGui::SmallButton("Classic"))
        ImGui::StyleColorsClassic();

    ImGui::SliderFloat("Overlay opacity", &ImGui::GetStyle().Alpha, 0.3f, 1.0f, "%.2f");
    ImGui::SliderFloat("UI font scale", &ImGui::GetIO().FontGlobalScale, 0.5f, 2.0f, "%.2f");

    ImGui::Checkbox("Dear ImGui demo window", &g_show_imgui_demo);
    ImGui::Checkbox("Dear ImGui metrics / debugger", &g_show_imgui_metrics);
}

static DebugPanel g_panel_overlay = {
    .category = "Tools", .name = "Overlay",
    .keywords = "theme dark light classic opacity alpha ui font scale imgui demo metrics debugger",
    .draw = panel_overlay, .dev_only = true};

void debug_ui_register_builtin_shell_panels() {
    debug_ui_register(&g_panel_overlay);
}

void debug_ui_render() {
    // Toggled with F5
    if (!show_imgui)
        return;

    static ImGuiTextFilter filter;
    int force_open = -1;// set by the expand/collapse-all buttons; -1 = leave as-is

    ImGui::SetNextWindowSize(ImVec2(440, 680), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("SWE1R Debug")) {
        draw_info_header();

        // Reserve room for the "Filter" label and the two right-hand buttons so
        // they stay inside the window (a fixed reserve clipped them on the right).
        const ImGuiStyle &style = ImGui::GetStyle();
        const float reserve = ImGui::CalcTextSize("Filter").x + style.ItemInnerSpacing.x +
                              ImGui::CalcTextSize("Expand all").x + style.FramePadding.x * 2.0f +
                              ImGui::CalcTextSize("Collapse all").x + style.FramePadding.x * 2.0f +
                              style.ItemSpacing.x * 2.0f;
        filter.Draw("Filter", -reserve);
        ImGui::SameLine();
        if (ImGui::SmallButton("Expand all"))
            force_open = 1;
        ImGui::SameLine();
        if (ImGui::SmallButton("Collapse all"))
            force_open = 0;

        ImGui::Separator();

        // One labeled separator per category (first-seen registration order),
        // then a collapsing-header section per panel under it.
        for (size_t i = 0; i < g_panels.size(); i++) {
            const char *category = g_panels[i]->category;

            bool already_seen = false;
            for (size_t j = 0; j < i; j++) {
                if (std::strcmp(g_panels[j]->category, category) == 0) {
                    already_seen = true;
                    break;
                }
            }
            if (already_seen)
                continue;

            // Count the visible sections in this category.
            int visible = 0;
            for (DebugPanel *p: g_panels) {
                if (std::strcmp(p->category, category) != 0)
                    continue;
                if (p->dev_only && !debug_ui_show_dev_panels)
                    continue;
                if (panel_passes_filter(filter, p))
                    visible++;
            }
            if (visible == 0)
                continue;

            // A category header only earns its keep when it groups 2+ sections.
            if (visible > 1)
                ImGui::SeparatorText(category);
            for (DebugPanel *p: g_panels) {
                if (std::strcmp(p->category, category) != 0)
                    continue;
                if (p->dev_only && !debug_ui_show_dev_panels)
                    continue;
                if (!panel_passes_filter(filter, p))
                    continue;

                // A filter match force-opens the section without persisting that state -- only
                // real toggles and expand/collapse-all write p->open.
                const bool filtering = filter.IsActive();
                if (filtering)
                    ImGui::SetNextItemOpen(true, ImGuiCond_Always);
                else if (force_open != -1)
                    ImGui::SetNextItemOpen(force_open == 1, ImGuiCond_Always);
                else
                    ImGui::SetNextItemOpen(p->open, ImGuiCond_Once);

                const bool is_open = ImGui::CollapsingHeader(p->name);
                if (!filtering)
                    p->open = is_open;
                if (is_open) {
                    ImGui::PushID(p->name);
                    ImGui::Indent();
                    p->draw();
                    ImGui::Unindent();
                    ImGui::PopID();
                }
            }
        }

        // Footer: log-window toggle + developer mode (kept at the bottom so the
        // section list stays the focus).
        ImGui::Separator();
        ImGui::Checkbox("Show log window", &g_show_log);
        ImGui::SameLine();
        ImGui::Checkbox("Developer mode", &debug_ui_show_dev_panels);

        // The check runs once at startup, so a change here takes effect next launch.
        static int check_updates = -1;
        if (check_updates < 0)
            check_updates = config::get_int("settings", "check_updates", 1);
        bool check_updates_on = check_updates != 0;
        if (ImGui::Checkbox("Check for updates on launch", &check_updates_on)) {
            check_updates = check_updates_on;
            config::set_bool("settings", "check_updates", check_updates_on);
            config::save();
        }
        ImGui::SameLine();
        help_marker("Once at launch, checks GitHub for a newer release and shows a banner up top.\n"
                    "Nothing about you is sent. Takes effect next launch.");
    }
    ImGui::End();

    // Optional floating windows, drawn outside the shell window.
    imgui_draw_log_window(&g_show_log);
    if (g_show_imgui_demo)
        ImGui::ShowDemoWindow(&g_show_imgui_demo);
    if (g_show_imgui_metrics)
        ImGui::ShowMetricsWindow(&g_show_imgui_metrics);

    save_if_state_changed();
}
