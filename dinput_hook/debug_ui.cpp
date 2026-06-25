#include "debug_ui.h"
#include "imgui_utils.h"

#include <vector>
#include <string>
#include <cstring>
#include <cfloat>

#include <windows.h>
#include <imgui.h>

// show_imgui (the F5 overlay toggle) and settings_ini_path() come from imgui_utils.h.

#if !defined(NDEBUG)
bool debug_ui_show_dev_panels = true;
#else
bool debug_ui_show_dev_panels = false;
#endif

static std::vector<DebugPanel *> g_panels;

void debug_ui_register(DebugPanel *panel) {
    g_panels.push_back(panel);
}

// Panel names and ini keys are ASCII literals we control, so a byte-wise widen
// is enough to feed the wide GetPrivateProfile* API (matches the ini path type).
static std::wstring widen(const char *s) {
    std::wstring w;
    for (; *s; s++)
        w.push_back((wchar_t) (unsigned char) *s);
    return w;
}

void debug_ui_load_settings() {
    const wchar_t *ini = settings_ini_path();
    debug_ui_show_dev_panels =
        GetPrivateProfileIntW(L"debug_ui", L"show_dev_panels", debug_ui_show_dev_panels, ini);
    for (DebugPanel *p: g_panels)
        p->open = GetPrivateProfileIntW(L"debug_ui_panels", widen(p->name).c_str(), p->open, ini);
}

static void save_settings() {
    const wchar_t *ini = settings_ini_path();
    WritePrivateProfileStringW(L"debug_ui", L"show_dev_panels",
                               debug_ui_show_dev_panels ? L"1" : L"0", ini);
    for (DebugPanel *p: g_panels)
        WritePrivateProfileStringW(L"debug_ui_panels", widen(p->name).c_str(),
                                   p->open ? L"1" : L"0", ini);
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

// Built-in shell section: ImGui-level conveniences (theme, opacity, the demo and
// metrics windows). These are overlay chrome, not a game subsystem, so they live
// in the shell rather than being registered from a delta file.
static bool g_show_imgui_demo = false;
static bool g_show_imgui_metrics = false;

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
    .category = "Tools", .name = "Overlay", .draw = panel_overlay, .dev_only = true};

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
        ImGui::Text("%.0f FPS (%.2f ms)", ImGui::GetIO().Framerate,
                    1000.0f / ImGui::GetIO().Framerate);
        ImGui::SameLine();
        ImGui::Checkbox("Developer panels", &debug_ui_show_dev_panels);
        ImGui::SameLine();
        help_marker("F5 toggles this window.\n"
                    "Enable 'Developer panels' for the dev-only sections.\n"
                    "Type in the filter to find a section by name.");

        // Rolling FPS sparkline (auto-scaled), most recent sample on the right.
        static float fps_history[120] = {};
        static int fps_cursor = 0;
        fps_history[fps_cursor] = ImGui::GetIO().Framerate;
        fps_cursor = (fps_cursor + 1) % IM_ARRAYSIZE(fps_history);
        ImGui::PlotLines("##fps", fps_history, IM_ARRAYSIZE(fps_history), fps_cursor, nullptr, 0.0f,
                         FLT_MAX, ImVec2(-FLT_MIN, 40));

        filter.Draw("Filter", -160.0f);
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

            // Skip the whole category if nothing under it is currently visible.
            bool any_visible = false;
            for (DebugPanel *p: g_panels) {
                if (std::strcmp(p->category, category) != 0)
                    continue;
                if (p->dev_only && !debug_ui_show_dev_panels)
                    continue;
                if (filter.PassFilter(p->name)) {
                    any_visible = true;
                    break;
                }
            }
            if (!any_visible)
                continue;

            ImGui::SeparatorText(category);
            for (DebugPanel *p: g_panels) {
                if (std::strcmp(p->category, category) != 0)
                    continue;
                if (p->dev_only && !debug_ui_show_dev_panels)
                    continue;
                if (!filter.PassFilter(p->name))
                    continue;

                // Expand/collapse-all forces every section this frame; otherwise
                // seed from the ini on first appearance and mirror the live state
                // back so the user's clicks persist.
                if (force_open != -1)
                    ImGui::SetNextItemOpen(force_open == 1, ImGuiCond_Always);
                else
                    ImGui::SetNextItemOpen(p->open, ImGuiCond_Once);
                p->open = ImGui::CollapsingHeader(p->name);
                if (p->open) {
                    ImGui::PushID(p->name);
                    ImGui::Indent();
                    p->draw();
                    ImGui::Unindent();
                    ImGui::PopID();
                }
            }
        }
    }
    ImGui::End();

    // Optional ImGui-owned windows, drawn outside the shell window.
    if (g_show_imgui_demo)
        ImGui::ShowDemoWindow(&g_show_imgui_demo);
    if (g_show_imgui_metrics)
        ImGui::ShowMetricsWindow(&g_show_imgui_metrics);

    save_if_state_changed();
}
