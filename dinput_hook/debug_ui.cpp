#include "debug_ui.h"
#include "imgui_utils.h"

#include <vector>
#include <string>
#include <cstring>
#include <cstdio>

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

static bool category_visible(const char *category) {
    for (DebugPanel *p: g_panels)
        if (std::strcmp(p->category, category) == 0 && (!p->dev_only || debug_ui_show_dev_panels))
            return true;
    return false;
}

// Persist open-state whenever it changes from any source -- a menu toggle, a
// window's own [x] close button, or the View toggle. Comparing against last
// frame's snapshot is simpler than threading a dirty flag through every path.
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

void debug_ui_render() {
    // Toggled with F5
    if (!show_imgui)
        return;

    if (ImGui::BeginMainMenuBar()) {
        // One menu per category, in first-seen registration order.
        for (size_t i = 0; i < g_panels.size(); i++) {
            const char *category = g_panels[i]->category;

            bool already_seen = false;
            for (size_t j = 0; j < i; j++) {
                if (std::strcmp(g_panels[j]->category, category) == 0) {
                    already_seen = true;
                    break;
                }
            }
            if (already_seen || !category_visible(category))
                continue;

            if (ImGui::BeginMenu(category)) {
                for (DebugPanel *p: g_panels) {
                    if (std::strcmp(p->category, category) != 0)
                        continue;
                    if (p->dev_only && !debug_ui_show_dev_panels)
                        continue;
                    ImGui::MenuItem(p->name, nullptr, &p->open);
                }
                ImGui::EndMenu();
            }
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Developer panels", nullptr, &debug_ui_show_dev_panels);
            ImGui::EndMenu();
        }

        // FPS readout, right-aligned in the bar (was the first line of the monolith).
        char fps[64];
        snprintf(fps, sizeof(fps), "%.0f FPS (%.2f ms)", ImGui::GetIO().Framerate,
                 1000.0f / ImGui::GetIO().Framerate);
        ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize(fps).x -
                        ImGui::GetStyle().ItemSpacing.x * 2);
        ImGui::TextUnformatted(fps);

        ImGui::EndMainMenuBar();
    }

    for (DebugPanel *p: g_panels) {
        if (!p->open)
            continue;
        if (p->dev_only && !debug_ui_show_dev_panels)
            continue;

        if (p->default_w > 0.0f)
            ImGui::SetNextWindowSize(ImVec2(p->default_w, p->default_h), ImGuiCond_FirstUseEver);
        if (ImGui::Begin(p->name, &p->open))
            p->draw();
        ImGui::End();
    }

    save_if_state_changed();
}
