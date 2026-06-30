#include "debug_ui.h"
#include "imgui_utils.h"
#include "mod_version.h"
#include "update_check.h"

#include <vector>
#include <string>
#include <cstring>

#include <windows.h>
#include <shellapi.h>
#include <imgui.h>

// show_imgui (the F5 overlay toggle) and settings_ini_path() come from imgui_utils.h.

bool debug_ui_show_dev_panels = false;

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

// Open a URL in the user's default browser. ShellExecute "open" on an http(s)
// URL hands it to the registered handler -- no extra window/process management.
static void open_url(const char *url) {
    ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
}

// A section matches the filter by its header name OR its registered keywords, so
// typing a control name ("msaa", "vsync", "boost") surfaces the section that
// holds it rather than only sections whose header text matches.
static bool panel_passes_filter(const ImGuiTextFilter &filter, const DebugPanel *p) {
    return filter.PassFilter(p->name) || (p->keywords && filter.PassFilter(p->keywords));
}

// Identity + community links banner at the top of the overlay: who/what/version,
// one-click GitHub / Discord / issue links, and -- once the background check
// lands a result -- an "update available" line with a Download button.
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
        open_url(MOD_GITHUB_URL);
    ImGui::SameLine();
    if (ImGui::SmallButton("Discord"))
        open_url(MOD_DISCORD_URL);
    ImGui::SameLine();
    if (ImGui::SmallButton("Report an issue / feedback"))
        open_url(MOD_ISSUES_URL);

    // Filled asynchronously by the worker; absent until a newer release than
    // MOD_VERSION is found (and never shown at all when up to date or offline).
    std::string latest, url;
    if (update_check_get_result(&latest, &url)) {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(120, 230, 140, 255));
        ImGui::Text("Update available: %s", latest.c_str());
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (ImGui::SmallButton("Download"))
            open_url(url.c_str());
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
        // Identity + links + update banner. The live FPS readout and sparkline
        // that used to sit here now live in the Render > FPS section.
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

                // While the filter is active, reveal every matching section so the
                // control you searched for is on screen -- but don't persist that
                // transient open-state; only real toggles and expand/collapse-all
                // change p->open. Otherwise seed from the ini on first appearance
                // and mirror the live state back so the user's clicks persist.
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

        // Update-check opt-out. Seeded once from the ini and written back on
        // change; the check itself runs once at startup, so this takes effect
        // next launch. Shares the [settings] key the worker reads.
        static int check_updates = -1;
        if (check_updates < 0)
            check_updates =
                GetPrivateProfileIntW(L"settings", L"check_updates", 1, settings_ini_path());
        bool check_updates_on = check_updates != 0;
        if (ImGui::Checkbox("Check for updates on launch", &check_updates_on)) {
            check_updates = check_updates_on;
            WritePrivateProfileStringW(L"settings", L"check_updates",
                                       check_updates_on ? L"1" : L"0", settings_ini_path());
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
