#include "debug_ui.h"
#include "imgui_utils.h"
#include "config.h"

#include <algorithm>
#include <vector>
#include <string>
#include <cstring>
#include <cfloat>

#include <imgui.h>

#include "build_id.h"// SWR_BUILD_* (generated at build time)

extern "C" {
#include <globals.h>
#include <Swr/swrUI.h>
}

// show_imgui (the F5 overlay toggle) comes from imgui_utils.h.

bool debug_ui_show_dev_panels = true;

static std::vector<DebugPanel *> g_panels;

// Top-level menus in toolbar order. Any other top-level category (e.g. one from a
// branch that predates this list) still gets a menu, after these.
static const char *const k_menu_order[] = {"Game", "Settings", "Mods", "Debug"};

// A panel opened from the toolbar this frame: its window is placed near the click
// (first use only -- after that imgui.ini remembers where the user put it) and focused.
static DebugPanel *g_just_opened = nullptr;
static ImVec2 g_just_opened_pos;

// Panels under this top-level menu share one window, one tab each; their menu
// items open that window with the clicked tab selected.
static const char *const k_tabbed_menu = "Settings";
static bool g_tabbed_open = false;
static DebugPanel *g_tabbed_current = nullptr;// tab shown last frame
static DebugPanel *g_tabbed_select = nullptr; // tab to force-select this frame

void debug_ui_register(DebugPanel *panel) {
    g_panels.push_back(panel);
}

static void apply_overlay_theme(int theme);

void debug_ui_load_settings() {
    // Overlay look (Help > Overlay). Clamped to the slider ranges in case the ini was hand-edited.
    apply_overlay_theme(config::get_int("debug_ui", "theme", 0));
    ImGui::GetStyle().Alpha =
        std::clamp(config::get_float("debug_ui", "opacity", 1.0f), 0.3f, 1.0f);
    ImGui::GetIO().FontGlobalScale =
        std::clamp(config::get_float("debug_ui", "font_scale", 1.0f), 0.5f, 2.0f);
}

static bool panel_visible(const DebugPanel *p) {
    return !p->dev_only || debug_ui_show_dev_panels;
}

static bool panel_tabbed(const DebugPanel *p) {
    const size_t n = std::strlen(k_tabbed_menu);
    return std::strncmp(p->category, k_tabbed_menu, n) == 0 &&
           (p->category[n] == '\0' || p->category[n] == '/');
}

// Built-in shell panel: ImGui-level conveniences (theme, opacity, the demo and
// metrics windows). These are overlay chrome, not a game subsystem, so they live
// in the shell rather than being registered from a delta file.
static bool g_show_imgui_demo = false;
static bool g_show_imgui_metrics = false;
static bool g_show_log = false;// floating hook.log window (toggled from the Help menu)
static bool g_show_about = false;

// Same build stamp the crash reports carry, so a player can quote it without
// having to reproduce the crash first.
static const char *const k_build_text = SWR_BUILD_DIRTY
                                            ? (SWR_BUILD_BRANCH " @ " SWR_BUILD_COMMIT "-dirty")
                                            : (SWR_BUILD_BRANCH " @ " SWR_BUILD_COMMIT);
static const char *const k_repo_url = "https://github.com/tim-tim707/SW_RACER_RE";

enum OverlayTheme { THEME_DARK, THEME_LIGHT, THEME_CLASSIC };
static int g_overlay_theme = THEME_DARK;

static void apply_overlay_theme(int theme) {
    g_overlay_theme = theme;
    if (theme == THEME_LIGHT)
        ImGui::StyleColorsLight();
    else if (theme == THEME_CLASSIC)
        ImGui::StyleColorsClassic();
    else
        ImGui::StyleColorsDark();
}

static void save_overlay_style() {
    config::set_int("debug_ui", "theme", g_overlay_theme);
    config::set_float("debug_ui", "opacity", ImGui::GetStyle().Alpha);
    config::set_float("debug_ui", "font_scale", ImGui::GetIO().FontGlobalScale);
    config::save();
}

static void panel_overlay() {
    static const char *const theme_names[] = {"Dark", "Light", "Classic"};
    ImGui::TextUnformatted("Theme:");
    for (int i = 0; i < IM_ARRAYSIZE(theme_names); i++) {
        ImGui::SameLine();
        if (ImGui::SmallButton(theme_names[i])) {
            apply_overlay_theme(i);
            save_overlay_style();
        }
    }

    // Save on release rather than every frame of a drag.
    ImGui::SliderFloat("Overlay opacity", &ImGui::GetStyle().Alpha, 0.3f, 1.0f, "%.2f");
    if (ImGui::IsItemDeactivatedAfterEdit())
        save_overlay_style();
    ImGui::SliderFloat("UI font scale", &ImGui::GetIO().FontGlobalScale, 0.5f, 2.0f, "%.2f");
    if (ImGui::IsItemDeactivatedAfterEdit())
        save_overlay_style();

    ImGui::Checkbox("Dear ImGui demo window", &g_show_imgui_demo);
    ImGui::Checkbox("Dear ImGui metrics / debugger", &g_show_imgui_metrics);
}

static DebugPanel g_panel_overlay = {
    .category = "Help", .name = "Overlay", .draw = panel_overlay, .dev_only = false};

void debug_ui_register_builtin_shell_panels() {
    debug_ui_register(&g_panel_overlay);
}

// True if `path` is `prefix` itself or lies under it ("A/B" is under "A").
static bool path_under(const std::string &path, const std::string &prefix) {
    return path.size() > prefix.size() && path.compare(0, prefix.size(), prefix) == 0 &&
           path[prefix.size()] == '/';
}

static bool menu_has_visible_panels(const std::string &prefix) {
    for (DebugPanel *p: g_panels) {
        const std::string path = p->category;
        if (panel_visible(p) && (path == prefix || path_under(path, prefix)))
            return true;
    }
    return false;
}

// Contents of the menu at `prefix`: its own panels as items and one submenu per
// child path segment, interleaved in registration order.
static void draw_menu_contents(const std::string &prefix) {
    std::vector<std::string> seen;
    for (DebugPanel *p: g_panels) {
        if (!panel_visible(p))
            continue;
        const std::string path = p->category;
        if (path == prefix) {
            if (panel_tabbed(p)) {
                if (ImGui::MenuItem(p->name, nullptr, g_tabbed_open && g_tabbed_current == p)) {
                    if (!g_tabbed_open)
                        g_just_opened_pos = ImGui::GetMousePos();
                    g_tabbed_open = true;
                    g_tabbed_select = p;
                }
            } else if (ImGui::MenuItem(p->name, nullptr, p->open)) {
                p->open = !p->open;
                if (p->open) {
                    g_just_opened = p;
                    g_just_opened_pos = ImGui::GetMousePos();
                }
            }
            continue;
        }
        if (!path_under(path, prefix))
            continue;

        const size_t start = prefix.size() + 1;
        const size_t slash = path.find('/', start);
        const std::string segment =
            path.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        bool already = false;
        for (const std::string &s: seen)
            already = already || s == segment;
        if (already)
            continue;
        seen.push_back(segment);

        if (ImGui::BeginMenu(segment.c_str())) {
            draw_menu_contents(prefix + "/" + segment);
            ImGui::EndMenu();
        }
    }
}

static void draw_top_menu(const std::string &name) {
    if (!menu_has_visible_panels(name))
        return;
    if (ImGui::BeginMenu(name.c_str())) {
        draw_menu_contents(name);
        ImGui::EndMenu();
    }
}

static void draw_help_menu() {
    if (!ImGui::BeginMenu("Help"))
        return;
    draw_menu_contents("Help");
    ImGui::MenuItem("Hook log", nullptr, &g_show_log);
    ImGui::Separator();
    ImGui::MenuItem("About", nullptr, &g_show_about);
    if (ImGui::MenuItem("Copy build stamp", k_build_text))
        ImGui::SetClipboardText(k_build_text);
    ImGui::Separator();
    ImGui::TextDisabled("F5 shows / hides this toolbar.");
    ImGui::EndMenu();
}

static void draw_toolbar() {
    if (!ImGui::BeginMainMenuBar())
        return;

    std::vector<std::string> drawn;
    for (const char *name: k_menu_order) {
        draw_top_menu(name);
        drawn.push_back(name);
    }
    for (DebugPanel *p: g_panels) {
        const std::string path = p->category;
        const std::string top = path.substr(0, path.find('/'));
        bool already = top == "Help";// drawn last, by draw_help_menu
        for (const std::string &s: drawn)
            already = already || s == top;
        if (already)
            continue;
        drawn.push_back(top);
        draw_top_menu(top);
    }
    draw_help_menu();

    char fps_text[48];
    snprintf(fps_text, sizeof(fps_text), "%.0f FPS (%.2f ms)", ImGui::GetIO().Framerate,
             1000.0f / ImGui::GetIO().Framerate);
    const float spare = ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(fps_text).x -
                        ImGui::GetStyle().ItemSpacing.x;
    if (spare > 0.0f)
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + spare);
    ImGui::TextDisabled("%s", fps_text);

    ImGui::EndMainMenuBar();
}

static void draw_panel_windows() {
    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    for (DebugPanel *p: g_panels) {
        if (!p->open || !panel_visible(p) || panel_tabbed(p))
            continue;

        if (p == g_just_opened) {
            ImGui::SetNextWindowPos(ImVec2(g_just_opened_pos.x, g_just_opened_pos.y + 8.0f),
                                    ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowFocus();
        }
        // Width fixed on first use, height fits the content; long panels scroll.
        ImGui::SetNextWindowSize(ImVec2(440.0f, 0.0f), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSizeConstraints(ImVec2(240.0f, 60.0f),
                                            ImVec2(FLT_MAX, viewport->WorkSize.y * 0.9f));
        if (ImGui::Begin(p->name, &p->open)) {
            ImGui::PushID(p->name);
            p->draw();
            ImGui::PopID();
        }
        ImGui::End();
    }
    g_just_opened = nullptr;
}

static void draw_tabbed_window() {
    if (!g_tabbed_open)
        return;

    if (g_tabbed_select) {
        ImGui::SetNextWindowPos(ImVec2(g_just_opened_pos.x, g_just_opened_pos.y + 8.0f),
                                ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowFocus();
    }
    if (g_tabbed_select)
        g_tabbed_current = g_tabbed_select;
    g_tabbed_select = nullptr;

    // Fall back to the first entry when nothing is selected yet.
    std::vector<DebugPanel *> entries;
    float sidebar_w = 0.0f;
    for (DebugPanel *p: g_panels) {
        if (!panel_tabbed(p) || !panel_visible(p))
            continue;
        entries.push_back(p);
        sidebar_w = std::max(sidebar_w, ImGui::CalcTextSize(p->name).x);
    }
    if (entries.empty())
        return;
    if (std::find(entries.begin(), entries.end(), g_tabbed_current) == entries.end())
        g_tabbed_current = entries[0];
    sidebar_w += ImGui::GetStyle().WindowPadding.x * 2.0f + ImGui::GetFontSize() * 2.0f;

    ImGui::SetNextWindowSize(ImVec2(720.0f, 640.0f), ImGuiCond_FirstUseEver);
    if (ImGui::Begin(k_tabbed_menu, &g_tabbed_open)) {
        // A separator wherever the menu sub-path changes.
        if (ImGui::BeginChild("##sidebar", ImVec2(sidebar_w, 0.0f), ImGuiChildFlags_Borders)) {
            const char *group = nullptr;
            for (DebugPanel *p: entries) {
                if (group != nullptr && std::strcmp(group, p->category) != 0)
                    ImGui::Separator();
                group = p->category;
                if (ImGui::Selectable(p->name, p == g_tabbed_current))
                    g_tabbed_current = p;
            }
        }
        ImGui::EndChild();
        ImGui::SameLine();

        ImGui::PushID(g_tabbed_current->name);
        if (ImGui::BeginChild("##body"))
            g_tabbed_current->draw();
        ImGui::EndChild();
        ImGui::PopID();
    }
    ImGui::End();
}

static void draw_about_window() {
    if (!g_show_about)
        return;
    if (ImGui::Begin("About", &g_show_about,
                     ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse)) {
        ImGui::TextUnformatted("SW_RACER_RE");
        ImGui::TextDisabled("Star Wars Episode I: Racer, reverse-engineered and extended.");
        ImGui::Separator();
        ImGui::Text("Build: %s", k_build_text);
        ImGui::TextLinkOpenURL(k_repo_url);
    }
    ImGui::End();
}

// The 2D shell's mode-select main menu (pushed by swrObjHang_UpdateSplashScreen @0x435240).
static const int SWRUI_PAGE_MAIN_MENU = 0xb;

static bool on_main_menu() {
    if (g_objHang2 == nullptr || (g_objHang2->flag & 1) == 0)
        return false;
    const swrUI_unk *page = swrUI_GetCurrentPage();
    return page != nullptr && page->id == SWRUI_PAGE_MAIN_MENU;
}

// While the toolbar is hidden, point players at it from the main menu.
static void draw_toolbar_hint() {
    if (!on_main_menu())
        return;

    const char *text = "Press F5 for mod settings";
    ImFont *font = ImGui::GetFont();
    const float font_size = ImGui::GetFontSize() * 1.25f;
    const ImVec2 text_size = font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, text);
    const ImVec2 pad = ImVec2(font_size * 0.6f, font_size * 0.25f);

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    const ImVec2 min = ImVec2(viewport->WorkPos.x + (viewport->WorkSize.x - text_size.x) * 0.5f - pad.x,
                              viewport->WorkPos.y);
    const ImVec2 max = ImVec2(min.x + text_size.x + pad.x * 2.0f, min.y + text_size.y + pad.y * 2.0f);
    ImDrawList *draw = ImGui::GetForegroundDrawList();
    draw->AddRectFilled(min, max, IM_COL32(0, 0, 0, 170), font_size * 0.3f,
                        ImDrawFlags_RoundCornersBottom);
    draw->AddText(font, font_size, ImVec2(min.x + pad.x, min.y + pad.y), IM_COL32(255, 255, 255, 230),
                  text);
}

void debug_ui_render() {
    // Toggled with F5
    if (!show_imgui) {
        draw_toolbar_hint();
        return;
    }

    draw_toolbar();
    draw_panel_windows();
    draw_tabbed_window();

    // Optional floating windows owned by the shell.
    imgui_draw_log_window(&g_show_log);
    draw_about_window();
    if (g_show_imgui_demo)
        ImGui::ShowDemoWindow(&g_show_imgui_demo);
    if (g_show_imgui_metrics)
        ImGui::ShowMetricsWindow(&g_show_imgui_metrics);
}
