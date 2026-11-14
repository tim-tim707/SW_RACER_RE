#include "tfps.h"
#include "hook_helper.h"
#include "imgui_utils.h"
#include "game_deltas/swrMain_delta.h"    // swr_fixedTimestep, swr_fixedTimestepHz
#include "game_deltas/swrMain_smoothing.h"// swr_fixedTimestepSmoothing, swr_fixedTimestepPrediction

#include <cmath>
#include <cstdio>
#include <cstring>
#include <cfloat>

#include <imgui.h>
#include <GLFW/glfw3.h>

extern "C" {
#include <globals.h>
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
}

void save_settings_ini();

static const int SCORE_IDENTIFIER_LOCAL = 0x4c6f636c;// 'Locl'
static const int POD_COUNT = 23;
static const int PART_HEALTH_NEW = 0xFF;

// Traction (upgrade category 0) parts by level, as named in the shop. The community quotes the
// number alone: "24/20" = 24 fps on the stock R-20.
static const int traction_part_numbers[6] = {20, 60, 80, 100, 300, 600};

enum TfpsContext {
    TFPS_CONTEXT_MULTIPLAYER,
    TFPS_CONTEXT_FREE_PLAY,
    TFPS_CONTEXT_TOURNAMENT,
};

enum TfpsFpsMode {
    TFPS_FPS_VSYNC,
    TFPS_FPS_FIXED,
    TFPS_FPS_LIMIT,
    TFPS_FPS_UNCAPPED,
};

struct TractionPart {
    int level; // 0 (stock R-20) .. 5 (R-600)
    int health;// 0 .. 0xFF (new)
};

static float g_chip_bottom = 0.0f;

static int clamp_int(int v, int lo, int hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

static TfpsContext current_context() {
    if (multiplayer_enabled != 0 || multiplayer_in_mp != 0)
        return TFPS_CONTEXT_MULTIPLAYER;
    if (g_objHang2 != nullptr && g_objHang2->isTournamentMode != 0)
        return TFPS_CONTEXT_TOURNAMENT;
    return TFPS_CONTEXT_FREE_PLAY;
}

static TractionPart profile_traction() {
    return {clamp_int((uint8_t) swrRace_traction_upgrade_level, 0, 5),
            (uint8_t) swrRace_traction_upgrade_health};
}

static TractionPart effective_traction(TfpsContext ctx) {
    switch (ctx) {
        case TFPS_CONTEXT_MULTIPLAYER:
            if (!imgui_state.mp_allow_upgrades)
                return {0, PART_HEALTH_NEW};
            return {clamp_int(imgui_state.mp_upgrade_levels[0], 0, 5),
                    clamp_int(imgui_state.mp_traction_health, 0, 255)};
        case TFPS_CONTEXT_FREE_PLAY:
            if (imgui_state.freeplay_traction_override)
                return {clamp_int(imgui_state.freeplay_traction_level, 0, 5),
                        clamp_int(imgui_state.freeplay_traction_health, 0, 255)};
            return profile_traction();
        case TFPS_CONTEXT_TOURNAMENT:
        default:
            return profile_traction();
    }
}

// Base antiSkid + one traction part, as swrRace_ApplyUpgradesToStats does
// (category 0 touches only antiSkid).
static float upgraded_anti_skid(int pod, TractionPart part) {
    PodHandlingData stats = swrRacer_PodHandlingData[pod];
    swrRace_CalculateUpgradedStat(&stats, 0, part.level, (float) (part.health * 0.003921569));
    return stats.antiSkid;
}

static swrScore *local_score() {
    if (multiplayer_enabled != 0) {
        if (playerNumber < 0 || playerNumber >= 20)
            return nullptr;
        swrScore *score = &swrScores[playerNumber];
        return score->identifier == SCORE_IDENTIFIER_LOCAL ? score : nullptr;
    }
    for (int i = 0; i < 20; i++) {
        if (swrScores[i].identifier == SCORE_IDENTIFIER_LOCAL)
            return &swrScores[i];
    }
    return nullptr;
}

static int score_pod(const swrScore *score) {
    if (score == nullptr || score->pilotId == nullptr)
        return -1;
    const int pod = *score->pilotId;
    return (pod >= 0 && pod < POD_COUNT) ? pod : -1;
}

// Push the context's traction onto the local racer's score entry (what a restart rebuilds
// from) and, mid-race, onto the live pod the flight model reads.
static void apply_traction_live() {
    const TfpsContext ctx = current_context();
    if (ctx == TFPS_CONTEXT_TOURNAMENT)
        return;
    if (ctx == TFPS_CONTEXT_MULTIPLAYER && multiplayer_enabled == 0)
        return;

    swrScore *score = local_score();
    const int pod = score_pod(score);
    if (pod < 0)
        return;

    const float anti_skid = upgraded_anti_skid(pod, effective_traction(ctx));
    score->podStats.antiSkid = anti_skid;
    if (currentPlayer_Test != nullptr && score->obj_test_ptr == currentPlayer_Test)
        currentPlayer_Test->podStats.antiSkid = anti_skid;
}

typedef void *(swrObjHang_BuildRosterSinglePlayer_t) (swrObjHang * hang, int *out);

void *swrObjHang_BuildRosterSinglePlayer_delta(swrObjHang *hang, int *out) {
    void *result = hook_call_original(
        (swrObjHang_BuildRosterSinglePlayer_t *) swrObjHang_BuildRosterSinglePlayer_ADDR, hang,
        out);

    if (!imgui_state.freeplay_traction_override || multiplayer_enabled != 0)
        return result;
    if (hang == nullptr || hang->isTournamentMode != 0)
        return result;

    swrScore *score = local_score();
    const int pod = score_pod(score);
    if (pod < 0)
        return result;
    score->podStats.antiSkid = upgraded_anti_skid(pod, effective_traction(TFPS_CONTEXT_FREE_PLAY));
    return result;
}

static TfpsFpsMode current_fps_mode() {
    if (swr_fixedTimestep)
        return TFPS_FPS_FIXED;
    if (imgui_state.target_fps != 0)
        return TFPS_FPS_LIMIT;
    return imgui_state.vsync ? TFPS_FPS_VSYNC : TFPS_FPS_UNCAPPED;
}

static int refresh_rate() {
    GLFWwindow *window = glfwGetCurrentContext();
    GLFWmonitor *monitor = window != nullptr ? glfwGetWindowMonitor(window) : nullptr;
    if (monitor == nullptr)
        monitor = glfwGetPrimaryMonitor();
    const GLFWvidmode *mode = monitor != nullptr ? glfwGetVideoMode(monitor) : nullptr;
    return mode != nullptr ? mode->refreshRate : 60;
}

// The frame rate the simulation steps at, the number players quote.
static int physics_fps(TfpsFpsMode mode) {
    switch (mode) {
        case TFPS_FPS_FIXED:
            return (int) std::lround(swr_fixedTimestepHz);
        case TFPS_FPS_LIMIT:
            return imgui_state.target_fps;
        case TFPS_FPS_VSYNC:
            return refresh_rate();
        case TFPS_FPS_UNCAPPED:
        default:
            return (int) std::lround(ImGui::GetIO().Framerate);
    }
}

static void set_fps_mode(TfpsFpsMode mode, int fps) {
    switch (mode) {
        case TFPS_FPS_VSYNC:
            swr_fixedTimestep = false;
            imgui_state.target_fps = 0;
            imgui_state.vsync = true;
            break;
        case TFPS_FPS_FIXED:
            swr_fixedTimestep = true;
            swr_fixedTimestepHz = (float) clamp_int(fps, 20, 120);
            imgui_state.target_fps = 0;
            imgui_state.vsync = true;
            break;
        case TFPS_FPS_LIMIT:
            swr_fixedTimestep = false;
            imgui_state.target_fps = clamp_int(fps, 10, 200);
            imgui_state.vsync = false;
            break;
        case TFPS_FPS_UNCAPPED:
            swr_fixedTimestep = false;
            imgui_state.target_fps = 0;
            imgui_state.vsync = false;
            break;
    }
    save_settings_ini();
}

static void format_fps_label(char *buf, size_t size) {
    const TfpsFpsMode mode = current_fps_mode();
    snprintf(buf, size, "%s%d %s", mode == TFPS_FPS_UNCAPPED ? "~" : "", physics_fps(mode),
             mode == TFPS_FPS_FIXED ? "Hz" : "fps");
}

// "R60", or "R60 (217)" when the part's health is below new (255); the stock part ignores health.
static void format_traction_label(char *buf, size_t size) {
    const TractionPart part = effective_traction(current_context());
    if (part.level != 0 && part.health != PART_HEALTH_NEW)
        snprintf(buf, size, "R%d (%d)", traction_part_numbers[part.level], part.health);
    else
        snprintf(buf, size, "R%d", traction_part_numbers[part.level]);
}

static void draw_rate_picker(TfpsFpsMode mode, int fps) {
    const int lo = mode == TFPS_FPS_FIXED ? 20 : 10;
    const int hi = mode == TFPS_FPS_FIXED ? 120 : 200;
    const int presets[] = {24, 30, 36, 48, 60, 120};
    const ImVec4 active = ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive);
    for (int i = 0; i < IM_ARRAYSIZE(presets); i++) {
        if (i != 0)
            ImGui::SameLine(0.0f, ImGui::GetStyle().ItemInnerSpacing.x);
        char label[8];
        snprintf(label, sizeof(label), "%d", presets[i]);
        const bool selected = fps == presets[i];
        if (selected)
            ImGui::PushStyleColor(ImGuiCol_Button, active);
        if (ImGui::Button(label) && !selected)
            set_fps_mode(mode, presets[i]);
        if (selected)
            ImGui::PopStyleColor();
    }
    int value = fps;
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10.0f);
    if (ImGui::SliderInt("##tfps_rate", &value, lo, hi, mode == TFPS_FPS_FIXED ? "%d Hz" : "%d fps",
                         ImGuiSliderFlags_AlwaysClamp))
        set_fps_mode(mode, value);
}

// Render smoothing between fixed ticks: 0% prediction interpolates (one tick behind, smooth),
// 100% extrapolates (no lag, can jitter at low tick rates).
static void draw_smoothing_options() {
    if (ImGui::Checkbox("Smooth rendering", &swr_fixedTimestepSmoothing))
        save_settings_ini();
    if (!swr_fixedTimestepSmoothing)
        return;
    ImGui::Indent();
    float pct = swr_fixedTimestepPrediction * 100.0f;
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10.0f);
    if (ImGui::SliderFloat("##tfps_prediction", &pct, 0.0f, 100.0f, "%.0f%% prediction",
                           ImGuiSliderFlags_AlwaysClamp)) {
        swr_fixedTimestepPrediction = pct / 100.0f;
        save_settings_ini();
    }
    ImGui::SetItemTooltip("0%% interpolates between ticks (smooth, one tick behind).\n"
                          "100%% extrapolates ahead (no lag, may jitter at low rates).");
    ImGui::Unindent();
}

static void draw_fps_section() {
    const TfpsFpsMode mode = current_fps_mode();
    const int fps = physics_fps(mode);
    const char *mode_names[] = {"VSync", "Fixed timestep", "Frame limit", "Uncapped"};
    for (int m = 0; m < 4; m++) {
        if (ImGui::RadioButton(mode_names[m], mode == m) && mode != m)
            set_fps_mode((TfpsFpsMode) m, fps);
        if (mode != m)
            continue;
        ImGui::Indent();
        switch (mode) {
            case TFPS_FPS_VSYNC:
                ImGui::TextDisabled("Display refresh: %d Hz", fps);
                break;
            case TFPS_FPS_FIXED:
                draw_rate_picker(mode, fps);
                draw_smoothing_options();
                break;
            case TFPS_FPS_LIMIT:
                draw_rate_picker(mode, fps);
                break;
            case TFPS_FPS_UNCAPPED:
                ImGui::TextDisabled("Follows the render rate\n(%d fps now)", fps);
                break;
        }
        ImGui::Unindent();
    }
}

// Returns true when the level or health changed.
static bool draw_part_picker(int *level, int *health) {
    bool changed = false;
    for (int i = 0; i < 6; i++) {
        char label[16];
        snprintf(label, sizeof(label), "R%d", traction_part_numbers[i]);
        if (ImGui::RadioButton(label, *level == i) && *level != i) {
            *level = i;
            changed = true;
        }
        if (*level != i || i == 0)
            continue;
        ImGui::Indent();
        ImGui::SetNextItemWidth(ImGui::GetFontSize() * 10.0f);
        if (ImGui::SliderInt("##tfps_health", health, 0, PART_HEALTH_NEW, "health %d",
                             ImGuiSliderFlags_AlwaysClamp))
            changed = true;
        ImGui::Unindent();
    }
    return changed;
}

static void draw_traction_section() {
    const TfpsContext ctx = current_context();
    const char *context_names[] = {"Multiplayer", "Free Play", "Tournament"};
    char title[48];
    snprintf(title, sizeof(title), "Traction (%s)", context_names[ctx]);
    ImGui::SeparatorText(title);

    bool changed = false;
    switch (ctx) {
        case TFPS_CONTEXT_TOURNAMENT: {
            const TractionPart part = profile_traction();
            ImGui::Text("R%d, health %d", traction_part_numbers[part.level], part.health);
            ImGui::TextDisabled("Tournament parts change only\nat Watto's shop or the junkyard.");
            break;
        }
        case TFPS_CONTEXT_FREE_PLAY: {
            if (ImGui::Checkbox("Override profile part", &imgui_state.freeplay_traction_override))
                changed = true;
            if (imgui_state.freeplay_traction_override) {
                ImGui::Indent();
                changed |= draw_part_picker(&imgui_state.freeplay_traction_level,
                                            &imgui_state.freeplay_traction_health);
                ImGui::Unindent();
            } else {
                const TractionPart part = profile_traction();
                ImGui::TextDisabled("Using the profile's R%d, health %d.",
                                    traction_part_numbers[part.level], part.health);
            }
            break;
        }
        case TFPS_CONTEXT_MULTIPLAYER: {
            int level = imgui_state.mp_allow_upgrades ? imgui_state.mp_upgrade_levels[0] : 0;
            if (draw_part_picker(&level, &imgui_state.mp_traction_health)) {
                imgui_state.mp_upgrade_levels[0] = level;
                // Picking a part opts in to MP upgrades; the other categories keep their levels.
                imgui_state.mp_allow_upgrades = true;
                changed = true;
            }
            ImGui::TextDisabled("Applies to your own pod only.");
            break;
        }
    }

    if (changed) {
        save_settings_ini();
        apply_traction_live();
    }
}

// The on-screen FPS counter (drawn by draw_fps_overlay in imgui_utils.cpp).
static void draw_counter_options() {
    const ImGuiIO &io = ImGui::GetIO();
    ImGui::TextDisabled("Rendering %.0f fps (%.2f ms)", io.Framerate, 1000.0f / io.Framerate);
    if (ImGui::Checkbox("Show FPS counter", &imgui_state.show_fps_overlay))
        save_settings_ini();
    if (!imgui_state.show_fps_overlay)
        return;
    ImGui::Indent();
    if (ImGui::Checkbox("Graph", &imgui_state.show_fps_graph))
        save_settings_ini();
    if (ImGui::Checkbox("Performance breakdown", &imgui_state.show_perf_breakdown))
        save_settings_ini();
    ImGui::Unindent();
}

static void draw_fps_body() {
    draw_fps_section();
    ImGui::Separator();
    draw_counter_options();
    ImGui::Separator();
    if (ImGui::Checkbox("Always show FPS", &imgui_state.tfps_pin_fps))
        save_settings_ini();
    ImGui::SetItemTooltip("Keep this button in the top-right corner while the toolbar is hidden.");
}

static void draw_traction_body() {
    draw_traction_section();
    ImGui::Separator();
    if (ImGui::Checkbox("Always show traction", &imgui_state.tfps_pin_traction))
        save_settings_ini();
    ImGui::SetItemTooltip("Keep this button in the top-right corner while the toolbar is hidden.");
}

static void fps_tooltip() {
    const char *mode_names[] = {"VSync", "Fixed timestep", "Frame limit", "Uncapped"};
    ImGui::SetTooltip("Physics frame rate (%s)", mode_names[current_fps_mode()]);
}

static void traction_tooltip() {
    const TractionPart part = effective_traction(current_context());
    ImGui::SetTooltip("Traction R%d, health %d", traction_part_numbers[part.level], part.health);
}

struct TfpsButton {
    const char *id;
    void (*format)(char *, size_t);
    void (*body)();
    void (*tooltip)();
};

static const TfpsButton k_fps_button = {"###tfps_fps", format_fps_label, draw_fps_body,
                                        fps_tooltip};
static const TfpsButton k_traction_button = {"###tfps_traction", format_traction_label,
                                             draw_traction_body, traction_tooltip};

// The pinned corner bar draws its labels a little larger; in the toolbar they match the bar so they
// fit its height.
static const float k_pinned_label_scale = 1.25f;

static float label_font_size(float scale) {
    return ImGui::GetFont()->FontSize * ImGui::GetIO().FontGlobalScale * scale;
}

static float label_text_width(const char *text, float scale) {
    return ImGui::GetFont()->CalcTextSizeA(label_font_size(scale), FLT_MAX, 0.0f, text).x;
}

static float button_width(const TfpsButton &b, float scale) {
    char label[32];
    b.format(label, sizeof(label));
    return label_text_width(label, scale) + ImGui::GetStyle().ItemSpacing.x * 2.0f;
}

static float separator_width(float scale) {
    return label_text_width("/", scale) + ImGui::GetStyle().ItemSpacing.x;
}

static void draw_button(const TfpsButton &b) {
    char label[48];
    b.format(label, sizeof(label));
    std::snprintf(label + std::strlen(label), sizeof(label) - std::strlen(label), "%s", b.id);
    if (ImGui::BeginMenu(label)) {
        b.body();
        ImGui::EndMenu();
    } else if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        b.tooltip();
    }
}

static void draw_buttons(bool fps, bool traction) {
    if (fps)
        draw_button(k_fps_button);
    if (fps && traction)
        ImGui::TextDisabled("/");
    if (traction)
        draw_button(k_traction_button);
}

static float buttons_width(bool fps, bool traction, float scale) {
    float w = 0.0f;
    if (fps)
        w += button_width(k_fps_button, scale);
    if (fps && traction)
        w += separator_width(scale);
    if (traction)
        w += button_width(k_traction_button, scale);
    return w;
}

float tfps_menu_bar_item_width() {
    return buttons_width(true, true, 1.0f);
}

void tfps_draw_menu_bar_item() {
    draw_buttons(true, true);
}

void tfps_draw_chip() {
    g_chip_bottom = 0.0f;
    const bool fps = imgui_state.tfps_pin_fps;
    const bool traction = imgui_state.tfps_pin_traction;
    if (show_imgui || (!fps && !traction))
        return;

    const float width =
        buttons_width(fps, traction, k_pinned_label_scale) + ImGui::GetStyle().ItemSpacing.x;
    const float height =
        label_font_size(k_pinned_label_scale) + ImGui::GetStyle().FramePadding.y * 2.0f;

    const ImGuiViewport *viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x, viewport->WorkPos.y),
                            ImGuiCond_Always, ImVec2(1.0f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(width, height));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_MenuBar |
                                   ImGuiWindowFlags_NoSavedSettings |
                                   ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
                                   ImGuiWindowFlags_NoBackground;
    // Menu bar fill cleared; a translucent plate is drawn in its place.
    const ImVec4 plate = ImGui::GetStyleColorVec4(ImGuiCol_MenuBarBg);
    ImGui::PushStyleColor(ImGuiCol_MenuBarBg, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowMinSize, ImVec2(1.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    const bool visible = ImGui::Begin("##tfps_pinned", nullptr, flags);
    ImGui::PopStyleVar(4);
    ImGui::PopStyleColor();
    // Kept on the window, so the menu bar height (sized in Begin) follows from the next frame on.
    ImGui::SetWindowFontScale(k_pinned_label_scale);
    if (visible) {
        const ImVec2 min = ImGui::GetWindowPos();
        const ImVec2 max =
            ImVec2(min.x + ImGui::GetWindowWidth(), min.y + ImGui::GetWindowHeight());
        // The window is all menu bar, so its content clip rect is empty; widen it for the plate.
        ImDrawList *draw = ImGui::GetWindowDrawList();
        draw->PushClipRect(min, max, false);
        draw->AddRectFilled(min, max,
                            ImGui::GetColorU32(ImVec4(plate.x, plate.y, plate.z, plate.w * 0.45f)),
                            ImGui::GetFontSize() * 0.5f, ImDrawFlags_RoundCornersBottomLeft);
        draw->PopClipRect();
    }
    if (visible && ImGui::BeginMenuBar()) {
        draw_buttons(fps, traction);
        ImGui::EndMenuBar();
        g_chip_bottom = ImGui::GetWindowPos().y + height;
    }
    ImGui::End();
}

float tfps_chip_bottom() {
    return g_chip_bottom;
}
