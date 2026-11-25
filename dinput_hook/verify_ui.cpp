#include "verify_ui.h"

#include "debug_ui.h"
#include "imgui_utils.h"
#include "lockstep.h"
#include "shadow.h"
#include "game_deltas/swrMain_delta.h"// swr_fixedTimestep

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <imgui.h>

extern "C" {
#include <hook_mode.h>
}

// Debug > Verification: lockstep recording and shadow mode for live play. Recording captures each
// race's inputs and per-frame state hashes, so whatever shadow mode flags can be replayed to the
// same frame; shadow mode runs each selected reimpl next to retail and reports where they differ.

namespace {

const char *const kBlockBegin = "# --- Verification window: shadow mode ---";
const char *const kBlockEnd = "# --- end Verification window ---";

char g_pattern[128] = "swrRace_*";
float g_record_hz = 0.0f;
bool g_record_every = true;
char g_filter[64] = "";
bool g_only_problems = false;
std::string g_config_note;

const ImVec4 kRed(0.95f, 0.35f, 0.35f, 1.0f);
const ImVec4 kGreen(0.45f, 0.85f, 0.45f, 1.0f);
const ImVec4 kYellow(0.95f, 0.8f, 0.3f, 1.0f);
const ImVec4 kGray(0.55f, 0.55f, 0.55f, 1.0f);

std::vector<std::string> read_lines(const char *path) {
    std::vector<std::string> lines;
    FILE *f = fopen(path, "r");
    if (!f)
        return lines;
    char buf[512];
    while (fgets(buf, sizeof(buf), f)) {
        std::string l = buf;
        while (!l.empty() && (l.back() == '\n' || l.back() == '\r'))
            l.pop_back();
        lines.push_back(l);
    }
    fclose(f);
    return lines;
}

// reimpl_config.txt without the window's block; `had` says whether one was there.
std::vector<std::string> config_without_block(bool *had) {
    std::vector<std::string> out;
    bool inside = false;
    *had = false;
    for (const std::string &l: read_lines(HOOK_MODE_CONFIG_FILE)) {
        if (l == kBlockBegin) {
            inside = true;
            *had = true;
            continue;
        }
        if (inside) {
            if (l == kBlockEnd)
                inside = false;
            continue;
        }
        out.push_back(l);
    }
    return out;
}

bool write_lines(const std::vector<std::string> &lines) {
    FILE *f = fopen(HOOK_MODE_CONFIG_FILE, "w");
    if (!f)
        return false;
    for (const std::string &l: lines)
        fprintf(f, "%s\n", l.c_str());
    fclose(f);
    return true;
}

void install_for_next_launch(bool install) {
    bool had;
    std::vector<std::string> lines = config_without_block(&had);
    if (install) {
        lines.push_back(kBlockBegin);
        lines.push_back(std::string("shadow ") + g_pattern);
        lines.push_back("shadow_budget_ms 3");
        lines.push_back(kBlockEnd);
    }
    g_config_note = write_lines(lines) ? (install ? "Written to reimpl_config.txt; restart the game to install."
                                                  : "Removed from reimpl_config.txt; takes effect on restart.")
                                       : "Could not write reimpl_config.txt.";
}

void wrapped(const ImVec4 &color, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::TextWrapped("%s", buf);
    ImGui::PopStyleColor();
}

void section_recording() {
    LockstepStatus ls;
    lockstep_get_status(&ls);
    if (g_record_hz <= 0.0f)
        g_record_hz = imgui_state.target_fps > 0 ? (float) imgui_state.target_fps : 60.0f;

    const bool replaying = ls.mode == 2 && !ls.finished;
    bool recording = ls.mode == 1 && (ls.armed || ls.active);

    ImGui::BeginDisabled(replaying);
    if (ImGui::Checkbox("Record races", &recording)) {
        if (recording)
            lockstep_arm_record(g_record_hz, g_record_every);
        else
            lockstep_disarm();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Checkbox("every race", &g_record_every) && ls.mode == 1)
        lockstep_set_continuous(g_record_every);

    ImGui::BeginDisabled(recording || replaying);
    ImGui::SetNextItemWidth(120.0f);
    ImGui::InputFloat("fixed rate (Hz)", &g_record_hz, 0.0f, 0.0f, "%.0f");
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("A recorded race runs one sim tick per frame at this rate.\n"
                          "Cap the frame rate to the same value or the race runs fast or slow.");

    if (replaying)
        wrapped(kYellow, "Replaying %s: frame %u, %u mismatched", ls.path, ls.frame, ls.mismatches);
    else if (ls.active)
        wrapped(kRed, "REC  frame %u  -> %s", ls.frame, ls.path);
    else if (ls.armed)
        wrapped(kYellow, "Armed: the next race started from the menus is recorded.");
    else
        ImGui::TextDisabled("Not recording.");
    if (ls.last_result[0])
        wrapped(kGray, "Last: %s", ls.last_result);

    if (recording || ls.armed) {
        if (ls.fixed_timestep_on) {
            wrapped(kRed, "Fixed-timestep physics is on: recordings will not start.");
            if (ImGui::SmallButton("Turn off for this session"))
                swr_fixedTimestep = false;
        }
        const int cap = imgui_state.target_fps;
        if (cap <= 0)
            wrapped(kYellow, "No FPS cap: set one to %.0f so the race runs at real speed.", ls.hz);
        else if ((float) cap != ls.hz)
            wrapped(kYellow, "FPS cap %d differs from the %.0f Hz recording rate.", cap, ls.hz);
        if (!ls.vanilla)
            wrapped(kGray, "Mods and deltas are active: replay with the same build and settings.");
    }
}

void section_shadow_setup() {
    ImGui::TextWrapped("Shadow mode is not installed this launch. It hooks the chosen functions at startup.");
    ImGui::SetNextItemWidth(200.0f);
    ImGui::InputText("functions", g_pattern, sizeof(g_pattern));
    ImGui::SetItemTooltip("A function name, or a prefix ending in '*'. Names that suggest input, sound,\n"
                          "rendering, menus or file access are skipped automatically.");
    bool had;
    config_without_block(&had);
    if (ImGui::Button(had ? "Update for next launch" : "Install on next launch"))
        install_for_next_launch(true);
    if (had) {
        ImGui::SameLine();
        if (ImGui::Button("Remove"))
            install_for_next_launch(false);
    }
    if (!g_config_note.empty())
        ImGui::TextDisabled("%s", g_config_note.c_str());
}

void section_shadow() {
    ShadowStatus st;
    shadow_get_status(&st);
    if (st.installed == 0) {
        section_shadow_setup();
        return;
    }

    bool enabled = st.enabled;
    if (ImGui::Checkbox("Compare", &enabled))
        shadow_set_enabled(enabled);
    ImGui::SameLine();
    bool anytime = st.anytime;
    if (ImGui::Checkbox("outside recorded races too", &anytime))
        shadow_set_anytime(anytime);
    ImGui::SetItemTooltip("Without a recording, a mismatch can't be replayed to its frame.");

    float budget = (float) st.budget_ms;
    ImGui::SetNextItemWidth(200.0f);
    if (ImGui::SliderFloat("budget per frame", &budget, 0.0f, 16.0f, budget <= 0.0f ? "no limit" : "%.1f ms"))
        shadow_set_budget_ms(budget);
    ImGui::SetItemTooltip("Each comparison costs about 1.5 ms. One per frame is always allowed.");

    if (!st.enabled)
        ImGui::TextDisabled("Paused.");
    else if (!st.anytime && !(lockstep_shadow_frame() >= 0))
        ImGui::TextDisabled("Waiting for a recorded race.");
    else
        ImGui::TextColored(kGreen, "Comparing.");
    ImGui::Text("%llu comparisons, %u rounds", (unsigned long long) st.compared, st.rounds);
    ImGui::SameLine();
    if (st.mismatches)
        ImGui::TextColored(kRed, "%u mismatches", st.mismatches);
    else
        ImGui::TextColored(kGreen, "no mismatches");
    if (st.quirks) {
        ImGui::SameLine();
        ImGui::TextDisabled("(%u known quirks)", st.quirks);
        ImGui::SetItemTooltip("Differences that come from retail itself (leftover registers, uninitialized\n"
                              "stack). They are listed below in gray and not counted as mismatches.");
    }
    wrapped(kGray, "last frame %.1f ms, worst %.0f ms, %u frames over budget, %.1f s total", st.last_frame_ms,
                        st.worst_frame_ms, st.over_budget_frames, st.total_ms / 1000.0);
    if (ImGui::SmallButton("Reset counts"))
        shadow_reset_stats();
    ImGui::SameLine();
    if (ImGui::SmallButton("Write summary to shadow.log"))
        shadow_report();

    const int n = shadow_function_count();
    std::vector<ShadowFunctionStats> fns;
    int reached = 0, bad = 0;
    for (int i = 0; i < n; i++) {
        ShadowFunctionStats f;
        if (!shadow_get_function(i, &f) || !f.ready)
            continue;
        fns.push_back(f);
        reached += f.compared > 0;
        bad += f.mismatches > 0;
    }
    ImGui::SeparatorText("Coverage");
    char overlay[64];
    snprintf(overlay, sizeof(overlay), "%d / %d functions compared", reached, (int) fns.size());
    ImGui::ProgressBar(fns.empty() ? 0.0f : (float) reached / (float) fns.size(), ImVec2(-1.0f, 0.0f), overlay);
    wrapped(kGray, "%d clean, %d mismatched, %d not reached yet", reached - bad, bad, (int) fns.size() - reached);

    ImGui::SetNextItemWidth(160.0f);
    ImGui::InputTextWithHint("##filter", "filter", g_filter, sizeof(g_filter));
    ImGui::SameLine();
    ImGui::Checkbox("problems only", &g_only_problems);
    ImGui::SetItemTooltip("Hide functions that were compared with no mismatch.");

    std::stable_sort(fns.begin(), fns.end(), [](const ShadowFunctionStats &a, const ShadowFunctionStats &b) {
        auto rank = [](const ShadowFunctionStats &f) { return f.mismatches ? 0 : f.compared ? 2 : 1; };
        return rank(a) < rank(b);
    });
    const ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                                  ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("coverage", 6, flags, ImVec2(0.0f, 220.0f))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthStretch, 3.0f);
        const float w = ImGui::CalcTextSize("000000").x;
        ImGui::TableSetupColumn("Calls", ImGuiTableColumnFlags_WidthFixed, w);
        ImGui::TableSetupColumn("Cmp", ImGuiTableColumnFlags_WidthFixed, w);
        ImGui::TableSetupColumn("Bad", ImGuiTableColumnFlags_WidthFixed, w * 0.7f);
        ImGui::TableSetupColumn("First", ImGuiTableColumnFlags_WidthFixed, w);
        ImGui::TableSetupColumn("ms", ImGuiTableColumnFlags_WidthFixed, w * 0.7f);
        ImGui::TableHeadersRow();
        for (const ShadowFunctionStats &f: fns) {
            if (g_filter[0] && !strstr(f.name, g_filter))
                continue;
            if (g_only_problems && f.compared && !f.mismatches)
                continue;
            const ImVec4 color = f.mismatches ? kRed : f.compared ? kGreen : kGray;
            const char *tag = f.disabled ? " (stopped)" : (f.quirks && !f.mismatches) ? " (quirk)" : "";
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(color, "%s%s", f.name, tag);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\ncalls %u, compared %u, mismatches %u, known quirks %u, warnings %u,\n"
                                  "unreliable %u, avg %.2f ms, worst %.2f ms",
                                  f.name, f.calls, f.compared, f.mismatches, f.quirks, f.warnings, f.unreliable,
                                  f.avg_ms, f.max_ms);
            ImGui::TableNextColumn();
            ImGui::Text("%u", f.calls);
            ImGui::TableNextColumn();
            ImGui::Text("%u", f.compared);
            ImGui::TableNextColumn();
            if (f.mismatches)
                ImGui::TextColored(kRed, "%u", f.mismatches);
            else
                ImGui::TextDisabled("0");
            ImGui::TableNextColumn();
            if (f.first_frame >= 0)
                ImGui::Text("%d", f.first_frame);
            else if (f.first_frame < -1)
                ImGui::Text("live %d", -f.first_frame - 2);
            else
                ImGui::TextDisabled("-");
            ImGui::TableNextColumn();
            if (f.compared)
                ImGui::Text("%.1f", f.avg_ms);
            else
                ImGui::TextDisabled("-");
        }
        ImGui::EndTable();
    }

    // Mismatches, newest first
    const ShadowMismatch *ring;
    const int total = shadow_recent_mismatches(&ring);
    ImGui::SeparatorText("Mismatches");
    if (total == 0) {
        wrapped(kGray, "None yet. Details of every mismatch also go to shadow.log.");
        return;
    }
    if (ImGui::SmallButton("Copy list")) {
        std::string text;
        for (int k = 0; k < std::min(total, 64); k++) {
            const ShadowMismatch &m = ring[(total - 1 - k) % 64];
            char line[320];
            snprintf(line, sizeof(line), "%s %s %d: %s%s%s%s%s\n", m.function, m.live ? "live" : "frame",
                     m.frame, m.what, m.unreliable ? " (unreliable)" : "", m.known ? " (known quirk: " : "",
                     m.known ? m.known : "", m.known ? ")" : "");
            text += line;
        }
        ImGui::SetClipboardText(text.c_str());
    }
    ImGui::SameLine();
    ImGui::TextDisabled("first 3 per function, details in shadow.log; known quirks in gray");
    if (ImGui::BeginChild("mismatches", ImVec2(0.0f, 160.0f), ImGuiChildFlags_Borders)) {
        for (int k = 0; k < std::min(total, 64); k++) {
            const ShadowMismatch &m = ring[(total - 1 - k) % 64];
            ImGui::TextColored(m.known ? kGray : kRed, "%s", m.function);
            ImGui::SameLine();
            if (m.live)
                ImGui::TextDisabled("live frame %d (not replayable)", m.frame);
            else
                ImGui::TextDisabled("frame %d", m.frame);
            if (m.unreliable) {
                ImGui::SameLine();
                ImGui::TextColored(kYellow, "unreliable");
            }
            ImGui::Indent();
            if (m.known)
                wrapped(kGray, "known retail quirk: %s", m.known);
            else
                ImGui::TextWrapped("%s", m.what[0] ? m.what : "(see shadow.log)");
            ImGui::Unindent();
        }
    }
    ImGui::EndChild();
}

void panel_verification() {
    ImGui::SeparatorText("Lockstep recording");
    section_recording();
    ImGui::SeparatorText("Shadow mode");
    section_shadow();
}

DebugPanel g_panel_verification = {
    .category = "Debug", .name = "Verification", .draw = panel_verification, .dev_only = false};

}// namespace

void verify_ui_RegisterPanels() {
    debug_ui_register(&g_panel_verification);
}
