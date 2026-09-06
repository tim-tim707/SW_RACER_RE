//
// AI tuning -- see ai_tuning.h.
//
#include "ai_tuning.h"
#include "hook_helper.h"
#include "debug_ui.h"
#include "imgui_utils.h"
#include "config.h"
#include "game_deltas/window_mode.h"// persist_settings_ini

#include <imgui.h>

#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cwchar>

extern "C" {
#include <Swr/swrObj.h>   // InitAISettingsForTrack_ADDR, NumLocalPlayers
#include <Swr/swrRace.h>  // swrRace_UpdateCatchup_ADDR, swrRace_ApplyPodProximityForce_ADDR
#include <Swr/swrEvent.h> // swrEvent_FindNearestObjects
#include <Swr/swrSpline.h>// swrSpline_GetTrackLength
#include <Swr/swrText.h>  // swrText_FormatPodName
#include <Primitives/rdVector.h>
#include <General/stdMath.h>
#include <globals.h>// swrRace_AILevel, ai_spread, ai_track_script, swrScoresPtr
#include <types_enums.h>
}

// Defined in hook_helper.cpp (registers a raw game-address detour); not prototyped there.
extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

// Defined in main.cpp: writes/reverts the AI full-LOD .text patches (gated by ai_full_lod).
extern "C" void set_ai_full_lod(bool on);


// --- config (tunable from the "AI" panel, persisted to [ai] in the ini) ---

struct AITuningConfig {
    bool level_override = false;
    float level = 1.0f;// the per-track table runs ~0.85..1.14, before the AI Speed setting
    bool spread_override = false;
    float spread = 35.0f;// typical authored value (the per-track table runs 20..40)
    bool scripted_ai = true;
    float rubberband = 1.0f;    // 0 = AI pace ignores the player, 1 = vanilla, >1 amplified
    float ai_speed_scale = 1.0f;// flat post-scale on every AI's speed multiplier
    bool ai_blocking = true;    // AI steer into a local human trying to pass (vanilla)
    float avoidance = 1.0f;     // scale on the whole nearest-pod steering nudge
    bool player_catchup = false;// extend the splitscreen catch-up boost to a solo human
    float player_catchup_cap = 1.25f;
};

static AITuningConfig g_cfg;

// The game's own debug keys clamp these two the same way (swrRace_DebugSetGameValue cases 2/3),
// so the panel uses the same ranges rather than inventing wider ones.
static const float AI_LEVEL_MIN = 0.2f;
static const float AI_LEVEL_MAX = 2.0f;
static const float AI_SPREAD_MIN = 2.0f;
static const float AI_SPREAD_MAX = 200.0f;

// What InitAISettingsForTrack picked for the current track, captured before we overwrite it.
// Nothing is applied until a track load has filled these in -- the globals are meaningless in
// the front-end, and an override placed there would be clobbered by the next load anyway.
static bool g_track_captured = false;
static float g_track_level = 0.0f;
static float g_track_spread = 0.0f;
static int g_track_script = -1;

// Push the current config into the game's AI globals. Called from the track-load hook and again
// whenever a panel widget changes, so overrides take hold mid-race without a restart.
static void apply_tuning() {
    if (!g_track_captured)
        return;
    swrRace_AILevel = g_cfg.level_override ? g_cfg.level : g_track_level;
    ai_spread = g_cfg.spread_override ? g_cfg.spread : g_track_spread;
    ai_track_script = g_cfg.scripted_ai ? g_track_script : -1;
}

// --- config persistence ([ai] in SW_RACER_RE.ini) ----------------------

static void load_config() {
    g_cfg.level_override = config::get_int("ai", "level_override", g_cfg.level_override) != 0;
    g_cfg.level = config::get_float("ai", "level", g_cfg.level);
    g_cfg.spread_override = config::get_int("ai", "spread_override", g_cfg.spread_override) != 0;
    g_cfg.spread = config::get_float("ai", "spread", g_cfg.spread);
    g_cfg.scripted_ai = config::get_int("ai", "scripted_ai", g_cfg.scripted_ai) != 0;
    g_cfg.rubberband = config::get_float("ai", "rubberband", g_cfg.rubberband);
    g_cfg.ai_speed_scale = config::get_float("ai", "ai_speed_scale", g_cfg.ai_speed_scale);
    g_cfg.ai_blocking = config::get_int("ai", "ai_blocking", g_cfg.ai_blocking) != 0;
    g_cfg.avoidance = config::get_float("ai", "avoidance", g_cfg.avoidance);
    g_cfg.player_catchup = config::get_int("ai", "player_catchup", g_cfg.player_catchup) != 0;
    g_cfg.player_catchup_cap =
        config::get_float("ai", "player_catchup_cap", g_cfg.player_catchup_cap);
}

static void save_config() {
    config::set_bool("ai", "level_override", g_cfg.level_override);
    config::set_float("ai", "level", g_cfg.level);
    config::set_bool("ai", "spread_override", g_cfg.spread_override);
    config::set_float("ai", "spread", g_cfg.spread);
    config::set_bool("ai", "scripted_ai", g_cfg.scripted_ai);
    config::set_float("ai", "rubberband", g_cfg.rubberband);
    config::set_float("ai", "ai_speed_scale", g_cfg.ai_speed_scale);
    config::set_bool("ai", "ai_blocking", g_cfg.ai_blocking);
    config::set_float("ai", "avoidance", g_cfg.avoidance);
    config::set_bool("ai", "player_catchup", g_cfg.player_catchup);
    config::set_float("ai", "player_catchup_cap", g_cfg.player_catchup_cap);
    config::save();
}

// --- panel ---------------------------------------------------------------

// Hover help for the control just submitted (the help_marker idiom from debug_ui.cpp).
static void tooltip(const char *text) {
    if (ImGui::BeginItemTooltip()) {
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 30.0f);
        ImGui::TextUnformatted(text);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

static void panel_ai() {
    bool dirty = false;

    ImGui::SeparatorText("Difficulty");
    if (g_track_captured)
        ImGui::Text("Track default: level %.3f, spread %.0f", g_track_level, g_track_spread);
    else
        ImGui::TextDisabled("Track default: (load a track)");

    dirty |= ImGui::Checkbox("Override level", &g_cfg.level_override);
    tooltip("Base speed multiplier for the field. Drives the pace-setter directly; the rest of "
            "the field station-keeps behind it. Unchecked, each track uses its own authored "
            "value scaled by the AI Speed menu setting.");
    ImGui::BeginDisabled(!g_cfg.level_override);
    dirty |= ImGui::SliderFloat("Level", &g_cfg.level, AI_LEVEL_MIN, AI_LEVEL_MAX, "%.3f");
    ImGui::EndDisabled();

    dirty |= ImGui::Checkbox("Override spread", &g_cfg.spread_override);
    tooltip("How far apart the field spaces itself (1 point is roughly 50 units of rank "
            "spacing). Lower = a tighter pack, less strung out.");
    ImGui::BeginDisabled(!g_cfg.spread_override);
    dirty |= ImGui::SliderFloat("Spread", &g_cfg.spread, AI_SPREAD_MIN, AI_SPREAD_MAX, "%.0f");
    ImGui::EndDisabled();

    ImGui::SeparatorText("Pacing");
    dirty |= ImGui::SliderFloat("Rubberband", &g_cfg.rubberband, 0.0f, 2.0f, "%.2f");
    tooltip("1.00 = stock. 0 = AI hold a flat pace and stop reacting to how far ahead or behind "
            "you are. Above 1 exaggerates it.");
    dirty |= ImGui::SliderFloat("AI speed", &g_cfg.ai_speed_scale, 0.5f, 1.5f, "%.2fx");
    tooltip("Flat scale on every AI's speed, applied after their pacing. The knob that bites "
            "hardest -- AI level only steers the pace-setter.");

    dirty |= ImGui::Checkbox("Player catch-up assist", &g_cfg.player_catchup);
    tooltip("Gives a trailing solo human the speed boost the game already gives a trailing "
            "splitscreen player. Off in the stock game, and single-player only.");
    ImGui::BeginDisabled(!g_cfg.player_catchup);
    dirty |= ImGui::SliderFloat("Assist cap", &g_cfg.player_catchup_cap, 1.0f, 1.5f, "%.2fx");
    ImGui::EndDisabled();

    ImGui::SeparatorText("Behavior");
    dirty |= ImGui::Checkbox("AI block you", &g_cfg.ai_blocking);
    tooltip("Stock: a lone AI steers INTO you as you try to pass (it only does this to a human, "
            "and never in a crowd). Off = it moves aside instead.");
    dirty |= ImGui::SliderFloat("Avoidance", &g_cfg.avoidance, 0.0f, 2.0f, "%.2fx");
    tooltip("Strength of the whole nearest-pod steering nudge. 0 = AI hold their line and never "
            "swerve for another pod.");

    dirty |= ImGui::Checkbox("Scripted shortcuts", &g_cfg.scripted_ai);
    tooltip("Stock: on six signature tracks the AI are scripted to take or avoid a shortcut at a "
            "set point in the lap. Off = they choose freely.");

    ImGui::SeparatorText("Fidelity");
    if (ImGui::Checkbox("Full LOD (no model pop-in)", &imgui_state.ai_full_lod)) {
        set_ai_full_lod(imgui_state.ai_full_lod);
        persist_settings_ini();// this one lives in imgui_state, not our [ai] block
    }
    tooltip("Puts every racer on the full pod model instead of the low-detail bot model, so AI "
            "stop popping between detail levels.");

    ImGui::Separator();
    if (ImGui::Button("Reset to stock")) {
        const bool full_lod = imgui_state.ai_full_lod;// owned by the graphics settings, not us
        g_cfg = AITuningConfig();
        imgui_state.ai_full_lod = full_lod;
        dirty = true;
    }

    if (dirty) {
        apply_tuning();
        save_config();
    }
}

// Dev inspector: the live pacing state of every racer, which is what the knobs above move.
// speedMultiplier is what actually scales the pod in swrRace_UpdateSpeed; target/smoothed are
// swrRace_AI's aiSpeedTarget and the value it slews toward it at 0.2/sec.
static void panel_ai_racers() {
    // swrScoresPtr outlives the race and its obj_test_ptr entries dangle once the pods are
    // freed, so gate on the judge entity actually being resident.
    if (swrScoresPtr == nullptr || swrEvent_GetItem('Jdge', 0) == nullptr) {
        ImGui::TextDisabled("Not in a race.");
        return;
    }

    const ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollX;
    if (!ImGui::BeginTable("ai_racers", 8, flags, ImVec2(0.0f, 260.0f)))
        return;

    ImGui::TableSetupColumn("Pos");
    ImGui::TableSetupColumn("Pilot");
    ImGui::TableSetupColumn("Role");
    ImGui::TableSetupColumn("Speed");
    ImGui::TableSetupColumn("Target");
    ImGui::TableSetupColumn("Smoothed");
    ImGui::TableSetupColumn("Gap lead");
    ImGui::TableSetupColumn("Gap you");
    ImGui::TableHeadersRow();

    for (int i = 0; i < 20; i++) {
        const swrScore *score = &swrScoresPtr[i];
        const swrRace *pod = score->obj_test_ptr;
        if (pod == nullptr)
            continue;

        char name[128] = {0};
        if (score->pilotId != nullptr && *score->pilotId >= 0 && *score->pilotId < 23)
            swrText_FormatPodName(*score->pilotId, name, sizeof(name));

        const char *role = "AI";
        if ((pod->flags0 & swrObjTest_FLAG0_LOCAL) != 0)
            role = "you";
        else if ((pod->flags0 & swrObjTest_FLAG0_AI) == 0)
            role = "remote";
        else if ((pod->flags0 & swrObjTest_FLAG0_AI_SIMPLE) != 0)
            role = "pace-setter";
        else if ((pod->flags0 &
                  (swrObjTest_FLAG0_AI_TETHER_LOCAL1 | swrObjTest_FLAG0_AI_TETHER_LOCAL2)) != 0)
            role = "tethered";

        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%d", (int) (short) score->results_P1_Position);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(strip_text_codes(name).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(role);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", pod->speedMultiplier);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", pod->aiSpeedTarget);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", pod->paceMultiplier);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", pod->gapToLeader);
        ImGui::TableNextColumn();
        ImGui::Text("%.3f", pod->gapToLocalPlayer1);
    }
    ImGui::EndTable();

    ImGui::TextDisabled("Gaps are in laps (progress), signed: positive = you are ahead.\n"
                        "Speed is the multiplier applied to the pod this frame.");
}

static DebugPanel g_panel_ai = {.category = "Race",
                                .name = "AI",
                                .draw = panel_ai,
                                .dev_only = false};
static DebugPanel g_panel_ai_racers = {.category = "Inspect",
                                       .name = "AI Racers",
                                       .draw = panel_ai_racers,
                                       .dev_only = true};


void ai_tuning_RegisterPanels() {
    load_config();
    debug_ui_register(&g_panel_ai);
    debug_ui_register(&g_panel_ai_racers);
}

typedef void(__cdecl *InitAISettingsForTrack_t)(swrObjJdge *judge);
typedef void(__cdecl *swrRace_UpdateCatchup_t)(swrRace *player);
typedef void(__cdecl *swrRace_ApplyPodProximityForce_t)(swrRace *player);

extern "C" void __cdecl InitAISettingsForTrack_delta(swrObjJdge *judge) {
    hook_call_original((InitAISettingsForTrack_t) InitAISettingsForTrack_ADDR, judge);

    g_track_level = swrRace_AILevel;
    g_track_spread = ai_spread;
    g_track_script = ai_track_script;
    g_track_captured = true;
    apply_tuning();
}

extern "C" void __cdecl swrRace_UpdateCatchup_delta(swrRace *player) {
    hook_call_original((swrRace_UpdateCatchup_t) swrRace_UpdateCatchup_ADDR, player);
    if (player == nullptr)
        return;

    const bool local = (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0;

    if (!local && (player->flags0 & swrObjTest_FLAG0_AI) != 0) {
        // Only speedMultiplier is ours to touch. paceMultiplier is swrRace_AI's slew state (it
        // ramps toward aiSpeedTarget at 0.2/sec and would compound if we wrote back into it), and
        // it is separately what scales AI cornering in swrRace_AutopilotSteer -- so scaling speed
        // here leaves the AI's steering authority at stock values.
        if (g_cfg.rubberband == 1.0f && g_cfg.ai_speed_scale == 1.0f)
            return;
        const float m = 1.0f + (player->speedMultiplier - 1.0f) * g_cfg.rubberband;
        player->speedMultiplier = m * g_cfg.ai_speed_scale;
        return;
    }

    // Catch-up assist for a solo human. Vanilla runs this only for a trailing splitscreen player
    // (NumLocalPlayers() > 1, paced on the gap to local player 1); reuse the same formula against
    // the gap to the race leader so it means something with one human on the grid.
    if (local && g_cfg.player_catchup && multiplayer_enabled == 0 && NumLocalPlayers() <= 1 &&
        player->gapToLeader > 0.0f) {
        const float trackLen = swrSpline_GetTrackLength();
        if (trackLen > 0.0f) {
            const float invTrackLen = 500000.0f / trackLen;
            const float boost = (player->gapToLeader * 100.0f) / invTrackLen + 1.0f;
            player->speedMultiplier = std::min(boost, g_cfg.player_catchup_cap);
        }
    }
}

// Radius and gain of the nearest-pod steering nudge, from the original (.rdata 0x4ad810-0x4ad81c).
static const float PROXIMITY_RADIUS = 50.0f;
static const float PROXIMITY_GAIN = 0.2f;
static const float PROXIMITY_FORCE_SCALE = 0.1f * 8.0f;

extern "C" void __cdecl swrRace_ApplyPodProximityForce_delta(swrRace *player) {
    if (g_cfg.ai_blocking && g_cfg.avoidance == 1.0f) {
        hook_call_original((swrRace_ApplyPodProximityForce_t) swrRace_ApplyPodProximityForce_ADDR,
                           player);
        return;
    }

    // Parameterized copy of the original (src/Swr/swrRace.c): same neighbor query and same force
    // curve, with the block/avoid sign forced positive when blocking is off and the force scaled.
    float distsSq[4];
    void *objs[4];
    rdVector3 deltas[4];

    float sign = 1.0f;
    player->speedLoss = 0.0f;
    const int count = swrEvent_FindNearestObjects('Test', (rdVector3 *) &player->transform.vD,
                                                  PROXIMITY_RADIUS * PROXIMITY_RADIUS, player, 4,
                                                  distsSq, deltas, objs);
    if (count < 1)
        return;

    rdVector3 cross;
    rdVector_Cross3(&cross, (rdVector3 *) &player->transform.vB, deltas);
    const float dist = stdMath_Sqrt(distsSq[0]);
    const float closeness = (PROXIMITY_RADIUS - dist) * PROXIMITY_GAIN;
    const float force = closeness * closeness * PROXIMITY_FORCE_SCALE * g_cfg.avoidance;
    // Which side the nearest pod is on: cross(forward, delta) projected on the gravity axis.
    const float side = player->world_gravity.y * cross.y + player->world_gravity.z * cross.z +
                       player->world_gravity.x * cross.x;

    // Block instead of avoid: exactly one pod nearby, it is a local human, and it is behind us.
    if (g_cfg.ai_blocking && count == 1 &&
        (((swrRace *) objs[0])->flags0 & swrObjTest_FLAG0_LOCAL) != 0 &&
        player->transform.vB.z * deltas[0].z + player->transform.vB.y * deltas[0].y +
                deltas[0].x * player->transform.vB.x <
            0.0f) {
        sign = -1.0f;
    }
    if (0.0f < side)
        player->turnRateTarget = sign * force + player->turnRateTarget;
    else if (side < 0.0f)
        player->turnRateTarget = player->turnRateTarget - sign * force;
}

void ai_tuning_RegisterHooks() {
    hook_function("InitAISettingsForTrack", (uint32_t) InitAISettingsForTrack_ADDR,
                  (uint8_t *) InitAISettingsForTrack_delta);
    hook_function("swrRace_UpdateCatchup", (uint32_t) swrRace_UpdateCatchup_ADDR,
                  (uint8_t *) swrRace_UpdateCatchup_delta);
    hook_function("swrRace_ApplyPodProximityForce", (uint32_t) swrRace_ApplyPodProximityForce_ADDR,
                  (uint8_t *) swrRace_ApplyPodProximityForce_delta);
}
