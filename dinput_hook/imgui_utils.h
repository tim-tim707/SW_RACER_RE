#pragma once

#include <string>

#include "node_utils.h"
#include "gltf_utils.h"

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

typedef struct ImGuiState {
    bool draw_test_scene;
    bool draw_meshes;
    bool draw_renderList;
    bool debug_lambertian_cubemap;
    bool debug_ggx_cubemap;
    bool debug_ggxLut;
    // Show dynamic replacements
    bool show_replacementTries;
    std::string replacementTries;
    bool debug_env_cubemap;
    bool HD_replacement;
    bool show_original_and_replacements;

    bool collect_textures_skip_pod_textures;
    std::set<TEXID> collected_textures;

    int msaa_samples = 1;
    int anisotropy = 8;
    int target_fps = 0;// frame-rate cap for the GL present path; 0 = unlimited
    bool enable_fog = true;
    bool enable_gamepad_nav = true;
    bool cache_meshes = true;// cache per-mesh GL geometry; static meshes upload once, not every frame
    bool hd_font = true;// swap the game's built-in fonts for HD replacements (live toggle via journal)
    bool ai_full_lod = true;// force every racer (incl. AI) onto the full pod model (no LOD pop-in)
    bool show_fps_overlay = false;// pinned top-right FPS readout + frame-time graph
    bool show_fps_graph = false;// graph beneath the FPS overlay number (opt-in)
    bool show_pod_names = true;// draw the overhead racer labels (MP player names / SP place numbers)
    bool mp_disable_collision = true;// in multiplayer, skip pod-to-pod collision for the local
                                   // player so they pass through other racers (track collision kept)
    bool mp_allow_upgrades = false;// master gate: in multiplayer, layer the player-chosen upgrades
                                   // below onto the local pod (vanilla MP races everyone on raw base
                                   // stats, and MP has no pilot-profile step to source upgrades from)
    int mp_upgrade_levels[7] = {0, 0, 0, 0, 0, 0, 0};// per-category upgrade level 0(stock)..5(max), in
                                   // order: traction, turning, acceleration, top speed, air brake,
                                   // cooling, repair (applied at full part condition)

    bool enable_picking_texture_when_hovering = false;
    bool pick_through_transparent_objects = true;
    std::optional<TEXID> picked_texture_id;

    // Resolution-independent 2D UI. When false, every 2D
    // consumer reproduces vanilla behavior; the shared transform is inert.
    bool ui_resolution_independent = false;
    // User UI-scale slider; multiplies ui_layout_scale(). 1.0 == no change.
    float ui_scale = 1.0f;
    // Camera FOV multiplier (1.0 == game default; >1 widens the view / zooms out). Aspect ratio is
    // handled in the projection (Hor+: the 4:3 vertical fov is held constant across ratios). Persisted.
    float fov_scale = 1.0f;

    // Far-plane clip. The PC release draws to the fog horizon with no hard far clip (rdCamera_New
    // passes bFarClip = 0), so the GL scene projection defaults to an infinite far plane. The console
    // versions honored a hard far clip (short draw distance / geometry pop-in); console_far_clip
    // reproduces that by clipping at the game's own per-viewport far_clipping (the camera-man's
    // draw distance, already scaled by the VIDEO_DRAWDISTANCE config) times console_far_scale.
    // scale 1.0 == the game's full draw distance; lower == shorter / more aggressive console pop-in.
    // The near plane stays at the game's zNear. Persisted.
    bool console_far_clip = false;
    float console_far_scale = 1.0f;

    // Audio volumes the vanilla engine never persisted, kept mod-side (SW_RACER_RE.ini [settings]).
    // master_volume drives the A3D device output gain (scales every swrSound channel); the engine
    // forces that gain to 1.0 at the tail of swrSound_Startup on every boot, so we re-apply this.
    // cutscene_volume scales the Smush cinematic audio, which runs on its own DirectSound path and
    // otherwise ignores every audio setting (the startup movies play at hardcoded full volume).
    float master_volume = 1.0f;  // 0..1, applied via swrSound_SetOutputGain
    float cutscene_volume = 0.7f;// 0..1, multiplied by master_volume for Smush cinematics
} ImGuiState;

extern "C" {
extern char show_imgui;
extern bool imgui_initialized;
extern ImGuiState imgui_state;
}

const RdMaterial *material_from_texture_id(TEXID id);
GLuint gl_texture_from_texture_id(TEXID id);

// Absolute path to SW_RACER_RE.ini (next to the exe). Shared so the debug-ui
// shell persists its panel state into the same file as the graphics settings.
const wchar_t *settings_ini_path();

void imgui_Update();
void imgui_render_node(swrModel_Node *node);

// Floating hook.log viewer; *p_open gates visibility (cleared by the window's [x]).
void imgui_draw_log_window(bool *p_open);

// Reads the persisted HD-font toggle from the ini into imgui_state.hd_font and
// returns it. Consulted at font-load time, which runs before read_settings_ini().
bool read_hd_font_setting();
