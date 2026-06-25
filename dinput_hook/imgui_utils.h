#pragma once

#include <string>

#include "node_utils.h"
#include "gltf_utils.h"

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

typedef struct ImGuiState {
    bool show_debug;
    bool draw_test_scene;
    bool draw_meshes;
    bool draw_renderList;
    bool debug_lambertian_cubemap;
    bool debug_ggx_cubemap;
    bool debug_ggxLut;
    // Show dynamic replacements
    bool show_replacementTries;
    std::string replacementTries;
    bool show_logs;
    bool debug_env_cubemap;
    bool HD_replacement;
    bool show_original_and_replacements;

    bool collect_textures_skip_pod_textures;
    std::set<TEXID> collected_textures;

    int msaa_samples = 1;
    int anisotropy = 8;
    int target_fps = 0;// frame-rate cap for the GL present path; 0 = unlimited
    bool enable_fog = true;
    bool cache_meshes = true;// cache per-mesh GL geometry; static meshes upload once, not every frame
    bool ai_full_lod = true;// force every racer (incl. AI) onto the full pod model (no LOD pop-in)
    bool show_fps_overlay = false;// pinned top-right FPS readout + frame-time graph
    bool show_fps_graph = true;// graph beneath the FPS overlay number
    bool show_pod_names = true;// draw the overhead racer labels (MP player names / SP place numbers)

    bool enable_picking_texture_when_hovering = false;
    bool pick_through_transparent_objects = true;
    std::optional<TEXID> picked_texture_id;
} ImGuiState;

extern "C" {
extern char show_imgui;
extern bool imgui_initialized;
extern ImGuiState imgui_state;
}

const RdMaterial *material_from_texture_id(TEXID id);
GLuint gl_texture_from_texture_id(TEXID id);

void imgui_Update();
void imgui_render_node(swrModel_Node *node);
void opengl_render_imgui();
