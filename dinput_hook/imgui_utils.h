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
    std::string logs;
    bool debug_env_cubemap;
    bool show_original_and_replacements;
} ImGuiState;

extern char show_imgui;
extern bool imgui_initialized;
extern ImGuiState imgui_state;

void imgui_render_node(swrModel_Node *node);
void opengl_render_imgui();
void gltfModel_to_imgui(gltfModel &model);
