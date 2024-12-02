#pragma once

#include <string>

#include "node_utils.h"
#include "tinygltf/gltf_utils.h"

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

enum ImGuiStateFlags {
    ImGuiStateFlags_NONE = 0,
    ImGuiStateFlags_RESET = 1 << 0,
    ImGuiStateFlags_RECOMPILE = 1 << 1,
};
typedef struct ImGuiState {
    bool show_debug;
    bool draw_test_scene;
    bool draw_meshes;
    bool draw_renderList;
    bool show_gltf_data;
    std::string vertex_shd;
    std::string fragment_shd;
    ImGuiStateFlags shader_flags;
    bool show_fragment;
    bool debug_lambertian_cubemap;
    bool debug_ggx_cubemap;
    bool debug_ggxLut;
    // Show dynamic replacements
    bool show_replacementTries;
    uint8_t replacedTries[323];// 323 MODELIDs
    std::string replacementTries;
    bool debug_env_cubemap;
    float modelMatScale[3];
} ImGuiState;

extern bool imgui_initialized;
extern ImGuiState imgui_state;

void imgui_render_node(swrModel_Node *node);
void opengl_render_imgui();
void gltfModel_to_imgui(gltfModel &model);
