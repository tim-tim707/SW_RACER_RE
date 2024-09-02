//
// Created by tly on 10.03.2024.
//

#pragma once

#include <string>

void init_renderer_hooks();

enum ImGuiStateFlags {
    ImGuiStateFlags_NONE = 0,
    ImGuiStateFlags_RESET = 1 << 0,
    ImGuiStateFlags_RECOMPILE = 1 << 1,
};
typedef struct ImGuiState {
    bool show_debug;
    bool draw_meshes;
    bool draw_renderList;
    std::string vertex_shd;
    std::string fragment_shd;
    ImGuiStateFlags shader_flags;
    bool show_fragment;
} ImGuiState;

extern ImGuiState imgui_state;

void opengl_render_imgui();
