//
// Created by tly on 10.03.2024.
//

#pragma once

#include <string>

void init_renderer_hooks();

typedef struct ImGuiState {
    bool show_debug;
    std::string s;
} ImGuiState;

void opengl_render_imgui();
