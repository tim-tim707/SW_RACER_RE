//
// Created by tly on 10.03.2024.
//

#pragma once

#include "imgui_utils.h"

extern "C" int stdDisplay_Update_Hook();

void init_renderer_hooks();

void opengl_render_imgui();
