//
// Created by tly on 10.03.2024.
//

#pragma once

#include "imgui_utils.h"

extern GLuint default_framebuffer;

extern "C" int stdDisplay_Update_Hook();

extern "C" void init_renderer_hooks();

// Drop a GL texture name from the LOD-deswizzle "already done" set when its texture is freed, so a
// reused name (after a track reload) is unscrambled again. Called from std3D_ClearTexture_delta.
void deswizzle_forget_texture(GLuint handle);
