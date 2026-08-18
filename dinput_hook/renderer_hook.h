//
// Created by tly on 10.03.2024.
//

#pragma once

#include "imgui_utils.h"

extern GLuint default_framebuffer;

// Drop the N64 mesh path's GL state shadows (bound program/texture, render mode, cull face,
// texture params). Must be called by any path that touches that GL state outside render_mesh --
// the glTF replacement draws call it since they can run mid-traversal between meshes.
void invalidate_mesh_gl_state_cache();

// True if an AABB (min xyz, max xyz, in the space mvp maps from) is completely outside the clip
// volume of mvp (row-vector convention, clip = v * mvp). Conservative: never culls a visible box.
bool aabb_outside_frustum(const float aabb[6], const rdMatrix44 &mvp);

extern "C" int stdDisplay_Update_Hook();

extern "C" void init_renderer_hooks();
