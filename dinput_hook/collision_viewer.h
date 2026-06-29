#pragma once

// Track collision-mesh debug overlay. Walks the in-race track scene graph the same way the
// game's own collision query does (swrModel_CollideNodeRecursiveRay): gating child nodes on
// flags_2 against the per-planet-track mask, reaching the collision_vertices the pod physics
// actually tests against, and draws them color-coded by surface reaction. Pure debug overlay in
// the renderer-replacement layer - the simulation is untouched. Gated by imgui_state.show_collision.

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

#include "types.h"

// Draw the collision overlay for the in-race track scene. root_node must be the live in-race root
// (&someRootNode); proj_mat/view_mat are the same matrices used for the visual scene draw so the
// overlay aligns with the rendered geometry (the mirror flag is already baked into proj_mat). The
// overlay is drawn double-sided. No-op outside a race or when the toggle is off.
void render_collision_overlay(const swrViewport &vp, const swrModel_Node *root_node,
                              const rdMatrix44 &proj_mat, const rdMatrix44 &view_mat);
