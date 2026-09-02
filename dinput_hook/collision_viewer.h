#pragma once

// Track collision-mesh debug overlay: walks the in-race scene graph the way
// swrModel_CollideNodeRecursiveRay does and draws the collision_vertices the pod physics tests
// against, color-coded by surface reaction. The simulation is untouched.

extern "C" {
#include <swr.h>
#include <Swr/swrModel.h>
}

#include "types.h"

// root_node must be the live in-race root (&someRootNode); proj_mat/view_mat are the visual scene
// draw's matrices (mirror flag already baked in). No-op outside a race or when the toggle is off.
void render_collision_overlay(const swrViewport &vp, const swrModel_Node *root_node,
                              const rdMatrix44 &proj_mat, const rdMatrix44 &view_mat);
