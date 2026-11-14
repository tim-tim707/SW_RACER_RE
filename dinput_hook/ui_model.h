#pragma once

#include <cstdint>

extern "C" {
#include "types.h"
}

// UI-aligned 3D models: front-end holograms the game places at a fixed offset from the front-end
// camera (swrObjHang_cameraMatrix) so they sit beside a 2D panel. The game picks those offsets for a
// 4:3 screen at UI scale 1.0; the remap carries the model along with the 2D UI instead.
//
// In camera space (vA right, vB forward, vC up) a model at lateral a / up u / depth d lands
// a * f0 / d pixels from the screen centre, f0 being the vanilla 4:3 focal length in pixels. The
// remap scales that offset by the UI scale about the screen centre (as the 2D box scales), adds the
// owning UI cluster's anchor shift converted to camera units at the model's depth, and divides out
// the user FOV multiplier; the model's size scales the same way. Depth is untouched.

// Remaps |m| in place for a model placed on behalf of |owner_site| (the EXE call site of the code
// that owns the matching 2D panel; its UI cluster, if any, decides the anchor shift).
void ui_model_remap(rdMatrix44 *m, uintptr_t owner_site);

// Owner of the swrModel_NodeSetTransform call at |set_transform_site|, or 0 when that call does not
// place a UI-aligned model.
uintptr_t ui_model_owner_for(uintptr_t set_transform_site);

// Scope for swrObjHang_PositionHoloNode: records which screen asked for the hologram.
struct UiModelHoloScope {
    explicit UiModelHoloScope(uintptr_t caller_site);
    ~UiModelHoloScope();
};
