#include "ui_model.h"

#include "imgui_utils.h"
#include "ui_hud.h"
#include "ui_transform.h"

#include <cmath>

extern "C" {
#include <globals.h>
}

namespace {

// Return address of each swrModel_NodeSetTransform call that places a UI-aligned model.
struct ModelSite {
    uintptr_t site;
    bool holo; // owner = the swrObjHang_PositionHoloNode caller, not the site itself
};

constexpr ModelSite kModelSites[] = {
    // swrRace_UpdateStatPartModels: inspected part hologram (camera + 6 right, 30 deep, 3.5 up).
    {0x004561db, false},
    // swrObjHang_PositionHoloNode: holo node at camera + (x + 18, 126 deep, y - 20); called by the
    // part shop, pit droid shop and results screens.
    {0x0045732e, true},
};

uintptr_t g_holo_owner = 0;

float dot3(const rdVector4 &a, const rdVector3 &b) {
    return a.x * b.x + a.y * b.y + a.z * b.z;
}

} // namespace

UiModelHoloScope::UiModelHoloScope(uintptr_t caller_site) {
    g_holo_owner = caller_site;
}

UiModelHoloScope::~UiModelHoloScope() {
    g_holo_owner = 0;
}

uintptr_t ui_model_owner_for(uintptr_t set_transform_site) {
    for (const ModelSite &s : kModelSites) {
        if (s.site == set_transform_site)
            return s.holo ? g_holo_owner : s.site;
    }
    return 0;
}

void ui_model_remap(rdMatrix44 *m, uintptr_t owner_site) {
    if (!ui_enabled() || m == nullptr || rdCamera_pCurCamera == nullptr)
        return;
    const float h = (float) swrDisplay_screenHeight;
    const float t = 1.0f / tanf(0.5f * rdCamera_pCurCamera->fov / 180.0f * 3.14159f);
    if (h <= 0.0f || !(t > 0.0f))
        return;
    // Vanilla 4:3 focal length in pixels (horizontal fov over a 4:3-wide screen of this height).
    const float f0 = t * (4.0f / 3.0f) * h * 0.5f;
    const float ui_scale = imgui_state.ui_scale > 0.0f ? imgui_state.ui_scale : 1.0f;
    const float fov_scale = imgui_state.fov_scale > 0.0f ? imgui_state.fov_scale : 1.0f;

    // Anchor shift of the owner's cluster relative to the plain centred box, in screen pixels.
    float shift_x = 0.0f, shift_y = 0.0f;
    HudElement el = ui_hud_element_at(owner_site);
    if (el.cluster != HUD_CLUSTER_NONE) {
        UiXform xf = ui_hud_cluster_xform(el.cluster);
        shift_x = xf.tx - ui_center_offset_px();
        shift_y = xf.ty - ui_center_offset_y_px();
    }

    const rdMatrix44 &cam = swrObjHang_cameraMatrix;
    rdVector3 rel = {m->vD.x - cam.vD.x, m->vD.y - cam.vD.y, m->vD.z - cam.vD.z};
    const float lateral = dot3(cam.vA, rel);
    const float depth = dot3(cam.vB, rel);
    const float up = dot3(cam.vC, rel);
    if (depth <= 0.0f)
        return;

    const float new_lateral = fov_scale * (lateral * ui_scale + shift_x * depth / f0);
    const float new_up = fov_scale * (up * ui_scale - shift_y * depth / f0);
    m->vD.x = cam.vD.x + cam.vA.x * new_lateral + cam.vB.x * depth + cam.vC.x * new_up;
    m->vD.y = cam.vD.y + cam.vA.y * new_lateral + cam.vB.y * depth + cam.vC.y * new_up;
    m->vD.z = cam.vD.z + cam.vA.z * new_lateral + cam.vB.z * depth + cam.vC.z * new_up;

    const float size = ui_scale * fov_scale;
    rdVector4 *basis[3] = {&m->vA, &m->vB, &m->vC};
    for (rdVector4 *v : basis) {
        v->x *= size;
        v->y *= size;
        v->z *= size;
    }
}
