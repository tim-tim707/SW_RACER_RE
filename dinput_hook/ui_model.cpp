#include "ui_model.h"

#include "imgui_utils.h"
#include "ui_hud.h"
#include "ui_transform.h"

#include <cmath>

extern "C" {
#include <globals.h>
#include <types_enums.h>
#include <Swr/swrRace.h>
}

namespace {

enum ModelPick {
    MODEL_ALWAYS,        // every model placed from the site
    MODEL_SELECTED_PART, // only the selected part, while its detail view is open
};

// Return address of each swrModel_NodeSetTransform call that places a UI-aligned model.
struct ModelSite {
    uintptr_t site;
    // Code that owns the matching 2D panel; 0 = the swrObjHang_PositionHoloNode caller.
    uintptr_t owner;
    ModelPick pick;
};

// The shop parts are loaded into swr_sceneModels from INGAME_MODELID_map_tat1_part, one per
// uiUpgradeInfos2 entry (LoadUpgradeModelsIntoScene_Maybe).
bool is_featured_part(const swrModel_NodeTransformed *node) {
    if (swrObjHang_partDetailActive == 0 && swrObjHang_partDetailClosing == 0)
        return false;
    const int sel = swrRace_MenuSelectedItem;
    if (sel < 0 || sel >= swrRace_MenuMaxSelection)
        return false;
    const swrModel_Header *header = swr_sceneModels[INGAME_MODELID_map_tat1_part + sel];
    return header != nullptr && (const void *) header->entries[0].node == (const void *) node;
}

constexpr ModelSite kModelSites[] = {
    // swrRace_UpdateStatPartModels: the shelf parts are world props, but the selected one is the
    // featured part framed inside the buy panel's ring (shop and junkyard).
    {0x00455fb0, swrRace_DrawPartShopScreen_ADDR, MODEL_SELECTED_PART},
    // swrRace_UpdateStatPartModels: inspected part hologram (camera + 6 right, 30 deep, 3.5 up),
    // shown beside the part shop buy panel.
    {0x004561db, swrRace_DrawPartShopScreen_ADDR, MODEL_ALWAYS},
    // swrRace_DrawUpgradesPanel (slot grid + stat table + one part model per slot at
    // camera + uiUpgradeInfos[i].vector1, 40 deep); the models follow the slot grid's cluster.
    {0x00455d80, swrRace_DrawUpgradesPanel_ADDR, MODEL_ALWAYS},
    // swrObjHang_PositionHoloNode: holo node at camera + (x + 18, 126 deep, y - 20); called by the
    // part shop, pit droid shop and results screens.
    {0x0045732e, 0, MODEL_ALWAYS},
    // DrawTrackPreview: course-select track hologram, a third of the way from the camera to the
    // holo target; no panel cluster, so it scales about the screen centre.
    {0x00456e43, 0x00456e43, MODEL_ALWAYS},
    {0x00457052, 0x00457052, MODEL_ALWAYS},
};

uintptr_t g_holo_owner = 0;

// Pulled-in depth as a multiple of the near plane: keeps the model's own front half (up to 3/4 of
// its centre depth) clear of the near clip.
constexpr float kNearPullMargin = 4.0f;

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

uintptr_t ui_model_owner_for(uintptr_t set_transform_site, const swrModel_NodeTransformed *node) {
    for (const ModelSite &s : kModelSites) {
        if (s.site != set_transform_site)
            continue;
        if (s.pick == MODEL_SELECTED_PART && !is_featured_part(node))
            return 0;
        return s.owner != 0 ? s.owner : g_holo_owner;
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

    float new_lateral = fov_scale * (lateral * ui_scale + shift_x * depth / f0);
    float new_up = fov_scale * (up * ui_scale - shift_y * depth / f0);
    float new_depth = depth;
    float size = ui_scale * fov_scale;

    // These are UI, but they sit 30-126 units out in the world and sink into nearby geometry (the
    // junkyard floor). Scaling position and size about the eye leaves the projected image identical,
    // so pull them in to just past the near plane, where the world can no longer cover them.
    const rdClipFrustum *frustum = rdCamera_pCurCamera->pClipFrustum;
    if (frustum != nullptr && frustum->zNear > 0.0f) {
        const float near_depth = frustum->zNear * imgui_state.near_clip_scale * kNearPullMargin;
        if (near_depth > 0.0f && depth > near_depth) {
            const float k = near_depth / depth;
            new_lateral *= k;
            new_up *= k;
            new_depth = near_depth;
            size *= k;
        }
    }

    m->vD.x = cam.vD.x + cam.vA.x * new_lateral + cam.vB.x * new_depth + cam.vC.x * new_up;
    m->vD.y = cam.vD.y + cam.vA.y * new_lateral + cam.vB.y * new_depth + cam.vC.y * new_up;
    m->vD.z = cam.vD.z + cam.vA.z * new_lateral + cam.vB.z * new_depth + cam.vC.z * new_up;

    rdVector4 *basis[3] = {&m->vA, &m->vB, &m->vC};
    for (rdVector4 *v : basis) {
        v->x *= size;
        v->y *= size;
        v->z *= size;
    }
}
