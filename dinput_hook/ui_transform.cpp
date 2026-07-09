#include "ui_transform.h"

#include "imgui_utils.h"

#include <globals.h>

int ui_menu_text_depth = 0;

/* Layer/group transform stack. The composed top is what the emit applies; an
 * empty stack reads as identity so menus (which push nothing) are unaffected.
 * Each slot already stores its composition with the slot below, so
 * ui_layer_current() is O(1). */
enum {
    UI_LAYER_STACK_MAX = 8,
};
static UiXform g_layer_stack[UI_LAYER_STACK_MAX];
static int g_layer_depth = 0;

UiXform ui_xform_identity(void) {
    UiXform x = {1.0f, 0.0f, 0.0f};
    return x;
}

UiXform ui_xform_compose(UiXform outer, UiXform inner) {
    /* outer(inner(p)) = outer.scale*(inner.scale*p + inner.t) + outer.t */
    UiXform r;
    r.scale = outer.scale * inner.scale;
    r.tx = outer.scale * inner.tx + outer.tx;
    r.ty = outer.scale * inner.ty + outer.ty;
    return r;
}

UiXform ui_xform_invert(UiXform x) {
    UiXform r;
    float s = (x.scale != 0.0f) ? x.scale : 1.0f;
    r.scale = 1.0f / s;
    r.tx = -x.tx / s;
    r.ty = -x.ty / s;
    return r;
}

UiVec2 ui_xform_apply(UiXform x, UiVec2 p) {
    UiVec2 r;
    r.x = x.scale * p.x + x.tx;
    r.y = x.scale * p.y + x.ty;
    return r;
}

float ui_layout_scale(void) {
    float s = (float) swrDisplay_screenHeight / UI_DESIGN_H;
    return s * imgui_state.ui_scale;
}

float ui_sprite_scale(void) {
    // The sprite/text draw space is the engine's own recip-defined space (~320x240), NOT the
    // 640x480 widget space. Its non-stretched axis is Y = screen_height * heightRecip; use that
    // uniformly so sprites/text reach full size and align with the widget/hit space (which is
    // ui_layout_scale, ~half of this). Derived from the recip, not a hardcoded design height.
    return (float) ((double) swrDisplay_screenHeight * swrUI_designHeightRecip) * imgui_state.ui_scale;
}

static float anchor_screen_x(UiAnchorH h) {
    switch (h) {
    case UI_H_CENTER:
        return (float) swrDisplay_screenWidth * 0.5f;
    case UI_H_RIGHT:
        return (float) swrDisplay_screenWidth;
    default:
        return 0.0f;
    }
}

static float anchor_screen_y(UiAnchorV v) {
    switch (v) {
    case UI_V_MIDDLE:
        return (float) swrDisplay_screenHeight * 0.5f;
    case UI_V_BOTTOM:
        return (float) swrDisplay_screenHeight;
    default:
        return 0.0f;
    }
}

static float anchor_design_x(UiAnchorH h) {
    switch (h) {
    case UI_H_CENTER:
        return UI_DESIGN_W * 0.5f;
    case UI_H_RIGHT:
        return UI_DESIGN_W;
    default:
        return 0.0f;
    }
}

static float anchor_design_y(UiAnchorV v) {
    switch (v) {
    case UI_V_MIDDLE:
        return UI_DESIGN_H * 0.5f;
    case UI_V_BOTTOM:
        return UI_DESIGN_H;
    default:
        return 0.0f;
    }
}

UiVec2 ui_anchor_point(UiAnchorH h, UiAnchorV v) {
    UiVec2 p = {anchor_screen_x(h), anchor_screen_y(v)};
    return p;
}

UiVec2 ui_design_to_screen(UiAnchorH h, UiAnchorV v, UiVec2 design) {
    float s = ui_layout_scale();
    UiVec2 r;
    r.x = anchor_screen_x(h) + s * (design.x - anchor_design_x(h));
    r.y = anchor_screen_y(v) + s * (design.y - anchor_design_y(v));
    return r;
}

UiVec2 ui_screen_to_design(UiAnchorH h, UiAnchorV v, UiVec2 screen) {
    float s = ui_layout_scale();
    if (s == 0.0f)
        s = 1.0f;
    UiVec2 r;
    r.x = anchor_design_x(h) + (screen.x - anchor_screen_x(h)) / s;
    r.y = anchor_design_y(v) + (screen.y - anchor_screen_y(v)) / s;
    return r;
}

float ui_center_offset_px(void) {
    if (!ui_enabled())
        return 0.0f;
    // Uniform-width UI box = UI_DESIGN_W * ui_layout_scale() (== sprite-design-width * ui_sprite_scale).
    // Half the leftover framebuffer width pillarboxes it. Goes negative (overflow both sides) only if
    // the ui_scale slider pushes the box wider than the window, which is still correctly centered.
    float ui_w = UI_DESIGN_W * ui_layout_scale();
    return ((float) swrDisplay_screenWidth - ui_w) * 0.5f;
}

float ui_anchor_element_dx(UiAnchorH h) {
    if (!ui_enabled() || h == UI_H_CENTER)
        return 0.0f;
    // The centering path already adds ui_center_offset_px() to this element's on-screen position; to
    // reach the real left edge subtract one center offset, to reach the real right edge add one.
    // Convert that framebuffer offset into the element's 640-space widget units (ui_layout_scale).
    float s = ui_layout_scale();
    if (s <= 0.0f)
        return 0.0f;
    float d = ui_center_offset_px() / s;
    return (h == UI_H_LEFT) ? -d : d;
}

UiVec2 ui_project_px_to_design(UiVec2 px) {
    UiVec2 r;
    if (ui_enabled() && swrDisplay_screenWidth > 0 && swrDisplay_screenHeight > 0) {
        // The draw applies ui_sprite_scale uniformly; divide by it so the round trip recovers the
        // original framebuffer pixel. ui_scale (the slider) is included, so projected elements stay
        // locked to the world/scene regardless of UI-scale rather than drifting with it.
        float s = ui_sprite_scale();
        if (s <= 0.0f)
            s = 1.0f;
        r.x = px.x / s;
        r.y = px.y / s;
        return r;
    }
    // Vanilla: design = pixel / (screenDim * recip). screenDim*recip is the draw's per-axis scale,
    // and 1/recip is the design dimension, so this equals the engine's own (pixel/screen)*design.
    float gx = (float) ((double) swrDisplay_screenWidth * swrUI_designWidthRecip);
    float gy = (float) ((double) swrDisplay_screenHeight * swrUI_designHeightRecip);
    if (gx == 0.0f)
        gx = 1.0f;
    if (gy == 0.0f)
        gy = 1.0f;
    r.x = px.x / gx;
    r.y = px.y / gy;
    return r;
}

void ui_layer_push(UiXform x) {
    if (g_layer_depth >= UI_LAYER_STACK_MAX)
        return;
    UiXform base = ui_layer_current();
    g_layer_stack[g_layer_depth] = ui_xform_compose(base, x);
    g_layer_depth++;
}

void ui_layer_pop(void) {
    if (g_layer_depth > 0)
        g_layer_depth--;
}

UiXform ui_layer_current(void) {
    if (g_layer_depth == 0)
        return ui_xform_identity();
    return g_layer_stack[g_layer_depth - 1];
}

int ui_enabled(void) {
    return imgui_state.ui_resolution_independent ? 1 : 0;
}
