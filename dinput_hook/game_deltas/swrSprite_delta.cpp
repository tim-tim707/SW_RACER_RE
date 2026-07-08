#include "swrSprite_delta.h"

#include "../ui_transform.h"
#include "../hook_helper.h"

extern "C" {
#include <Swr/swrSprite.h>
#include <Swr/swrUI.h>
}

#include <globals.h>
#include <windows.h>

#include <cmath>
#include <unordered_map>

// Buttons tagged for edge-anchoring (see the AddNavButton/AddOkButton/NewButton deltas below).
static std::unordered_map<const void *, UiAnchorH> g_anchored_buttons;
static UiAnchorH g_pending_button_anchor = UI_H_CENTER;
static int g_pending_button = 0;

// The text glyph scale lives in rdProcEntry_Add2DQuad2 as screen_dim * swrText_design{Width,Height}
// Recip (read-only .rdata doubles, one per axis). Menu TEXT therefore stretches independently of the
// sprite/frame scale. To make text un-stretch AND track the UI-scale slider, patch BOTH recips so
// each product equals ui_sprite_scale() (which already folds in ui_scale); restore the originals
// when disabled. Patching only X (the earlier approach) left the vertical scale stuck on vanilla, so
// the slider visibly changed text width but not height. Writing .rdata needs VirtualProtect (a raw
// write crashes).
static double g_orig_text_recipX = 0.0;
static double g_orig_text_recipY = 0.0;
static int g_text_recip_saved = 0;

static void ui_patch_recip(double *recip, double target) {
    if (*recip == target)
        return;
    DWORD old_protect;
    if (VirtualProtect((void *) recip, sizeof(double), PAGE_READWRITE, &old_protect)) {
        *recip = target;
        VirtualProtect((void *) recip, sizeof(double), old_protect, &old_protect);
    }
}

static void ui_apply_text_recip(int enabled) {
    if (!g_text_recip_saved) {
        g_orig_text_recipX = swrText_designWidthRecip;
        g_orig_text_recipY = swrText_designHeightRecip;
        g_text_recip_saved = 1;
    }
    double targetX = g_orig_text_recipX;
    double targetY = g_orig_text_recipY;
    if (enabled && swrDisplay_screenWidth > 0 && swrDisplay_screenHeight > 0) {
        // Both axes draw at the uniform ui_sprite_scale, so text reaches full size, stays square,
        // and scales with the ui_scale slider on both axes.
        targetX = (double) ui_sprite_scale() / (double) swrDisplay_screenWidth;
        targetY = (double) ui_sprite_scale() / (double) swrDisplay_screenHeight;
    }
    ui_patch_recip(&swrText_designWidthRecip, targetX);
    ui_patch_recip(&swrText_designHeightRecip, targetY);
}

// The in-race minimap radar is positioned around a design-space anchor constant (swrObjJdge_minimapAnchorX),
// read ONLY by swrObjJdge_DrawRaceHUD (screen X = racerRelX - anchor, so the radar centers at -anchor).
// Detouring the minimap draw to shift the dots corrupts the radar (RenderMiniMapDotsAndCrosses has a
// non-standard calling convention), so instead shift the anchor itself: the game then computes AND
// draws the dots at the centered position through its own un-hooked path. Same .rdata VirtualProtect
// pattern as the text recip; the radar draws at ui_sprite_scale (the patched text recip), so the
// design shift is the px offset / that scale. Decreasing the anchor moves the radar right (center =
// -anchor). Restore the original when disabled.
static float g_orig_minimap_anchor_x = 0.0f;
static int g_minimap_anchor_saved = 0;

static void ui_apply_radar_center(int enabled) {
    if (!g_minimap_anchor_saved) {
        g_orig_minimap_anchor_x = swrObjJdge_minimapAnchorX;
        g_minimap_anchor_saved = 1;
    }
    float target = g_orig_minimap_anchor_x;
    if (enabled) {
        float s = ui_sprite_scale();
        if (s > 0.0f)
            target = g_orig_minimap_anchor_x - ui_center_offset_px() / s;
    }
    if (swrObjJdge_minimapAnchorX != target) {
        DWORD old_protect;
        if (VirtualProtect(&swrObjJdge_minimapAnchorX, sizeof(float), PAGE_READWRITE, &old_protect)) {
            swrObjJdge_minimapAnchorX = target;
            VirtualProtect(&swrObjJdge_minimapAnchorX, sizeof(float), old_protect, &old_protect);
        }
    }
}

// 0x0044f640
void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale) {
    ui_apply_text_recip(ui_enabled());
    ui_apply_radar_center(ui_enabled());
    if (!ui_enabled()) {
        // Vanilla: X and Y scale independently to fill the framebuffer (the 4:3 stretch).
        *out_xscale = (float) ((double) swrDisplay_screenWidth * swrUI_designWidthRecip);
        *out_yscale = (float) ((double) swrDisplay_screenHeight * swrUI_designHeightRecip);
        return;
    }
    // Uniform sprite draw scale (the engine's own recip-defined space, ~2x the widget/cursor
    // scale). Pairs with the text recip patch above and the cursor remap in stdConsole_delta.
    float s = ui_sprite_scale();
    *out_xscale = s;
    *out_yscale = s;
}

// 0x0042bb00
void swrSprite_SetPosF_delta(short id, short x, short y) {
    UiVec2 px = {(float) x, (float) y};
    UiVec2 design = ui_project_px_to_design(px);
    // Call the ORIGINAL (trampoline), NOT swrSprite_SetPos by name -- that resolves to the hooked
    // EXE address and would (a) infinitely recurse and (b) apply the centering offset, which would
    // wrongly shift these projected/world sprites. The original keeps them world-locked.
    hook_call_original(swrSprite_SetPos, id, (short) lroundf(design.x), (short) lroundf(design.y));
}

// The 2D UI has TWO design spaces and sprites live in both, split by the DRAW CALLER (not the
// texture source): sprites emitted by the swrUI front-end element tree (menu chrome, backgrounds,
// buttons) are 640x480 and draw at ui_layout_scale (~2.869); sprites set by direct callers (in-race
// HUD, hangar pod/decorations) are 320x240 and draw at ui_sprite_scale (~5.738, 2x). The centering
// offset must divide by the matching scale or one group shifts 2x the other. We detect "element-
// tree sprite" by wrapping swrUI_RenderElementSprites and flagging the SetPos calls it makes.
typedef void (*swrUI_RenderElementSprites_t)(void *);
static int g_in_element_render = 0;

// 0x004151f0. Also publishes the current element's edge anchor for the sprite + label sinks. swrUI_
// RenderTree draws each element as RenderElementSprites(e) then RunCallbacks(e, 9) (the label), so
// setting ui_active_anchor here (and leaving it set) covers BOTH this element's sprites and its
// immediately-following label; the next element overwrites it. Untagged elements reset it to
// UI_H_CENTER, so only tagged buttons deviate from plain centering.
void swrUI_RenderElementSprites_delta(void *ui) {
    auto it = g_anchored_buttons.find(ui);
    ui_active_anchor = (it != g_anchored_buttons.end()) ? it->second : UI_H_CENTER;
    g_in_element_render++;
    hook_call_original((swrUI_RenderElementSprites_t) swrUI_RenderElementSprites_ADDR, ui);
    g_in_element_render--;
}

// Edge-anchoring the standard menu Back/Cancel/Quit, OK and Settings buttons keeps their stored
// element position UNCHANGED (in the 0..639 range the layout expects) and instead shifts them to the
// screen edge at the DRAW sinks: swrUI_RenderElementSprites_delta publishes each element's anchor via
// ui_active_anchor, and the sprite sink (swrSprite_SetPos_delta) + the menu-text sink
// (swrText_CreateTextEntry1_delta) offset by ui_anchor_offset_px() instead of the plain centering
// offset. The one thing that also needs the shift is the click test: swrUI_HitTest clamps the
// hit-rect to the element's bbox, so a moved rect would clip; swrUI_HitTest_delta therefore shifts
// each tagged button's rect AND bbox transiently for the duration of the test only. Moving the
// stored coords directly instead (an earlier approach) pushed them out of [0,639] and the bbox clip
// clamped both the click area and the label -- hence the sink approach. AddNavButton/AddOkButton flag
// which button swrUI_NewButton is about to create; the Settings button (built directly with element
// id 0xf, unique to it) is recognized in NewButton. All shifts are 0 when res-independence is off.
// (g_anchored_buttons / g_pending_button* are declared near the top of this file.)
typedef void (*swrUI_AddNavButton_t)(void *, int, int, int, int);
typedef void (*swrUI_AddOkButton_t)(void *, int, int);
typedef void *(*swrUI_NewButton_t)(void *, int, int, char *, int, int, int, int, int, int);
typedef swrUI_unk *(*swrUI_HitTest_t)(swrUI_unk *, int, int);

// 0x00411170 -- Back/Cancel/Quit. Mark the button swrUI_NewButton is about to create for the left
// edge. Prototype-only in the header (native callers), so call the original through an _ADDR cast.
void swrUI_AddNavButton_delta(void *page, int id, int x, int y, int kind) {
    g_pending_button = 1;
    g_pending_button_anchor = UI_H_LEFT;
    hook_call_original((swrUI_AddNavButton_t) swrUI_AddNavButton_ADDR, page, id, x, y, kind);
    g_pending_button = 0;
}

// 0x00411210 -- OK. Mark it for the right edge.
void swrUI_AddOkButton_delta(void *page, int x, int y) {
    g_pending_button = 1;
    g_pending_button_anchor = UI_H_RIGHT;
    hook_call_original((swrUI_AddOkButton_t) swrUI_AddOkButton_ADDR, page, x, y);
    g_pending_button = 0;
}

// The main-menu / aux-page "Settings" button is built directly by swrUI_BuildMenuPages via
// swrUI_NewButton with element id 0xf (used for nothing else), not by the AddNavButton/AddOkButton
// helpers, so tag it here so it edge-anchors to the left like the Back button.
enum {
    swrUI_ELEMENT_ID_SETTINGS_BUTTON = 0xf,
};

// 0x004132a0 -- swrUI_NewButton. Tag the element created for a Back/OK button (pending from the
// AddNav/AddOk helpers) or the Settings button (id 0xf) so the render/hit-test hooks anchor it.
void *swrUI_NewButton_delta(void *parent, int id, int font, char *text, int x, int y, int width,
                            int height, int flags, int param10) {
    void *ui = hook_call_original((swrUI_NewButton_t) swrUI_NewButton_ADDR, parent, id, font, text,
                                  x, y, width, height, flags, param10);
    if (ui != NULL) {
        if (g_pending_button)
            g_anchored_buttons[ui] = g_pending_button_anchor;
        else if (id == swrUI_ELEMENT_ID_SETTINGS_BUTTON)
            g_anchored_buttons[ui] = UI_H_LEFT;
    }
    return ui;
}

// 0x004150e0 -- swrUI_HitTest. The element's stored rect stays centered (so its label is not clipped
// by the bbox), but its sprites/label draw at the edge, so the click test needs the rect at the edge
// too. Shift each tagged button's rect AND its clip bbox by the anchor delta for the duration of the
// original test, then restore -- swrSprite_BBoxFit would otherwise clamp the shifted rect back to the
// centered bbox. Menu elements persist for the session (built once by swrUI_BuildMenuPages), so the
// tag map holds live pointers; the widget_class guard skips anything that is not a button.
void *swrUI_HitTest_delta(void *root, int cursor_x, int cursor_y) {
    for (auto &kv: g_anchored_buttons) {
        swrUI_unk *e = (swrUI_unk *) kv.first;
        if (e->widget_class != 2)
            continue;
        int dx = (int) lroundf(ui_anchor_element_dx(kv.second));
        e->x += dx;
        e->width += dx;
        e->bbox.x += dx;
        e->bbox.x2 += dx;
    }
    swrUI_unk *hit =
        hook_call_original((swrUI_HitTest_t) swrUI_HitTest_ADDR, (swrUI_unk *) root, cursor_x, cursor_y);
    for (auto &kv: g_anchored_buttons) {
        swrUI_unk *e = (swrUI_unk *) kv.first;
        if (e->widget_class != 2)
            continue;
        int dx = (int) lroundf(ui_anchor_element_dx(kv.second));
        e->x -= dx;
        e->width -= dx;
        e->bbox.x -= dx;
        e->bbox.x2 -= dx;
    }
    return hit;
}

// A sprite is in the 640-design widget space (ui_layout_scale) if EITHER it is emitted by the swrUI
// element tree (buttons, menu chrome -- caught by g_in_element_render) OR it is a loose-TGA/HD
// sprite (menu backgrounds + logos, which are set by direct callers but authored at 640). Everything
// else (out_spriteblock HUD + hangar in-game sprites, set by direct callers at 320) uses the
// ui_sprite_scale space. Resolve the sprite's texture pointer back to swrSpriteTexIsTGA.
static int swrSpriteTex_is_tga(const swrSpriteTexture *tex) {
    if (tex == NULL)
        return 0;
    for (int i = 0; i < 149; i++) {
        if (swrSpriteTexItems[i].texture == tex)
            return swrSpriteTexIsTGA[i];
    }
    return 0;
}

static int swrSprite_id_is_tga(short id) {
    if (id < 0 || id >= 251)
        return 0;
    return swrSpriteTex_is_tga(swrSprite_array[id].texture);
}

// 0x00428660
void swrSprite_SetPos_delta(short id, short x, short y) {
    // Center the 2D UI: shift sprites right by the centering offset, dividing by the sprite's own
    // position scale -- 640-design (element-tree OR TGA) -> ui_layout_scale, else (direct/HUD/game,
    // 320-design) -> ui_sprite_scale. Element-tree sprites use the per-element edge anchor
    // (ui_active_anchor, published by swrUI_RenderElementSprites_delta) instead of plain centering, so
    // a tagged Back/OK/Settings button's chrome shifts to its screen edge; UI_H_CENTER (the default
    // for every other element) equals the plain centering offset, so nothing else changes. Direct/HUD
    // and TGA-background sprites stay plain-centered. Negative special ids (cursor) are left alone;
    // projected sprites bypass this via swrSprite_SetPosF_delta's trampoline call. ui_anchor_offset_px
    // / ui_center_offset_px are 0 when the toggle is off.
    if (id >= 0) {
        bool widget_space = g_in_element_render || swrSprite_id_is_tga(id);
        float s = widget_space ? ui_layout_scale() : ui_sprite_scale();
        float off = g_in_element_render ? ui_anchor_offset_px(ui_active_anchor) : ui_center_offset_px();
        if (s > 0.0f)
            x = (short) (x + lroundf(off / s));
    }
    // Call the ORIGINAL via the trampoline; calling swrSprite_SetPos by name would re-enter this
    // same hook (the symbol resolves to the hooked EXE address) -> infinite recursion.
    hook_call_original(swrSprite_SetPos, id, x, y);
}
