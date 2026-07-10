#include "swrSprite_delta.h"

#include "../ui_transform.h"
#include "../hook_helper.h"
#include "../imgui_utils.h" // imgui_initialized + imgui_state.cursor_use_game_sprite

extern "C" {
#include <Swr/swrSprite.h>
#include <Swr/swrUI.h>
}

#include <globals.h>
#include <windows.h>

#include <GLFW/glfw3.h>

#include <cmath>

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

// 0x004151f0
void swrUI_RenderElementSprites_delta(void *ui) {
    g_in_element_render++;
    hook_call_original((swrUI_RenderElementSprites_t) swrUI_RenderElementSprites_ADDR, ui);
    g_in_element_render--;
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
    // 320-design) -> ui_sprite_scale. Negative special ids (cursor) are left alone; projected sprites
    // bypass this via swrSprite_SetPosF_delta's trampoline call. The matching TEXT split lives in
    // swrText_CreateTextEntry1_delta. ui_center_offset_px() is 0 when the toggle is off.
    if (id >= 0) {
        bool widget_space = g_in_element_render || swrSprite_id_is_tga(id);
        float s = widget_space ? ui_layout_scale() : ui_sprite_scale();
        if (s > 0.0f)
            x = (short) (x + lroundf(ui_center_offset_px() / s));
    }
    // Call the ORIGINAL via the trampoline; calling swrSprite_SetPos by name would re-enter this
    // same hook (the symbol resolves to the hooked EXE address) -> infinite recursion.
    hook_call_original(swrSprite_SetPos, id, x, y);
}
// Cursor visibility (see imgui_state.cursor_use_game_sprite). Default is the OS pointer, so the
// game's own software cursor sprite (swrUISprite_d_cursor_rgb_0 = 249) must stay hidden: the vanilla
// swrSprite_DisplayCursor shows it whenever swrSprite_mouseVisible >= 1 and relies on
// swrUI_ProcessMouse re-hiding it (via stdConsole_GetCursorPos_delta) the same frame; on screens where
// ProcessMouse early-outs -- notably the post-race results screen -- that re-hide is skipped and the
// software cursor leaks on top of the OS cursor (issue #192), so we force it hidden here without
// touching swrSprite_mouseVisible (swrUI_ProcessMouse still runs its hit-testing). In game-cursor mode
// the OS pointer is hidden instead, so we draw the sprite (and fix up its position, see below). When
// OS-cursor management is absent (imgui not initialized, e.g. RENDERER_REPLACEMENT=OFF) the software
// cursor IS the real cursor, so fall back to the vanilla EXE routine via its trampoline.
typedef void (*swrSprite_DisplayCursor_t)(void);

void swrSprite_DisplayCursor_delta(void) {
    // No OS-cursor management (imgui not up, e.g. RENDERER_REPLACEMENT=OFF): the software cursor IS
    // the real cursor, so run the vanilla routine via its trampoline.
    if (!imgui_initialized) {
        hook_call_original((swrSprite_DisplayCursor_t) swrSprite_DisplayCursor_ADDR);
        return;
    }
    // Game-cursor mode: the OS pointer is hidden by update_os_cursor, so draw the software cursor
    // sprite. Let vanilla handle visibility + the sprite's dim/color/flags first. Vanilla positions
    // the sprite via stdConsole_GetCursorPos -> swrSprite_SetPos, but that path returns coords tuned
    // for menu HIT-TESTING (layout space with the UI-centering offset removed), NOT for drawing, so
    // the sprite lands off from the pointer. Reposition it at the true framebuffer pixel of the OS
    // pointer, converted into the sprite's own draw space and bypassing UI-centering via the SetPos
    // trampoline. The cursor sprite is a 640x480 widget-space sprite (draws at ui_layout_scale), so
    // invert that scale when the resolution-independent transform is on; when off, use the per-axis
    // vanilla stretch scale. Harmless when the sprite is hidden (vanilla already set it invisible).
    if (imgui_state.cursor_use_game_sprite) {
        hook_call_original((swrSprite_DisplayCursor_t) swrSprite_DisplayCursor_ADDR);
        GLFWwindow *window = glfwGetCurrentContext();
        int ww = 0;
        int wh = 0;
        glfwGetWindowSize(window, &ww, &wh);
        if (ww > 0 && wh > 0 && swrDisplay_screenWidth > 0 && swrDisplay_screenHeight > 0) {
            double cx = 0.0;
            double cy = 0.0;
            glfwGetCursorPos(window, &cx, &cy);
            UiVec2 px = {(float) cx * (float) swrDisplay_screenWidth / (float) ww,
                        (float) cy * (float) swrDisplay_screenHeight / (float) wh};
            UiVec2 d = ui_enabled() ? ui_screen_to_design(UI_H_LEFT, UI_V_TOP, px)
                                    : ui_project_px_to_design(px);
            hook_call_original(swrSprite_SetPos, (short) swrUISprite_d_cursor_rgb_0,
                               (short) lroundf(d.x), (short) lroundf(d.y));
        }
        return;
    }
    // OS-cursor mode (default): the OS pointer is the visible cursor, so keep sprite 249 hidden.
    swrSprite_SetVisible(swrUISprite_d_cursor_rgb_0, 0);
}
