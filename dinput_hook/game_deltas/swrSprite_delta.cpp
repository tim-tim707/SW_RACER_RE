#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "swrSprite_delta.h"

#include "../ui_transform.h"
#include "../ui_hud.h"
#include "../ui_menu.h"
#include "../hook_helper.h"
#include "../camera/camera.h"// freecam_HudSpriteHidden
#include "../imgui_utils.h"   // imgui_initialized + imgui_state.cursor_use_game_sprite

#include "../stb_image.h"

extern "C" {
#include <Swr/swrSprite.h>
#include <Swr/swrUI.h>
}

#include <globals.h>
#include <windows.h>

#include <cctype>
#include <GLFW/glfw3.h>
#include <cmath>
#include <unordered_map>
#include <unordered_set>

// swrUI menu elements anchored to a screen edge (see ui_menu.h). applied_dx/dy is the design-space
// shift currently baked into the element (its x/y, child sprite slot offsets, and clip bbox); the render
// hook reconciles it to the live anchor shift every frame, since that shift follows the framebuffer
// size and the UI scale, which change with no menu relayout. match_id / match_class guard against a
// freed element address being reused by a different element.
struct AnchoredElement {
    MenuAnchor anchor;
    int applied_dx;
    int applied_dy;
    int match_id;
    int match_class;
};
static std::unordered_map<const void *, AnchoredElement> g_anchored_elements;

static bool anchored_element_valid(const void *ui, const AnchoredElement &e) {
    const swrUI_unk *el = (const swrUI_unk *) ui;
    return el->id == e.match_id && el->widget_class == e.match_class;
}

// swrUI_SetPos (0x00414b60). Moving x/y through it (rather than poking ui->x) is what cascades the
// shift into the element's child sprite SLOT offsets -- swrUI_RenderElementSprites emits each border
// sprite from its slot coords, so a raw ui->x poke moves the label but leaves the chrome behind. Call
// the trampoline (not the hooked name) so the SetPos hook does not re-add the shift.
typedef void (*swrUI_SetPos_t)(void *, int, int);

// Live design-space shift for an anchor, rounded to the element's integer coord space.
static int anchor_dx(const MenuAnchor &a) {
    return (int) lroundf(ui_anchor_element_dx(a.h));
}
static int anchor_dy(const MenuAnchor &a) {
    return (int) lroundf(ui_anchor_element_dy(a.v));
}

// Move a tagged element by (ddx, ddy): position + child sprites via the game's SetPos, then the clip
// bbox, which SetPos does not touch but HitTest and the label clip both read.
static void move_anchored_element(void *ui, int ddx, int ddy) {
    swrUI_unk *e = (swrUI_unk *) ui;
    hook_call_original((swrUI_SetPos_t) swrUI_SetPos_ADDR, ui, e->x + ddx, e->y + ddy);
    e->bbox.x += ddx;
    e->bbox.x2 += ddx;
    e->bbox.y += ddy;
    e->bbox.y2 += ddy;
}
#include <cstring>
#include <filesystem>
#include <vector>

extern "C" FILE *hook_log;

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
// Detouring the minimap draw to shift the dots corrupts the radar (swrSprite_RenderMiniMapDotsAndCrosses has a
// non-standard calling convention), so instead shift the anchor itself: the game then computes AND
// draws the dots at the shifted position through its own un-hooked path. Same .rdata VirtualProtect
// pattern as the text recip; the radar draws at ui_sprite_scale (the patched text recip), so the
// design shift is the px offset / that scale. Decreasing the anchor moves the radar right.
//
// The radar is RIGHT-anchored to the real screen edge. Vanilla it sits at the right of the 4:3 box; a
// plain centering shift (one ui_center_offset_px) would only keep it at the pillarboxed box's right.
// Shifting by TWO center offsets moves it the extra half-pillar out to the true right edge. Restore
// the original when disabled.
static float g_orig_minimap_anchor_x = 0.0f;
static int g_minimap_anchor_saved = 0;

static void ui_apply_radar_anchor(int enabled) {
    if (!g_minimap_anchor_saved) {
        g_orig_minimap_anchor_x = swrObjJdge_minimapAnchorX;
        g_minimap_anchor_saved = 1;
    }
    float target = g_orig_minimap_anchor_x;
    if (enabled) {
        float s = ui_sprite_scale();
        if (s > 0.0f)
            target = g_orig_minimap_anchor_x - 2.0f * ui_center_offset_px() / s;
    }
    if (swrObjJdge_minimapAnchorX != target) {
        DWORD old_protect;
        if (VirtualProtect(&swrObjJdge_minimapAnchorX, sizeof(float), PAGE_READWRITE, &old_protect)) {
            swrObjJdge_minimapAnchorX = target;
            VirtualProtect(&swrObjJdge_minimapAnchorX, sizeof(float), old_protect, &old_protect);
        }
    }
}

// swrSprite_UpdateSunAndLensFlareForSun gates the lens-flare chain -- and fades the sun glow -- on the sun's
// distance from screen center, measured in RAW FRAMEBUFFER PIXELS then scaled by
// lensFlare_screenCenterDistScale (vanilla 0.0125 == 1/80). The resulting radii (flare shows within
// <=160px, glow-fade within <=80px) were tuned for the 640x480 framebuffer. At higher resolutions the
// pixel distance grows but the constant does not, so the flare radius collapses to a tiny dead-center
// circle and the flares almost never appear (the sun sprite, drawn unconditionally, still does).
// Scale the constant by UI_DESIGN_H/screenHeight so both radii stay proportional to the framebuffer
// (no-op at 480p). Same .rdata VirtualProtect pattern as the text recip / radar anchor; the constant
// is read ONLY by that one function, so patching it has no other side effects. Applied unconditionally
// -- the bug is framebuffer-resolution driven, independent of the res-independent UI toggle -- and
// per-frame so it tracks live resolution changes (a resize costs one settle frame, imperceptible).
static float g_orig_flare_dist_scale = 0.0f;
static int g_flare_dist_scale_saved = 0;

static void ui_patch_float(float *addr, float target) {
    if (*addr == target)
        return;
    DWORD old_protect;
    if (VirtualProtect((void *) addr, sizeof(float), PAGE_READWRITE, &old_protect)) {
        *addr = target;
        VirtualProtect((void *) addr, sizeof(float), old_protect, &old_protect);
    }
}

static void ui_apply_flare_center_dist_scale(void) {
    if (!g_flare_dist_scale_saved) {
        g_orig_flare_dist_scale = lensFlare_screenCenterDistScale;
        g_flare_dist_scale_saved = 1;
    }
    if (swrDisplay_screenHeight <= 0)
        return;
    ui_patch_float(&lensFlare_screenCenterDistScale,
                   g_orig_flare_dist_scale * (UI_DESIGN_H / (float) swrDisplay_screenHeight));
}

// swrSprite_UpdateLightStreakSprites tilts each anamorphic light streak by angle = (pivotX - screenX) * scale,
// where screenX is the streak's projected position in RAW FRAMEBUFFER PIXELS but pivotX (160.0) and
// scale (0.33333) are tuned for a 640px-wide screen. At higher framebuffer widths the pixel span
// grows while the constants do not, so the angle is over-driven and the streaks tilt to extreme
// wrong directions. Rescale the pixel->angle mapping to the 640px reference: pivotX *= screenWidth/640
// (keeps angle==0 at the same fractional X) and scale /= screenWidth/640 (keeps the per-fraction slope
// constant). No-op at 640px wide. Both constants are read ONLY by that function, so patching them has
// no other side effects. Same per-frame, unconditional application as the flare radius above; the
// streak SIZE (100.0/depth clamped) is depth-based and drawn at ui_sprite_scale, so it needs no fix.
static float g_orig_streak_pivot_x = 0.0f;
static float g_orig_streak_rot_scale = 0.0f;
static int g_streak_rot_saved = 0;

static void ui_apply_light_streak_rotation(void) {
    if (!g_streak_rot_saved) {
        g_orig_streak_pivot_x = lightStreak_rotationPivotX;
        g_orig_streak_rot_scale = lightStreak_rotationScale;
        g_streak_rot_saved = 1;
    }
    if (swrDisplay_screenWidth <= 0)
        return;
    float w_ratio = (float) swrDisplay_screenWidth / UI_DESIGN_W;
    ui_patch_float(&lightStreak_rotationPivotX, g_orig_streak_pivot_x * w_ratio);
    ui_patch_float(&lightStreak_rotationScale, g_orig_streak_rot_scale / w_ratio);
}

// swrSprite_UpdateLightStreakSprites only spawns a streak when its light source is within
// swrPlayerHUD_lightStreakParam world units of the camera. The game uses 1500.0 on most tracks and
// already bumps this to 10000.0 for Ord Ibanna (swrObjJdge_InitTrack), where distant lights read as
// streaks. Push the reach further still -- ~3x that far value -- so streaks appear from far-off bright
// sources on every track. Forced every frame because the game re-asserts 1500.0 at race
// start/teardown; ui_patch_float no-ops once the value already matches. Writable .data; read only by
// swrSprite_UpdateLightStreakSprites.
static const float kLightStreakFarDistance = 30000.0f;

static void ui_apply_light_streak_distance(void) {
    ui_patch_float(&swrPlayerHUD_lightStreakParam, kLightStreakFarDistance);
}

// 0x0044f640
void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale) {
    ui_apply_flare_center_dist_scale();
    ui_apply_light_streak_rotation();
    ui_apply_light_streak_distance();
    ui_apply_text_recip(ui_enabled());
    ui_apply_radar_anchor(ui_enabled());
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

// Sprite positions are stored int16 in the engine's ~320x240 design grid (swrSprite.x/.y); at draw
// time swrSprite_Draw2 scales them up by ui_sprite_scale (~screenHeight/240), so at high resolutions
// the position can only land on a ~4-6px grid and the smoothly-moving projected sprites (sun, lens
// flares, light streaks) visibly stairstep. To recover sub-pixel precision WITHOUT touching the
// (carefully tuned) menu/HUD sprite path, sprites placed through the PROJECTED seam (this SetPosF) are
// stored on an N-times-finer design grid and drawn by swrSprite_Draw2_delta at scale/N. The size and
// streak-endpoint fields are temporarily scaled by N there too, so the geometry handed to
// swrSprite_Draw1 is identical to vanilla (the N cancels) -- only the int16 position quantization
// shrinks by 1/N (to well under a pixel). g_sprite_proj_fine[id] marks which sprites take this path;
// it is set here and cleared by swrSprite_SetPos_delta (the menu/HUD path). Active only when the
// resolution-independent transform is on; a no-op at 640x480 (scale == 2).
enum { UI_PROJ_POS_SUBDIV = 16 };
static int g_sprite_proj_fine[251];

static short ui_clamp_i16(float v) {
    long r = lroundf(v);
    if (r < -32768)
        r = -32768;
    if (r > 32767)
        r = 32767;
    return (short) r;
}

// 0x0042bb00
void swrSprite_SetPosF_delta(short id, short x, short y) {
    UiVec2 px = {(float) x, (float) y};
    UiVec2 design = ui_project_px_to_design(px);
    if (id >= 0 && id < 251) {
        if (ui_enabled()) {
            // Store on the finer design grid; swrSprite_Draw2_delta divides the draw scale back out.
            g_sprite_proj_fine[id] = 1;
            design.x *= (float) UI_PROJ_POS_SUBDIV;
            design.y *= (float) UI_PROJ_POS_SUBDIV;
        } else {
            g_sprite_proj_fine[id] = 0;
        }
    }
    // Call the ORIGINAL (trampoline), NOT swrSprite_SetPos by name -- that resolves to the hooked
    // EXE address and would (a) infinitely recurse and (b) apply the centering offset, which would
    // wrongly shift these projected/world sprites. The original keeps them world-locked.
    hook_call_original(swrSprite_SetPos, id, ui_clamp_i16(design.x), ui_clamp_i16(design.y));
}

// The 2D UI has TWO design spaces and sprites live in both, split by the DRAW CALLER (not the
// texture source): sprites emitted by the swrUI front-end element tree (menu chrome, backgrounds,
// buttons) are 640x480 and draw at ui_layout_scale (~2.869); sprites set by direct callers (in-race
// HUD, hangar pod/decorations) are 320x240 and draw at ui_sprite_scale (~5.738, 2x). The centering
// offset must divide by the matching scale or one group shifts 2x the other. We detect "element-
// tree sprite" by wrapping swrUI_RenderElementSprites and flagging the SetPos calls it makes.
typedef void (*swrUI_RenderElementSprites_t)(void *);
static int g_in_element_render = 0;

// 0x004151f0. Also the per-frame reconcile point for anchored elements: RenderTree calls this once per
// element every frame, so before emitting a tagged element's sprites we true up its baked shift to the
// live anchor shift, which follows the window size and UI scale with no menu relayout. The shift is 0
// in steady state, so the move only runs on the frames right after a resize or scale change. This is
// also where elements with no creation hook (the splash trademarks) are tagged, by element id.
void swrUI_RenderElementSprites_delta(void *ui) {
    swrUI_unk *e = (swrUI_unk *) ui;
    MenuAnchor id_anchor;
    if (!g_anchored_elements.contains(ui) && ui_menu_element_anchor(e->id, &id_anchor))
        g_anchored_elements[ui] = {id_anchor, 0, 0, e->id, e->widget_class};
    auto it = g_anchored_elements.find(ui);
    if (it != g_anchored_elements.end() && anchored_element_valid(ui, it->second)) {
        int dx = anchor_dx(it->second.anchor);
        int dy = anchor_dy(it->second.anchor);
        int ddx = dx - it->second.applied_dx;
        int ddy = dy - it->second.applied_dy;
        if (ddx != 0 || ddy != 0) {
            move_anchored_element(ui, ddx, ddy);
            it->second.applied_dx = dx;
            it->second.applied_dy = dy;
        }
    }
    g_in_element_render++;
    hook_call_original((swrUI_RenderElementSprites_t) swrUI_RenderElementSprites_ADDR, ui);
    g_in_element_render--;
}

// Anchoring a menu button MOVES the element's stored position, then lets the uniform 2D centering carry
// it the rest of the way, so every reader of the element -- its border sprites, its label (drawn from
// &ui->x by swrUI_ButtonProc), its label clip (&ui->bbox), swrUI_HitTest and swrUI_ElementContainsPoint
// -- agrees, with no per-sink special-casing and no click/visual desync.
typedef void *(*swrUI_NewButton_t)(void *, int, int, char *, int, int, int, int, int, int);
typedef void *(*swrUI_NewLabel_t)(void *, int, int, char *, int, int, int, int);

// Tag a freshly created element by the call site that created it and move it to its anchor; the
// SetPos hook keeps it there across relayout, the render hook across resizes.
static void *anchor_created_element(void *ui, uintptr_t site) {
    MenuAnchor anchor;
    if (ui == NULL || !ui_menu_create_anchor(site, &anchor))
        return ui;
    const swrUI_unk *e = (const swrUI_unk *) ui;
    int dx = anchor_dx(anchor);
    int dy = anchor_dy(anchor);
    g_anchored_elements[ui] = {anchor, dx, dy, e->id, e->widget_class};
    if (dx != 0 || dy != 0)
        move_anchored_element(ui, dx, dy);
    return ui;
}

// 0x004132a0 -- swrUI_NewButton.
void *swrUI_NewButton_delta(void *parent, int id, int font, char *text, int x, int y, int width,
                            int height, int flags, int param10) {
    uintptr_t site = UI_CALL_SITE();
    return anchor_created_element(hook_call_original((swrUI_NewButton_t) swrUI_NewButton_ADDR, parent,
                                                     id, font, text, x, y, width, height, flags,
                                                     param10),
                                  site);
}

// 0x004131c0 -- swrUI_NewLabel.
void *swrUI_NewLabel_delta(void *parent, int id, int font, char *text, int x, int y, int flags,
                           int param8) {
    uintptr_t site = UI_CALL_SITE();
    return anchor_created_element(hook_call_original((swrUI_NewLabel_t) swrUI_NewLabel_ADDR, parent,
                                                     id, font, text, x, y, flags, param8),
                                  site);
}

// 0x00414b60 -- swrUI_SetPos. Re-apply the shift currently baked into a tagged element (the same one
// its bbox carries) whenever the front-end relayout repositions it. Deliberately not the live shift:
// the render hook is the single place that advances position and bbox together, so a resize can never
// leave them disagreeing.
void swrUI_SetPos_delta(void *ui, int x, int y) {
    auto it = g_anchored_elements.find(ui);
    if (it != g_anchored_elements.end() && anchored_element_valid(ui, it->second)) {
        x += it->second.applied_dx;
        y += it->second.applied_dy;
    }
    hook_call_original((swrUI_SetPos_t) swrUI_SetPos_ADDR, ui, x, y);
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

// Menu/hangar images that get special res-independent handling, keyed by the loose TGA files they load
// from (swrObjHang_LoadScreenAssets calls swrSprite_GetTextureFromTGA("data\\images\\<name>", id)).
// Two groups:
//   - BACKDROPS: full-screen art (greyedsplash / podhangar_backdrop / podhangar_backdrop2 / splash).
//     Unlike every other 2D element they should COVER the window, so they are stretched to fill.
//   - LOGO parts: the top-left title logo (episode1 / star / wars / racer). These should hug the real
//     LEFT edge like the Back/Settings buttons instead of sitting in the centered 4:3 box; RACER slides
//     in from the true left edge. They keep their aspect (NOT stretched).
// swrSprite_GetTextureFromTGA_delta records each matched texture's id; a sprite is recognized at draw
// time by resolving its texture back to one of those ids. Matching by these specific files (not just
// "is a TGA") leaves the pilot portraits and everything else square-pixel and centered.
static const char *const g_backdrop_tga_names[] = {
    "greyedsplash.tga",
    "podhangar_backdrop.tga",
    "podhangar_backdrop2.tga",
    "splash.tga",
};
static const char *const g_logo_tga_names[] = {
    "episode1.tga",
    "star.tga",
    "wars.tga",
    "racer.tga",
};
static std::unordered_set<int> g_backdrop_tex_ids;
static std::unordered_set<int> g_logo_tex_ids;

// Case-insensitive match of a TGA path's basename against a name list.
static bool tga_basename_matches(const char *path, const char *const *names, size_t count) {
    if (path == NULL)
        return false;
    const char *base = path;
    for (const char *p = path; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    for (size_t n = 0; n < count; n++) {
        const char *a = base;
        const char *b = names[n];
        while (*a != '\0' && *b != '\0' &&
               tolower((unsigned char) *a) == tolower((unsigned char) *b)) {
            a++;
            b++;
        }
        if (*a == '\0' && *b == '\0')
            return true;
    }
    return false;
}

// 0x004114d0 -- swrSprite_GetTextureFromTGA. Tag the texture id of each backdrop/logo file as it loads
// (its texture pointer is stored against this id in swrSpriteTexItems) so the sprite sinks can recognize
// its sprites at draw time. Pure passthrough for every other texture.
typedef swrSpriteTexture *(*swrSprite_GetTextureFromTGA_t)(char *, int);
swrSpriteTexture *swrSprite_GetTextureFromTGA_delta(char *filename_tga, int id) {
    swrSpriteTexture *tex = hook_call_original(
        (swrSprite_GetTextureFromTGA_t) swrSprite_GetTextureFromTGA_ADDR, filename_tga, id);
    if (tex != NULL) {
        if (tga_basename_matches(filename_tga, g_backdrop_tga_names,
                                 sizeof(g_backdrop_tga_names) / sizeof(g_backdrop_tga_names[0])))
            g_backdrop_tex_ids.insert(id);
        else if (tga_basename_matches(filename_tga, g_logo_tga_names,
                                      sizeof(g_logo_tga_names) / sizeof(g_logo_tga_names[0])))
            g_logo_tex_ids.insert(id);
    }
    return tex;
}

// The texture-table id (swrSpriteTexItems[].id) backing a sprite slot, or -1 if none. Used to test a
// sprite against the tagged backdrop/logo id sets.
static int swrSprite_tex_id(short id) {
    if (id < 0 || id >= 251)
        return -1;
    const swrSpriteTexture *tex = swrSprite_array[id].texture;
    if (tex == NULL)
        return -1;
    for (int i = 0; i < 149; i++) {
        if (swrSpriteTexItems[i].texture == tex)
            return swrSpriteTexItems[i].id;
    }
    return -1;
}

static bool swrSprite_id_is_backdrop(short id) {
    return !g_backdrop_tex_ids.empty() && g_backdrop_tex_ids.count(swrSprite_tex_id(id)) != 0;
}

static bool swrSprite_id_is_logo(short id) {
    return !g_logo_tex_ids.empty() && g_logo_tex_ids.count(swrSprite_tex_id(id)) != 0;
}

// 0x004286f0 -- swrSprite_SetDim. width/height are scale MULTIPLIERS on the texture's natural size
// (not absolute design pixels), so we can't just set them to the framebuffer -- that blows the texture
// up hundreds of times into one big smear. Instead each axis is stretched by window / UI-box size, where
// the box is UI_DESIGN_W/H * ui_layout_scale(). That ratio folds in the UI-scale slider the same way
// the draw scale does, so it cancels out and the backdrop fills the window at any UI scale.
// Recomputed each call, so a resize refills.
// Everything else, and the res-independence-off path, passes through unchanged.
void swrSprite_SetDim_delta(short id, float width, float height) {
    if (ui_enabled()) {
        if (swrSprite_id_is_backdrop(id)) {
            float box_w = UI_DESIGN_W * ui_layout_scale();
            float box_h = UI_DESIGN_H * ui_layout_scale();
            if (box_w > 0.0f && swrDisplay_screenWidth > 0)
                width *= (float) swrDisplay_screenWidth / box_w;
            if (box_h > 0.0f && swrDisplay_screenHeight > 0)
                height *= (float) swrDisplay_screenHeight / box_h;
        } else {
            // In-race HUD elements whose width follows their cluster (header backing, connectors,
            // progress-ring rails), drawn at ui_sprite_scale.
            HudElement el = ui_hud_element_at(UI_CALL_SITE());
            if (el.span != HUD_SPAN_NONE)
                width = ui_hud_span_width(el.span, width, ui_sprite_scale());
        }
    }
    hook_call_original(swrSprite_SetDim, id, width, height);
}

// 0x00428660
void swrSprite_SetPos_delta(short id, short x, short y) {
    // Menu/HUD path (design-space coords): this sprite is NOT on the finer projected grid, so clear
    // its marker in case the id was previously used for a projected sprite.
    if (id >= 0 && id < 251)
        g_sprite_proj_fine[id] = 0;
    // Center the 2D UI: shift sprites by the centering offsets, dividing by the sprite's own
    // position scale -- 640-design (element-tree OR TGA) -> ui_layout_scale, else (direct/HUD/game,
    // 320-design) -> ui_sprite_scale. Uniform for every element; edge-anchored buttons ride this by
    // having their stored position moved (see swrUI_NewButton_delta), not by a special offset here.
    // Negative special ids (cursor) are left alone; projected sprites bypass this via
    // swrSprite_SetPosF_delta's trampoline call. ui_center_offset_px() is 0 when the toggle is off.
    if (id >= 0) {
        if (ui_enabled() && ui_hud_marker_mode >= 0 && id >= swrUISprite_pilotSprite_20 &&
            id <= swrUISprite_pilotSprite_40) {
            // Per-racer position marker (drawn only inside swrObjJdge_DrawRaceHUD): remap its X by the
            // live HUD mode -- right strip (mode 0) or full-width ring (mode 1) -- instead of centering.
            // The race HUD reuses the pilot-sprite slots from pilotSprite_20 up as one marker per racer,
            // so the 20 racers swrScores holds span pilotSprite_20..pilotSprite_40.
            x = (short) lroundf(ui_hud_marker_x((float) x, ui_hud_marker_mode));
            float s = ui_sprite_scale();
            if (s > 0.0f)
                y = (short) (y + lroundf(ui_center_offset_y_px() / s));
        } else if (ui_enabled() && swrSprite_id_is_backdrop(id)) {
            // Full-screen backdrop: pin the design origin to the true framebuffer origin (0,0 -> 0,0)
            // and let swrSprite_SetDim_delta stretch it across the window, instead of pillarboxing it.
            x = 0;
            y = 0;
        } else if (ui_enabled() && swrSprite_id_is_logo(id)) {
            // Title logo: left-anchor by SKIPPING the centering shift, so its design x maps straight to
            // the real left edge (like the Back/Settings buttons) instead of into the centered 4:3 box.
            // RACER's slide-in (animated x) then comes from the true left edge. Kept at its aspect (no
            // stretch); y skips the vertical centering too, so the logo hugs the top.
        } else {
            bool widget_space = g_in_element_render || swrSprite_id_is_tga(id);
            float s = widget_space ? ui_layout_scale() : ui_sprite_scale();
            if (s > 0.0f) {
                // Most sprites ride the plain centering offset into the pillarboxed box; sprites
                // placed by a UI cluster's code ride its group transform instead (see ui_hud.h).
                float off = ui_center_offset_px();
                float off_y = ui_center_offset_y_px();
                HudElement el = ui_hud_element_at(UI_CALL_SITE());
                if (el.cluster != HUD_CLUSTER_NONE) {
                    UiXform xf = ui_hud_cluster_xform(el.cluster);
                    off = xf.tx;
                    off_y = xf.ty;
                }
                x = (short) (x + lroundf(off / s));
                y = (short) (y + lroundf(off_y / s));
            }
        }
    }
    // Call the ORIGINAL via the trampoline; calling swrSprite_SetPos by name would re-enter this
    // same hook (the symbol resolves to the hooked EXE address) -> infinite recursion.
    hook_call_original(swrSprite_SetPos, id, x, y);
}

// --- Sprite art replacement (assets/replacement_sprites/<id>.{png,jpg,jpeg}) ----------------------
//
// Sprites (2D UI: character portraits, flags, banners) are NOT reachable through the model
// texture_buffer_replacement path: they load from the SPRITE_BLOCK via swrSprite_LoadTexture, keyed
// by the swrSprite_NAME enum, and are tiled into pages (each page a separate RdMaterial/GL texture,
// drawn as its own quad). We hook the load: if a replacement image exists for the sprite id, we
// collapse the whole sprite onto a single full-size page (see apply_sprite_replacement) so it draws
// crisp, at the image's native resolution, and with no inter-tile seam.

typedef swrSpriteTexture *(*swrSprite_LoadTexture_t)(int);

// swrSprite_LoadTexture treats sprite index 99 specially (swrModel_BuildTiledTextureMaterial rather
// than the per-tile path); it isn't a normal single-image sprite, so we never replace it.
static constexpr int kTiledTextureSpriteIndex = 99;

// swrModel_ConvertTextureDataToRdMaterial stows the material's UV scale factors (orig/POT, X then Y)
// as two floats inside RdMaterial::aName at these byte offsets; swrSprite_Draw samples with them.
static constexpr int kMaterialUvScaleXOffset = 10;
static constexpr int kMaterialUvScaleYOffset = 14;

// stb_image implementation is compiled in gltf_utils.cpp; here we only pull in the decl. stb decodes
// PNG and JPEG (and more) transparently, so we accept whichever of these files exists for the id.
static bool decode_sprite_image(int id, std::vector<unsigned char> &out, int &w, int &h) {
    static const char *const exts[] = {"png", "jpg", "jpeg"};
    char path[260];
    bool found = false;
    for (const char *ext: exts) {
        snprintf(path, sizeof(path), "./assets/replacement_sprites/%d.%s", id, ext);
        if (std::filesystem::exists(path)) {
            found = true;
            break;
        }
    }
    if (!found)
        return false;

    stbi_set_flip_vertically_on_load(false);
    int channels = 0;
    unsigned char *data = stbi_load(path, &w, &h, &channels, STBI_rgb_alpha);
    if (!data) {
        fprintf(hook_log, "[sprite_replacement] failed to decode %s: %s\n", path,
                stbi_failure_reason());
        fflush(hook_log);
        return false;
    }
    out.assign(data, data + (size_t) w * h * 4);
    stbi_image_free(data);
    return true;
}

static void apply_sprite_replacement(int index, swrSpriteTexture *tex) {
    if (!tex || index == kTiledTextureSpriteIndex)
        return;

    std::vector<unsigned char> img;
    int pw = 0, ph = 0;
    if (!decode_sprite_image(index, img, pw, ph))
        return;

    swrSpriteTextureHeader &hdr = tex->header;
    const int full_w = hdr.width;
    const int full_h = hdr.height;
    if (full_w <= 0 || full_h <= 0 || hdr.page_count <= 0 || !hdr.page_table)
        return;

    // Collapse the tiled sprite to ONE full-size page so it draws as a single quad -- no inter-tile
    // seam -- at the image's native resolution. Reuse page 0's material/GL texture: upload the whole
    // image (V-flipped to undo the engine's vertical sampling flip), then set every field the sprite
    // draw uses for a full-size page. The draw's UV is page.dim / material-POT-dim, where the POT dims
    // live in the material (height = POT width, unk = POT height) -- leaving POT height at the tile's
    // value is what stretched the earlier attempt. Set page dims, the material POT dims, ddsd and the
    // aName UV factors all to the full sprite size so UV == 1 spans the whole texture over one quad.
    swrSpriteTexturePage *pages = hdr.page_table;
    RdMaterial *mat0 = (RdMaterial *) (uintptr_t) pages[0].offset;
    if (!mat0 || !mat0->aTextures || mat0->aTextures->pD3DSrcTexture == nullptr)
        return;
    tSystemTexture *sys0 = mat0->aTextures;
    GLuint gl_tex = (GLuint) (uintptr_t) sys0->pD3DSrcTexture;

    std::vector<unsigned char> flipped((size_t) pw * ph * 4);
    for (int r = 0; r < ph; r++)
        memcpy(&flipped[(size_t) r * pw * 4], &img[(size_t) (ph - 1 - r) * pw * 4], (size_t) pw * 4);

    glBindTexture(GL_TEXTURE_2D, gl_tex);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA8, pw, ph, 0, GL_RGBA, GL_UNSIGNED_BYTE, flipped.data());
    glGenerateMipmap(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, 0);

    // POT size = the UV denominators
    mat0->width = full_w;
    mat0->height = full_h;
    *(float *) (mat0->aName + kMaterialUvScaleXOffset) = 1.0f;
    *(float *) (mat0->aName + kMaterialUvScaleYOffset) = 1.0f;
    sys0->ddsd.dwWidth = full_w;
    sys0->ddsd.dwHeight = full_h;
    pages[0].width = (unsigned short) full_w;
    pages[0].height = (unsigned short) full_h;
    hdr.page_count = 1;

    fprintf(hook_log, "[sprite_replacement] sprite %d replaced (%dx%d)\n", index, pw, ph);
    fflush(hook_log);
}

// 0x00446ca0
swrSpriteTexture *swrSprite_LoadTexture_delta(int index) {
    // Call the ORIGINAL by address (its src reimpl is a HANG stub, so calling by symbol would abort);
    // it builds the paged sprite texture, then we apply any replacement image for this sprite id.
    swrSpriteTexture *tex =
        hook_call_original((swrSprite_LoadTexture_t) swrSprite_LoadTexture_ADDR, index);
    apply_sprite_replacement(index, tex);
    return tex;
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

// 0x00428030 -- swrSprite_Draw2. Draws one array sprite: it scales the sprite's position corner
// (x,y), size (width,height) and streak second-endpoint (unk0x4,unk0x6) by the passed UI scale and
// hands them to swrSprite_Draw1. For sprites on the finer projected grid (g_sprite_proj_fine), draw
// with scale/N while temporarily scaling the size/endpoint fields by N: swrSprite_Draw1 receives
// geometry identical to vanilla (the N cancels), but the position now reflects the finer int16 grid
// stored by swrSprite_SetPosF_delta -- eliminating the high-res stairstepping. All others draw
// unchanged. width/height are float (exact); the int16 endpoints are clamped in case an off-screen
// streak endpoint would overflow (that sprite is culled anyway).
//
// swrSprite_Draw2 is a reimplemented function, so the bare symbol resolves to the DLL reimpl address
// (its dormant body); call the EXE original via the _ADDR so hook_call_original keys on THIS forward
// hook's trampoline (same idiom as swrUI_RenderElementSprites_delta). Using the symbol would run the
// unfaithful reimpl and drop every sprite.
typedef void (*swrSprite_Draw2_t)(swrSprite *, int, float, float);

void swrSprite_Draw2_delta(swrSprite *sprite, int pass_flags, float xscale, float yscale) {
    short id = (short) (sprite - swrSprite_array);
    if (freecam_HudSpriteHidden(id))
        return;// freecam Hide-HUD: drop every array sprite except the light streaks
    if (id >= 0 && id < 251 && g_sprite_proj_fine[id]) {
        const float n = (float) UI_PROJ_POS_SUBDIV;
        const float w = sprite->width, h = sprite->height;
        const short u4 = sprite->unk0x4, u6 = sprite->unk0x6;
        sprite->width = w * n;
        sprite->height = h * n;
        sprite->unk0x4 = ui_clamp_i16((float) u4 * n);
        sprite->unk0x6 = ui_clamp_i16((float) u6 * n);
        hook_call_original((swrSprite_Draw2_t) swrSprite_Draw2_ADDR, sprite, pass_flags, xscale / n,
                           yscale / n);
        sprite->width = w;
        sprite->height = h;
        sprite->unk0x4 = u4;
        sprite->unk0x6 = u6;
        return;
    }
    hook_call_original((swrSprite_Draw2_t) swrSprite_Draw2_ADDR, sprite, pass_flags, xscale, yscale);
}
