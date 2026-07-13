#include <glad/glad.h>
#include <GLFW/glfw3.h>

#include "swrSprite_delta.h"

#include "../ui_transform.h"
#include "../hook_helper.h"

#include "../stb_image.h"

extern "C" {
#include <Swr/swrSprite.h>
#include <Swr/swrUI.h>
}

#include <globals.h>
#include <windows.h>

#include <cmath>
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

// UpdateSunAndLensFlareSprites2 gates the lens-flare chain -- and fades the sun glow -- on the sun's
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

// UpdateLightStreakSprites tilts each anamorphic light streak by angle = (pivotX - screenX) * scale,
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

// UpdateLightStreakSprites only spawns a streak when its light source is within
// swrPlayerHUD_lightStreakParam world units of the camera. The game uses 1500.0 on most tracks and
// already bumps this to 10000.0 for Ord Ibanna (swrObjJdge_InitTrack), where distant lights read as
// streaks. Push the reach further still -- ~3x that far value -- so streaks appear from far-off bright
// sources on every track. Forced every frame because the game re-asserts 1500.0 at race
// start/teardown; ui_patch_float no-ops once the value already matches. Writable .data; read only by
// UpdateLightStreakSprites.
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
    // Menu/HUD path (design-space coords): this sprite is NOT on the finer projected grid, so clear
    // its marker in case the id was previously used for a projected sprite.
    if (id >= 0 && id < 251)
        g_sprite_proj_fine[id] = 0;
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

    mat0->height = full_w;         // POT width  (X UV denominator)
    *(int *) mat0->unk = full_h;   // POT height (Y UV denominator)
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
