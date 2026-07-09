#include "swrSprite_delta.h"

#include "../ui_transform.h"
#include "../hook_helper.h"

extern "C" {
#include <Swr/swrSprite.h>
#include <Swr/swrUI.h>
}

#include <globals.h>
#include <windows.h>

#include <cctype>
#include <cmath>
#include <unordered_map>
#include <unordered_set>

// swrUI elements edge-anchored to a real screen edge: the standard Back/Cancel/Quit + Settings + OK
// buttons (tagged at creation, see the AddNavButton/AddOkButton/NewButton deltas), and the splash
// title-logo trademark text elements (tagged lazily by element id in the render hook). applied_dx is
// the design-space shift currently baked into the element (its x, its child sprite slot offsets, and
// its bbox); the render hook reconciles it to the live ui_anchor_element_dx() every frame so it tracks
// a window resize (the shift depends on the framebuffer width, which changes with no menu relayout).
// match_id identifies which kind, so a reused element address is never mis-shifted: -1 means a button
// (validated by widget_class == 2), otherwise the entry only applies while the element keeps that id.
enum {
    swrUI_ELEMENT_ID_SPLASH_TM_STARWARS = 0x272a,// STAR WARS trademark, animates with the STAR/WARS art
    swrUI_ELEMENT_ID_SPLASH_TM_RACER = 0x272b,   // RACER trademark, animates in with the RACER slide-in
};
struct AnchoredElement {
    UiAnchorH anchor;
    int applied_dx;
    int match_id;
};
static std::unordered_map<const void *, AnchoredElement> g_anchored_elements;
static UiAnchorH g_pending_button_anchor = UI_H_CENTER;
static int g_pending_button = 0;

// An anchor entry still applies to this element only if its identity matches, so a freed address reused
// by a different element is skipped. Buttons (match_id < 0) are validated by their widget class; the
// id-tagged logo trademarks by their element id.
static bool anchored_element_valid(const void *ui, const AnchoredElement &e) {
    const swrUI_unk *el = (const swrUI_unk *) ui;
    return (e.match_id < 0) ? (el->widget_class == 2) : (el->id == e.match_id);
}

// swrUI_SetPos (0x00414b60). Moving x through it (rather than poking ui->x) is what cascades the shift
// into the element's child sprite SLOT offsets -- swrUI_RenderElementSprites emits each normal border
// sprite from its slot coords, not from ui->x, so a raw ui->x poke moves the label but leaves the
// chrome behind. Call the trampoline (not the hooked name) so the SetPos hook does not re-add the shift.
typedef void (*swrUI_SetPos_t)(void *, int, int);

// Live design-space edge shift for an anchor, rounded to the element's integer coord space. 0 when
// res-independence is off or the anchor is centered.
static int anchor_dx(UiAnchorH h) {
    return (int) lroundf(ui_anchor_element_dx(h));
}

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

// 0x0044f640
void swrSprite_GetUIScale_delta(float *out_xscale, float *out_yscale) {
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

// 0x004151f0. Also the per-frame reconcile point for edge-anchored elements: RenderTree calls this once
// per element every frame, so before emitting a tagged element's sprites we true up its baked shift to
// the live ui_anchor_element_dx() (which follows the framebuffer width). A window resize changes that
// width without triggering a menu relayout, so without this the element would stay at its last-baked
// edge until the next swrUI_SetPos. The reconcile goes THROUGH swrUI_SetPos (not a raw ui->x poke) so
// the delta cascades into the child sprite slot offsets that RenderElementSprites draws the chrome
// from -- otherwise the border sprites lag the label until a hover forces a relayout. The bbox is not
// touched by SetPos, so shift it here too; x, chrome, label, and hit-rect then all move together.
// delta is 0 in steady state, so SetPos runs only on the frames right after a resize/toggle. This is
// also where the splash title-logo trademark elements are tagged (lazily, by id): they have no creation
// hook of their own, but RenderTree reaches them here every frame, and moving their x left-anchors both
// the element and its text (the label reads ui->x, and the text sink's centering cancels the shift).
void swrUI_RenderElementSprites_delta(void *ui) {
    swrUI_unk *e = (swrUI_unk *) ui;
    if (!g_anchored_elements.contains(ui) &&
        (e->id == swrUI_ELEMENT_ID_SPLASH_TM_STARWARS || e->id == swrUI_ELEMENT_ID_SPLASH_TM_RACER))
        g_anchored_elements[ui] = {UI_H_LEFT, 0, e->id};
    auto it = g_anchored_elements.find(ui);
    if (it != g_anchored_elements.end() && anchored_element_valid(ui, it->second)) {
        int dx = anchor_dx(it->second.anchor);
        int delta = dx - it->second.applied_dx;
        if (delta != 0) {
            hook_call_original((swrUI_SetPos_t) swrUI_SetPos_ADDR, ui, e->x + delta, e->y);
            e->bbox.x += delta;
            e->bbox.x2 += delta;
            it->second.applied_dx = dx;
        }
    }
    g_in_element_render++;
    hook_call_original((swrUI_RenderElementSprites_t) swrUI_RenderElementSprites_ADDR, ui);
    g_in_element_render--;
}

// Edge-anchoring the standard menu Back/Cancel/Quit, OK and Settings buttons MOVES the element's
// stored position to the screen edge and lets the existing uniform 2D centering carry it the rest of
// the way. Every reader of the element -- its border sprites (baked from ui->x), its label (drawn
// from the &ui->x bbox by swrUI_ButtonProc), its label clip (&ui->bbox), swrUI_HitTest and
// swrUI_ElementContainsPoint (both test ui->x) -- then agrees, so there is no per-sink special-casing
// and no click/visual desync. The move is expressed as a design-space delta ui_anchor_element_dx():
// after the uniform centering offset the element lands flush against its edge (a LEFT button whose
// natural x is 0 ends at the real left; OK ends at the real right). That delta depends on the
// framebuffer width, so it is kept LIVE (a window resize changes the edge with no menu relayout):
//   - x (and the element's child sprite offsets): moved via the game's own swrUI_SetPos. Re-applied
//     by swrUI_SetPos_delta on every reposition (the front-end relayout rewrites ui->x, so a one-time
//     move would snap back), and advanced to the live delta by swrUI_RenderElementSprites_delta.
//   - the clip bbox (ui->bbox): shifted alongside x. swrUI_HitTest clamps the hit-rect to it and
//     swrUI_ButtonProc clips the label to it, so it must move with the element or the click area and
//     the label get clamped back to centre. swrUI_SetPos does not touch it, so the render hook is the
//     single place that advances BOTH x and bbox together -- they can never drift apart on a resize.
// AddNavButton/AddOkButton flag which button swrUI_NewButton is about to create; the Settings button
// (built directly with element id 0xf, unique to it) is recognized in NewButton. All deltas are 0
// when res-independence is off. (g_anchored_elements / g_pending_button* are declared near the top.)
typedef void (*swrUI_AddNavButton_t)(void *, int, int, int, int);
typedef void (*swrUI_AddOkButton_t)(void *, int, int);
typedef void *(*swrUI_NewButton_t)(void *, int, int, char *, int, int, int, int, int, int);
// swrUI_SetPos_t is declared near the top (the render hook uses it too).

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

// 0x004132a0 -- swrUI_NewButton. Tag the created element and move it (position via the game's SetPos,
// clip bbox directly) to its edge; the swrUI_SetPos hook then keeps the position there across relayout.
void *swrUI_NewButton_delta(void *parent, int id, int font, char *text, int x, int y, int width,
                            int height, int flags, int param10) {
    void *ui = hook_call_original((swrUI_NewButton_t) swrUI_NewButton_ADDR, parent, id, font, text,
                                  x, y, width, height, flags, param10);
    if (ui == NULL)
        return ui;
    int anchored = 1;
    UiAnchorH anchor = UI_H_CENTER;
    if (g_pending_button)
        anchor = g_pending_button_anchor;
    else if (id == swrUI_ELEMENT_ID_SETTINGS_BUTTON)
        anchor = UI_H_LEFT;
    else
        anchored = 0;
    if (anchored) {
        int dx = anchor_dx(anchor);
        g_anchored_elements[ui] = {anchor, dx, -1};
        if (dx != 0) {
            swrUI_unk *e = (swrUI_unk *) ui;
            // Move x/width + child sprite offsets through the game's SetPos (the trampoline, not the
            // hook -- the shift is added explicitly here), then shift the clip bbox to match. The
            // render hook keeps dx live from here on (a resize re-shifts by the delta).
            hook_call_original((swrUI_SetPos_t) swrUI_SetPos_ADDR, ui, e->x + dx, e->y);
            e->bbox.x += dx;
            e->bbox.x2 += dx;
        }
    }
    return ui;
}

// 0x00414b60 -- swrUI_SetPos. Re-apply the CURRENTLY baked shift (applied_dx -- the same shift the
// bbox carries) whenever the front-end relayout repositions a tagged element, so its x stays at the
// edge (the initial move in NewButton would otherwise be overwritten) AND stays consistent with the
// bbox. Deliberately NOT the live shift: the render hook is the single place that advances both x and
// bbox to the live value, so a resize can never leave x and bbox disagreeing. Every other element
// passes through unchanged; anchored_element_valid skips a freed address reused by a different element.
void swrUI_SetPos_delta(void *ui, int x, int y) {
    auto it = g_anchored_elements.find(ui);
    if (it != g_anchored_elements.end() && anchored_element_valid(ui, it->second))
        x += it->second.applied_dx;
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

// In-race HUD sprites (direct 320-design swrSprite_SetPos callers) that anchor to a real screen edge
// instead of riding the plain centering into the pillarboxed 4:3 box. Keyed by swrSprite_array id.
// UI_H_RIGHT shifts by two centering offsets (out to the true right edge), UI_H_LEFT by zero (hug the
// true left); everything not listed stays plain-centered. Grows as the in-race HUD clusters are
// anchored (minimap / speedometer / lap+pos header / engine readout).
static UiAnchorH hud_sprite_anchor(short id) {
    // Engine damage readout (swrRace_InRaceEngineUI), bottom-LEFT cluster: 6 damage modules + 2 cooling
    // caps per player -- 0x1b-0x22 (player 1), 0x23-0x2a (player 2). Left-anchored so it hugs the real
    // left edge; the temp/warning text rides along via hud_text_anchor.
    if (id >= 0x1b && id <= 0x2a)
        return UI_H_LEFT;
    switch (id) {
    case 0x19:
        // Minimap radar gradient backing (swrObjJdge_LayoutHudFrameSprites). The radar dots are
        // right-anchored via swrObjJdge_minimapAnchorX (ui_apply_radar_anchor), so its backing must
        // move out to the same real right edge or it detaches from the dots.
        return UI_H_RIGHT;
    // Speedometer dial cluster (swrObjJdge_DrawSpeedDialHud): dial background / needle / boost lamps,
    // positioned as a unit relative to a base. 0xf-0x12 are player 1, 0x13-0x16 player 2 (splitscreen).
    // Right-anchored so the dial hugs the real right edge (each split viewport is full width, so both
    // players' dials anchor right within their own viewport).
    case 0xf:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x15:
    case 0x16:
        return UI_H_RIGHT;
    // Speedometer readout frame (swrObjJdge_LayoutHudFrameSprites, bottom): the left cap (3), the
    // stretchable inner surface the digital speed sits on (2), and the right cap (0xa). Right-anchored
    // to travel with the dial.
    case 2:
    case 3:
    case 0xa:
        return UI_H_RIGHT;
    // Header bar (swrObjJdge_LayoutHudFrameSprites, top). Lap holder (0) and its lap->time connector
    // (0xb) hug the LEFT; the full-width backing -- top rule (5) + blue gradient (0xd) -- pins to x=0
    // (LEFT) and is stretched to the window width in SetDim. The position holder (1) goes RIGHT. The
    // time holder (4) and the time->pos connector (0xc) stay centered. The connectors also lengthen a
    // little in SetDim to reach across the widened gap. Lap/position TEXT rides along via hud_text_anchor.
    case 0:
    case 5:
    case 0xb:
    case 0xd:
        return UI_H_LEFT;
    case 1:
        return UI_H_RIGHT;
    default:
        return UI_H_CENTER;
    }
}

// 0x004286f0 -- swrSprite_SetDim. width/height are scale MULTIPLIERS on the texture's natural size
// (not absolute design pixels), so we can't just set them to the framebuffer -- that blows the texture
// up hundreds of times into one big smear. A backdrop already fills the height (it was only pillarboxed
// on the sides), so we leave height alone and stretch the WIDTH by the pillarbox ratio
// screenWidth / boxWidth, where boxWidth = UI_DESIGN_W * ui_layout_scale() is the width the centered
// 4:3 box currently occupies. That turns the 4:3 box into a full-width fill. The ratio tracks
// ui_layout_scale (which folds in the UI-scale slider) the same way the draw scale does, so it cancels
// out and the backdrop fills the window at any UI scale. Recomputed each call, so a resize refills.
// Everything else, and the res-independence-off path, passes through unchanged.
void swrSprite_SetDim_delta(short id, float width, float height) {
    if (ui_enabled()) {
        if (swrSprite_id_is_backdrop(id)) {
            float box_w = UI_DESIGN_W * ui_layout_scale();
            if (box_w > 0.0f && swrDisplay_screenWidth > 0)
                width *= (float) swrDisplay_screenWidth / box_w;
        } else {
            // Header bar backing (swrObjJdge_LayoutHudFrameSprites), drawn at ui_sprite_scale: the top
            // rule (5) and blue gradient (0xd) span the full window (their SetPos pins x=0). The
            // connector lines (0xb/0xc) lengthen toward the widened gap; bridging the FULL box motion
            // (+center_offset/s) overshoots, so lengthen by a fraction of it -- tuned by eye to ~2.5x
            // the authored length -- while still scaling with the pillar so it grows on wider screens.
            float s = ui_sprite_scale();
            if (s > 0.0f && swrDisplay_screenWidth > 0) {
                if (id == 5 || id == 0xd)
                    width = (float) swrDisplay_screenWidth / s;
                else if (id == 0xb || id == 0xc)
                    width += 0.5f * ui_center_offset_px() / s;
            }
        }
    }
    hook_call_original(swrSprite_SetDim, id, width, height);
}

// 0x00428660
void swrSprite_SetPos_delta(short id, short x, short y) {
    // Center the 2D UI: shift sprites right by the centering offset, dividing by the sprite's own
    // position scale -- 640-design (element-tree OR TGA) -> ui_layout_scale, else (direct/HUD/game,
    // 320-design) -> ui_sprite_scale. Uniform for every element; edge-anchored buttons ride this by
    // having their stored position moved (see swrUI_NewButton_delta), not by a special offset here.
    // Negative special ids (cursor) are left alone; projected sprites bypass this via
    // swrSprite_SetPosF_delta's trampoline call. ui_center_offset_px() is 0 when the toggle is off.
    if (id >= 0) {
        if (ui_enabled() && swrSprite_id_is_backdrop(id)) {
            // Full-screen backdrop: pin the design origin to the true framebuffer origin (0,0 -> 0,0)
            // and let swrSprite_SetDim_delta stretch it across the window, instead of pillarboxing it.
            x = 0;
            y = 0;
        } else if (ui_enabled() && swrSprite_id_is_logo(id)) {
            // Title logo: left-anchor by SKIPPING the centering shift, so its design x maps straight to
            // the real left edge (like the Back/Settings buttons) instead of into the centered 4:3 box.
            // RACER's slide-in (animated x) then comes from the true left edge. Kept at its aspect (no
            // stretch); y unchanged.
        } else {
            bool widget_space = g_in_element_render || swrSprite_id_is_tga(id);
            float s = widget_space ? ui_layout_scale() : ui_sprite_scale();
            if (s > 0.0f) {
                // Most sprites ride the plain centering offset into the pillarboxed box. A few in-race
                // HUD sprites instead anchor to a real screen edge (see hud_sprite_anchor): RIGHT shifts
                // by two centering offsets to reach the true right edge, LEFT by zero to hug the true
                // left. Only direct HUD sprites are edge-anchored; element-tree/TGA sprites stay centered.
                float off = ui_center_offset_px();
                if (!widget_space) {
                    UiAnchorH a = hud_sprite_anchor(id);
                    if (a == UI_H_RIGHT)
                        off = 2.0f * off;
                    else if (a == UI_H_LEFT)
                        off = 0.0f;
                }
                x = (short) (x + lroundf(off / s));
            }
        }
    }
    // Call the ORIGINAL via the trampoline; calling swrSprite_SetPos by name would re-enter this
    // same hook (the symbol resolves to the hooked EXE address) -> infinite recursion.
    hook_call_original(swrSprite_SetPos, id, x, y);
}
