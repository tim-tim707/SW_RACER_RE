#include "swrPlayerHUD_delta.h"

#include <cstdio>
#include <cmath>

extern "C" {
#include <macros.h>
#include <Swr/swrPlayerHUD.h>
#include <Swr/swrText.h>
#include <Swr/swrMultiplayer.h>
#include <Primitives/rdVector.h>
#include <globals.h>
}

#include "../hook_helper.h"
#include "../imgui_utils.h" // imgui_state.show_pod_names (the debug-menu toggle)
#include "../sdf_text.h" // sdf_text_set_subpos (sub-grid label placement on the SDF path)
#include "../ui_transform.h" // ui_project_px_to_design (resolution-independent label placement)

// ===========================================================================================
// Multiplayer: player names above pods.
//
// The HUD already draws a small label above each racer (the race position number) via
// swrPlayerHUD_RenderDistanceText -> swrText_CreateTextEntry2, doing all the world->screen
// projection, distance fade, occlusion (don't show through track geometry) and splitscreen-pass
// handling. We want the same labels in multiplayer but showing the human player's name instead of
// the number -- so rather than re-implement that projection (and its ~13 tuning constants), we
// reuse it verbatim and only swap the drawn string (and scale/nudge its draw position).
//
// swrPlayerHUD_RenderDistanceText_delta wraps the renderer: in single-player it just calls the
// original (numbers over AI untouched); in multiplayer it builds a per-slot name label, sets a
// redirect flag, runs the original, then clears the flag. While the flag is set,
// swrText_CreateTextEntry2_delta (which the original calls for each visible, non-occluded racer)
// maps the draw back to its racer slot by the screen position the renderer just stored, swaps in
// that slot's name and adjusts the draw x/y.
//
// Slot mapping: the sprite slot is the racer entity's obj.id; in multiplayer the swrScores[] index
// is the player number (see swrObjHang_BuildRosterMultiplayer), so swrScores[N] -> obj_test_ptr ->
// obj.id maps player N to its slot, and swrMultiplayer_GetPlayerNameAscii(N) is its name.
//
// Size + placement: all of the game's text fonts are the same height, so "~F0" (which renders a
// font at half scale, the 0.5 factor at 0x004ac64c) shrinks the name. "~c" centres it -- it works
// at half scale because it shifts the anchor by GetStringWidth/2 in the same virtual space the
// glyphs render in, so the shift and the rendered width scale together. "~F0" also scales the glyph
// *position* by 0.5 (the same 0.5 factor applied to the glyph x in rdProcEntry_Add2DQuad2), landing
// the label at half the intended screen coordinate; we undo that by scaling the draw position by
// 200%.
//
// Whether the labels render at all is the "Overhead racer labels" debug-menu toggle
// (imgui_state.show_pod_names, persisted to SW_RACER_RE.ini as show_pod_names); off hides them in
// both SP and MP. Label placement is baked in as constants below (HUD_NAME_POS_PCT / OFFSET_*).
// ===========================================================================================

typedef void(swrPlayerHUD_RenderDistanceText_t)(void *viewport, bool secondaryPass);
typedef char *(swrMultiplayer_GetPlayerNameAscii_t)(int playerIndex);
typedef int(swrMultiplayer_GetRacerId_t)(int playerIndex);
typedef void(swrText_RenderEntries1_t)(void);

#define HUD_NAME_MAX_RACERS 20 // swrScores[20] / player_sprite arrays are sized 20
#define HUD_NAME_MAX_PODS 23   // swrRacer_PodData[23] (character-name fallback bound)
#define HUD_NAME_FONT 0        // full-alphabet font; "~F0" renders it at half scale

// Label placement, baked in (was INI-tunable during bring-up; final values per review).
#define HUD_NAME_POS_PCT 200 // % scale on the draw x/y (undoes the ~F 0.5 position scale)
#define HUD_NAME_OFFSET_X 0  // px nudge right after the scale (negative = left)
#define HUD_NAME_OFFSET_Y 0  // px nudge down after the scale (negative = up)

// Lift the label above the projected pod point so the number/name clears the pod instead of sitting
// on it. The lift is in design-space units (resolution-independent, unlike the game's fixed 13 px)
// AND scales with the pod's apparent size, which is proportional to 1/distance -- otherwise a far
// (tiny) pod gets the same big gap as a near (large) one. raise = RAISE_AT_REF * (REF_DIST / dist),
// clamped; distance is the pod->camera distance the game itself uses for the distance fade.
#define HUD_LABEL_RAISE_AT_REF 16.0f    // design-space lift at the reference distance
#define HUD_LABEL_RAISE_REF_DIST 120.0f // world-unit distance at which the lift == HUD_LABEL_RAISE_AT_REF
#define HUD_LABEL_RAISE_MIN 4.0f        // clamp so a very distant pod's label doesn't collapse onto it
#define HUD_LABEL_RAISE_MAX 48.0f       // clamp so a very close pod's label doesn't fly off the top

static char g_slotName[HUD_NAME_MAX_RACERS][40]; // "~F0~c~s" + name, indexed by sprite slot (obj.id)
static char g_numLabel[16];                      // SP: "~F0~c~s" + opponent position number
static bool g_mpNameRedirect = false;
static bool g_secondaryPass = false;

// --- Occlusion debounce ---------------------------------------------------------------------------
// The game hides a label behind world geometry by CPU-reading the DirectDraw Z-buffer
// (swrPlayerHUD_SampleOcclusion). That read is unreliable under the modern GL renderer, so a
// clearly-visible label flickers to "occluded" for stray frames and two adjacent racers' labels
// alternate rapidly. We keep the occlusion behaviour but debounce it (primary pass only): record
// every label the original draws, and for a slot that is on-screen yet undrawn this frame, keep
// re-showing its last label for a few frames before actually letting it hide.
#define HUD_LABEL_OCCLUSION_HYSTERESIS 20 // frames a label persists through (possibly false) occlusion
                                           // (~0.33s @60fps; the game's 16-bit depth read is coarse at
                                           // distance, so a clear-LOS opponent can read "occluded" for
                                           // short runs -- bridge them before actually hiding the label)
#define HUD_PIXEL_POS_OFFSCREEN (-1000)  // sentinel the renderer writes for culled/off-screen slots

struct HudLabelState {
    int occludedStreak;  // consecutive primary-pass frames on-screen but not drawn by the original
    bool drawnThisFrame; // the original drew this slot this frame (reset each primary frame)
    char color[4];       // last drawn r, g, b, a
    char text[48];       // last drawn label string (already "~F0~c~s"...)
};
static HudLabelState g_label[HUD_NAME_MAX_RACERS];
static bool g_recordState = false; // true while the primary-pass original runs (record its draws)

// Match a label draw back to its racer slot by the screen position the renderer stored just before
// calling us (see swrText_CreateTextEntry2_delta). Uses the current pass's sprite-position array.
static int hud_slot_for_pos(int16_t sx, int16_t sy) {
    const int *px = g_secondaryPass ? player_sprite_pixel_pos_x2 : player_sprite_pixel_pos_x;
    const int *py = g_secondaryPass ? player_sprite_pixel_pos_y2 : player_sprite_pixel_pos_y;
    for (int slot = 0; slot < HUD_NAME_MAX_RACERS; slot++)
        if (px[slot] == sx && py[slot] == sy)
            return slot;
    return -1;
}

// Draw a small "~F0~c~s" label (name / position number) at a projected framebuffer-pixel anchor:
// pre-scale the anchor 200% (undo the ~F 0.5 position halve), convert to design space, lift it above
// the pod (resolution-independent), and register the exact fractional position for the SDF path.
// Shared by the live draw and the occlusion-debounce re-show.
static void hud_emit_small_label(int16_t px, int16_t py, char r, char g, char b, char a, char *text,
                                 float raiseDesign) {
    px = (int16_t) ((int) px * HUD_NAME_POS_PCT / 100 + HUD_NAME_OFFSET_X);
    py = (int16_t) ((int) py * HUD_NAME_POS_PCT / 100 + HUD_NAME_OFFSET_Y);
    UiVec2 design = ui_project_px_to_design(UiVec2{(float) px, (float) py});
    design.y -= raiseDesign; // lift above the pod (design-space, scaled to the pod's apparent size)
    if (imgui_state.sdf_text)
        sdf_text_set_subpos((int) lroundf(design.x), (int) lroundf(design.y), design.x, design.y);
    hook_call_original(swrText_CreateTextEntry1, (int) lroundf(design.x), (int) lroundf(design.y), r,
                       g, b, a, text);
}

// Design-space height to lift a label above its pod, scaled by the pod's apparent size (1/distance)
// so it hugs the pod at any range. Distance is pod->camera, as the game's own fade uses.
static float hud_label_raise(int slot) {
    if (slot < 0 || slot >= HUD_NAME_MAX_RACERS)
        return HUD_LABEL_RAISE_AT_REF;
    typedef float(rdVector_Dist3_t)(const rdVector3 *, const rdVector3 *);
    float dist = ((rdVector_Dist3_t *) rdVector_Dist3_ADDR)(&player_sprite_positions_on_map[slot],
                                                            &rdVector_model_translation);
    if (dist < 1.0f)
        dist = 1.0f;
    float raise = HUD_LABEL_RAISE_AT_REF * HUD_LABEL_RAISE_REF_DIST / dist;
    if (raise < HUD_LABEL_RAISE_MIN)
        raise = HUD_LABEL_RAISE_MIN;
    if (raise > HUD_LABEL_RAISE_MAX)
        raise = HUD_LABEL_RAISE_MAX;
    return raise;
}

void swrPlayerHUD_RenderDistanceText_delta(void *viewport, bool secondaryPass) {
    if (!imgui_state.show_pod_names) {
        // Toggle off: draw nothing (no overhead labels in SP or MP). Skipping the original is safe
        // -- player_sprite_pixel_pos is only consumed by swrPlayerHUD_SampleOcclusion, which feeds
        // back into this same renderer.
        return;
    }

    g_secondaryPass = secondaryPass;
    const bool primary = !secondaryPass;
    if (primary)
        for (int slot = 0; slot < HUD_NAME_MAX_RACERS; slot++)
            g_label[slot].drawnThisFrame = false;

    if (multiplayer_enabled != 0) {
        // Multiplayer: build a per-slot human-player name label for the redirect (AI keep numbers).
        for (int slot = 0; slot < HUD_NAME_MAX_RACERS; slot++)
            g_slotName[slot][0] = '\0';

        for (int player = 0; player < HUD_NAME_MAX_RACERS; player++) {
            if (swrScores[player].identifier == 0) // empty roster slot
                continue;
            swrRace *racer = swrScores[player].obj_test_ptr;
            if (!racer)
                continue;
            const int slot = racer->obj.id;
            if (slot < 0 || slot >= HUD_NAME_MAX_RACERS)
                continue;

            const char *name = ((swrMultiplayer_GetPlayerNameAscii_t *)
                                    swrMultiplayer_GetPlayerNameAscii_ADDR)(player);
            if (name && name[0]) {
                snprintf(g_slotName[slot], sizeof(g_slotName[slot]), "~F%d~c~s%s", HUD_NAME_FONT, name);
            } else {
                // No player name for this slot: fall back to the character name.
                const int podIndex =
                    ((swrMultiplayer_GetRacerId_t *) swrMultiplayer_GetRacerId_ADDR)(player);
                if (podIndex >= 0 && podIndex < HUD_NAME_MAX_PODS) {
                    char podName[32];
                    swrText_FormatPodName(podIndex, podName, sizeof(podName));
                    snprintf(g_slotName[slot], sizeof(g_slotName[slot]), "~F%d~c~s%s", HUD_NAME_FONT,
                             podName);
                }
            }
        }
        g_mpNameRedirect = true;
    }

    g_recordState = primary;
    hook_call_original((swrPlayerHUD_RenderDistanceText_t *) swrPlayerHUD_RenderDistanceText_ADDR,
                       viewport, secondaryPass);
    g_recordState = false;
    g_mpNameRedirect = false;

    if (!primary)
        return;

    // Occlusion debounce: re-show labels that are on-screen this frame but the original didn't draw
    // (its occlusion sample said hidden), for up to HUD_LABEL_OCCLUSION_HYSTERESIS frames. The
    // renderer refreshes pixel_pos every frame regardless of the occlusion decision, so re-project
    // from the current pixel_pos -- the debounced label keeps following the pod instead of freezing.
    for (int slot = 0; slot < HUD_NAME_MAX_RACERS; slot++) {
        HudLabelState *st = &g_label[slot];
        if (st->drawnThisFrame)
            continue; // freshly drawn; occludedStreak already reset in the entry hook
        if (player_sprite_pixel_pos_x[slot] == HUD_PIXEL_POS_OFFSCREEN || st->text[0] == '\0') {
            st->occludedStreak = 0; // off-screen / never shown -> forget it
            st->text[0] = '\0';
            continue;
        }
        st->occludedStreak++;
        if (st->occludedStreak <= HUD_LABEL_OCCLUSION_HYSTERESIS)
            hud_emit_small_label((int16_t) player_sprite_pixel_pos_x[slot],
                                 (int16_t) player_sprite_pixel_pos_y[slot], st->color[0],
                                 st->color[1], st->color[2], st->color[3], st->text,
                                 hud_label_raise(slot));
    }
}

void swrText_CreateTextEntry2_delta(int16_t screen_x, int16_t screen_y, char r, char g, char b,
                                    char a, char *screenText) {
    // The renderer stored this racer's screen position into the sprite-position arrays right before
    // calling us, so match it back to its slot (for the MP name and the occlusion-debounce record).
    const int slot = hud_slot_for_pos(screen_x, screen_y);

    // A "small label" (name / position number) is rendered like the MP names: "~F0" half scale,
    // "~c" centered, "~s" shadowed. label != NULL selects that path (with the shared 200%/lift/SDF
    // handling in hud_emit_small_label); the "~f1" highlight marker falls through as-is.
    char *label = NULL;
    if (g_mpNameRedirect && slot >= 0 && g_slotName[slot][0]) {
        label = g_slotName[slot]; // multiplayer human player -> name
    } else if (screenText[0] == '~' && screenText[1] == 's') {
        // Opponent position number, built by the game as "~s%d" (shadow + number) in the default
        // full-size font, left-aligned -- so at high res it reads uncentered and too large. Rebuild
        // it small + centered like the names.
        snprintf(g_numLabel, sizeof(g_numLabel), "~F%d~c~s%s", HUD_NAME_FONT, &screenText[2]);
        label = g_numLabel;
    }

    if (label == NULL) {
        // Unhandled label (e.g. the "~f1" highlight marker): draw as-is, resolution-independently.
        // Draw through the ORIGINAL swrText_CreateTextEntry1 (the raw, already-design-space entry);
        // calling it by name would re-enter the Entry1 centering hook and shift this world-locked text.
        UiVec2 design = ui_project_px_to_design(UiVec2{(float) screen_x, (float) screen_y});
        if (imgui_state.sdf_text)
            sdf_text_set_subpos((int) lroundf(design.x), (int) lroundf(design.y), design.x, design.y);
        hook_call_original(swrText_CreateTextEntry1, (int) lroundf(design.x), (int) lroundf(design.y),
                           r, g, b, a, screenText);
        return;
    }

    // Record the draw so the occlusion debounce can re-show it if the next frame's sample drops it.
    if (g_recordState && slot >= 0) {
        HudLabelState *st = &g_label[slot];
        st->drawnThisFrame = true;
        st->occludedStreak = 0;
        st->color[0] = r;
        st->color[1] = g;
        st->color[2] = b;
        st->color[3] = a;
        snprintf(st->text, sizeof(st->text), "%s", label);
    }

    hud_emit_small_label(screen_x, screen_y, r, g, b, a, label, hud_label_raise(slot));
}

void swrText_RenderEntries1_delta(void) {
    hook_call_original((swrText_RenderEntries1_t *) swrText_RenderEntries1_ADDR);
    // Our half-size labels use the "~F" code, which leaves swrText_halfScale set after the last one
    // renders (swrText_RenderString only resets it per string). Clear it so the minimap text drawn
    // after this batch -- which doesn't go through RenderString -- isn't shrunk too.
    swrText_halfScale = 0;
}
