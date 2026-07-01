#include "swrPlayerHUD_delta.h"

#include <cstdio>
#include <cmath>

extern "C" {
#include <macros.h>
#include <Swr/swrPlayerHUD.h>
#include <Swr/swrText.h>
#include <Swr/swrMultiplayer.h>
#include <globals.h>
}

#include "../hook_helper.h"
#include "../imgui_utils.h" // imgui_state.show_pod_names (the debug-menu toggle)
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

static char g_slotName[HUD_NAME_MAX_RACERS][40]; // "~F0~c~s" + name, indexed by sprite slot (obj.id)
static bool g_mpNameRedirect = false;
static bool g_mpNameSecondaryPass = false;

void swrPlayerHUD_RenderDistanceText_delta(void *viewport, bool secondaryPass) {
    if (!imgui_state.show_pod_names) {
        // Toggle off: draw nothing (no overhead labels in SP or MP). Skipping the original is safe
        // -- player_sprite_pixel_pos is only consumed by swrPlayerHUD_SampleOcclusion, which feeds
        // back into this same renderer.
        return;
    }

    if (multiplayer_enabled == 0) {
        // Single-player: position numbers over AI, unchanged.
        hook_call_original((swrPlayerHUD_RenderDistanceText_t *) swrPlayerHUD_RenderDistanceText_ADDR,
                           viewport, secondaryPass);
        return;
    }

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

        const char *name =
            ((swrMultiplayer_GetPlayerNameAscii_t *) swrMultiplayer_GetPlayerNameAscii_ADDR)(player);
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

    g_mpNameSecondaryPass = secondaryPass;
    g_mpNameRedirect = true;
    hook_call_original((swrPlayerHUD_RenderDistanceText_t *) swrPlayerHUD_RenderDistanceText_ADDR,
                       viewport, secondaryPass);
    g_mpNameRedirect = false;
}

void swrText_CreateTextEntry2_delta(int16_t screen_x, int16_t screen_y, char r, char g, char b,
                                    char a, char *screenText) {
    if (g_mpNameRedirect) {
        // The renderer stored this racer's screen position into the sprite-position arrays for the
        // current pass right before calling us, so match it back to the slot (and thus the name).
        const int *px =
            g_mpNameSecondaryPass ? player_sprite_pixel_pos_x2 : player_sprite_pixel_pos_x;
        const int *py =
            g_mpNameSecondaryPass ? player_sprite_pixel_pos_y2 : player_sprite_pixel_pos_y;
        for (int slot = 0; slot < HUD_NAME_MAX_RACERS; slot++) {
            if (px[slot] == screen_x && py[slot] == screen_y && g_slotName[slot][0]) {
                // Scale the draw position by pos_pct (200% undoes the ~F 0.5 position scale); "~c"
                // in the string handles centring. Then apply the fine-tune offsets.
                screen_x = (int16_t) ((int) screen_x * HUD_NAME_POS_PCT / 100 + HUD_NAME_OFFSET_X);
                screen_y = (int16_t) ((int) screen_y * HUD_NAME_POS_PCT / 100 + HUD_NAME_OFFSET_Y);
                screenText = g_slotName[slot];
                break;
            }
        }
    }

    // Resolution-independent seam (the only caller is swrPlayerHUD_RenderDistanceText): this label is
    // placed by framebuffer pixel, so re-derive its design coordinate -- ui_project_px_to_design folds
    // in the vanilla per-axis normalization when res-independence is off, so the redirect above and SP
    // numbers stay byte-identical there. Draw through the ORIGINAL swrText_CreateTextEntry1 (the raw,
    // already-design-space entry) via the trampoline; calling it by name would re-enter the Entry1
    // centering hook and shift this world-locked text.
    UiVec2 design = ui_project_px_to_design(UiVec2{(float) screen_x, (float) screen_y});
    hook_call_original(swrText_CreateTextEntry1, (int) lroundf(design.x), (int) lroundf(design.y), r,
                       g, b, a, screenText);
}

void swrText_RenderEntries1_delta(void) {
    hook_call_original((swrText_RenderEntries1_t *) swrText_RenderEntries1_ADDR);
    // Our half-size labels use the "~F" code, which leaves swrText_halfScale set after the last one
    // renders (swrText_RenderString only resets it per string). Clear it so the minimap text drawn
    // after this batch -- which doesn't go through RenderString -- isn't shrunk too.
    swrText_halfScale = 0;
}
