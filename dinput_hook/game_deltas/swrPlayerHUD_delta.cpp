#include "swrPlayerHUD_delta.h"

#include <windows.h>
#include <filesystem>
#include <cstdio>
#include <cstdlib>

extern "C" {
#include <macros.h>
#include <Swr/swrPlayerHUD.h>
#include <Swr/swrText.h>
#include <Swr/swrMultiplayer.h>
#include <globals.h>
}

#include "../hook_helper.h"
#include "../imgui_utils.h" // imgui_state.show_pod_names (the debug-menu toggle)

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
// both SP and MP. The remaining placement knobs live in SW_RACER_RE.ini [settings] (edit + relaunch,
// no rebuild):
//   name_label_pos_pct  (default 200) percent to scale the draw x/y by (undoes the 0.5 scale)
//   name_label_offset_x (default 0)   pixels to nudge right (negative = left), after the scale
//   name_label_offset_y (default 0)   pixels to nudge down (negative = up), after the scale
// ===========================================================================================

typedef void(swrPlayerHUD_RenderDistanceText_t)(void *viewport, bool secondaryPass);
typedef char *(swrMultiplayer_GetPlayerNameAscii_t)(int playerIndex);
typedef int(swrMultiplayer_GetRacerId_t)(int playerIndex);
typedef void(swrText_RenderEntries1_t)(void);

#define HUD_NAME_MAX_RACERS 20 // swrScores[20] / player_sprite arrays are sized 20
#define HUD_NAME_MAX_PODS 23   // swrRacer_PodData[23] (character-name fallback bound)
#define HUD_NAME_FONT 0        // full-alphabet font; "~F0" renders it at half scale

static char g_slotName[HUD_NAME_MAX_RACERS][40]; // "~F0~c~s" + name, indexed by sprite slot (obj.id)
static bool g_mpNameRedirect = false;
static bool g_mpNameSecondaryPass = false;

static int g_labelPosPct = 200;
static int g_labelOffsetX = 0;
static int g_labelOffsetY = 0;

static int read_ini_int(const wchar_t *key, int fallback, const wchar_t *ini) {
    wchar_t buf[32];
    if (GetPrivateProfileStringW(L"settings", key, L"", buf, (DWORD) std::size(buf), ini) == 0)
        return fallback; // key absent -> default
    return _wtoi(buf);    // _wtoi handles a leading '-' (GetPrivateProfileIntW does not)
}

static void load_label_settings_once() {
    static bool loaded = false;
    if (loaded)
        return;
    loaded = true;

    wchar_t module_path[1024];
    GetModuleFileNameW(nullptr, module_path, (DWORD) std::size(module_path));
    const std::wstring ini =
        (std::filesystem::path(module_path).parent_path() / "SW_RACER_RE.ini").wstring();

    g_labelPosPct = read_ini_int(L"name_label_pos_pct", 200, ini.c_str());
    g_labelOffsetX = read_ini_int(L"name_label_offset_x", 0, ini.c_str());
    g_labelOffsetY = read_ini_int(L"name_label_offset_y", 0, ini.c_str());

    fprintf(hook_log, "[mpnames] pos_pct=%d offset_x=%d offset_y=%d\n", g_labelPosPct, g_labelOffsetX,
            g_labelOffsetY);
    fflush(hook_log);
}

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

    load_label_settings_once();

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
                screen_x = (int16_t) ((int) screen_x * g_labelPosPct / 100 + g_labelOffsetX);
                screen_y = (int16_t) ((int) screen_y * g_labelPosPct / 100 + g_labelOffsetY);
                screenText = g_slotName[slot];
                break;
            }
        }
    }

    hook_call_original(swrText_CreateTextEntry2, screen_x, screen_y, r, g, b, a, screenText);
}

void swrText_RenderEntries1_delta(void) {
    hook_call_original((swrText_RenderEntries1_t *) swrText_RenderEntries1_ADDR);
    // Our half-size labels use the "~F" code, which leaves swrText_halfScale set after the last one
    // renders (swrText_RenderString only resets it per string). Clear it so the minimap text drawn
    // after this batch -- which doesn't go through RenderString -- isn't shrunk too.
    swrText_halfScale = 0;
}
