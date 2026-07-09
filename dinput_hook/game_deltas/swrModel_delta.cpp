#include "swrModel_delta.h"
#include "glad/glad.h"

#include <vector>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <format>

#include "../hook_helper.h"
#include "../node_utils.h"
#include "../stb_image.h"
#include "../custom_tracks.h"
#include "../nv_dds/nv_dds.h"
#include "../imgui_utils.h"
#include "../ui_transform.h"
#include "../patch.h"

#include <regex>

extern "C" {
#include <Swr/swrModel.h>
#include <Swr/swrSprite.h>
#include <Swr/swrText.h>
#include <Swr/swrUI.h>
#include <Swr/swrLoader.h>
#include <Swr/swrAssetBuffer.h>
#include <Swr/swrText.h>
}

#include <globals.h>
#include <macros.h>
#include <types_enums.h>

#include "tracks_delta.h"

extern "C" FILE *hook_log;

extern std::vector<AssetPointerToModel> asset_pointer_to_model;

typedef void (*Original_ConvertTextureDataToRdMaterial)(int texture_type_a, int texture_type_b,
                                                        int orig_width, int orig_height, int width,
                                                        int height, swrMaterial **texture_data_ptr,
                                                        uint8_t **palette_ptr, char flipSomething,
                                                        char adjustWidthHeightFlag);

// C was this close to being perfect, but Andrew Kelley gave us zig
#define HD_FONT_WIDTH 512
#define HD_FONT_HEIGHT 1024
unsigned char font_0_0_buffer[HD_FONT_WIDTH * HD_FONT_HEIGHT / 2];
unsigned char font_1_0_buffer[HD_FONT_WIDTH * HD_FONT_HEIGHT / 2];
unsigned char font_1_1_buffer[HD_FONT_WIDTH * HD_FONT_HEIGHT / 2];
unsigned char font_1_2_buffer[HD_FONT_WIDTH * HD_FONT_HEIGHT / 2];
unsigned char font_4_0_buffer[HD_FONT_WIDTH * HD_FONT_HEIGHT / 2];

int readFontToBuffer(unsigned char *out_buffer, const char *path) {
    stbi_set_flip_vertically_on_load(false);

    int widthRead;
    int heightRead;
    int nbChannels;
    unsigned char *data = stbi_load(path, &widthRead, &heightRead, &nbChannels, STBI_rgb_alpha);

    if (data == NULL) {
        return 1;
    }

    assert(widthRead == HD_FONT_WIDTH && "font does not have a width of 512");
    assert(heightRead == HD_FONT_HEIGHT && "font does not have a height of 1024");
    assert(nbChannels == 4 && "font does not have 4 channels");

    // Convert to gray 4bits
    size_t j = 0;
    size_t l = 0;
    // read pixels 2 by 2 to pack them in a single byte, since the format is 4-bit greyscale
    for (size_t i = 0; i < HD_FONT_WIDTH * HD_FONT_HEIGHT * nbChannels; i += 2 * nbChannels) {
        uint8_t gray1 = (data[i + 0] + data[i + 1] + data[i + 2]) / 3;
        uint8_t gray2 = (data[i + 4] + data[i + 5] + data[i + 6]) / 3;
        // Ignore 3rd and 7th values (alphas)

        // Divide by 16 (<=> & 0xF0) to get from 8 bits to 4 bits, then shift to be on the left or the right
        out_buffer[j] = (gray1 & 0xF0) | ((gray2 & 0xF0) >> 4);
        j += 1;
    }

#if 0
#define STRINGIFY(x) #x
    // Generate the C buffers which can be used directly instead of loading a png
    // Experiment shows that this doesn't change the loading time perceptibly
    fprintf(hook_log, "const unsigned char buffer[" STRINGIFY(HD_FONT_WIDTH) " * " STRINGIFY(
                          HD_FONT_HEIGHT) " / 2] = \"");
    for (size_t i = 0; i < HD_FONT_WIDTH * HD_FONT_HEIGHT / 2; i++) {
        if (out_buffer[i] == 0) {
            fprintf(hook_log, "\\0");
        } else {
            fprintf(hook_log, "\\x%02X", out_buffer[i]);
        }
    }
    fprintf(hook_log, "\"\n");
    fflush(hook_log);
#undef STRINGIFY
#endif

    stbi_image_free(data);

    return 0;
}

// Added loading font from font files, and using 512, 1024 as a resolution
// Unrolled all static loops

// --- HD font replacement: journaled live toggle (modding API, issue #153) --------------------
// The vanilla swrText_InitFonts (0x0042d720) and the HD path populate the SAME font-table slots
// (and write identical font-metadata globals), differing only in which swrMaterial each slot
// points at. So we keep BOTH font sets resident and flip the toggle by journaling the slot
// pointers: enable = PatchPointer the HD material over the built-in one (capturing it); disable =
// UndoOwner("hd_font") restores the built-in. The original is always run first so the built-in
// materials exist to revert to. This makes the F5 toggle apply live, no restart.
struct HdFontSlot {
    swrMaterial **page;// font-table glyph-page slot the converter fills (swrText_fonts[f].pages[p])
    uint8_t *buffer;   // HD texture data the slot is pointed at before conversion
};
static const HdFontSlot kHdFontSlots[] = {
    {&swrText_fonts[3].pages[0], font_0_0_buffer},
    {&swrText_fonts[0].pages[0], font_1_0_buffer},
    {&swrText_fonts[0].pages[1], font_1_1_buffer},
    {&swrText_fonts[0].pages[2], font_1_2_buffer},// font_1_2 also backs fonts[1]/[2] (font_2_0/3_0)
    {&swrText_fonts[1].pages[0], font_1_2_buffer},
    {&swrText_fonts[2].pages[0], font_1_2_buffer},
    {&swrText_fonts[4].pages[0], font_4_0_buffer},
};
static const int kNumHdFontSlots = (int) (sizeof(kHdFontSlots) / sizeof(kHdFontSlots[0]));
static swrMaterial *g_hdFontMaterial[kNumHdFontSlots];// converted HD materials, built once
static bool g_hdFontsBuilt = false;

// Read the HD font PNGs and convert them into rdMaterials once, leaving the live font-table slots
// on their built-in materials. Conversion only ever happens here (at startup or first enable), so
// the runtime toggle is a pure pointer swap. Returns false if any asset is missing -> HD stays off.
static bool ensure_hd_fonts_built() {
    if (g_hdFontsBuilt)
        return true;

    static const struct {
        uint8_t *buffer;
        const char *path;
    } files[] = {
        {font_0_0_buffer, "./assets/textures/fonts/font0_0.png"},
        {font_1_0_buffer, "./assets/textures/fonts/font1_0.png"},
        {font_1_1_buffer, "./assets/textures/fonts/font1_1.png"},
        {font_1_2_buffer, "./assets/textures/fonts/font1_2.png"},
        {font_4_0_buffer, "./assets/textures/fonts/font4_0.png"},
    };
    for (const auto &f: files) {
        if (readFontToBuffer(f.buffer, f.path) != 0) {
            fprintf(hook_log, "[hd_font] missing %s; keeping built-in fonts.\n", f.path);
            fflush(hook_log);
            return false;
        }
    }

    Original_ConvertTextureDataToRdMaterial converter =
        (Original_ConvertTextureDataToRdMaterial) swrModel_ConvertTextureDataToRdMaterial_ADDR;
    uint8_t *palette = nullptr;
    for (int i = 0; i < kNumHdFontSlots; i++) {
        swrMaterial **page = kHdFontSlots[i].page;
        swrMaterial *builtin = *page;                  // built-in material (set by the original)
        *page = (swrMaterial *) kHdFontSlots[i].buffer;// point at HD data, then convert in place
        converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, page,
                  &palette, 1, 0);
        g_hdFontMaterial[i] = *page;// remember the converted HD material
        *page = builtin;            // leave the live slot on the built-in
    }
    g_hdFontsBuilt = true;
    fprintf(hook_log, "[hd_font] built %d HD font materials.\n", kNumHdFontSlots);
    fflush(hook_log);
    return true;
}

// Live toggle: point the font-table slots at the HD materials (journaled so it reverts cleanly) or
// restore the built-in materials. Safe any time after swrText_InitFonts_delta has run. Returns
// false if HD was requested but its assets are missing (caller should clear the toggle).
extern "C" bool set_hd_fonts(bool on) {
    if (!on) {
        UndoOwner("hd_font");
        return true;
    }
    if (!ensure_hd_fonts_built())
        return false;
    for (int i = 0; i < kNumHdFontSlots; i++)
        PatchPointer("hd_font", kHdFontSlots[i].page, (uint32_t) (uintptr_t) g_hdFontMaterial[i]);
    return true;
}

// 0x0042d720
void swrText_InitFonts_delta(void) {
    // Always load the built-in fonts first so their materials exist and the font-table slots hold
    // valid pointers; the HD swap (if enabled) then journals over those slots so it toggles live.
    // This runs before read_settings_ini(), so read the persisted toggle directly here.
    hook_call_original((void (*)(void)) swrText_InitFonts_ADDR);
    if (read_hd_font_setting() && !set_hd_fonts(true))
        imgui_state.hd_font = false;// assets missing -> reflect that the built-in fonts are in use
}

// We don't have the original function decompiled properly yet
swrModel_Header *swrModel_LoadFromId_delta(MODELID id) {
    // if (id > CUSTOM_TRACK_MODELID_BEGIN) {
    //     fprintf(hook_log, "model id load: %d\n", id);
    //     fflush(hook_log);
    // }
    const bool is_custom_track = prepare_loading_custom_track_model(&id);

    char *model_asset_pointer_begin = swrAssetBuffer_GetBuffer();
    swrModel_Header *header = hook_call_original(swrModel_LoadFromId, id);
    char *model_asset_pointer_end = swrAssetBuffer_GetBuffer();
    if (is_custom_track) {
        finalize_loading_custom_track_model(header);
    } else {
        fixup_custom_model(header);
    }

    // remove all models whose asset pointer is invalid:
    std::erase_if(asset_pointer_to_model, [&](const AssetPointerToModel &elem) {
        return elem.asset_pointer_begin >= model_asset_pointer_begin;
    });

    asset_pointer_to_model.emplace_back() = {
        model_asset_pointer_begin,
        model_asset_pointer_end,
        id,
    };

    // setting this to 0 skips the generation of the renderDroid scene graph in the RenderAll
    // functions. it's not needed since the renderer replacement uses the swrModel_Node scene graph #
    // directly.
    assetBufferModelLoaded = 0;

    return header;
}

// Cleanup
#undef HD_FONT_WIDTH
#undef HD_FONT_HEIGHT

void **texture_buffer_replacement = nullptr;

// 0x00447420
void swrModel_InitializeTextureBuffer_delta() {
    // this version of the function removes a texture count limit and makes it possible to resize
    // the texture buffer when a new custom track is laoded with more textures. this currently
    // assumes that the out_textureblock.bin file from the custom track only appends to the textures
    // and does not replace existing ones. the behavior is not totally clear if that happens.
    const uint32_t prev_texture_count = texture_count;

    swrLoader_OpenBlock(swrLoader_TYPE_TEXTURE_BLOCK);
    swrLoader_ReadAt(swrLoader_TYPE_TEXTURE_BLOCK, 0, &texture_count, 4u);
    texture_count = SWAP32(texture_count);

    texture_buffer_replacement =
        (void **) realloc(texture_buffer_replacement, texture_count * sizeof(uint32_t));
    // clear the new textures:
    if (prev_texture_count < texture_count)
        memset(texture_buffer_replacement + prev_texture_count, 0,
               (texture_count - prev_texture_count) * sizeof(void *));

    char *range_begin = (char *) 0x00447420;
    char *range_end = (char *) 0x004475ED;
    DWORD old_protect;
    VirtualProtect(range_begin, range_end - range_begin, PAGE_EXECUTE_READWRITE, &old_protect);

    *(void **) 0x4474B1 = texture_buffer_replacement;
    *(void **) 0x4474C4 = texture_buffer_replacement;
    *(void **) 0x447555 = texture_buffer_replacement;
    *(void **) 0x4475D5 = texture_buffer_replacement;
    *(void **) 0x4475E7 = texture_buffer_replacement + texture_count;

    VirtualProtect(range_begin, range_end - range_begin, old_protect, &old_protect);

    swrLoader_CloseBlock(swrLoader_TYPE_TEXTURE_BLOCK);
}

// Menu-text scope: ui_menu_text_depth (shared, in ui_transform) is held > 0 while a swrUI / front-end
// text path runs, so swrText_CreateTextEntry1_delta uses the widget (640) scale for menu text and the
// HUD (320) scale for direct/in-race callers. Caller-based, not game-state-based: the pause menu
// draws menu text mid-race and still needs the menu scale. (swrObjHang_F0 is flagged in its existing
// delta in swrObjHang_delta.cpp, since that function is already hooked for the MP input fix.)
typedef void (*swrUI_DrawText_t)(int, int, int, int, int, int, int, char *, int, int, int);
typedef void (*swrUI_DrawTextAligned_t)(int, char *, short *, unsigned int, int, int, int, int, int,
                                        int, int);

// 0x004173c0
void swrUI_DrawText_delta(int font, int x, int y, int color0, int color1, int color2, int color3,
                          char *text, int unk9, int unk10, int disabled) {
    ui_menu_text_depth++;
    // swrUI_DrawText is prototype-only (no linkable body), so pass a function-pointer cast of its
    // address to hook_call_original -- the hooks map is keyed by address, so this resolves the
    // trampoline (the original) without needing the symbol.
    hook_call_original((swrUI_DrawText_t) swrUI_DrawText_ADDR, font, x, y, color0, color1, color2,
                       color3, text, unk9, unk10, disabled);
    ui_menu_text_depth--;
}

// 0x00417540 -- swrUI_DrawTextAligned (screen titles like "SELECT VEHICLE", aligned/centered text).
// Flags menu text the same way; it does not route through the hooked swrUI_DrawText, so it needs
// its own wrapper. (ui_menu_text_depth is a counter, so nesting is safe.)
void swrUI_DrawTextAligned_delta(int font, char *text, short *bbox, unsigned int alignFlags,
                                 int color0, int color1, int color2, int color3, int unk9,
                                 int unk10, int unk11) {
    ui_menu_text_depth++;
    hook_call_original((swrUI_DrawTextAligned_t) swrUI_DrawTextAligned_ADDR, font, text, bbox,
                       alignFlags, color0, color1, color2, color3, unk9, unk10, unk11);
    ui_menu_text_depth--;
}

// Edge-anchored in-race HUD text, keyed by the exact design x the game draws it at (from
// swrRace_InRaceTimer / swrObjJdge_DrawSpeedDialHud). These strings sit on HUD clusters that anchor to
// a screen edge (see hud_sprite_anchor in swrSprite_delta), so their text must ride the same edge or it
// detaches from the frame. RIGHT shifts by two centering offsets (real right edge), LEFT by zero (real
// left); everything else -- centered messages, the timer, countdown -- stays plain-centered. Matched by
// exact x (not a range) so a centered string near these columns is never caught. Only consulted for
// HUD text (ui_menu_text_depth == 0); menu text is unaffected.
static UiAnchorH hud_text_anchor(int x) {
    switch (x) {
    case 0xf4:// 244: "BOOST" text (swrObjJdge_DrawSpeedDialHud)
    case 254: // digital speed readout (swrRace_InRaceTimer), sits on the right-anchored speedo frame
        return UI_H_RIGHT;
    case 0x36:// 54: engine temp/warning text (ENGINE/FIRE, TEMP/WARN, OVERHEAT, Warning, Repair) --
              // rides the bottom-left engine readout (swrRace_InRaceEngineUI)
    case 42:  // lap counter "#/#" + "LAP" label (minimap / arrow HUD modes) -- rides the header lap
    case 62:  // lap counter "#/#" + "LAP" label (progress-ring HUD mode)     holder (sprite 0), LEFT
        return UI_H_LEFT;
    case 0x116:// 278: position counter "#/#" + "POS" label -- rides the header position holder (sprite 1)
        return UI_H_RIGHT;
    default:
        return UI_H_CENTER;
    }
}

// Shared X shift for every entries1 (menu/HUD) text string, whichever wrapper emitted it:
// swrText_CreateTextEntry1, swrText_CreateColorlessEntry1, and swrText_CreateColorlessFormattedEntry1
// all sink into swrText_CreateEntry. Menu text (inside a swrUI_DrawText scope) lives in the 640
// widget space (ui_layout_scale); all other text in the ~320 draw space (ui_sprite_scale). Match the
// divisor to the text's space so it shifts the same px as its sibling sprites. HUD text on an
// edge-anchored cluster (hud_text_anchor) rides that edge instead of plain centering. Returns x
// unchanged when centering is off (ui_center_offset_px() is 0).
static int ui_center_text_x(int x) {
    // In-race position-marker number text (drawn only inside swrObjJdge_DrawRaceHUD): remap X by HUD
    // mode exactly like its marker sprite, so the number rides the right strip / full-width ring.
    if (ui_hud_marker_mode >= 0 && !ui_menu_text_depth)
        return (int) lroundf(ui_hud_marker_x((float) x, ui_hud_marker_mode));
    float s = ui_menu_text_depth ? ui_layout_scale() : ui_sprite_scale();
    if (s > 0.0f) {
        float off = ui_center_offset_px();
        if (!ui_menu_text_depth) {
            UiAnchorH a = hud_text_anchor(x);
            if (a == UI_H_RIGHT)
                off = 2.0f * off;
            else if (a == UI_H_LEFT)
                off = 0.0f;
        }
        x += (int) lroundf(off / s);
    }
    return x;
}

// 0x00450530
void swrText_CreateTextEntry1_delta(int x, int y, int r, int g, int b, int a, char *screenText) {
    // Center the 2D UI by shifting the text origin right (see ui_center_text_x). Call the ORIGINAL
    // via the trampoline; calling swrText_CreateTextEntry1 by name would re-enter this same hook (the
    // symbol resolves to the hooked EXE address) -> infinite recursion. swrText_CreateTextEntry2_delta
    // calls the DLL copy (not this hook), keeping projected text world-locked.
    hook_call_original(swrText_CreateTextEntry1, ui_center_text_x(x), y, r, g, b, a, screenText);
}

// 0x00450560 -- swrText_CreateColorlessEntry1 and 0x00450590 -- swrText_CreateColorlessFormattedEntry1.
// Sibling wrappers that call swrText_CreateEntry DIRECTLY (NOT via swrText_CreateTextEntry1), so the
// CreateTextEntry1 hook never sees them. The hangar screen TITLES ("SELECT VEHICLE" in
// swrRace_SelectVehicle, "MAIN MENU" in swrRace_MainMenu) are drawn through CreateColorlessEntry1 at
// x=0xa0; without these hooks the titles miss the centering offset and sit left of the pillarboxed
// UI. Apply the same shift as CreateTextEntry1.
void swrText_CreateColorlessEntry1_delta(short x, short y, char *screenText) {
    hook_call_original(swrText_CreateColorlessEntry1, (short) ui_center_text_x(x), y, screenText);
}

void swrText_CreateColorlessFormattedEntry1_delta(int formatInt, short x, short y,
                                                  char *screenText) {
    hook_call_original(swrText_CreateColorlessFormattedEntry1, formatInt,
                       (short) ui_center_text_x(x), y, screenText);
}

// 0x004505c0 -- swrText_CreateEntry2. Writes the entries2 buffer (drawn by swrText_RenderEntries2 at
// the same recip scale as entries1). Its ONLY caller is the in-race pause menu, which draws the
// option text through this at x=0xa0; the projected distance/name labels use the unrelated
// swrText_CreateTextEntry2 (0x42c7a0), which routes through entries1, so offsetting entries2 here
// shifts only the pause options. Same centering as CreateTextEntry1.
void swrText_CreateEntry2_delta(short x, short y, char r, char g, char b, char a,
                                char *screenText) {
    hook_call_original(swrText_CreateEntry2, (short) ui_center_text_x(x), y, r, g, b, a,
                       screenText);
}

// 0x00450310
// Parallel per-entry clip arrays (verified from the disassembly at 0x450310, now named in
// data_symbols.syms): swrTextEntries1ClipRect[count] = L/T/R/B, swrTextEntries1ClipEnabled[count]
// = the per-entry enable flag; count = swrTextEntries1Count. The input rect[0..3] is a 640x480
// design-space L/T/R/B.
void swrText_SetEntryClipRect_delta(int *rect) {
    const int count = swrTextEntries1Count;
    if (count <= 0 || count >= 0x80 || rect == NULL)
        return;

    int *clip = swrTextEntries1ClipRect[count];
    int *clip_enabled = swrTextEntries1ClipEnabled;

    int left, top, right, bottom;
    if (ui_enabled() && swrDisplay_screenWidth > 0 && swrDisplay_screenHeight > 0) {
        // Uniform 640-space scale on all four edges so the clip box matches the now-uniform text
        // (and scales with the ui_scale slider). clipY already used screen_height/480 in vanilla;
        // only clipX changes (was the stretched screen_width/640). The centering offset shifts the
        // box's X edges right by the same amount the text moved, so clipped text stays inside it.
        float s = ui_layout_scale();
        float off = ui_center_offset_px();
        left = (int) ((float) rect[0] * s + off);
        top = (int) ((float) rect[1] * s);
        right = (int) ((float) rect[2] * s + off);
        bottom = (int) ((float) rect[3] * s);
    } else {
        // Vanilla: L/R * screen_width/640, T/B * screen_height/480 (integer, truncated toward zero).
        left = (int) ((int64_t) rect[0] * swrDisplay_screenWidth / 640);
        top = (int) ((int64_t) rect[1] * swrDisplay_screenHeight / 480);
        right = (int) ((int64_t) rect[2] * swrDisplay_screenWidth / 640);
        bottom = (int) ((int64_t) rect[3] * swrDisplay_screenHeight / 480);
    }

    clip_enabled[count] = 1;
    clip[0] = left;
    clip[1] = top;
    clip[2] = right;
    clip[3] = bottom;
}
