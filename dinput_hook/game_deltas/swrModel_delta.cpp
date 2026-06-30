#include "swrModel_delta.h"
#include "glad/glad.h"

#include <vector>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <format>

#include "../hook_helper.h"
#include "../node_utils.h"
#include "../stb_image.h"
#include "../custom_tracks.h"
#include "../nv_dds/nv_dds.h"
#include "../imgui_utils.h"
#include "../patch.h"

#include <regex>

extern "C" {
#include <Swr/swrModel.h>
#include <Swr/swrSprite.h>
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
        swrMaterial *builtin = *page;                       // built-in material (set by the original)
        *page = (swrMaterial *) kHdFontSlots[i].buffer;     // point at HD data, then convert in place
        converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, page, &palette,
                  1, 0);
        g_hdFontMaterial[i] = *page;                        // remember the converted HD material
        *page = builtin;                                    // leave the live slot on the built-in
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