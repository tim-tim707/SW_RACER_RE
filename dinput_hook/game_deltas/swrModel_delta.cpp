#include "swrModel_delta.h"

#include <vector>
#include <algorithm>
#include <cassert>
#include <cstring>

#include "../hook_helper.h"
#include "../node_utils.h"
#include "../stb_image.h"

extern "C" {
#include <Swr/swrModel.h>
#include <Swr/swrSprite.h>
#include <Swr/swrAssetBuffer.h>
}

#include <globals.h>
#include <macros.h>

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

// 0x0042d720
void swrModel_LoadFonts_delta(void) {
    int i;
    swrMaterial **material;
    swrMaterial **material2;
    swrMaterial **material3;
    uint8_t *palette;

    Original_ConvertTextureDataToRdMaterial converter =
        (Original_ConvertTextureDataToRdMaterial) 0x00445ee0;

    // Added
    if (readFontToBuffer(font_0_0_buffer, "./assets/textures/fonts/font0_0.png") != 0) {
        assert(false && "Could not read font at ./assets/textures/fonts/font0_0.png");
    }

    if (readFontToBuffer(font_1_0_buffer, "./assets/textures/fonts/font1_0.png") != 0) {
        assert(false && "Could not read font at ./assets/textures/fonts/font1_0.png");
    }
    if (readFontToBuffer(font_1_1_buffer, "./assets/textures/fonts/font1_1.png") != 0) {
        assert(false && "Could not read font at ./assets/textures/fonts/font1_1.png");
    }
    if (readFontToBuffer(font_1_2_buffer, "./assets/textures/fonts/font1_2.png") != 0) {
        assert(false && "Could not read font at ./assets/textures/fonts/font1_2.png");
    }

    if (readFontToBuffer(font_4_0_buffer, "./assets/textures/fonts/font4_0.png") != 0) {
        assert(false && "Could not read font at ./assets/textures/fonts/font4_0.png");
    }

    fprintf(hook_log, "Loaded all replacement fonts\n");
    fflush(hook_log);

    i = 0;
    palette = NULL;

    // Notice that font_1_2 is the same as font_2_0 and font_3_0

    (*(swrMaterial **) 0x004bf920) = (swrMaterial *) &(font_0_0_buffer[0]);
    material = (swrMaterial **) 0x004bf920;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material,
              &palette, 1, 0);

    (*(swrMaterial **) 0x004bf7e8) = (swrMaterial *) &(font_1_0_buffer[0]);
    material2 = (swrMaterial **) 0x004bf7e8;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material2,
              &palette, 1, 0);
    (*(swrMaterial **) 0x004bf7ec) = (swrMaterial *) &(font_1_1_buffer[0]);
    material2 = (swrMaterial **) 0x004bf7ec;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material2,
              &palette, 1, 0);
    (*(swrMaterial **) 0x004bf7f0) = (swrMaterial *) &(font_1_2_buffer[0]);
    material2 = (swrMaterial **) 0x004bf7f0;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material2,
              &palette, 1, 0);

    (*(swrMaterial **) 0x004bf850) = (swrMaterial *) &(font_1_2_buffer[0]);
    material2 = (swrMaterial **) 0x004bf850;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material2,
              &palette, 1, 0);

    (*(swrMaterial **) 0x004bf8b8) = (swrMaterial *) &(font_1_2_buffer[0]);
    material3 = (swrMaterial **) 0x004bf8b8;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material3,
              &palette, 1, 0);

    (*(swrMaterial **) 0x004bf988) = (swrMaterial *) &(font_4_0_buffer[0]);
    material2 = (swrMaterial **) 0x004bf988;
    converter(3, 0, HD_FONT_WIDTH, HD_FONT_HEIGHT, HD_FONT_WIDTH, HD_FONT_HEIGHT, material2,
              &palette, 1, 0);

    (*(int *) 0x0050c0c0) = 7;
    (*(int *) 0x00e99720) = 0x004bf918;
    (*(int *) 0x00e99724) = 0x004bf8b0;
    (*(int *) 0x00e99728) = 0x004bf848;
    (*(int *) 0x00e9972c) = 0x004bf8b0;
    (*(int *) 0x00e99730) = 0x004bf980;
    (*(int *) 0x00e99734) = 0x004bf918;
    (*(int *) 0x00e99738) = 0x004bf7e0;
    (*(int *) 0x0050c0c4) = 0x004bf918;
    return;
}

// We don't have the original function decompiled properly yet
swrModel_Header *swrModel_LoadFromId_delta(MODELID id) {
    char *model_asset_pointer_begin = swrAssetBuffer_GetBuffer();
    auto header = hook_call_original(swrModel_LoadFromId, id);
    char *model_asset_pointer_end = swrAssetBuffer_GetBuffer();

    // remove all models whose asset pointer is invalid:
    std::erase_if(asset_pointer_to_model, [&](const auto &elem) {
        return elem.asset_pointer_begin >= model_asset_pointer_begin;
    });

    asset_pointer_to_model.emplace_back() = {
        model_asset_pointer_begin,
        model_asset_pointer_end,
        id,
    };

    return header;
}

// Cleanup
#undef HD_FONT_WIDTH
#undef HD_FONT_HEIGHT
