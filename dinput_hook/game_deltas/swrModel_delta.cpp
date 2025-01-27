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

unsigned char *texture_font0 = nullptr;
unsigned char *texture_font1 = nullptr;
unsigned char *texture_font2 = nullptr;
unsigned char *texture_font3 = nullptr;
unsigned char *texture_font4 = nullptr;

// 0x0042d720
void swrModel_LoadFonts_delta(void) {
    int i = 0;
    uint8_t *palette;
    swrMaterial **texture_material;

    // TODO: read font file data from asset and patch the pointer accordingly
    //  off = PatchTextureTable(off, 0x4BF91C, 0x42D745, 0x42D753, 512, 1024, "font0");
    //         off = PatchTextureTable(off, 0x4BF7E4, 0x42D786, 0x42D794, 512, 1024, "font1");
    //         off = PatchTextureTable(off, 0x4BF84C, 0x42D7C7, 0x42D7D5, 512, 1024, "font2");
    //         off = PatchTextureTable(off, 0x4BF8B4, 0x42D808, 0x42D816, 512, 1024, "font3");
    //         off = PatchTextureTable(off, 0x4BF984, 0x42D849, 0x42D857, 512, 1024, "font4");

    //  off = PatchTextureTable(off, 0x4BF91C,  _, "font0");
    //         off = PatchTextureTable(off, 0x4BF7E4, _, "font1");
    //         off = PatchTextureTable(off, 0x4BF84C, _, "font2");
    //         off = PatchTextureTable(off, 0x4BF8B4, _, "font3");
    //         off = PatchTextureTable(off, 0x4BF984, _, "font4");

    // int width, height, nrChannels;
    // unsigned char *data =
    //     stbi_load("./assets/textures/fonts/font0_0.png", &width, &height, &nrChannels, 4);
    // if (data == NULL) {
    //     assert(false && "Couldnt read font_0_0");
    // }

    // if (texture_font0 != nullptr) {
    //     stbi_image_free(texture_font0);
    //     texture_font0 = nullptr;
    // }

    // texture_font0 = data;
    // Lets leak
    // stbi_image_free(data);

    // count = 1
    // read font_0 to buffer and write font_0_data_ptr to the address below
    // use our own pointer instead
    texture_material = (swrMaterial **) (0x004bf920);
    // texture_material = (swrMaterial **) &texture_font0;
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1024, 512, 1024, texture_material, &palette,
                                            1, 0);

    // count = 3
    texture_material = (swrMaterial **) (0x004bf7e8);// [0]
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1024, 512, 1024, texture_material, &palette,
                                            1, 0);
    texture_material = (swrMaterial **) (0x004bf7e8 + 4);// [1]
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1025, 512, 1024, texture_material, &palette,
                                            1, 0);
    texture_material = (swrMaterial **) (0x004bf7e8 + 8);// [2]
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1025, 512, 1024, texture_material, &palette,
                                            1, 0);

    // count = 1
    texture_material = (swrMaterial **) (0x004bf850);
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1025, 512, 1024, texture_material, &palette,
                                            1, 0);

    // count = 1
    texture_material = (swrMaterial **) (0x004bf8b8);
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1025, 512, 1024, texture_material, &palette,
                                            1, 0);

    // count = 1
    texture_material = (swrMaterial **) (0x004bf988);
    swrModel_ConvertTextureDataToRdMaterial(3, 0, 512, 1025, 512, 1024, texture_material, &palette,
                                            1, 0);

    // number of fonts in font table
    int *p = (int *) (0x0050c0c0);
    *p = 7;
    // font items
    // struct { i32 unk, i32 nbSprites, data_ptrs[] };
    p = (int *) (0x00e99720);
    *p = 0x004bf918;
    p = (int *) (0x0099724);
    *p = 0x004bf8b0;
    p = (int *) (0x0099728);
    *p = 0x004bf848;
    p = (int *) (0x009972c);
    *p = 0x004bf8b0;
    p = (int *) (0x0099730);
    *p = 0x004bf980;
    p = (int *) (0x0099734);
    *p = 0x004bf918;
    p = (int *) (0x0099738);
    *p = 0x004bf7e0;
    p = (int *) (0x0050c0c4);
    *p = 0x004bf918;

    return;
}

typedef void (*Original_ConvertTextureDataToRdMaterial)(int texture_type_a, int texture_type_b,
                                                        int orig_width, int orig_height, int width,
                                                        int height, swrMaterial **texture_data_ptr,
                                                        uint8_t **palette_ptr, char flipSomething,
                                                        char adjustWidthHeightFlag);

// width * height / 2 bytes
constexpr const int width = 512;
constexpr const int height = 1024;
uint8_t buffer[width * height / 2];

void swrModel_LoadFonts_delta2(void) {
    int i;
    swrMaterial **material;
    swrMaterial **material2;
    swrMaterial **material3;
    uint8_t *palette;

    Original_ConvertTextureDataToRdMaterial converter =
        (Original_ConvertTextureDataToRdMaterial) 0x00445ee0;

    stbi_set_flip_vertically_on_load(false);

    int widthRead;
    int heightRead;
    int nbChannels;
    unsigned char *data = stbi_load(
        "./assets/textures/fonts/font0_0.png", &widthRead, &heightRead,
        //                                 &nbChannels, STBI_rgb_alpha);
        // unsigned char *data = stbi_load("./assets/textures/fonts/font0_0.png", &widthRead, &heightRead,
        &nbChannels, STBI_rgb_alpha);
    if (data == NULL) {
        assert(false && "Could not find font0_0.png");
    }

    assert(widthRead == width && "font0_0.png does not have a width of 512");
    assert(heightRead == height && "font0_0.png does not have a height of 1024");
    assert(nbChannels == 4 && "font0_0.png does not have 4 channels");

    size_t k = 0;
    size_t l = 0;
    // read pixels 2 by 2 to pack them in a single byte, since the format is 4-bit greyscale
    for (size_t j = 0; j < width * height * nbChannels; j += 2 * nbChannels) {
        uint8_t gray1 = (data[j + 0] + data[j + 1] + data[j + 2]) / 3;
        uint8_t gray2 = (data[j + 4] + data[j + 5] + data[j + 6]) / 3;
        // Ignore 3rd and 7th values (alphas)

        // Divide by 16 (<=> & 0xF0) to get from 8 bits to 4 bits, then shift to be on the left or the right
        buffer[k] = (gray1 & 0xF0) | ((gray2 & 0xF0) >> 4);
        k += 1;
    }

    stbi_image_free(data);

    i = 0;
    palette = NULL;

    (*(swrMaterial **) 0x004bf920) = (swrMaterial *) &(buffer[0]);
    material = (swrMaterial **) 0x004bf920;
    converter(3, 0, width, height, width, height, material, &palette, 1, 0);

    material2 = (swrMaterial **) 0x004bf7e8;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material2, &palette, 1, 0);
    material2 = (swrMaterial **) 0x004bf7ec;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material2, &palette, 1, 0);
    material2 = (swrMaterial **) 0x004bf7f0;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material2, &palette, 1, 0);

    material2 = (swrMaterial **) 0x004bf850;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material2, &palette, 1, 0);

    material3 = (swrMaterial **) 0x004bf8b8;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material3, &palette, 1, 0);

    material2 = (swrMaterial **) 0x004bf988;
    converter(3, 0, 0x40, 0x80, 0x40, 0x80, material2, &palette, 1, 0);

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
