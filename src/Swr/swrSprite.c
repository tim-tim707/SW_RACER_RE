#include "swrSprite.h"

#include "macros.h"
#include "globals.h"
#include "engine_config.h"
#include "swr.h"
#include "swrLoader.h"
#include "swrAssetBuffer.h"
#include "swrUI.h"
#include "swrObj.h"
#include "swrText.h"
#include "swrModel.h"
#include "swrRender.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <General/utils.h>
#include <General/stdMath.h>

#include <Engine/rdMaterial.h>
#include <Platform/std3D.h>
#include <Raster/rdCache.h>
#include <Win95/stdConsole.h>

extern swrSpriteTexture* FUN_00445b40();

// 0x004081e0
void swrSprite_SetCursorVisibility2(int visibility)
{
    if (visibility != 0)
    {
        swrSprite_mouseVisible = swrSprite_mouseVisible + 1;
        return;
    }
    swrSprite_mouseVisible = swrSprite_mouseVisible + -1;
}

// 0x00408200
bool swrSprite_IsCursorVisible(void)
{
    return 0 < swrSprite_mouseVisible;
}

// 0x00408210
void swrSprite_SetCursorVisibility(int visible)
{
    swrSprite_mouseVisible = visible;
}

// 0x00408220
void swrSprite_DisplayCursor(void)
{
    int x;
    int y;

    if (swrSprite_mouseVisible < 1) {
        swrSprite_SetVisible(swrUISprite_d_cursor_rgb_0, 0);
    } else if (stdConsole_GetCursorPos(&x, &y) != 0) {
        swrSprite_SetPos(swrUISprite_d_cursor_rgb_0, x, y);
        swrSprite_SetDim(swrUISprite_d_cursor_rgb_0, 1.0f, 1.0f);
        swrSprite_SetColor(swrUISprite_d_cursor_rgb_0, 0xff, 0xff, 0xff, 0xff);
        swrSprite_SetVisible(swrUISprite_d_cursor_rgb_0, 1);
        swrSprite_SetFlag(swrUISprite_d_cursor_rgb_0, 0x800);
        swrSprite_SetFlag(swrUISprite_d_cursor_rgb_0, 0x10000);
    }
}

// Bytes per element for a TGA bit depth (pixel or colormap entry).
static int swrSprite_TgaBytesPerElement(uint8_t bits)
{
    if (bits <= 8)
        return 1;
    if (bits <= 16)
        return 2;
    return (bits > 24) + 3;
}

// Loads an uncompressed or RLE TGA as a one-page sprite texture, tiles it and assigns it to sprite id.
// The image-id field is never skipped (TGAs used by the game have none).
// 0x004114d0
swrSpriteTexture* swrSprite_GetTextureFromTGA(char* filename_tga, int id)
{
    swrSpriteTextureHeader* tex = NULL;
    swrSpriteTexturePage* page = NULL;
    void* pixels = NULL;
    uint8_t header[SWR_TGA_HEADER_SIZE];
    stdFile_t file;
    int bytesPerPixel;
    int width, height;
    size_t size;
    swrSpriteTexture* tiled;

    if (filename_tga == NULL)
        return NULL;
    file = stdPlatform_hostServices_ptr->fileOpen(filename_tga, "rb");
    if (file == 0)
        goto fail;
    stdPlatform_hostServices_ptr->fileRead(file, header, SWR_TGA_HEADER_SIZE);
    tex = (swrSpriteTextureHeader*)malloc(sizeof(swrSpriteTextureHeader));
    if (tex == NULL)
        goto fail;
    memset(tex, 0, sizeof(swrSpriteTextureHeader));
    page = (swrSpriteTexturePage*)malloc(sizeof(swrSpriteTexturePage));
    if (page == NULL)
        goto fail;
    memset(page, 0, sizeof(swrSpriteTexturePage));

    // skip the colormap: length (bytes 5-6) * entry size (byte 7)
    stdPlatform_hostServices_ptr->fseek(file, (header[5] | (header[6] << 8)) * swrSprite_TgaBytesPerElement(header[7]), SEEK_CUR);
    width = header[12] | (header[13] << 8);
    height = header[14] | (header[15] << 8);
    bytesPerPixel = swrSprite_TgaBytesPerElement(header[16]);
    size = bytesPerPixel * height * width;
    pixels = malloc(size);
    if (header[2] < SWR_TGA_IMAGE_TYPE_RLE_FIRST)
        stdPlatform_hostServices_ptr->fileRead(file, pixels, size);
    else
        swrSprite_ReadTgaRLEData(file, pixels, bytesPerPixel, height * width);
    stdPlatform_hostServices_ptr->fileClose(file);

    tex->page_table = page;
    tex->width = width;
    tex->height = height;
    tex->page_count = 1;
    tex->unk6 = height;
    tex->palette_offset = 0;
    tex->format = 5;
    switch (bytesPerPixel) {
    case 1:
        tex->page_width_align = 1;
        break;
    case 2:
        tex->page_width_align = 2;
        break;
    case 3:
        tex->page_width_align = 7;
        break;
    case 4:
        tex->page_width_align = 3;
        break;
    default:
        goto fail;
    }
    page->offset = (uint32_t)pixels;
    page->width = width;
    page->height = height;
    tiled = (swrSpriteTexture*)swrModel_SplitTextureIntoTiles(tex, bytesPerPixel);
    swrSprite_AssignTextureToId(tiled, id, 1);
    return tiled;

fail:
    if (tex != NULL)
        free(tex);
    if (page != NULL)
        free(page);
    if (pixels != NULL)
        free(pixels);
    if (file != 0)
        stdPlatform_hostServices_ptr->fileClose(file);
    return NULL;
}

// 0x00411720
int swrUI_IsTextEntryActive(void)
{
    return swrUI_textEntryActive;
}

// 0x00412650
void swrSprite_LoadAllSprites(void)
{
    if (SpritesLoaded)
        swrSprite_UnloadAllSprites();
    swrSprite_LoadFromId(swrSprite_lightstar_glowstar_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_topbtm_light_blue_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_as_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_tee_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_seb_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_rat_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_ald_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_maw_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_bum_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_wan_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_mar_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_ebe_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_dud_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_gas_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_clegg_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_elan_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_neeva_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_boz_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_boles_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_ody_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_fud_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_ben_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_slide_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_toy_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_flag_bullseye_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_anakin_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_teemto_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_sebulba_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_ratts_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_aldar_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_mawhonic_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_bumpy_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_wan_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_mars_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_ebe_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_dud_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_gasgano_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_clegg_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_elan_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_neva_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_bozzie_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_boles_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_ody_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_fud_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_ben_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_slide_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_toy_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_int_bullseye_rgb, NULL);
    swrSprite_LoadFromId(swrSprite_sq_brdr_b, "sq_brdr_b");
    swrSprite_LoadFromId(swrSprite_sq_brdr_bl, "sq_brdr_bl");
    swrSprite_LoadFromId(swrSprite_sq_brdr_br, "sq_brdr_br");
    swrSprite_LoadFromId(swrSprite_sq_brdr_l, "sq_brdr_l");
    swrSprite_LoadFromId(swrSprite_sq_brdr_r, "sq_brdr_r");
    swrSprite_LoadFromId(swrSprite_sq_brdr_t, "sq_brdr_t");
    swrSprite_LoadFromId(swrSprite_sq_brdr_tl, "sq_brdr_tl");
    swrSprite_LoadFromId(swrSprite_sq_brdr_tr, "sq_brdr_tr");
    swrSprite_LoadFromId(swrSprite_radio_unchecked, "radio_unchecked");
    swrSprite_LoadFromId(swrSprite_radio_checked, "radio_checked");
    swrSprite_LoadFromId(swrSprite_axis_check_circ, "axis_check_circ");
    swrSprite_LoadFromId(swrSprite_axis_check_circ_selected, "axis_check_circ_selected");
    swrSprite_LoadFromId(swrSprite_tiny_box, "tiny_box");
    swrSprite_LoadFromId(swrSprite_tiny_box_selected, "tiny_box_selected");
    swrSprite_LoadFromId(swrSprite_axis_check_center, "axis_check_center");
    swrSprite_LoadFromId(swrSprite_axis_check_end, "axis_check_end");
    swrSprite_LoadFromId(swrSprite_axis_check_strch, "axis_check_strch");
    swrSprite_LoadFromId(swrSprite_window_end, "window_end");
    swrSprite_LoadFromId(swrSprite_window_strchbars, "window_strchbars");
    swrSprite_LoadFromId(swrSprite_window_end_selected, "window_end_selected");
    swrSprite_LoadFromId(swrSprite_window_strchbars_selected, "window_strchbars_selected");
    swrSprite_LoadFromId(swrSprite_ok_button, "ok_button");
    swrSprite_LoadFromId(swrSprite_ok_button_selected, "ok_button_selected");
    swrSprite_LoadFromId(swrSprite_sml_window_end, "sml_window_end");
    swrSprite_LoadFromId(swrSprite_sml_window_strch, "sml_window_strch");
    swrSprite_LoadFromId(swrSprite_sml_window_end_selected, "sml_window_end_selected");
    swrSprite_LoadFromId(swrSprite_sml_window_strch_selected, "sml_window_strch_selected");
    swrSprite_LoadFromId(swrSprite_settings_btn_end, "settings_btn_end");
    swrSprite_LoadFromId(swrSprite_settings_btn_strch_end, "settings_btn_strch_end");
    swrSprite_LoadFromId(swrSprite_settings_btn_end2, "settings_btn_end2");
    swrSprite_LoadFromId(swrSprite_settings_btn_strch_selected, "settings_btn_strch_selected");
    swrSprite_LoadFromId(swrSprite_settings_btn_end_selected, "settings_btn_end_selected");
    swrSprite_LoadFromId(swrSprite_settings_btn_end2_selected, "settings_btn_end2_selected");
    swrSprite_LoadFromId(swrSprite_settings_btnback_end, "settings_btnback_end");
    swrSprite_LoadFromId(swrSprite_edit_window_corner, "edit_window_corner");
    swrSprite_LoadFromId(swrSprite_edit_window_vert, "edit_window_vert");
    swrSprite_LoadFromId(swrSprite_edit_window_hor, "edit_window_hor");
    swrSprite_LoadFromId(swrSprite_edit_window_bar_end, "edit_window_bar_end");
    swrSprite_LoadFromId(swrSprite_edit_window_bar_strch, "edit_window_bar_strch");
    swrSprite_LoadFromId(swrSprite_edit_window_bar_end_selected, "edit_window_bar_end_selected");
    swrSprite_LoadFromId(swrSprite_edit_windowbar_strch_selected, "edit_window_bar_strch_selected");
    swrSprite_LoadFromId(swrSprite_sml_edit_box_corner, "sml_edit_box_corner");
    swrSprite_LoadFromId(swrSprite_sml_edit_box_left, "sml_edit_box_left");
    swrSprite_LoadFromId(swrSprite_sml_edit_box_bottom, "sml_edit_box_bottom");
    swrSprite_LoadFromId(swrSprite_edit_window_selected_end, "edit_window_selected_end");
    swrSprite_LoadFromId(swrSprite_edit_window_selected_strch, "edit_window_selected_strch");
    swrSprite_LoadFromId(swrSprite_editwindow_segmented, "editwindow_segmented");
    swrSprite_LoadFromId(swrSprite_editwindow_segmented_selected, "editwindow_segmented_selected");
    swrSprite_LoadFromId(swrSprite_segment, "segment");
    swrSprite_LoadFromId(swrSprite_segment_selected, "segment_selected");
    swrSprite_LoadFromId(swrSprite_undrline_tab, "undrline_tab");
    swrSprite_LoadFromId(swrSprite_undrline_mid_strch, "undrline_mid_strch");
    swrSprite_LoadFromId(swrSprite_undrline_corner, "undrline_corner");
    swrSprite_LoadFromId(swrSprite_sml_undrline_tab, "sml_undrline_tab");
    swrSprite_LoadFromId(swrSprite_sml_undrline_strch, "sml_undrline_strch");
    swrSprite_LoadFromId(swrSprite_sml_undrline_corner, "sml_undrline_corner");
    swrSprite_LoadFromId(swrSprite_sliderbar_end, "sliderbar_end");
    swrSprite_LoadFromId(swrSprite_sliderbar_strch, "sliderbar_strch");
    swrSprite_LoadFromId(swrSprite_sliderbar_end_selected, "sliderbar_end_selected");
    swrSprite_LoadFromId(swrSprite_sliderbar_strch_selected, "sliderbar_strch_selected");
    swrSprite_LoadFromId(swrSprite_vsliderbar_end, "vsliderbar_end");
    swrSprite_LoadFromId(swrSprite_vsliderbar_strch, "vsliderbar_strch");
    swrSprite_LoadFromId(swrSprite_vslider_end_selected, "vsliderbar_end_selected");
    swrSprite_LoadFromId(swrSprite_vslider_strch_selected, "vsliderbar_strch_selected");
    swrSprite_LoadFromId(swrSprite_slider_bracket, "slider_bracket");
    swrSprite_LoadFromId(swrSprite_slider_gradient, "slider_gradient");
    swrSprite_LoadFromId(swrSprite_slider_plus, "slider_plus");
    swrSprite_LoadFromId(swrSprite_slider_minus, "slider_minus");
    swrSprite_LoadFromId(swrSprite_slider_point, "slider_point");
    swrSprite_LoadFromId(swrSprite_slider_point_center, "slider_point_center");
    swrSprite_LoadFromId(swrSprite_hline, "hline");
    swrSprite_LoadFromId(swrSprite_bline, "vline");
    swrSprite_LoadFromId(swrSprite_branch, "branch");
    swrSprite_LoadFromId(swrSprite_background, "background");
    swrSprite_NewSprite(250, swrSprite_GetTextureFromTGA("data\\images\\background.tga", 250));
    swrSprite_NewSprite(249, swrSprite_LoadTextureById(swrSprite_d_cursor_rgb));
    SpritesLoaded = 1;
}

// 0x00412e20 TODO: crashes on release, works fine on debug
void swrSprite_UnloadAllSprites(void)
{
    swrUI_ClearAllSprites(swrUI_unk_ptr);
    swrSprite_FreeSprites();
    SpritesLoaded = 0;
}

// 0x00412e90 TODO; crashes on release, works fine on debug
int swrSprite_LoadFromId(swrSprite_NAME id, char* tga_file_optional)
{
    swrSpriteTexture* texture;
    char filepath[1024];

    texture = swrSprite_GetTextureFromId(id);
    if (texture == NULL)
    {
        if (tga_file_optional != NULL)
        {
            sprintf(filepath, "%s\\%s.tga", "data\\images", tga_file_optional);
            swrSprite_GetTextureFromTGA(filepath, id);
            return 1;
        }
        texture = swrSprite_LoadTextureById(id);
        if (texture == NULL)
        {
            return 0;
        }
        swrSprite_AssignTextureToId(texture, id, 0);
    }
    return 1;
}

// 0x00412f20
int swrSprite_CreateFromTextureId(int textureId)
{
    swrSpriteTexture* tex;
    int id;

    tex = swrSprite_GetTextureFromId(textureId);
    if (tex == NULL) {
        return 0;
    }
    id = swrSprite_FindFreeId();
    if (id == 0) {
        return 0;
    }
    swrSprite_NewSprite((short)id, tex);
    return id;
}

// 0x00412f60
void swrSprite_ClearSprites(swrUI_unk* swrui_unk)
{
    int* id;
    int i;

    i = 0;
    if (0 < swrui_unk->sprite_count)
    {
        id = &swrui_unk->ui_elements[0].sprite_ingameId;
        do
        {
            if ((0xfa < (unsigned int)*id) && ((unsigned int)*id < 400))
            {
                swrSprite_NewSprite(*(short*)id, NULL);
                *id = 0;
            }
            i = i + 1;
            id = id + 0xe;
        } while (i < swrui_unk->sprite_count);
    }
}

// 0x00416fd0
void swrSprite_AssignTextureToId(swrSpriteTexture* spriteTex, int id, int from_tga)
{
    swrSpriteTexItem* texItems;
    int* texIsTGA;

    texIsTGA = swrSpriteTexIsTGA;
    texItems = swrSpriteTexItems;
    do {
        if (texItems->texture == NULL) {
            texItems->texture = spriteTex;
            texItems->id = id;
            *texIsTGA = from_tga;
            return;
        }
        texItems = texItems + 1;
        texIsTGA = texIsTGA + 1;
    } while (texItems < swrSpriteTexItems + (sizeof(swrSpriteTexItems) / sizeof(swrSpriteTexItems[0])));
}

// 0x00417010
swrSpriteTexture* swrSprite_GetTextureFromId(int id)
{
    swrSpriteTexItem* texItems;

    texItems = swrSpriteTexItems;
    do {
        if (texItems->id == id)
            return texItems->texture;
        texItems = texItems + 1;
    } while (texItems < swrSpriteTexItems + (sizeof(swrSpriteTexItems) / sizeof(swrSpriteTexItems[0])));
    return NULL;
}

// 0x00417040
int swrSprite_FindFreeId(void)
{
    int id;

    for (id = SWR_SPRITE_DYNAMIC_FIRST; id < SWR_SPRITE_DYNAMIC_END; id++) {
        if (swrSprite_array[id].texture == NULL) {
            return id;
        }
    }
    return 0;
}

// 0x00417120 TODO: crashes on release, works fine on debug
void swrSprite_GetTextureDimFromId(swrSprite_NAME spriteId, int* out_width, int* out_height)
{
    swrSpriteTexture* tmp;

    tmp = swrSprite_GetTextureFromId(spriteId);
    if (tmp != NULL)
    {
        if (out_width != NULL)
        {
            *out_width = (int)(short)(tmp->header).width;
        }
        if (out_height != NULL)
        {
            *out_height = (int)(short)(tmp->header).height;
        }
    }
}

// 0x00417090 TODO: crashes on game startup
void swrSprite_FreeSprites(void)
{
    swrSpriteTexItem* texItems;
    uint32_t* page_offset;
    unsigned int page_count;
    int* texIsTGA;
    swrSpriteTexture* texture;

    texIsTGA = swrSpriteTexIsTGA;
    texItems = swrSpriteTexItems;
    do
    {
        if ((*texIsTGA != 0) && (texture = texItems->texture, texture != NULL))
        {
            page_count = 0;
            if ((texture->header).page_count != 0)
            {
                page_offset = &((texture->header).page_table)->offset;
                do
                {
                    rdMaterial_Free((RdMaterial*)*page_offset);
                    page_offset = page_offset + 2;
                    page_count = page_count + 1;
                } while (page_count < (unsigned int)(int)(short)(texture->header).page_count);
            }
            free((texture->header).page_table);
            free(texture);
        }
        texItems->texture = NULL;
        texItems->id = 0;
        *texIsTGA = 0;
        texItems = texItems + 1;
        texIsTGA = texIsTGA + 1;
    } while (texItems < swrSpriteTexItems + (sizeof(swrSpriteTexItems) / sizeof(swrSpriteTexItems[0])));
}

// 0x00417150 TODO: Crashes on release, works fine on debug
void swrSprite_GetBBoxFromId(swrSprite_NAME spriteId, swrSprite_BBox* box)
{
    unsigned int* out_height;
    unsigned int* out_width;

    if (box != NULL)
    {
        out_height = &box->x2;
        out_width = &box->y2;
        box->y = 0;
        box->x = 0;
        *out_height = 0;
        *out_width = 0;
        swrSprite_GetTextureDimFromId(spriteId, (int*)out_width, (int*)out_height);
        *out_width = *out_width - 1;
        *out_height = *out_height - 1;
    }
}

// 0x004172c0
int swrSprite_IsInsideBBox(swrSprite_BBox* bbox, int x, int y)
{
    if (((((int)bbox->x <= x) && (x <= (int)bbox->x2)) && ((int)bbox->y <= y)) && (y <= (int)bbox->y2))
    {
        return 1;
    }
    return 0;
}

// 0x00417900
void swrSprite_MoveBBoxTo(swrSprite_BBox* box, int newX, int newY)
{
    unsigned int tmpx;
    unsigned int tmpy;

    if (box != NULL)
    {
        tmpx = box->y;
        tmpy = box->x;
        box->x = newX;
        box->y = newY;
        box->x2 = (box->x2 - tmpy) + newX;
        box->y2 = (box->y2 - tmpx) + newY;
    }
}

// 0x00417f00
void swrSprite_BBoxFit(swrSprite_BBox* bboxSmaller, swrSprite_BBox* bboxLarger)
{
    if ((bboxSmaller != NULL) && (bboxLarger != NULL))
    {
        if ((int)bboxSmaller->x < (int)bboxLarger->x)
        {
            bboxSmaller->x = bboxLarger->x;
        }
        if ((int)bboxSmaller->y < (int)bboxLarger->y)
        {
            bboxSmaller->y = bboxLarger->y;
        }
        if ((int)bboxLarger->x2 < (int)bboxSmaller->x2)
        {
            bboxSmaller->x2 = bboxLarger->x2;
        }
        if ((int)bboxLarger->y2 < (int)bboxSmaller->y2)
        {
            bboxSmaller->y2 = bboxLarger->y2;
        }
    }
}

// 0x0041a9a0
void swrSprite_MoveBBox(swrSprite_BBox* bbox_dest, swrSprite_BBox* bbox_src, int bMoveX, int bMoveY)
{
    if ((bbox_dest != NULL) && (bbox_src != NULL))
    {
        if (bMoveX != 0)
        {
            swrSprite_MoveBBoxTo(bbox_dest, ((int)(((bbox_src->x2 - bbox_dest->x2) + bbox_dest->x) - bbox_src->x) >> 1) + bbox_src->x, bbox_dest->y);
        }
        if (bMoveY != 0)
        {
            swrSprite_MoveBBoxTo(bbox_dest, bbox_dest->x, ((int)(((bbox_dest->y + bbox_src->y2) - bbox_dest->y2) - bbox_src->y) >> 1) + bbox_src->y);
        }
    }
}

// 0x0041aa10
void swrSprite_TranslateBBox(swrSprite_BBox* bbox, int x, int y)
{
    if (bbox != NULL)
    {
        bbox->x = bbox->x + x;
        bbox->x2 = bbox->x2 + x;
        bbox->y = bbox->y + y;
        bbox->y2 = bbox->y2 + y;
    }
}

// 0x00428030
void swrSprite_Draw2(swrSprite* a1, int a2, float a3, float a4)
{
    unsigned int flags;
    unsigned int drawFlags;

    if (swrViewport_force320x240 != 0)
        return;
    flags = a1->flags;
    if ((flags & swrSprite_FLAGS_VISIBLE) == 0 || (flags & a2) == 0)
        return;

    if (a1->texture == NULL) {
        // a is sign-extended before the compare, so the a >= 0xff branch is unreachable
        if ((int8_t)a1->a < 0xff) {
            swrSprite_Draw1(NULL, (int)(a1->x * a3), (int)(a1->y * a4), a1->width * a3 * 0.0625f, a1->height * a4, 0.0f, 0, 0, swrSprite_DRAWFLAGS_UNK_2, a1->r, a1->g, a1->b, a1->a);
            return;
        }
        swrSprite_Draw1(NULL, (int)(a1->x * a3), (int)(a1->y * a4), a1->width * a3 * 0.0625f, a1->height * a4, 0.0f, 0, 0, swrSprite_DRAWFLAGS_TEXTURED, a1->r, a1->g, a1->b, 0xff);
        return;
    }

    drawFlags = 0;
    if (flags & swrSprite_FLAGS_Z_OFFSET)
        drawFlags = swrSprite_DRAWFLAGS_Z_OFFSET;
    if ((a2 & swrSprite_FLAGS_PASS_1) == 0)
        drawFlags &= ~swrSprite_DRAWFLAGS_Z_OFFSET;
    if (flags & swrSprite_FLAGS_UNK_10)
        drawFlags |= swrSprite_DRAWFLAGS_UNK_8000;
    if ((int8_t)a1->a != 0xff || (flags & swrSprite_FLAGS_TRANSLUCENT))
        drawFlags |= swrSprite_DRAWFLAGS_TRANSLUCENT;
    if (flags & swrSprite_FLAGS_CENTERED)
        drawFlags |= swrSprite_DRAWFLAGS_CENTERED;
    if (flags & swrSprite_FLAGS_MIRROR_X)
        drawFlags |= swrSprite_DRAWFLAGS_FLIP_X;
    if (flags & swrSprite_FLAGS_MIRROR_Y)
        drawFlags |= swrSprite_DRAWFLAGS_FLIP_Y;
    if (flags & swrSprite_FLAGS_UNK_40)
        drawFlags |= swrSprite_DRAWFLAGS_UNK_10000;
    if (flags & swrSprite_FLAGS_CLAMP_UV)
        drawFlags |= swrSprite_DRAWFLAGS_CLAMP_U | swrSprite_DRAWFLAGS_CLAMP_V;
    if (flags & swrSprite_FLAGS_ROTATED)
        drawFlags |= swrSprite_DRAWFLAGS_ROTATED;
    if (flags & swrSprite_FLAGS_TEXTURED)
        drawFlags |= swrSprite_DRAWFLAGS_TEXTURED;
    if (flags & swrSprite_FLAGS_HIDDEN)
        drawFlags |= swrSprite_DRAWFLAGS_HIDDEN;
    if (flags & swrSprite_FLAGS_UNK_200)
        drawFlags |= swrSprite_DRAWFLAGS_UNK_2;
    if (flags & swrSprite_FLAGS_DOUBLE_RES)
        drawFlags |= swrSprite_DRAWFLAGS_DOUBLE_RES;
    swrSprite_Draw1(a1->texture, (int)(a1->x * a3), (int)(a1->y * a4), a1->width * a3, a1->height * a4, a1->rotation_angle, (int)(a1->unk0x4 * a3), (int)(a1->unk0x6 * a4), drawFlags, a1->r, a1->g, a1->b, a1->a);
}

// 0x00428270
int swrSprite_DrawSomeSprites(int a1)
{
    int mask;
    int count;
    int i;

    if (a1 == 2) {
        mask = swrSprite_FLAGS_PASS_1;
    } else if (a1 == 1) {
        mask = swrSprite_FLAGS_PASS_2;
    } else {
        mask = swrSprite_FLAGS_PASS_3;
        if (a1 != 3)
            mask = a1;
    }
    count = swrSprite_extraSpriteCount;
    for (i = 0; i < swrSprite_extraSpriteCount; i++) {
        swrSprite_Draw2(swrSprite_extraSprites[i], mask, 1.0f, 1.0f);
        count = swrSprite_extraSpriteCount;
    }
    if (a1 == 3)
        swrSprite_extraSpriteCount = 0;
    return count;
}

// 0x004282f0
void swrSprite_NewSprite(short id, swrSpriteTexture* tex)
{
    int id_;

    if (id < 400)
    {
        id_ = (int)id;
        if (swrSprite_SpriteCount <= id_)
        {
            swrSprite_SpriteCount = id_ + 1;
        }
        swrSprite_array[id_].x = 0;
        swrSprite_array[id_].y = 0;
        swrSprite_array[id_].width = 1.0;
        swrSprite_array[id_].height = 1.0;
        swrSprite_array[id_].rotation_angle = 0;
        swrSprite_array[id_].flags = 1;
        swrSprite_array[id_].r = 0xff;
        swrSprite_array[id_].g = 0xff;
        swrSprite_array[id_].b = 0xff;
        swrSprite_array[id_].a = 0xff;
        swrSprite_array[id_].texture = tex;
    }
}

// 0x00428370 TODO: crashes on release mode game startup, fine on debug
void swrSprite_ResetAllSprites(void)
{
    int i;

    swrSprite_UnloadAllSprites();
    i = 0;
    if (0 < swrSprite_SpriteCount)
    {
        do
        {
            swrSprite_NewSprite((short)i, NULL);
            i = i + 1;
        } while (i < swrSprite_SpriteCount);
    }
    swrSprite_SpriteCount = 0;
}

// 0x004283B0
void swrSprite_DrawSprites(int x)
{
    float xscale;
    float yscale;
    int mask;
    int i;

    swrSprite_InitDrawing();
    swrSprite_GetUIScale(&xscale, &yscale);
    if (x == 2) {
        mask = swrSprite_FLAGS_PASS_1;
    } else if (x == 1) {
        mask = swrSprite_FLAGS_PASS_2;
    } else {
        mask = swrSprite_FLAGS_PASS_3;
        if (x != 3)
            mask = x;
    }

    // the fade alphas are signed chars, so the a >= 0xff branches are unreachable
    if (x == 3 && swrSprite_unk2_a > 0) {
        if (swrSprite_unk2_a < 0xff)
            swrSprite_Draw1(NULL, 0, 0, xscale * 20.0f, yscale * 240.0f, 0.0f, 0, 0, swrSprite_DRAWFLAGS_UNK_2, swrSprite_unk2_r, swrSprite_unk2_g, swrSprite_unk2_b, swrSprite_unk2_a);
        else
            swrSprite_Draw1(NULL, 0, 0, xscale * 20.0f, yscale * 240.0f, 0.0f, 0, 0, 0, swrSprite_unk2_r, swrSprite_unk2_g, swrSprite_unk2_b, 0xff);
    }

    for (i = 0; i < swrSprite_SpriteCount; i++)
        swrSprite_Draw2(&swrSprite_array[i], mask, xscale, yscale);
    swrSprite_DrawSomeSprites(x);

    if (x == 3) {
        if (swrSprite_unk1_a > 0) {
            if (swrSprite_unk1_a < 0xff)
                swrSprite_Draw1(NULL, 0, 0, xscale * 20.0f, yscale * 240.0f, 0.0f, 0, 0, swrSprite_DRAWFLAGS_UNK_2, swrSprite_unk1_r, swrSprite_unk1_g, swrSprite_unk1_b, swrSprite_unk1_a);
            else
                swrSprite_Draw1(NULL, 0, 0, xscale * 20.0f, yscale * 240.0f, 0.0f, 0, 0, 0, swrSprite_unk1_r, swrSprite_unk1_g, swrSprite_unk1_b, 0xff);
        }
        if (swrSprite_unk_visible != 0) {
            swrSprite_Draw1(NULL, 0, 0, xscale * 20.0f, yscale * swrSprite_unk_x, 0.0f, 0, 0, swrSprite_DRAWFLAGS_UNK_2, 0, 0, 0, 0xff);
            swrSprite_Draw1(NULL, 0, (int)(yscale * swrSprite_unk_y), xscale * 20.0f, (240.0f - swrSprite_unk_y) * yscale, 0.0f, 0, 0, swrSprite_DRAWFLAGS_UNK_2, 0, 0, 0, 0xff);
        }
    }
    swr_noop2();
}

// 0x004285d0
void swrSprite_SetVisible(short id, int visible)
{
    if (id == -0xc9) {
        swrSprite_unk_visible = visible != 0;
        return;
    }
    if (id == -0x67) {
        swrSprite_unk1_a = -(visible != 0);
        return;
    }
    if (id == -0x68) {
        swrSprite_unk2_a = -(visible != 0);
        return;
    }
    if (-1 < id) {
        if (visible != 0) {
            swrSprite_array[id].flags = swrSprite_array[id].flags | 0x20;
            return;
        }
        swrSprite_array[id].flags = swrSprite_array[id].flags & 0xffffffdf;
    }
}

// 0x00428660
void swrSprite_SetPos(short id, short x, short y)
{
    if (id == -0xc9)
    {
        swrSprite_unk_x = (float)x;
        swrSprite_unk_y = (float)y;
        return;
    }
    if (-1 < id)
    {
        swrSprite_array[id].x = x;
        swrSprite_array[id].y = y;
    }
}

// 0x004286c0
void swrSprite_SetSecondPos_Maybe(short id, short u, short v)
{
    if (id > -1) {
        swrSprite_array[id].unk0x4 = u;
        swrSprite_array[id].unk0x6 = v;
    }
}

// 0x004286f0
void swrSprite_SetDim(short id, float width, float height)
{
    if (-1 < id)
    {
        swrSprite_array[id].width = width;
        swrSprite_array[id].height = height;
    }
}

// 0x00428720
void swrSprite_SetRotation(short id, float rotation)
{
    if (-1 < id)
        swrSprite_array[id].rotation_angle = rotation;
}

// 0x00428740
void swrSprite_SetColor(short id, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (id == -0x67)
    {
        swrSprite_unk1_r = r;
        swrSprite_unk1_g = g;
        swrSprite_unk1_b = b;
        swrSprite_unk1_a = a;
        return;
    }
    if (id == -0x68)
    {
        swrSprite_unk2_r = r;
        swrSprite_unk2_g = g;
        swrSprite_unk2_b = b;
        swrSprite_unk2_a = a;
        return;
    }
    if (-1 < id)
    {
        swrSprite_array[id].r = r;
        swrSprite_array[id].g = g;
        swrSprite_array[id].b = b;
        swrSprite_array[id].a = a;
    }
}

// 0x004287e0
void swrSprite_SetFlag(short id, unsigned int flag)
{
    swrSprite_array[id].flags = swrSprite_array[id].flags | flag;
}

// 0x00428800
void swrSprite_UnsetFlag(short id, unsigned int flag)
{
    swrSprite_array[id].flags = swrSprite_array[id].flags & ~flag;
}

// 0x0042bb00
void swrSprite_SetPosF(short id, short x, short y)
{
    short design_y;
    short design_x;

    design_y = (short)(int)(((float)y / (float)swrDisplay_screenHeight) * 240.0f);
    design_x = (short)(int)(((float)x / (float)swrDisplay_screenWidth) * 320.0f);
    swrSprite_SetPos(id, design_x, design_y);
}

// 0x0042D910
int16_t swrSprite_setCurrentTextPos(int16_t x, int16_t y)
{
    currentTextPosX = x;
    currentTextPosY = y;
    return x;
}

// 0x0042D930
short swrSprite_getCurrentTextPos(int16_t* x, int16_t* y)
{
    *x = currentTextPosX;
    *y = currentTextPosY;
    return currentTextPosY;
}

// The text-glyph quad emitter. Takes a design-space rect (x0,y0 = pos, x1,y1 = size) and a
// texel-space UV rect, scales the rect from design space to the actual framebuffer, grows the
// accumulated on-screen text bounding box (swrText_bbox*), optionally half-scales the glyph,
// scissors against the text clip rect (sliding the UVs to match the clamped edges), applies the
// 0xbf diagonal-flip orientation, then hands the final screen+UV quad to rdProcEntry_Add2DQuad.
// 0x0042D990
void rdProcEntry_Add2DQuad2(short a1, short a2, short a3, short a4, short a5, short a6, short a7, short a8)
{
    // Design (640x480-ish) -> framebuffer scale; a negative reciprocal falls back to identity.
    float scaleX = (float)swrDisplay_screenWidth * (float)swrText_designWidthRecip;
    float scaleY = (float)swrDisplay_screenHeight * (float)swrText_designHeightRecip;
    if (scaleX < 0.0f)
        scaleX = 1.0f;
    if (scaleY < 0.0f)
        scaleY = 1.0f;

    short dx = a1 - a3;
    short dy = a2 - a4;
    float left = (float)(int)dx;
    float top = (float)(int)dy;
    float right = (float)(int)(short)(a5 + dx);
    float bottom = (float)(int)(short)(a6 + dy);

    float minXf = scaleX * left;
    float minYf = scaleY * top;
    float maxXf = scaleX * right;
    float maxYf = scaleY * bottom;

    // Grow the accumulated text bounding box (empty when bboxMaxX < bboxMinX).
    if (swrText_bboxMaxX < swrText_bboxMinX) {
        swrText_bboxMinX = (short)(int)minXf;
        swrText_bboxMinY = (short)(int)minYf;
        swrText_bboxMaxX = (short)(int)maxXf;
        swrText_bboxMaxY = (short)(int)maxYf;
    } else {
        if (minXf < (float)swrText_bboxMinX)
            swrText_bboxMinX = (short)(int)minXf;
        if (minYf < (float)swrText_bboxMinY)
            swrText_bboxMinY = (short)(int)minYf;
        if ((float)swrText_bboxMaxX < maxXf)
            swrText_bboxMaxX = (short)(int)maxXf;
        if ((float)swrText_bboxMaxY < maxYf)
            swrText_bboxMaxY = (short)(int)maxYf;
    }

    // Glyph UVs (the font atlas is 64 texels wide, 128 tall).
    float tex_u0 = (float)(int)a7 * (1.0f / 64.0f);
    float tex_u1 = (float)((int)a5 + (int)a7) * (1.0f / 64.0f);
    float tex_v0 = (float)(int)a8 * (1.0f / 128.0f);
    float tex_v1 = (float)((int)a6 + (int)a8) * (1.0f / 128.0f);

    // Screen coordinates: the bbox extents, optionally halved for half-scale text.
    float rsx = swrText_halfScale ? scaleX * 0.5f : scaleX;
    float rsy = swrText_halfScale ? scaleY * 0.5f : scaleY;
    short sx0 = (short)(int)(rsx * left);
    short sy0 = (short)(int)(rsy * top);
    short sx1 = (short)(int)(rsx * right);
    short sy1 = (short)(int)(rsy * bottom);

    // Scissor against the text clip rect, sliding the matching UV edge to keep the glyph aligned.
    if (swrText_clipEnabled != 0) {
        if (sx0 > swrText_clipRight || sy0 > swrText_clipBottom || sx1 < swrText_clipLeft || sy1 < swrText_clipTop)
            return;
        if (sx0 < swrText_clipLeft) {
            int d = swrText_clipLeft - sx0;
            sx0 = (short)(sx0 + d);
            tex_u0 += (float)d;
        }
        if (sy0 < swrText_clipTop) {
            int d = swrText_clipTop - sy0;
            sy0 = (short)(sy0 + d);
            tex_v0 += (float)d;
        }
        if (sx1 > swrText_clipRight) {
            int d = sx1 - swrText_clipRight;
            sx1 = (short)(sx1 - d);
            tex_u1 -= (float)d;
        }
        if (sy1 > swrText_clipBottom) {
            int d = sy1 - swrText_clipBottom;
            sy1 = (short)(sy1 - d);
            tex_v1 -= (float)d;
        }
    }

    // orientation 0xbf = diagonal flip: swap the U and V endpoints.
    if (swrText_orientation == 0xbf) {
        float tmpU = tex_u0;
        tex_u0 = tex_u1;
        tex_u1 = tmpU;
        float tmpV = tex_v0;
        tex_v0 = tex_v1;
        tex_v1 = tmpV;
    }

    rdProcEntry_Add2DQuad(sx0, sy0, sx1, sy1, tex_u0, tex_v0, tex_u1, tex_v1);
}

// 0x0042D950
uint8_t swrSprite_setCurrentSpriteColor(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    currentSpriteColor[0] = r;
    currentSpriteColor[1] = g;
    currentSpriteColor[2] = b;
    currentSpriteColor[3] = a;
    swrSprite_colorApplied = 0;
    return a;
}

// 0x004321B0
void rdProcEntry_Add2DPolygon(short x0, short y0, short x1, short y1, float tex_width, float tex_height, BOOL textured, BOOL add_z_offset, swrSpriteTexture* texture)
{
    float position;
    if (swrSpriteTexture_dial_gradient_rgb != NULL && swrSpriteTexture_dial_gradient_rgb == texture) {
        position = speedDialPosition1;
    } else {
        if (swrSpriteTexture_dial_gradient_rgb2 == NULL || swrSpriteTexture_dial_gradient_rgb2 != texture)
            return;
        position = speedDialPosition2;
    }

    RdCacheProcEntry* pEntry = rdCache_GetProcEntry();
    if (textured == 1)
        rdMaterial_SaturateTextureR4G4B4A4(rdModel_CurrentMaterial);

    rdVector4* aColors = pEntry->aVertColors;
    pEntry->flags = RD_FF_ZWRITE_DISABLED | RD_FF_TEX_CLAMP_Y | RD_FF_TEX_CLAMP_X | RD_FF_TEX_TRANSLUCENT;
    pEntry->lightingMode = RD_LIGHTING_LIT;
    pEntry->pMaterial = rdModel_CurrentMaterial;
    pEntry->matCelNum = 0;
    pEntry->distance = 0.0f;
    pEntry->uv_offset.x = 0.0f;
    pEntry->uv_offset.y = 0.0f;
    rdVector3* aVertices = pEntry->aVertices;
    rdVector2* aUVs = pEntry->aUVCoords;

    float z = rdCamera_pCurCamera->pClipFrustum->zNear;
    if (add_z_offset == 1)
        z = 100.0f;

    const int midY = ((int)y0 + (int)y1) >> 1;
    const int midX = ((int)x1 + (int)x0) >> 1;
    const float u = tex_width / (float)(unsigned int)pEntry->pMaterial->width;
    const float v = tex_height / (float)(unsigned int)pEntry->pMaterial->height;
    const float uHalf = u * 0.5f;
    const float vHalf = v * 0.5f;

    if (position < 0.25) {
        const float scale = position * 4.0f;
        pEntry->numVertices = 3;
        const short t = (short)(int)((float)(x1 - x0) * scale);
        aVertices[2].x = (float)(x1 - t);
        aVertices[2].y = (float)y0;
        aVertices[2].z = z;
        aUVs[2].y = 0.0f;
        aUVs[2].x = u * scale;
    } else if (position < 0.75) {
        pEntry->numVertices = 4;
        const float scale = (position + position) - 0.5f;
        aVertices[2].x = (float)x0;
        aVertices[2].y = (float)y0;
        aVertices[2].z = z;
        aVertices[3].x = (float)x0;
        const short t = (short)(int)((float)(y1 - y0) * scale);
        aVertices[3].y = (float)(t + y0);
        aVertices[3].z = z;
        aUVs[2].x = u;
        aUVs[2].y = 0.0f;
        aUVs[3].x = u;
        aUVs[3].y = v * scale;
    } else {
        const float scale = position * 4.0f - 3.0f;
        pEntry->numVertices = 5;
        aVertices[2].x = (float)x0;
        aVertices[2].y = (float)y0;
        aVertices[2].z = z;
        aVertices[3].x = (float)x0;
        aVertices[3].y = (float)y1;
        aVertices[3].z = z;
        const short t = (short)(int)((float)(x1 - (short)midX) * scale);
        aVertices[4].x = (float)(t + x0);
        aVertices[4].y = (float)y1;
        aVertices[4].z = z;
        aUVs[2].x = u;
        aUVs[3].x = u;
        aUVs[2].y = 0.0f;
        aUVs[3].y = v;
        aUVs[4].y = v;
        aUVs[4].x = u - (position - 0.75f) * 4.0 * (u - uHalf);
    }

    aVertices[0].x = (float)x1;
    aVertices[0].y = (float)(short)midY;
    aVertices[0].z = z;
    aVertices[1].x = (float)x1;
    aVertices[1].y = (float)y0;
    aVertices[1].z = z;
    aUVs[0].x = 0.0f;
    aUVs[0].y = vHalf;
    aUVs[1].x = 0.0f;
    aUVs[1].y = 0.0f;
    for (unsigned int i = 0; i < (unsigned int)pEntry->numVertices; i++)
        aColors[i] = rdProcEntry_CurrentColor;

    rdCache_AddProcFace(pEntry->numVertices, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
}

// 0x004325B0
void rdProcEntry_Add2DQuad3(short x0, short y0, short x1, short y1, float tex_width, float tex_height, BOOL textured, BOOL add_z_offset)
{
    RdCacheProcEntry* pEntry = rdCache_GetProcEntry();
    if (textured == 1)
        rdMaterial_SaturateTextureR4G4B4A4(rdModel_CurrentMaterial);

    pEntry->flags = RD_FF_ZWRITE_DISABLED | RD_FF_TEX_CLAMP_Y | RD_FF_TEX_CLAMP_X | RD_FF_TEX_TRANSLUCENT;
    pEntry->lightingMode = RD_LIGHTING_LIT;
    pEntry->numVertices = 4;
    pEntry->uv_offset.x = 0.0f;
    pEntry->uv_offset.y = 0.0f;
    pEntry->pMaterial = rdModel_CurrentMaterial;
    pEntry->matCelNum = 0;
    pEntry->distance = 0.0f;

    rdVector3* aVertices = pEntry->aVertices;
    rdVector2* aUVs = pEntry->aUVCoords;
    rdVector4* aColors = pEntry->aVertColors;

    float z = rdCamera_pCurCamera->pClipFrustum->zNear;
    if (add_z_offset == 1)
        z = 50.0f;

    aVertices[0].x = (float)(int)x0;
    aVertices[0].y = (float)(int)y0;
    aVertices[1].x = (float)(int)x0;
    aVertices[1].y = (float)(int)y1;
    aVertices[2].x = (float)(int)x1;
    aVertices[2].y = (float)(int)y1;
    aVertices[3].x = (float)(int)x1;
    aVertices[3].y = (float)(int)y0;
    for (int i = 0; i < 4; i++) {
        aVertices[i].z = z;
        aColors[i] = rdProcEntry_CurrentColor;
    }

    aUVs[0].x = tex_width / (float)(unsigned int)pEntry->pMaterial->width;
    aUVs[0].y = 0.0f;
    aUVs[1].x = tex_width / (float)(unsigned int)pEntry->pMaterial->width;
    aUVs[1].y = tex_height / (float)(unsigned int)pEntry->pMaterial->height;
    aUVs[2].x = 0.0f;
    aUVs[2].y = tex_height / (float)(unsigned int)pEntry->pMaterial->height;
    aUVs[3].x = 0.0f;
    aUVs[3].y = 0.0f;

    rdCache_AddProcFace(pEntry->numVertices, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
}

// Emit an arbitrary 2D quad from four explicit corner points (x0,y0)..(x3,y3), fixed
// full-texture UVs (0,0)-(1,1). Like rdProcEntry_Add2DQuad but the caller gives all four
// corners instead of an axis-aligned rect. Uses the current material + current color.
// 0x004327E0
void rdProcEntry_Add2DQuad4(short x0, short y0, short x1, short y1, short x2, short y2, short x3, short y3)
{
    RdCacheProcEntry* pEntry = rdCache_GetProcEntry();
    pEntry->flags = RD_FF_ZWRITE_DISABLED | RD_FF_TEX_CLAMP_Y | RD_FF_TEX_CLAMP_X | RD_FF_TEX_TRANSLUCENT;
    pEntry->lightingMode = RD_LIGHTING_LIT;
    pEntry->numVertices = 4;
    pEntry->uv_offset.x = 0.0f;
    pEntry->uv_offset.y = 0.0f;
    pEntry->matCelNum = 0;
    pEntry->pMaterial = rdModel_CurrentMaterial;
    pEntry->distance = 0.0f;

    const float z = rdCamera_pCurCamera->pClipFrustum->zNear;
    rdVector3* aVertices = pEntry->aVertices;
    rdVector2* aUVs = pEntry->aUVCoords;
    rdVector4* aColors = pEntry->aVertColors;

    aVertices[0].x = (float)(int)x0;
    aVertices[0].y = (float)(int)y0;
    aVertices[1].x = (float)(int)x1;
    aVertices[1].y = (float)(int)y1;
    aVertices[2].x = (float)(int)x2;
    aVertices[2].y = (float)(int)y2;
    aVertices[3].x = (float)(int)x3;
    aVertices[3].y = (float)(int)y3;
    for (int i = 0; i < 4; i++) {
        aVertices[i].z = z;
        aColors[i] = rdProcEntry_CurrentColor;
    }

    aUVs[0].x = 1.0f;
    aUVs[0].y = 0.0f;
    aUVs[1].x = 1.0f;
    aUVs[1].y = 1.0f;
    aUVs[2].x = 0.0f;
    aUVs[2].y = 1.0f;
    aUVs[3].x = 0.0f;
    aUVs[3].y = 0.0f;

    rdCache_AddProcFace(pEntry->numVertices, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
}

// Emit an axis-aligned 2D quad spanning (x0,y0)-(x1,y1) with the given UV rect, at the
// near clip plane, using the current material + current color. The workhorse behind the
// 2D UI/sprite blits.
// 0x004329C0
void rdProcEntry_Add2DQuad(short x0, short y0, short x1, short y1, float tex_u0, float tex_v0, float tex_u1, float tex_v1)
{
    RdCacheProcEntry* pEntry = rdCache_GetProcEntry();
    pEntry->flags = RD_FF_ZWRITE_DISABLED | RD_FF_TEX_CLAMP_Y | RD_FF_TEX_CLAMP_X | RD_FF_TEX_TRANSLUCENT;
    pEntry->lightingMode = RD_LIGHTING_LIT;
    pEntry->numVertices = 4;
    pEntry->uv_offset.x = 0.0f;
    pEntry->uv_offset.y = 0.0f;
    pEntry->matCelNum = 0;
    pEntry->pMaterial = rdModel_CurrentMaterial;
    pEntry->distance = 0.0f;

    const float z = rdCamera_pCurCamera->pClipFrustum->zNear;
    rdVector3* aVertices = pEntry->aVertices;
    rdVector2* aUVs = pEntry->aUVCoords;
    rdVector4* aColors = pEntry->aVertColors;

    aVertices[0].x = (float)(int)x0;
    aVertices[0].y = (float)(int)y0;
    aVertices[1].x = (float)(int)x0;
    aVertices[1].y = (float)(int)y1;
    aVertices[2].x = (float)(int)x1;
    aVertices[2].y = (float)(int)y1;
    aVertices[3].x = (float)(int)x1;
    aVertices[3].y = (float)(int)y0;
    for (int i = 0; i < 4; i++) {
        aVertices[i].z = z;
        aColors[i] = rdProcEntry_CurrentColor;
    }

    aUVs[0].x = tex_u0;
    aUVs[0].y = tex_v0;
    aUVs[1].x = tex_u0;
    aUVs[1].y = tex_v1;
    aUVs[2].x = tex_u1;
    aUVs[2].y = tex_v1;
    aUVs[3].x = tex_u1;
    aUVs[3].y = tex_v0;

    rdCache_AddProcFace(pEntry->numVertices, rdCache_ProcFaceFLAGS_VERTICES | rdCache_ProcFaceFLAGS_UVS | rdCache_ProcFaceFLAGS_INTENSITIES);
}

// 0x00445c90
int swrSprite_UpperPowerOfTwo(int x)
{
    int power_of_two = 0x40000000; // 2^30
    unsigned int uVar2;
    int res = 0x1f;
    do
    {
        if (res == 0)
            break;
        uVar2 = power_of_two & x;
        power_of_two = power_of_two >> 1;
        res = res + -1;
    } while (uVar2 == 0);
    res = power_of_two * 2;
    if (res < x)
    {
        res = power_of_two << 2;
    }
    if (res < 16)
    {
        res = 16;
    }
    return res;
}

// 0x00445cd0
void swrModel_CreateTextureMaterialFromPixels(int srcWidth, int srcHeight, int width, int height, unsigned int bufferKind, void** outMaterial, uint8_t* pixels)
{
    tVBuffer buffer;
    tVBuffer* pBuffer = &buffer;

    RdMaterial* material = rdMaterial_Load(".\\data\\default.mat");
    swrModel_RegisterRootMaterial(bufferKind, material);
    sprintf(material->aName, "Rovermatic");
    // UV scale floats stored unaligned inside the name, overwriting its terminator
    *(float*)(material->aName + 10) = (float)srcWidth / (float)width;
    *(float*)(material->aName + 14) = (float)srcHeight / (float)height;
    material->colorInfo.redBPP = 5;
    material->colorInfo.greenBPP = 5;
    material->colorInfo.blueBPP = 5;
    material->colorInfo.RedShr = 3;
    material->colorInfo.GreenShr = 3;
    material->colorInfo.BlueShr = 3;
    material->num = 0;
    material->colorInfo.colorMode = T_STDCOLOR_RGBA;
    material->colorInfo.bpp = 16;
    material->colorInfo.alphaBPP = 1;
    material->colorInfo.redPosShift = 11;
    material->colorInfo.greenPosShift = 6;
    material->colorInfo.bluePosShift = 1;
    material->colorInfo.alphaPosShift = 0;
    material->colorInfo.AlphaShr = 7;
    material->formatType = STDCOLOR_FORMAT_RGBA_1BIT_ALPHA;
    material->width = width;
    material->height = height;
    material->curCelNum = 1;
    material->numCels = 0;

    pBuffer->bSurfaceAllocated = 0;
    pBuffer->lockSurfRefCount = 0;
    pBuffer->bVideoMemory = 0;
    pBuffer->rasterInfo.width = width;
    pBuffer->rasterInfo.height = height;
    pBuffer->rasterInfo.size = height * width * 2;
    pBuffer->rasterInfo.rowSize = width * 2;
    pBuffer->rasterInfo.rowWidth = width;
    pBuffer->rasterInfo.colorInfo = material->colorInfo;
    pBuffer->pPixels = pixels;
    pBuffer->dword5C = 0;

    std3D_ClearTexture(material->aTextures);
    std3D_AllocSystemTexture(material->aTextures, &pBuffer, 1, material->formatType);
    *outMaterial = material;
}

// 0x00445e50
void swrModel_ConvertIndexedTextureRows(int width, int height, int paddedWidth, uint8_t* indices, uint16_t* palette, uint16_t** outCursor)
{
    uint16_t* out = *outCursor;

    for (int row = height; row > 0; row--) {
        int written = 0;
        for (int x = width; x > 0; x--) {
            // N64 big-endian RGBA5551 -> little-endian ARGB1555
            uint16_t color = palette[*indices++];
            color = (uint16_t)((color << 8) | (color >> 8));
            *out++ = (uint16_t)((color >> 1) | (color << 15));
            written = width;
        }
        if (written < paddedWidth) {
            memset(out, 0, (paddedWidth - written) * sizeof(uint16_t));
            out += paddedWidth - written;
        }
    }
    *outCursor = out;
}

// 0x00445EE0
void swrModel_ConvertTextureDataToRdMaterial(int texture_type_a, int texture_type_b, int orig_width, int orig_height, int width, int height, swrMaterial** texture_data_ptr, uint8_t** palette_ptr, char flipSomething, char adjustWidthHeightFlag)
{
    tVBuffer buffer;
    tVBuffer* pBuffer = &buffer;
    uint16_t* palette = (uint16_t*)*palette_ptr;
    uint8_t* src = (uint8_t*)*texture_data_ptr;
    char mirrorS = 0;
    char mirrorT = 0;
    int rowsDone = 0; // left uninitialized in the original for unknown formats
    RdMaterial* material;
    uint16_t* pixels;
    uint16_t* out;
    uint16_t* in;
    unsigned int byteSize;
    int srcWidth;
    int srcHeight;
    int row;
    int x;

    *texture_data_ptr = NULL;
    *palette_ptr = NULL;
    if (src == NULL) {
        return;
    }

    material = rdMaterial_Load(".\\data\\default.mat");
    swrModel_RegisterRootMaterial((unsigned int)src, material);
    *texture_data_ptr = (swrMaterial*)material;

    srcWidth = orig_width;
    srcHeight = orig_height;
    if (adjustWidthHeightFlag & swrTexture_MIRROR_S) {
        srcWidth = orig_width * 2;
        mirrorS = 1;
        if (srcWidth > width) {
            width = swrSprite_UpperPowerOfTwo(srcWidth);
        }
    }
    if (adjustWidthHeightFlag & swrTexture_MIRROR_T) {
        srcHeight = orig_height * 2;
        mirrorT = 1;
        if (srcHeight > height) {
            height = swrSprite_UpperPowerOfTwo(srcHeight);
        }
    }

    byteSize = height * width * 2;
    pixels = swrModel_AllocMaterial((unsigned int)src, byteSize);
    sprintf(material->aName, "Rovermatic");
    // UV scale floats stored unaligned inside the name, overwriting its terminator
    *(float*)(material->aName + 10) = (float)srcWidth / (float)width;
    *(float*)(material->aName + 14) = (float)srcHeight / (float)height;
    material->num = 0;

    if ((texture_type_a == swrTexelFormat_RGBA && texture_type_b == swrTexelSize_32BIT) || (texture_type_a == swrTexelFormat_PC && (texture_type_b == swrTexelSize_8BIT || texture_type_b == swrTexelSize_32BIT)) || texture_type_a == swrTexelFormat_I || (texture_type_a == swrTexelFormat_IA && texture_type_b == swrTexelSize_4BIT)) {
        material->colorInfo.colorMode = T_STDCOLOR_RGBA;
        material->colorInfo.bpp = 16;
        material->colorInfo.redBPP = 4;
        material->colorInfo.greenBPP = 4;
        material->colorInfo.blueBPP = 4;
        material->colorInfo.alphaBPP = 4;
        material->colorInfo.redPosShift = 12;
        material->colorInfo.greenPosShift = 8;
        material->colorInfo.bluePosShift = 4;
        material->colorInfo.alphaPosShift = 0;
        material->colorInfo.RedShr = 4;
        material->colorInfo.GreenShr = 4;
        material->colorInfo.BlueShr = 4;
        material->colorInfo.AlphaShr = 4;
        material->formatType = STDCOLOR_FORMAT_RGBA;
    } else {
        material->colorInfo.colorMode = T_STDCOLOR_RGBA;
        material->colorInfo.bpp = 16;
        material->colorInfo.redBPP = 5;
        material->colorInfo.greenBPP = 5;
        material->colorInfo.blueBPP = 5;
        material->colorInfo.alphaBPP = 1;
        material->colorInfo.redPosShift = 11;
        material->colorInfo.greenPosShift = 6;
        material->colorInfo.bluePosShift = 1;
        material->colorInfo.alphaPosShift = 0;
        material->colorInfo.RedShr = 3;
        material->colorInfo.GreenShr = 3;
        material->colorInfo.BlueShr = 3;
        material->colorInfo.AlphaShr = 7;
        material->formatType = STDCOLOR_FORMAT_RGBA_1BIT_ALPHA;
    }
    material->width = width;
    material->height = height;
    material->curCelNum = 1;
    material->numCels = 0;

    pBuffer->bSurfaceAllocated = 0;
    pBuffer->lockSurfRefCount = 0;
    pBuffer->bVideoMemory = 0;
    pBuffer->rasterInfo.width = width;
    pBuffer->rasterInfo.height = height;
    pBuffer->rasterInfo.size = byteSize;
    pBuffer->rasterInfo.rowSize = width * 2;
    pBuffer->rasterInfo.rowWidth = width;
    pBuffer->rasterInfo.colorInfo = material->colorInfo;
    pBuffer->pPixels = (BYTE*)pixels;
    pBuffer->dword5C = 0;

    out = pixels;
    if (texture_type_a == swrTexelFormat_I && texture_type_b == swrTexelSize_4BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x += 2) {
                *out++ = (uint16_t)((*src >> 4) * 0x1111);
                *out++ = (uint16_t)((*src & 0xf) * 0x1111);
                src++;
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_IA && texture_type_b == swrTexelSize_4BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x += 2) {
                *out++ = (uint16_t)(((*src & 0xf0) << 8) | 0xfff);
                *out++ = (uint16_t)(((*src & 0xf) << 12) | 0xfff);
                src++;
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_I && texture_type_b == swrTexelSize_8BIT) {
        // only the high nibble of each 8-bit intensity is kept
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                if (flipSomething == 1) {
                    *out++ = (uint16_t)((*src >> 4) * 0x1111);
                } else {
                    *out++ = (uint16_t)(0xf000 | (*src >> 4) * 0x111);
                }
                src++;
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_CI && texture_type_b == swrTexelSize_4BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x += 2) {
                // N64 big-endian RGBA5551 -> little-endian ARGB1555
                uint16_t color = SWAP16(palette[*src >> 4]);
                *out++ = (uint16_t)((color >> 1) | (color << 15));
                color = SWAP16(palette[*src & 0xf]);
                *out++ = (uint16_t)((color >> 1) | (color << 15));
                src++;
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_CI && texture_type_b == swrTexelSize_8BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                uint16_t color = SWAP16(palette[*src++]);
                *out++ = (uint16_t)((color >> 1) | (color << 15));
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_PC && texture_type_b == swrTexelSize_8BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                *out++ = (uint16_t)(((*src++ >> 4) << 12) | 0xfff);
            }
            for (; x < width; x++, out++) {
                *out = out[-1];
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_PC && texture_type_b == swrTexelSize_16BIT) {
        in = (uint16_t*)src;
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                *out++ = *in++ | 0x8000;
            }
            for (; x < width; x++, out++) {
                *out = out[-1];
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_RGBA && texture_type_b == swrTexelSize_16BIT) {
        in = (uint16_t*)src;
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                uint16_t color = SWAP16(*in++);
                *out++ = (uint16_t)((color >> 1) | (color << 15));
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_PC && texture_type_b == swrTexelSize_32BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                uint32_t texel = *(uint32_t*)src;
                src += 4;
                *out++ = (uint16_t)(((texel >> 28) << 12) | (((texel >> 20) & 0xf) << 8) | (((texel >> 12) & 0xf) << 4) | ((texel >> 4) & 0xf));
            }
            for (; x < width; x++, out++) {
                *out = out[-1];
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_PC && texture_type_b == swrTexelSize_24BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                // 24-bit texels read with a dword load (one byte past the texel)
                uint32_t texel = *(uint32_t*)src;
                src += 3;
                *out++ = (uint16_t)(0x8000 | (((texel >> 19) & 0x1f) << 10) | (((texel >> 11) & 0x1f) << 5) | ((texel >> 3) & 0x1f));
            }
            for (; x < width; x++, out++) {
                *out = out[-1];
            }
            rowsDone = orig_height;
        }
    } else if (texture_type_a == swrTexelFormat_RGBA && texture_type_b == swrTexelSize_32BIT) {
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                // big-endian RGBA8888 -> ARGB4444
                uint32_t texel = SWAP32(*(uint32_t*)src);
                src += 4;
                *out++ = (uint16_t)((((texel >> 4) & 0xf) << 12) | (((texel >> 28) & 0xf) << 8) | (((texel >> 20) & 0xf) << 4) | ((texel >> 12) & 0xf));
            }
            for (; x < width; x++) {
                *out++ = 0;
            }
            rowsDone = orig_height;
        }
    }

    // faithful quirk: padding rows copy from orig_width texels back, not one padded row back
    for (row = rowsDone; row < height; row++) {
        for (x = 0; x < width; x++, out++) {
            *out = out[-orig_width];
        }
    }

    if (mirrorS) {
        uint16_t* dst = pixels + srcWidth - 1;
        in = pixels;
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < orig_width; x++) {
                *dst-- = *in++;
            }
            dst += width + orig_width;
            in += width - orig_width;
        }
    }
    if (mirrorT) {
        uint16_t* dst = pixels + (srcHeight - 1) * width;
        in = pixels;
        for (row = 0; row < orig_height; row++) {
            for (x = 0; x < srcWidth; x++) {
                *dst++ = *in++;
            }
            dst -= srcWidth + width;
            in += width - srcWidth;
        }
    }

    std3D_ClearTexture(material->aTextures);
    std3D_AllocSystemTexture(material->aTextures, &pBuffer, 1, material->formatType);
}

// 0x00446C20
void swrModel_DoConvertTextureDataToRdMaterial(swrMaterial** texture_data_ptr, uint8_t** palette_data_ptr)
{
    swrModel_MaterialTexture* texture = (swrModel_MaterialTexture*)((char*)texture_data_ptr - offsetof(swrModel_MaterialTexture, texture_data));
    int origWidth;
    int origHeight;
    int width;
    int height;

    if (texture->specs[0] != NULL) {
        origWidth = (int16_t)SWAP16(texture->width);
        origHeight = (int16_t)SWAP16(texture->height);
        width = swrSprite_UpperPowerOfTwo(origWidth);
        height = swrSprite_UpperPowerOfTwo(origHeight);
        // type is still big-endian here: low byte = swrTexelFormat, high byte = swrTexelSize
        swrModel_ConvertTextureDataToRdMaterial(texture->type & 0xff, texture->type >> 8, origWidth, origHeight, width, height, texture_data_ptr, palette_data_ptr, 1, ((uint8_t*)&texture->specs[0]->flags)[3]);
    }
    // back-pointer to the texture header, overwriting the U scale float written above
    *(swrModel_MaterialTexture**)((*texture_data_ptr)->filename + 10) = texture;
}

// 0x00446a20
void swrModel_BuildTiledTextureMaterial(void* tex)
{
    swrSpriteTextureHeader* header = (swrSpriteTextureHeader*)tex;
    int width = (short)header->width;
    int height = (short)header->height;
    uint16_t* palette = (uint16_t*)header->palette_offset;
    int potWidth = swrSprite_UpperPowerOfTwo(width);
    int potHeight = swrSprite_UpperPowerOfTwo(height);
    swrSpriteTexturePage* page = header->page_table;
    uint16_t* pixels = (uint16_t*)swrModel_AllocMaterial(page->offset, potHeight * potWidth * 2);
    uint16_t* cursor = pixels;
    void* material;

    // an align value above 3 keeps the previous mask, which starts out as potWidth
    unsigned int mask = potWidth;
    for (int i = (short)header->page_count - 1; i >= 0; i--) {
        page = &header->page_table[i];
        switch (header->page_width_align) {
        case 0:
            mask = 0xf;
            break;
        case 1:
            mask = 7;
            break;
        case 2:
            mask = 3;
            break;
        case 3:
            mask = 1;
            break;
        }
        swrModel_ConvertIndexedTextureRows(((short)page->width + mask) & ~mask, (short)page->height, potWidth, (uint8_t*)page->offset, palette, &cursor);
        page->width = 0;
        page->height = 0;
        page->offset = 0;
    }

    swrModel_CreateTextureMaterialFromPixels(width, height, potWidth, potHeight, page->offset, &material, (uint8_t*)pixels);
    header->page_table[0].width = (unsigned short)width;
    header->page_table[0].height = (unsigned short)height;
    header->page_table[0].offset = (uint32_t)material;
    header->page_count = 1;
}

// 0x00446b60
void swrModel_ConvertTileToRdMaterial(void* tex, void* tile)
{
    swrSpriteTextureHeader* header = (swrSpriteTextureHeader*)tex;
    swrSpriteTexturePage* page = (swrSpriteTexturePage*)tile;
    uint8_t* palette = (uint8_t*)header->palette_offset;
    int height = (short)page->height;
    unsigned int mask;

    switch (header->page_width_align) {
    case 0:
        mask = 0xf;
        break;
    case 1:
        mask = 7;
        break;
    case 2:
        mask = 3;
        break;
    case 3:
    case 7:
        mask = 1;
        break;
    default:
        // the EXE reuses the tile pointer as the mask here
        mask = (unsigned int)tile;
        break;
    }

    int width = (mask + (short)page->width) & ~mask;
    int potWidth = swrSprite_UpperPowerOfTwo(width);
    int potHeight = swrSprite_UpperPowerOfTwo(height);
    swrModel_ConvertTextureDataToRdMaterial(header->format, header->page_width_align, width, height, potWidth, potHeight, (swrMaterial**)&page->offset, &palette, 0, 0);
}

// 0x00446ca0
swrSpriteTexture* swrSprite_LoadTexture(int index)
{
    swrSpriteTexture* tex;
    swrSpriteTexturePage* pages;
    char* cursor;
    unsigned int spriteCount;
    unsigned int bounds[2];
    size_t size;
    unsigned int end;
    int i;

    swrLoader_OpenBlock(swrLoader_TYPE_SPRITE_BLOCK);
    tex = (swrSpriteTexture*)swrAssetBuffer_GetBuffer();
    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, 0, &spriteCount, sizeof(spriteCount));
    spriteCount = SWAP32(spriteCount);
    if (index < 0 || index >= (int)spriteCount)
        return NULL;

    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, index * 4 + 4, bounds, sizeof(bounds));
    for (i = 0; i < 2; i++)
        bounds[i] = SWAP32(bounds[i]);

    swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, bounds[0], &tex->header, sizeof(swrSpriteTextureHeader));
    tex->header.width = SWAP16(tex->header.width);
    tex->header.height = SWAP16(tex->header.height);
    tex->header.unk3 = SWAP16(tex->header.unk3);
    tex->header.palette_offset = SWAP32(tex->header.palette_offset);
    tex->header.page_count = SWAP16(tex->header.page_count);
    tex->header.unk6 = SWAP16(tex->header.unk6);
    tex->header.page_table = (swrSpriteTexturePage*)SWAP32(tex->header.page_table);

    // a paletted sprite without a palette loads only its header, and the asset buffer is not advanced
    cursor = (char*)tex;
    if (tex->header.format != 2 || tex->header.palette_offset != 0) {
        pages = (swrSpriteTexturePage*)(tex + 1);
        size = (short)tex->header.page_count * sizeof(swrSpriteTexturePage);
        swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, bounds[0] + sizeof(swrSpriteTextureHeader), pages, size);
        tex->header.page_table = pages;
        for (i = 0; i < (short)tex->header.page_count; i++) {
            tex->header.page_table[i].width = SWAP16(tex->header.page_table[i].width);
            tex->header.page_table[i].height = SWAP16(tex->header.page_table[i].height);
            tex->header.page_table[i].offset = SWAP32(tex->header.page_table[i].offset);
        }

        cursor = (char*)pages;
        if (tex->header.palette_offset != 0) {
            cursor = (char*)(((uintptr_t)cursor + size + 0xf) & ~0xf);
            size = tex->header.page_table[0].offset - tex->header.palette_offset;
            swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, bounds[0] + tex->header.palette_offset, cursor, size);
            tex->header.palette_offset = (uint32_t)cursor;
        }

        cursor = (char*)(((uintptr_t)cursor + size + 0xf) & ~0xf);
        for (i = 0; i < (short)tex->header.page_count; i++) {
            if (i == (short)tex->header.page_count - 1)
                end = bounds[1] - bounds[0];
            else
                end = tex->header.page_table[i + 1].offset;
            size = end - tex->header.page_table[i].offset;
            swrLoader_ReadAt(swrLoader_TYPE_SPRITE_BLOCK, bounds[0] + tex->header.page_table[i].offset, cursor, size);
            tex->header.page_table[i].offset = (uint32_t)cursor;
            if (index != swrSprite_dial_gradient_rgb)
                swrModel_ConvertTileToRdMaterial(tex, &tex->header.page_table[i]);
            cursor = (char*)(((uintptr_t)cursor + size + 0xf) & ~0xf);
        }
        if (index == swrSprite_dial_gradient_rgb)
            swrModel_BuildTiledTextureMaterial(tex);
    }
    swrLoader_CloseBlock(swrLoader_TYPE_SPRITE_BLOCK);
    swrAssetBuffer_SetBuffer(cursor);
    return tex;
}

// 0x00446fb0 TODO: crashes on release, works fine on debug
swrSpriteTexture* swrSprite_LoadTextureById(swrSprite_NAME index)
{
    return swrSprite_LoadTexture(index);
}

// 0x0044EF70
void swrSprite_SetViewport(int minX, int maxX, int minY, int maxY)
{
    spriteViewportMinX = minX;
    spriteViewportMinY = minY;
    spriteViewportMaxX = maxX;
    spriteViewportMaxY = maxY;
}

// 0x0044EFA0
void rdProcEntry_Add2DQuad5(int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, float a10, float a11)
{
    // rotates the rect (a2,a4)-(a3,a5) about its center; a1 and a6..a9 are unused
    const float cy = (float)(a5 + a4) * 0.5f;
    const float cx = (float)(a3 + a2) * 0.5f;
    const float dx0 = (float)a2 - cx;
    const float dx1 = (float)a3 - cx;
    const float dy0 = (float)a4 - cy;
    const float dy1 = (float)a5 - cy;

    const short y3 = (short)(int)(dy1 * a11 - dx0 * a10 + cy + 0.5f) >> 2;
    const short x3 = (short)(int)(cx + dy1 * a10 + dx0 * a11 + 0.5f) >> 2;
    const short y2 = (short)(int)(dy1 * a11 - dx1 * a10 + cy + 0.5f) >> 2;
    const short x2 = (short)(int)(cx + dy1 * a10 + dx1 * a11 + 0.5f) >> 2;
    const short y1 = (short)(int)(dy0 * a11 - dx1 * a10 + cy + 0.5f) >> 2;
    const short x1 = (short)(int)(cx + dx1 * a11 + dy0 * a10 + 0.5f) >> 2;
    const short y0 = (short)(int)(dy0 * a11 - dx0 * a10 + cy + 0.5f) >> 2;
    const short x0 = (short)(int)(cx + dy0 * a10 + dx0 * a11 + 0.5f) >> 2;
    rdProcEntry_Add2DQuad4(x0, y0, x1, y1, x2, y2, x3, y3);
}

// 0x0044F160
void swrSprite_Draw(int* arg0, swrSpriteTexture* a1, RdMaterial** a2, float a3, float a4, float a5, float a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, short a14, float a15, float a16, int a17)
{
    // a2 is the swrSpriteTexturePage: width/height shorts, then the page material
    swrSpriteTexturePage* page = (swrSpriteTexturePage*)a2;
    RdMaterial* material;
    unsigned int alignMask;
    int alignedWidth;
    int rowHeight;
    int doubleRes;
    int state;
    float viewMaxX;
    float viewMaxY;
    float viewMinX;
    float viewMinY;
    int x0;
    int y0;
    int x1;
    int y1;
    int swap;
    int uStart;
    int uEnd;
    int vStart;
    int vEnd;
    float texWidth;
    float texHeight;
    BOOL textured;
    BOOL addZOffset;

    rowHeight = (short)a1->header.unk6;
    switch (a1->header.page_width_align) {
    case 0:
        alignMask = 0xf;
        break;
    case 1:
        alignMask = 7;
        break;
    case 2:
        alignMask = 3;
        break;
    case 3:
        alignMask = 1;
        break;
    default:
        // the original reuses the a13 stack slot as the mask here
        alignMask = a13;
        break;
    }
    alignedWidth = ((short)page->width + alignMask) & ~alignMask;

    doubleRes = a17 & swrSprite_DRAWFLAGS_DOUBLE_RES;
    if (doubleRes) {
        spriteViewportMaxX = spriteViewportMaxX * 2;
        spriteViewportMaxY = spriteViewportMaxY * 2;
    }
    state = *arg0;
    viewMaxX = (float)spriteViewportMaxX;
    viewMaxY = (float)spriteViewportMaxY;
    viewMinX = (float)spriteViewportMinX;
    viewMinY = (float)spriteViewportMinY;
    if (!(a3 < viewMaxX) || !(a4 < viewMaxY) || a5 < viewMinX || a6 < viewMinY)
        goto done;

    // with HIDDEN the original also clamps a7/a8 to the viewport, but only to pass them to the stripped swr_noop2 below
    x0 = a3 < viewMinX ? spriteViewportMinX * 4 : (int)(a3 * 4.0f);
    y0 = a4 < viewMinY ? spriteViewportMinY * 4 : (int)(a4 * 4.0f);
    x1 = a5 < viewMaxX ? (int)(a5 * 4.0f) : spriteViewportMaxX * 4;
    y1 = a6 < viewMaxY ? (int)(a6 * 4.0f) : spriteViewportMaxY * 4;

    material = (RdMaterial*)page->offset;
    if (material != swrSprite_CurrentMaterial) {
        // the original also pushes U/V wrap flags (from the CLAMP_U and CLAMP_V bits) the callee ignores
        rdModel_SetCurrentMaterial(material);
        swrSprite_CurrentMaterial = (RdMaterial*)page->offset;
    }

    if (a17 & (swrSprite_DRAWFLAGS_HIDDEN | swrSprite_DRAWFLAGS_ROTATED)) {
        if ((short)a13 != 0) {
            uStart = 0;
            uEnd = alignedWidth << 6;
        } else {
            uStart = alignedWidth << 6;
            uEnd = 0;
        }
        if (a14 != 0) {
            vStart = rowHeight << 6;
            vEnd = 0;
        } else {
            vStart = 0;
            vEnd = rowHeight << 6;
        }
        if (a17 & swrSprite_DRAWFLAGS_HIDDEN)
            swr_noop2();
        else
            rdProcEntry_Add2DQuad5((int)&state, x0, x1, y0, y1, uEnd, uStart, vStart, vEnd, a15, a16);
    } else {
        texWidth = (float)a11 * (1.0f / 1024.0f) * (float)(abs(x0 - x1) >> 2) - 0.5f;
        texHeight = (float)a12 * (1.0f / 1024.0f) * (float)(abs(y0 - y1) >> 2) - 0.5f;
        if (doubleRes) {
            x0 >>= 3;
            y0 >>= 3;
            x1 >>= 3;
            y1 >>= 3;
        } else {
            x0 >>= 2;
            y0 >>= 2;
            x1 >>= 2;
            y1 >>= 2;
        }
        textured = (a17 & swrSprite_DRAWFLAGS_TEXTURED) != 0;
        addZOffset = (a17 & swrSprite_DRAWFLAGS_Z_OFFSET) != 0;
        if ((short)a13 != 0) {
            swap = x0;
            x0 = x1;
            x1 = swap;
        }
        if (a14 == 0) {
            swap = y0;
            y0 = y1;
            y1 = swap;
        }
        if (a1 == swrSpriteTexture_dial_gradient_rgb || a1 == swrSpriteTexture_dial_gradient_rgb2)
            rdProcEntry_Add2DPolygon(x1, y1, x0, y0, texWidth, texHeight, textured, addZOffset, a1);
        else
            rdProcEntry_Add2DQuad3(x1, y1, x0, y0, texWidth, texHeight, textured, addZOffset);
    }

done:
    *arg0 = state;
    if (doubleRes) {
        spriteViewportMaxX = spriteViewportMaxX / 2;
        spriteViewportMaxY = spriteViewportMaxY / 2;
    }
}

// 0x0044F5F0
void swrSprite_ResetCurrentMaterial()
{
    swr_noop2();
    swrSprite_CurrentMaterial = NULL;
}

// 0x0044F600
void swrSprite_InitDrawing()
{
    swrSprite_ResetCurrentMaterial();
    swrSprite_SetViewport(0, swrDisplay_screenWidth - 1, 0, swrDisplay_screenHeight - 1);
}

// 0x00428820
void swrSprite_SetDrawStateWord2_Maybe(unsigned int value)
{
    swrSprite_SetDrawStateWord_Maybe(value);
}

// 0x0044f630
void swrSprite_SetDrawStateWord_Maybe(unsigned int value)
{
    swrSprite_drawStateWord = value & 0xffff;
}

// 0x0044F640
void swrSprite_GetUIScale(float* out_xscale, float* out_yscale)
{
    *out_xscale = (float)swrDisplay_screenWidth * (float)swrUI_designWidthRecip;
    *out_yscale = (float)swrDisplay_screenHeight * (float)swrUI_designHeightRecip;
}

// 0x0044FEF0
int swrSprite_AddDotToMiniMap(char type, short x, short y)
{
    if (numMiniMapPositions >= SWR_MINIMAP_MAX_DOTS)
        return numMiniMapPositions;

    miniMapPositions[numMiniMapPositions][0] = x;
    miniMapPositions[numMiniMapPositions][1] = y;
    miniMapDotTypes[numMiniMapPositions] = type;
    return ++numMiniMapPositions;
}

// 0x0044FF30
void swrSprite_RenderMiniMapDotsAndCrosses()
{
    float trackFlicker;
    float markerFlicker;
    char glyph;
    char type;
    char prevType;
    int i;

    if (swrRace_GetPauseState() == 0) {
        trackFlicker = swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.5f - -0.5f;
        markerFlicker = swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.5f - -0.5f;
    } else {
        trackFlicker = 0.78f;
        markerFlicker = 0.83f;
    }
    if (numMiniMapPositions == 0)
        return;

    swrText_SetFont(0);
    swrText_SetupGlyph('.');
    glyph = '.';
    swrSprite_setCurrentSpriteColor(0, 0xff, 0, (uint8_t)(int)(miniMapAlpha * trackFlicker * 255.0f));
    prevType = swrMiniMapDot_TRACK;
    for (i = 0; i < numMiniMapPositions; i++) {
        type = miniMapDotTypes[i];
        if (type != prevType) {
            prevType = type;
            if (type == swrMiniMapDot_START_LINE) {
                swrSprite_setCurrentSpriteColor(0, 0xff, 0xff, (uint8_t)(int)(miniMapAlpha * 255.0f));
            } else if (type == swrMiniMapDot_RIVAL) {
                swrSprite_setCurrentSpriteColor(0xff, 0xff, 0, (uint8_t)(int)(miniMapAlpha * markerFlicker * 255.0f));
            } else {
                // faithful: retail range-checks types 3..4 here, but the test can never fail
                if (glyph != 'X') {
                    swrText_SetupGlyph('X');
                    glyph = 'X';
                }
                if (type == swrMiniMapDot_RIVAL_CROSS)
                    swrSprite_setCurrentSpriteColor(0, 0, 0xff, (uint8_t)(int)(miniMapAlpha * 255.0f));
                else
                    swrSprite_setCurrentSpriteColor(0x64, 0xff, 0x64, (uint8_t)(int)(miniMapAlpha * markerFlicker * 255.0f));
            }
        }
        swrText_DrawGlyph(miniMapPositions[i][0], miniMapPositions[i][1], 'p');
    }
    swr_noop2();
    numMiniMapPositions = 0;
}

// 0x0044F670
void swrSprite_Draw1(swrSpriteTexture* tex, short x, short y, float scaleX, float scaleY, float angle, short x2, short y2, unsigned int flags, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    swrSpriteTexturePage* page;
    int hflip;
    int vflip;
    float sinA;
    float cosA;
    float offsetX;
    float offsetY;
    int stepX;
    int stepY;
    unsigned int clampX;
    unsigned int clampY;
    int texelStepX;
    int texelStepY;
    int u0;
    int u1;
    int v0;
    int v1;
    int pageWidth;
    int rowHeight;
    int pageIndex;
    int screenTop;
    int screenLeft;
    int uTexel;
    int vTexel;
    float left;
    float top;
    float right;
    float bottom;
    int drawState;

    if (flags & swrSprite_DRAWFLAGS_SKIP)
        return;
    if (!(scaleX > 1e-05f) || !(scaleY > 1e-05f))
        return;
    if (scaleX == 1.0f && scaleY == 1.0f)
        flags |= swrSprite_DRAWFLAGS_UNSCALED;
    else
        flags &= ~swrSprite_DRAWFLAGS_UNSCALED;
    if (tex == NULL)
        return;

    page = tex->header.page_table;
    hflip = flags & swrSprite_DRAWFLAGS_FLIP_X;
    vflip = flags & swrSprite_DRAWFLAGS_FLIP_Y;
    if (flags & swrSprite_DRAWFLAGS_ROTATED) {
        stdMath_SinCos(angle, &sinA, &cosA);
    } else {
        sinA = 0.0f;
        cosA = 1.0f;
    }
    if (flags & swrSprite_DRAWFLAGS_CENTERED) {
        offsetX = (float)(short)tex->header.width * 0.5f * scaleX;
        offsetY = (float)(short)tex->header.height * 0.5f * scaleY;
    } else {
        offsetX = 0.0f;
        offsetY = 0.0f;
    }
    swrSprite_lastDrawFlags = flags;
    rdProcEntry_SetCurrentColor(0, 0, r, g, b, a);

    stepX = (int)(0.5f - -1024.0f / scaleX);
    stepY = (int)(0.5f - -1024.0f / scaleY);
    clampX = flags & (swrSprite_DRAWFLAGS_CLAMP_U | swrSprite_DRAWFLAGS_CLAMP_U_ALT);
    texelStepX = clampX ? SWR_SPRITE_TEXEL_STEP_ONE : stepX;
    clampY = flags & (swrSprite_DRAWFLAGS_CLAMP_V | swrSprite_DRAWFLAGS_CLAMP_V_ALT);
    texelStepY = clampY ? SWR_SPRITE_TEXEL_STEP_ONE : stepY;
    if (page == NULL)
        return;

    u0 = -1;
    v0 = -1;
    u1 = SWR_SPRITE_PAGE_CURSOR_START;
    v1 = SWR_SPRITE_PAGE_CURSOR_START;
    top = 0.0f;
    bottom = 0.0f;
    vTexel = 0;
    // never initialized in the original; swrSprite_Draw threads it through every page
    drawState = 0;
    for (pageIndex = 0; pageIndex < (short)tex->header.page_count; pageIndex++, page++) {
        pageWidth = (short)page->width;
        if (pageWidth <= 0)
            return;
        if (hflip)
            u0 = u1 - pageWidth;
        else
            u1 = u0 + pageWidth;

        // pages are laid out in rows; the vertical span is only recomputed when a page leaves the current row
        if (u0 < 0 || u1 > (short)tex->header.width) {
            rowHeight = page->height != 0 ? (short)page->height : (short)tex->header.unk6;
            if (v0 == -1) {
                if (vflip) {
                    v0 = (short)tex->header.height - rowHeight;
                    v1 = (short)tex->header.height;
                } else {
                    v0 = 0;
                    v1 = rowHeight;
                }
            } else if (vflip) {
                v1 = v0;
                v0 -= rowHeight;
            } else {
                v0 = v1;
                v1 += rowHeight;
            }
            if (v0 < 0)
                return;
            if (v1 > (short)tex->header.height)
                return;

            if (hflip) {
                u1 = (short)tex->header.width;
                u0 = u1 - pageWidth;
            } else {
                u0 = 0;
                u1 = pageWidth;
            }

            top = v0 * scaleY + (y - offsetY);
            bottom = v1 * scaleY + (y - offsetY);
            screenTop = (int)(top - -0.9999f);
            if (vflip == 0) {
                vTexel = (v1 - v0 - 1) * 32;
            } else {
                vTexel = ((int)(((float)screenTop - top) * stepY) + 0x10) >> 5;
                if (flags & swrSprite_DRAWFLAGS_HALF_TEXEL)
                    vTexel += 0x10;
                if (clampY)
                    vTexel += (int)((bottom - top) * -32.0f);
            }
        }

        left = u0 * scaleX + (x - offsetX);
        right = u1 * scaleX + (x - offsetX);
        screenLeft = (int)(left - -0.9999f);
        if (hflip) {
            uTexel = (u1 - u0 - 1) * 32;
            if (clampX)
                uTexel += (int)((right - left) * 32.0f);
        } else {
            uTexel = ((int)(((float)screenLeft - left) * stepX) + 0x10) >> 5;
            if (flags & swrSprite_DRAWFLAGS_HALF_TEXEL)
                uTexel += 0x10;
        }

        if (page->offset != 0)
            swrSprite_Draw(&drawState, tex, (RdMaterial**)page, left, top, right, bottom, x2, y2, uTexel, vTexel, texelStepX, texelStepY, hflip, vflip == 0, sinA, cosA, flags);

        if (hflip)
            u1 -= pageWidth;
        else
            u0 += pageWidth;
    }
}

// 0x00484130
void swrSprite_ResetDirtyRects(void)
{
    swrSprite_dirtyRectCount = 0;
}

// 0x00484020
void swrSprite_AddDirtyRect(short x1, short y1, short x2, short y2)
{
    double scaleX;
    double scaleY;
    short* rect;

    if (swrSprite_dirtyRectCount >= SWR_SPRITE_MAX_DIRTY_RECTS)
        return;

    x1--;
    y1--;
    x2++;
    y2++;
    if (x1 < 0)
        x1 = 0;
    if (y1 < 0)
        y1 = 0;
    if (x2 > swrDisplay_screenWidth - 1)
        x2 = swrDisplay_screenWidth - 1;
    if (y2 > swrDisplay_screenHeight - 1)
        y2 = swrDisplay_screenHeight - 1;
    if (x2 <= x1 || y2 <= y1)
        return;

    // doubles at 0x004ae0a8 / 0x004ae0b0
    scaleX = swrDisplay_screenWidth * (1.0 / SWR_SPRITE_DIRTY_RECT_REF_WIDTH);
    scaleY = swrDisplay_screenHeight * (1.0 / SWR_SPRITE_DIRTY_RECT_REF_HEIGHT);
    rect = &swrSprite_dirtyRects[swrSprite_dirtyRectCount * 4];
    rect[0] = (short)(x1 * scaleX);
    rect[1] = (short)(y1 * scaleY);
    rect[2] = (short)(x2 * scaleX);
    swrSprite_dirtyRectCount++;
    rect[3] = (short)(y2 * scaleY);
}
