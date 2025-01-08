#include "swrUI.h"

#include "globals.h"
#include "swrModel.h"
#include "swrSprite.h"
#include "swrText.h"

#include <macros.h>

// 0x00408640
void swrUI_UpdateProgressBar(int progressPercent)
{
    HANG("TODO");
}

// 0x00408800 TODO: Crashes on release, works fine on debug
void swrUI_ResetProgressBar(void)
{
    swrUI_progressBar_unk = 0;
    swrUI_UpdateProgressBar(0);
}

// 0x00411480
swrUI_unk* swrUI_GetUI1(void)
{
    return swrUI_unk_ptr;
}

// 0x00413fa0
int swrUI_GetValue(swrUI_unk* ui)
{
    HANG("TODO: members missing in type");
#if 0
    if (ui->value_available != 0)
    {
        return ui->value;
    }
    return -1;
#endif
}

// 0x00414b80
int swrUI_RunCallbacksScreenText(swrUI_unk* ui, char* screenText, int bool_unk)
{
    return swrUI_RunCallbacks(ui, 10, (int)screenText, bool_unk);
}

// 0x00414ba0
char* swrUI_GetAllocatedString(swrUI_unk* ui, char* str_out, int len)
{
    if ((str_out != NULL) && (ui->str_allocated != NULL))
    {
        strncpy(str_out, ui->str_allocated, len - 1);
        str_out[len + -1] = '\0';
        return str_out;
    }
    return ui->str_allocated;
}

// 0x00414be0
void swrUI_SetColorUnk(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->r = r;
    ui->g = g;
    ui->b = b;
    ui->a = a;
}

// 0x00414c10
void swrUI_SetColorUnk4(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->r4 = r;
    ui->g4 = g;
    ui->b4 = b;
    ui->a4 = a;
}

// 0x00414c40
void swrUI_SetColorUnk3(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->r3 = r;
    ui->g3 = g;
    ui->b3 = b;
    ui->a3 = a;
}

// 0x00414c70
void swrUI_SetColorUnk5(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->r5 = r;
    ui->g5 = g;
    ui->b5 = b;
    ui->a5 = a;
}

// 0x00414ca0
void swrUI_SetColorUnk2(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->r2 = r;
    ui->g2 = g;
    ui->b2 = b;
    ui->a2 = a;
}

// 0x00414d90
swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id)
{
    HANG("TODO, easy");
}

// 0x00414e30
void swrUI_SetSelected(swrUI_unk* ui, int bSelected)
{
    if (ui != NULL)
    {
        if (bSelected != 0)
        {
            ui->unk20_flag = ui->unk20_flag | swrUI_SELECTED;
            return;
        }
        ui->unk20_flag = ui->unk20_flag & ~swrUI_SELECTED;
    }
}

// 0x00414e60
int swrUI_RunCallbacks2(swrUI_unk* ui, int bool_unk)
{
    return swrUI_RunCallbacks(ui, 0xe, bool_unk, 0);
}

// 0x00414f00
void swrUI_SetUI5(swrUI_unk* ui)
{
    swrUI_unk5_ptr = ui;
}

// 0x00414fe0
swrUI_unk* swrUI_GetUI4(void)
{
    return swrUI_unk4_ptr;
}

// 0x00414ff0
swrUI_unk* swrUI_GetUI5(void)
{
    return swrUI_unk5_ptr;
}

// 0x00415000
swrUI_unk* swrUI_GetUI6(void)
{
    return swrUI_unk6_ptr;
}

// 0x00415010
void swrUI_ClearUI5(void)
{
    swrUI_SetUI5(NULL);
}

// 0x00415640
int swrUI_HandleKeyEvent(int virtual_key_code, int pressed)
{
    HANG("TODO");
}

// 0x004151a0
int swrUI_RunCallbacks(swrUI_unk* ui, int forward1, int forward2, int forward3)
{
    int res;

    if (ui != NULL)
    {
        if ((ui->fun2 != NULL) && (res = (ui->fun2)(ui, forward1, (void*)forward2, (swrUI_unk*)forward3), res != 0))
        {
            return res;
        }
        if (ui->fun != NULL)
        {
            res = (ui->fun)(ui, forward1, (void*)forward2, forward3);
            return res;
        }
    }
    return 0;
}

// 0x004157d0
int swrUI_ReplaceIndex(swrUI_unk* ui, int new_index)
{
    int old_index;

    old_index = ui->unk0_index;
    ui->unk0_index = new_index;
    return old_index;
}

// 0x00415810
void swrUI_SetBBox(swrUI_unk* ui, int x, int y, int x2, int y2)
{
    if (ui != NULL)
    {
        (ui->bbox).x = x;
        (ui->bbox).y = y;
        (ui->bbox).x2 = x2;
        (ui->bbox).y2 = y2;
    }
}

// 0x00416840
void swrUI_Enqueue(swrUI_unk* ui1, swrUI_unk* toEnqueue)
{
    swrUI_unk* psVar1;
    swrUI_unk* next;

    if (ui1 == NULL)
    {
        ui1 = swrUI_unk_ptr;
    }
    toEnqueue->prev2 = NULL;
    toEnqueue->next2 = NULL;
    toEnqueue->prev = ui1;
    next = ui1->next;
    if (next == NULL)
    {
        ui1->next = toEnqueue;
        return;
    }
    for (psVar1 = next->next2; psVar1 != NULL; psVar1 = psVar1->next2)
    {
        next = psVar1;
    }
    next->next2 = toEnqueue;
    toEnqueue->prev2 = next;
}

// 0x00416D70
int swrUI_HandleKeyEvent2(void* forward2, int)
{
    HANG("TODO");
}

// 0x00416d90
swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1* f1, swrUI_unk_F2* f2)
{
    HANG("TODO, easy");
}

// 0x00417060
void swrUI_ClearAllSprites(swrUI_unk* ui)
{
    if (ui != NULL)
    {
        do
        {
            if (ui->next != NULL)
            {
                swrUI_ClearAllSprites(ui->next);
            }
            swrSprite_ClearSprites(ui);
            ui = ui->next2;
        } while (ui != NULL);
    }
}

// 0x004174e0 TODO: crashes on game startup
char* swrUI_replaceAllocatedStr(char* str, char* mondo_text)
{
    size_t len;
    char* res;

    res = NULL;
    if (str != NULL)
    {
        free(str);
    }
    if (mondo_text != NULL)
    {
        len = strlen(mondo_text);
        res = (char*)malloc(len);
        strncpy(res, mondo_text, len - 1);
        res[len - 1] = '\0';
    }
    return res;
}

// 0x0041b5e0
swrUI_unk* swrUI_GetByValue(swrUI_unk* ui, int value)
{
    int* this_id;

    if (ui == NULL)
    {
        return NULL;
    }
    this_id = &ui->id;
    do
    {
        if (((*(byte*)&ui->unk20_flag & 0x80) != 0) && (ui->prev2->id != *this_id))
            break;
        ui = ui->prev2;
    } while (ui != NULL);
    while (true)
    {
        if (ui == NULL)
        {
            return NULL;
        }
        if (((ui->unk00_6 == 10) && (ui->id == *this_id)) && ((*(int*)(ui->unk538 + 8)) == value))
            break;
        ui = ui->next2;
    }
    return ui;
}

// 0x00420930
void swrUI_LoadTrackFromId(swrRace_TRACK trackId, char* buffer, size_t len)
{
    char* str;
    str = swrUI_GetTrackNameFromId(trackId);
    snprintf(buffer, len, "%s", str);
}

// 0x0043b0b0
void HandleCircuits(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0043fce0
void swrUI_TextMenu(int posX, int posY, int R, int G, int B, int A, char* screenText)
{
    HANG("TODO");
}

// 0x00440150
void MenuAxisHorizontal(void* pUnused, short posY)
{
    HANG("TODO");
}

// 0x004403e0
void swrUI_DrawRecord(swrObjHang* hang, int param_2, int param_3, float param_4, char param_5)
{
    HANG("TODO");
}

// 0x00440620
char* swrUI_GetTrackNameFromId(int trackId) // swrRace_TRACK
{
    char* res = NULL;
    switch (trackId)
    {
    case 0:
        res = swrText_Translate("/SCREENTEXT_497/~~The Boonta Training Course");
        return res;
    case 1:
        res = swrText_Translate("/SCREENTEXT_498 /~~The Boonta Classic");
        return res;
    case 2:
        res = swrText_Translate("/SCREENTEXT_499/~~Beedo's Wild Ride");
        return res;
    case 3:
        res = swrText_Translate("/SCREENTEXT_500/~~Howler Gorge");
        return res;
    case 4:
        res = swrText_Translate("/SCREENTEXT_501/~~Andobi Mountain Run");
        return res;
    case 5:
        res = swrText_Translate("/SCREENTEXT_539/~~Ando Prime Centrum");
        return res;
    case 6:
        res = swrText_Translate("/SCREENTEXT_503/~~Aquilaris Classic");
        return res;
    case 7:
        res = swrText_Translate("/SCREENTEXT_504/~~Sunken City");
        return res;
    case 8:
        res = swrText_Translate("/SCREENTEXT_505/~~Bumpy's Breakers");
        return res;
    case 9:
        res = swrText_Translate("/SCREENTEXT_506/~~Scrapper's Run");
        return res;
    case 10:
        res = swrText_Translate("/SCREENTEXT_507/~~Dethro's Revenge");
        return res;
    case 0xb:
        res = swrText_Translate("/SCREENTEXT_508/~~Abyss");
        return res;
    case 0xc:
        res = swrText_Translate("/SCREENTEXT_509/~~Baroo Coast");
        return res;
    case 0xd:
        res = swrText_Translate("/SCREENTEXT_510/~~Grabvine Gateway");
        return res;
    case 0xe:
        res = swrText_Translate("/SCREENTEXT_511/~~Fire Mountain Rally");
        return res;
    case 0xf:
        res = swrText_Translate("/SCREENTEXT_540/~~Inferno");
        return res;
    case 0x10:
        res = swrText_Translate("/SCREENTEXT_513/~~Mon Gazza Speedway");
        return res;
    case 0x11:
        res = swrText_Translate("/SCREENTEXT_514/~~Spice Mine Run");
        return res;
    case 0x12:
        res = swrText_Translate("/SCREENTEXT_515/~~Zugga Challenge");
        return res;
    case 0x13:
        res = swrText_Translate("/SCREENTEXT_516/~~Vengeance");
        return res;
    case 0x14:
        res = swrText_Translate("/SCREENTEXT_517/~~Executioner");
        return res;
    case 0x15:
        res = swrText_Translate("/SCREENTEXT_518/~~The_Gauntlet");
        return res;
    case 0x16:
        res = swrText_Translate("/SCREENTEXT_519/~~Malastare 100");
        return res;
    case 0x17:
        res = swrText_Translate("/SCREENTEXT_520/~~Dug Derby");
        return res;
    case 0x18:
        res = swrText_Translate("/SCREENTEXT_521/~~Sebulba's Legacy");
    }

    return res;
}

// 0x00440bc0
bool BeatEverything1stPlace(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00457C20
void swrUI_LoadPlanetModels()
{
    swrModel_LoadModelIntoScene(MODELID_pln_tatooine_part, -1, INGAME_MODELID_pln_tatooine_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_andoprime_part, -1, INGAME_MODELID_pln_andoprime_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_water_part, -1, INGAME_MODELID_pln_water_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_cloud_part, -1, INGAME_MODELID_pln_cloud_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_jungle_part, -1, INGAME_MODELID_pln_jungle_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_spice_part, -1, INGAME_MODELID_pln_spice_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_asteroid_part, -1, INGAME_MODELID_pln_asteroid_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_malastare_part, -1, INGAME_MODELID_pln_malastare_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_coruscant_cld_part, -1, INGAME_MODELID_pln_coruscant_cld_part, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_moon_part, -1, INGAME_MODELID_pln_moon_part0, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_moon_part, -1, INGAME_MODELID_pln_moon_part1, 0);
    swrModel_LoadModelIntoScene(MODELID_pln_moon_part, -1, INGAME_MODELID_pln_moon_part2, 0);
}

// 0x00457CF0
void swrUI_LoadMapPartModels()
{
    swrModel_LoadModelIntoScene(MODELID_map_tat1_part, -1, INGAME_MODELID_map_tat1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_tat2_part, -1, INGAME_MODELID_map_tat2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_a1_part, -1, INGAME_MODELID_map_a1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_a2_part, -1, INGAME_MODELID_map_a2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_a3_part, -1, INGAME_MODELID_map_a3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_h_part, -1, INGAME_MODELID_map_h_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_b1_part, -1, INGAME_MODELID_map_b1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_b2_part, -1, INGAME_MODELID_map_b2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_b3_part, -1, INGAME_MODELID_map_b3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_c1_part, -1, INGAME_MODELID_map_c1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_c2_part, -1, INGAME_MODELID_map_c2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_c3_part, -1, INGAME_MODELID_map_c3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_d1_part, -1, INGAME_MODELID_map_d1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_d2_part, -1, INGAME_MODELID_map_d2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_d3_part, -1, INGAME_MODELID_map_d3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_i_part, -1, INGAME_MODELID_map_i_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_e1_part, -1, INGAME_MODELID_map_e1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_e2_part, -1, INGAME_MODELID_map_e2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_e3_part, -1, INGAME_MODELID_map_e3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_f1_part, -1, INGAME_MODELID_map_f1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_f2_part, -1, INGAME_MODELID_map_f2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_f3_part, -1, INGAME_MODELID_map_f3_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_j1_part, -1, INGAME_MODELID_map_j1_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_j2_part, -1, INGAME_MODELID_map_j2_part, 0);
    swrModel_LoadModelIntoScene(MODELID_map_j3_part, -1, INGAME_MODELID_map_j3_part, 0);
}

// 0x00457ed0
void swrUI_LoadUIElements(void)
{
    swrSpriteTexture* tex;
    short id;
    swrUISprite spriteId;

    tex = swrSprite_LoadTexture_(swrSprite_whitesquare_rgb);
    spriteId = swrUISprite_newflare1_rgb_49;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0x90);
    tex = swrSprite_LoadTexture_(swrSprite_whitesquare_rgb);
    spriteId = swrUISprite_lightstar_glowstreak_rgb_3;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        swrSprite_SetFlag((short)spriteId, 0x2000);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0xa2);
    tex = swrSprite_LoadTexture_(swrSprite_window1_yellow_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_6, tex);
    tex = swrSprite_LoadTexture_(swrSprite_rectangle_blue_rgb);
    spriteId = swrUISprite_newflare1_rgb_7;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0x5f);
    tex = swrSprite_LoadTexture_(swrSprite_btm_light_blue_rgb);
    swrSprite_NewSprite(swrUISprite_btm_light_blue_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_bluehalf_rgb);
    swrSprite_NewSprite(swrUISprite_bluehalf_rgb_0, tex);
    tex = swrSprite_LoadTexture_(swrSprite_window1_select_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_16, tex);
    id = 0x57;
    do
    {
        swrSprite_SetFlag(id, 0x8000);
        id = id + 1;
    } while (id < 0x62);
}

// 0x00457fd0
void swrUI_LoadWindowUIElements(void)
{
    HANG("TODO");
}

// 0x004580e0
void swrUI_LoadPartsUIElements(void)
{
    swrSpriteTexture* tex;
    int id;

    tex = swrSprite_LoadTexture_(swrSprite_ui_buy_dnt_buy_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_35, tex);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_36, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_costvalue_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_37, tex);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_38, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_nw_part_name_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_39, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_nw_part_price_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_40, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_nw_part_window_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_41, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_nw_part_ylw_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_42, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_old_part_name_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_43, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_old_part_replace_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_44, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_old_part_window_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_45, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_old_part_ylw_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_46, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ui_vert_light_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_47, tex);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_48, tex);
    id = 0x74;
    do
    {
        swrSprite_SetFlag((short)id, 0x2000);
        swrSprite_SetFlag((short)id, 0x8000);
        id = id + 1;
    } while (id < 0x82);
}

// 0x00458250
void swrUI_LoadSelectionsUIElements(void)
{
    swrSpriteTexture* tex;
    int id;

    tex = swrSprite_LoadTexture_(swrSprite_ctrl_A_rgb);
    swrSprite_NewSprite(swrUISprite_symbol_2_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_B_rgb);
    swrSprite_NewSprite(swrUISprite_symbol_3_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_C_up_rgb);
    swrSprite_NewSprite(swrUISprite_award_third, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_C_down_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_down_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_C_left_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_left_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_C_right_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_right_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_Z_rgb);
    swrSprite_NewSprite(swrUISprite_award_second_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_ctrl_stick_rgb);
    swrSprite_NewSprite(swrUISprite_award_first_rgb, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_arrow_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_arrow_lit_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_circle_rgb);
    swrSprite_NewSprite(swrUISprite_select_circle_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_circle_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_bars_rgb);
    swrSprite_NewSprite(swrUISprite_select_bars_rgb, tex);
    id = 0xad;
    do
    {
        swrSprite_SetFlag((short)id, 4);
        id = id + 1;
    } while (id < 0xb0);
    id = 0xaa;
    do
    {
        swrSprite_SetFlag((short)id, 0x8000);
        id = id + 1;
    } while (id < 0xb1);
    tex = swrSprite_LoadTexture_(swrSprite_select_arrow_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_v_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_arrow_lit_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_v_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_circle_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_circle_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_circle_v_rgb_1, tex);
    tex = swrSprite_LoadTexture_(swrSprite_select_bars_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_bars_v_rgb, tex);
    id = 0xb4;
    do
    {
        swrSprite_SetFlag((short)id, 8);
        id = id + 1;
    } while (id < 0xb7);
    id = 0xb1;
    do
    {
        swrSprite_SetFlag((short)id, 0x8000);
        id = id + 1;
    } while (id < 0xb8);
}
