#include "swrUI.h"

#include "globals.h"

// 0x00411480
swrUI_unk* swrUI_GetUI1(void)
{
    return swrUI_unk_ptr;
}

// 0x00413fa0
int swrUI_GetValue(swrUI_unk* ui)
{
    if (ui->value_available != 0)
    {
        return ui->value;
    }
    return -1;
}

// 0x00414b80
int swrUI_RunCallbacksScreenText(swrUI_unk* ui, char* screenText, int bool_unk)
{
    return swrUI_RunCallbacks(ui, 10, screenText, bool_unk);
}

// 0x00414be0
void swrUI_SetColorUnk(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->unk4c0_r = r;
    ui->unk4c4_g = g;
    ui->unk4c8_b = b;
    ui->unk4cc_a = a;
}

// 0x00414c10
void swrUI_SetColorUnk3(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->unk4cc_r = r;
    ui->unk4cd_g = g;
    ui->unk4ce_b = b;
    ui->unk4cf_a = a;
}

// 0x00414c40
void swrUI_SetColorUnk4(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->unk4c8_r = r;
    ui->unk4c9_g = g;
    ui->unk4ca_b = b;
    ui->unk4cb_a = a;
}

// 0x00414c70
void swrUI_SetColorUnk5(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->unk4d0_r = r;
    ui->unk4d1_g = g;
    ui->unk4d2_b = b;
    ui->unk4d3_a = a;
}

// 0x00414ca0
void swrUI_SetColorUnk2(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    ui->unk4c4_r = r;
    ui->unk4c5_g = g;
    ui->unk4c6_b = b;
    ui->unk4c7_a = a;
}

// 0x00414d90
swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id)
{
    HANG("TODO, easy");
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

// 0x004151a0
int swrUI_RunCallbacks(swrUI_unk* ui, int forward1, int forward2, int forward3)
{
    int res;

    if (ui != NULL)
    {
        if ((ui->fun2 != NULL) && (res = (ui->fun2)(ui, forward1, forward2, forward3), res != 0))
        {
            return res;
        }
        if (ui->fun != NULL)
        {
            res = (ui->fun)(ui, forward1, forward2, forward3);
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
void swrUI_SetUnk(swrUI_unk* ui, int a, int b, int c, int d)
{
    if (ui != NULL)
    {
        ui->unk0_100 = a;
        ui->unk0_101 = b;
        ui->unk0_102 = c;
        ui->unk0_103 = d;
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

// 0x00416d90
swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1* f1, swrUI_unk_F2* f2)
{
    HANG("TODO, easy");
}

// 0x004174e0
char* swrUI_replaceAllocatedStr(char* str, char* mondo_text)
{
    size_t len;
    char* res;

    res = NULL;
    if (str != NULL)
    {
        stdlib__free(str);
    }
    if (mondo_text != NULL)
    {
        len = _strlen(mondo_text);
        res = (char*)stdlib__malloc(len);
        _strncpy(res, mondo_text, len - 1);
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
        if (((*(byte*)&ui->unk00_flag & 0x80) != 0) && (ui->prev2->id != *this_id))
            break;
        ui = ui->prev2;
    } while (ui != NULL);
    while (true)
    {
        if (ui == NULL)
        {
            return NULL;
        }
        if (((ui->unk00_6 == 10) && (ui->id == *this_id)) && (ui->value == value))
            break;
        ui = ui->next2;
    }
    return ui;
}
