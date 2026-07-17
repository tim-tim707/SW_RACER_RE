#include "swrUI.h"

#include "globals.h"
#include "swrModel.h"
#include "swrSprite.h"
#include "swrText.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <Primitives/rdVector.h>

#include <macros.h>

// 0x00408640
void swrUI_UpdateProgressBar(int progressPercent)
{
    struct tagRECT rect;
    LPDIRECTDRAWSURFACE4 surf;

    if (iDirectDraw4_error != 0)
        return;

    surf = stdDisplay_g_frontBuffer.pVSurface.pDDSurf;

    // top edge
    rect.left = swrUI_progressBarX;
    rect.top = swrUI_progressBarY;
    rect.right = swrUI_progressBarX + swrUI_progressBarWidth;
    rect.bottom = swrUI_progressBarY + 1;
    surf->lpVtbl->Blt(surf, (LPRECT)&rect, ddSurfaceForProgressBar, (LPRECT)&tagRect, 0x1000000 /* DDBLT_WAIT */, NULL);

    // bottom edge
    rect.left = swrUI_progressBarX;
    rect.right = swrUI_progressBarX + swrUI_progressBarWidth;
    rect.bottom = swrUI_progressBarY + swrUI_progressBarHeight;
    rect.top = rect.bottom - 1;
    surf->lpVtbl->Blt(surf, (LPRECT)&rect, ddSurfaceForProgressBar, (LPRECT)&tagRect, 0x1000000 /* DDBLT_WAIT */, NULL);

    // left edge
    rect.left = swrUI_progressBarX;
    rect.right = swrUI_progressBarX + 1;
    rect.top = swrUI_progressBarY;
    rect.bottom = swrUI_progressBarY + swrUI_progressBarHeight;
    surf->lpVtbl->Blt(surf, (LPRECT)&rect, ddSurfaceForProgressBar, (LPRECT)&tagRect, 0x1000000 /* DDBLT_WAIT */, NULL);

    // right edge
    rect.left = swrUI_progressBarX + swrUI_progressBarWidth - 1;
    rect.right = swrUI_progressBarX + swrUI_progressBarWidth;
    rect.top = swrUI_progressBarY;
    rect.bottom = swrUI_progressBarY + swrUI_progressBarHeight;
    surf->lpVtbl->Blt(surf, (LPRECT)&rect, ddSurfaceForProgressBar, (LPRECT)&tagRect, 0x1000000 /* DDBLT_WAIT */, NULL);

    // fill proportional to progress
    if (progressPercent > 100)
        progressPercent = 100;
    if (progressPercent < 0)
        progressPercent = 0;
    rect.left = swrUI_progressBarX;
    rect.right = swrUI_progressBarX + (progressPercent * swrUI_progressBarWidth) / 100;
    rect.top = swrUI_progressBarY;
    rect.bottom = swrUI_progressBarY + swrUI_progressBarHeight;
    surf->lpVtbl->Blt(surf, (LPRECT)&rect, ddSurfaceForProgressBar, (LPRECT)&tagRect, 0x1000000 /* DDBLT_WAIT */, NULL);
}

// 0x00408800 TODO: Crashes on release, works fine on debug
void swrUI_ResetProgressBar(void)
{
    swrUI_progressBar_unk = 0;
    swrUI_UpdateProgressBar(0);
}

// 0x00411390
void swrUI_AlignElementTo(swrUI_unk* a, swrUI_unk* b, unsigned int edgeFlags)
{
    if (a != NULL && b != NULL) {
        // ignore a request that pins both opposing edges of an axis at once
        if (((edgeFlags & 2) == 0 || (edgeFlags & 8) == 0) && ((edgeFlags & 1) == 0 || (edgeFlags & 4) == 0)) {
            if ((edgeFlags & 2) != 0)
                swrUI_SetPos(a, a->x, b->y);
            if ((edgeFlags & 8) != 0)
                swrUI_SetPos(a, a->x, (b->height - a->height) + a->y);
            if ((edgeFlags & 1) != 0)
                swrUI_SetPos(a, b->x, a->y);
            if ((edgeFlags & 4) != 0)
                swrUI_SetPos(a, (a->x - a->width) + b->width, a->y);
        }
    }
}

// 0x00411440
void swrUI_CenterElement(swrUI_unk* ui, int centerX, int centerY)
{
    int x;
    int y;

    if (ui != NULL) {
        y = ui->y;
        if (centerY != 0)
            y = ((y - ui->height) + 0x1df) >> 1; // center on the 480px-tall screen
        x = ui->x;
        if (centerX != 0)
            x = ((x - ui->width) + 0x27f) >> 1; // center on the 640px-wide screen
        swrUI_SetPos(ui, x, y);
    }
}

// 0x00411480
swrUI_unk* swrUI_GetUI1(void)
{
    return swrUI_unk_ptr;
}

// 0x00411490
void swrUI_EnableElement(swrUI_unk* ui)
{
    if (ui != NULL)
        ui->flags = ui->flags & ~swrUI_DISABLED;
}

// 0x004114b0
void swrUI_DisableElement(swrUI_unk* ui)
{
    if (ui != NULL)
        ui->flags = ui->flags | swrUI_DISABLED;
}

// 0x00411730
void swrUI_SetCaretActive(int active)
{
    swrUI_caretEnabled = active;
}

// 0x00411740
void swrUI_SetCaretRect(int x, int y, int w, int h)
{
    swrUI_caretX = x;
    swrUI_caretY = y;
    swrUI_caretW = w;
    swrUI_caretH = h;
}

// 0x004117e0
void swrUI_ResetPageStack(void)
{
    for (int i = 0; i < 20; i++)
        (&swrUI_pageStack)[i] = NULL;
    swrUI_pageStackDepth = 0;
}

// 0x00411800
int swrUI_GetPageStackDepth(void)
{
    return swrUI_pageStackDepth;
}

// 0x00411810
swrUI_unk* swrUI_GetCurrentPage(void)
{
    return (swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth];
}

// 0x00411820
void swrUI_PushMenuPage(int pageId)
{
    swrUI_unk* ui = NULL;
    if (pageId != 0)
        ui = swrUI_GetById(NULL, pageId);
    if (swrUI_prevPage != ui) {
        if ((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth] != NULL)
            swrUI_RunCallbacks2((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth], 0);
        swrUI_prevPage = (swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth];
        if ((unsigned int)swrUI_pageStackDepth < 0x14)
            swrUI_pageStackDepth = swrUI_pageStackDepth + 1;
        int forward2 = swrUI_pageStackDepth;
        if (pageId != 0) {
            (&swrUI_pageStack)[swrUI_pageStackDepth] = ui;
            if (ui != NULL) {
                swrUI_RunCallbacks(ui, 0x46, forward2, 0);
                swrUI_suppressBackPop = 0;
                return;
            }
        }
        swrUI_PopMenuPage();
    }
}

// 0x004118b0
void swrUI_PopMenuPage(void)
{
    if ((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth] != NULL)
        swrUI_RunCallbacks((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth], 0x47, swrUI_pageStackDepth, 0);
    swrUI_prevPage = (swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth];
    swrUI_suppressBackPop = 0;
    if (swrUI_pageStackDepth != 0)
        swrUI_pageStackDepth = swrUI_pageStackDepth - 1;
    if ((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth] != NULL)
        swrUI_RunCallbacks((swrUI_unk*)(&swrUI_pageStack)[swrUI_pageStackDepth], 0x46, swrUI_pageStackDepth, 0);
}

// 0x00412fb0
int swrUI_AddSprite(swrUI_unk* ui, int index, int spriteId, int* rect, int flag, int flag2)
{
    int i;

    if (index == -1) {
        if ((unsigned int)ui->sprite_count > 19) {
            return -1; // vanilla leaves the return register untouched here
        }
        for (i = 0; i < 20; i++) {
            if ((ui->ui_elements[i].flag & swrUI_SPRITE_SLOT_IN_USE) == 0) {
                ui->sprite_count = ui->sprite_count + 1;
                index = i;
                break;
            }
        }
        if (index == -1) {
            return i; // no free slot found
        }
    }
    ui->ui_elements[index].texture_id = spriteId;
    ui->ui_elements[index].width = 1.0f;
    ui->ui_elements[index].height = 1.0f;
    ui->ui_elements[index].flag = flag2 | swrUI_SPRITE_SLOT_IN_USE;
    swrUI_SetSpriteColor(ui, index, 0xff, 0xff, 0xff, 0xff);
    swrUI_SetSpriteRect(ui, index, rect);
    ui->sprite_count = 0;
    for (i = 0; i < 20; i++) {
        if ((ui->ui_elements[i].flag & swrUI_SPRITE_SLOT_IN_USE) != 0) {
            ui->sprite_count = ui->sprite_count + 1;
        }
    }
    swrUI_SetSpriteFlag(ui, index, flag);
    return index;
}

// 0x00413090
void swrUI_SetSpriteColor(swrUI_unk* ui, int slot, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (ui != NULL && slot >= 0 && slot < 20) {
        ui->ui_elements[slot].r = r;
        ui->ui_elements[slot].g = g;
        ui->ui_elements[slot].b = b;
        ui->ui_elements[slot].a = a;
    }
}

// 0x004130e0
void swrUI_SetSpriteFlag(swrUI_unk* ui, int slot, int enabled)
{
    if (enabled != 0) {
        ui->ui_elements[slot].flag = ui->ui_elements[slot].flag | swrUI_SPRITE_SLOT_ENABLED_UNK;
    } else {
        ui->ui_elements[slot].flag = ui->ui_elements[slot].flag & ~swrUI_SPRITE_SLOT_ENABLED_UNK;
    }
}

// 0x00413500
void swrUI_SetMaxLength(swrUI_unk* ui, int maxLength)
{
    if (ui != NULL)
        ui->max_length = maxLength;
}

// 0x004136f0
swrUI_unk* swrUI_FindChildByText(swrUI_unk* list, char* text)
{
    swrUI_unk* child;

    if (list != NULL && text != NULL && (child = list->next) != NULL) {
        do {
            if (child->str_allocated != NULL && strcmpi(child->str_allocated, text) == 0)
                return child;
            child = child->next2;
        } while (child != NULL);
    }
    return NULL;
}

// 0x004137a0
swrUI_unk* swrUI_GetSelectedItem(swrUI_unk* list)
{
    swrUI_unk* item;

    for (item = list->next; item != NULL; item = item->next2) {
        if (item->item_flags & swrUI_ITEM_SELECTED)
            return item;
    }
    return NULL;
}

// 0x004137d0
int swrUI_CountSelectableItems(swrUI_unk* ui)
{
    swrUI_unk* item;
    int count;

    count = 0;
    for (item = ui->next; item != NULL; item = item->next2) {
        // widget_class low byte with bits 0x4|0x8 set marks a selectable list item
        if (((uint8_t)item->widget_class & 0xc) == 0xc)
            count++;
    }
    return count;
}

// 0x004138b0
void swrUI_SetListHighlightColor(swrUI_unk* list, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (list != NULL) {
        list->r2 = r;
        list->g2 = g;
        list->b2 = b;
        list->a2 = a;
        swrUI_ApplyListColors(list);
    }
}

// 0x00413b10
int swrUI_GetNumberValue(swrUI_unk* ui)
{
    if (ui != NULL) {
        return *(int*)(ui->unk538 + 0x24); // number/slider value (+0x55c)
    }
    return 0;
}

// 0x00413b90
swrUI_unk* swrUI_NewSpriteElement(swrUI_unk* parent, int id, int* rect, int spriteId, int spriteFlag, swrUI_unk_F2* f2, int sizeUnk)
{
    swrUI_unk* ui;

    if (rect == NULL) {
        return NULL;
    }
    ui = swrUI_New(parent, id, -1, NULL, 0, sizeUnk, 0, (swrUI_unk_F1)swrUI_DefaultElementProc, (swrUI_unk_F2)f2);
    ui->flags = ui->flags | swrUI_STATIC;
    swrUI_SetSize(ui, rect[2] - rect[0] + 1, rect[3] - rect[1] + 1);
    swrUI_SetPos(ui, rect[0], rect[1]);
    swrUI_AddSprite(ui, 0, spriteId, rect, 1, spriteFlag);
    swrUI_SetSpriteColor(ui, 0, 0xff, 0xff, 0xff, 0xff);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_SPRITE;
    return ui;
}

// 0x00413fa0
int swrUI_GetValue(swrUI_unk* ui)
{
    if (*(int*)(ui->unk538 + 4) != 0) { // value-available flag (+0x53c)
        return *(int*)(ui->unk538 + 8); // stored value (+0x540)
    }
    return -1;
}

// 0x00414420
void swrUI_SetChecked(swrUI_unk* ui, unsigned int checked)
{
    unsigned int wasChecked;
    swrSprite_NAME spriteId;
    int texW;
    int texH;
    int rect[4];
    swrUI_unk* spriteElem;

    if (ui == NULL) {
        return;
    }
    wasChecked = ui->flags & swrUI_CHECKED;
    if (checked != 0) {
        // enforce single selection within the radio group first
        swrUI_ClearGroupChecked(ui);
        ui->flags = ui->flags | swrUI_CHECKED;
    } else {
        ui->flags = ui->flags & ~swrUI_CHECKED;
    }
    if ((ui->flags & swrUI_CHECK_CIRCLE_UNK) != 0) {
        spriteId = checked != 0 ? swrSprite_axis_check_circ_selected : swrSprite_axis_check_circ;
    } else if ((ui->flags & swrUI_VERTICAL) != 0) {
        spriteId = checked != 0 ? swrSprite_radio_checked : swrSprite_radio_unchecked;
    } else {
        spriteId = checked != 0 ? swrSprite_tiny_box_selected : swrSprite_tiny_box;
    }
    swrSprite_GetTextureDimFromId(spriteId, &texW, &texH);
    if (spriteId == swrSprite_tiny_box_selected || spriteId == swrSprite_tiny_box) {
        // boxes hug the right edge (width/height fields hold the right/bottom edge)
        rect[0] = ui->width - texW - 3;
        rect[2] = ui->width - 3;
    } else {
        rect[0] = ui->x + 3;
        rect[2] = ui->x + 3 + texW - 1;
    }
    rect[1] = ui->y + (int)((unsigned int)(ui->height - ui->y - texH + 1) >> 1);
    rect[3] = rect[1] + texH - 1;
    if (ui->next == NULL) {
        spriteElem = swrUI_NewSpriteElement(ui, 0, rect, spriteId, 0, NULL, 0);
        spriteElem->flags = spriteElem->flags | swrUI_CHECK_SPRITE_UNK;
    }
    swrUI_AddSprite(ui->next, 0, spriteId, rect, 1, 0);
    if (checked != wasChecked) {
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_CHECKED_CHANGED, ui->id, checked);
    }
}

// 0x00414590
void swrUI_ToggleChecked(swrUI_unk* ui)
{
    swrUI_SetChecked(ui, (ui->flags & swrUI_CHECKED) == 0);
}

// 0x00414ab0
void swrUI_SetValueText(swrUI_unk* ui, char* text, int value)
{
    ui->value_text = swrUI_replaceAllocatedStr(ui->value_text, text);
    ui->value = value;
}

// 0x00414ae0
void swrUI_SetValue(swrUI_unk* ui, int value)
{
    ui->value = value;
}

// 0x00414af0
char* swrUI_GetValueText(swrUI_unk* ui, char* out, int len)
{
    if (out != NULL && ui->value_text != NULL) {
        strncpy(out, ui->value_text, len - 1);
        out[len - 1] = '\0';
        return out;
    }
    return ui->value_text;
}

// 0x00414b40
void swrUI_SetSize(swrUI_unk* ui, int width, int height)
{
    swrUI_RunCallbacks(ui, 0xc, width, height);
}

// 0x00414b60
void swrUI_SetPos(swrUI_unk* ui, int x, int y)
{
    swrUI_RunCallbacks(ui, 0xb, x, y);
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

// 0x00414cd0
int swrUI_SetSlotValue(swrUI_unk* ui, int index, int value)
{
    int old;

    old = *(int*)(ui->unk01_10 + index * 4);
    *(int*)(ui->unk01_10 + index * 4) = value;
    return old;
}

// 0x00414cf0
int swrUI_GetSlotValue(swrUI_unk* ui, int index)
{
    return *(int*)(ui->unk01_10 + index * 4);
}

// 0x00414d90
swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id)
{
    if (ui == NULL) {
        ui = swrUI_unk_ptr;
    }
    if (ui->id == id) {
        return ui;
    }

    // Walk the element's child list (siblings linked via next2). List-item
    // widgets (class 0xc) are skipped; any other child with its own children
    // is searched recursively first, then matched directly.
    for (swrUI_unk* child = ui->next; child != NULL; child = child->next2) {
        if (child->widget_class == 0xc) {
            continue;
        }
        if (child->next != NULL) {
            swrUI_unk* found = swrUI_GetById(child, id);
            if (found != NULL) {
                return found;
            }
        }
        if (child->id == id) {
            return child;
        }
    }
    return NULL;
}

// 0x00414e30
void swrUI_SetSelected(swrUI_unk* ui, int bSelected)
{
    if (ui != NULL)
    {
        if (bSelected != 0)
        {
            ui->flags = ui->flags | swrUI_SELECTED;
            return;
        }
        ui->flags = ui->flags & ~swrUI_SELECTED;
    }
}

// 0x00414e60
int swrUI_RunCallbacks2(swrUI_unk* ui, int bool_unk)
{
    return swrUI_RunCallbacks(ui, 0xe, bool_unk, 0);
}

// 0x00414e80
int swrUI_IsElementVisible(swrUI_unk* ui)
{
    if (ui == NULL)
        return 1;
    do {
        if ((ui->flags & swrUI_VISIBLE) == 0)
            return 0;
        ui = ui->prev;
    } while (ui != NULL);
    return 1;
}

// 0x00414eb0
void swrUI_SetUI4(swrUI_unk* ui)
{
    if (swrUI_unk4_ptr != NULL) {
        swrUI_unk4_ptr->flags = swrUI_unk4_ptr->flags & ~swrUI_HOVERED;
    }
    swrUI_RunCallbacks(swrUI_unk4_ptr, swrUI_MSG_HOVER_CHANGED, 0, 0);
    swrUI_unk4_ptr = ui;
    if (ui != NULL) {
        ui->flags = ui->flags | swrUI_HOVERED;
    }
    swrUI_RunCallbacks(ui, swrUI_MSG_HOVER_CHANGED, 1, 0);
}

// 0x00414f00
void swrUI_SetUI5(swrUI_unk* ui)
{
    swrUI_unk5_ptr = ui;
}

// 0x00414f70
void swrUI_SetFocusedElement(swrUI_unk* element)
{
    if (element == NULL || (element->widget_class != 0 && (element->flags & swrUI_DISABLED) == 0)) {
        if (swrUI_focusedElement != NULL)
            swrUI_focusedElement->flags = swrUI_focusedElement->flags & ~swrUI_FOCUSED;
        swrUI_RunCallbacks(swrUI_focusedElement, 0xd, 0, 0);
        swrUI_focusedElement = element;
        if (element != NULL)
            element->flags = element->flags | swrUI_FOCUSED;
        swrUI_RunCallbacks(swrUI_focusedElement, 0xd, 1, 0);
    }
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
    return swrUI_focusedElement;
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

    old_index = ui->font_index;
    ui->font_index = new_index;
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

// 0x00415850
int swrUI_DefaultElementProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    HANG("TODO");
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
swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1 f1, swrUI_unk_F2 f2)
{
    unsigned int alloc_size = (size_unk1 + size_unk2) * 4 + 0x15c0;
    swrUI_unk* elem = (swrUI_unk*)malloc(alloc_size);
    for (unsigned int i = 0; i < alloc_size >> 2; i++) {
        ((int*)elem)[i] = 0;
    }

    if (f1 == NULL) {
        f1 = (swrUI_unk_F1)swrUI_DefaultElementProc;
    }
    elem->str_allocated = swrUI_replaceAllocatedStr(elem->str_allocated, mondo_text);
    elem->id = id;
    elem->flags = flag;
    elem->size_unk2 = size_unk2;
    elem->size_unk1 = size_unk1;
    elem->unk01_10 = elem->unk538 + size_unk1 * 4 + 0x38;
    elem->fun = f1;
    elem->fun2 = f2;
    elem->font_index = 0;
    swrUI_SetBBox(elem, 0, 0, 0x27f, 0x1df);
    swrUI_SetColorUnk(elem, 0xb7, 0xf5, 0xff, 0xff);
    swrUI_SetColorUnk2(elem, 0xb7, 0xf5, 0xff, 0xff);
    swrUI_SetColorUnk4(elem, 0xb7, 0xf5, 0xff, 0xff);
    swrUI_SetColorUnk3(elem, 0xff, 0xff, 0xff, 0xff);
    swrUI_SetColorUnk5(elem, 0xff, 0xff, 0xff, 0xff);
    swrUI_RunCallbacksScreenText(elem, mondo_text, 0);
    if (new_index == -1) {
        new_index = 0;
    }
    swrUI_ReplaceIndex(elem, new_index);
    swrUI_Enqueue(ui, elem);
    swrUI_RunCallbacks(elem, 0xf, 0, 0);
    return elem;
}

// 0x00416f20
void swrUI_OnSetElementSize(swrUI_unk* ui, int width, int height)
{
    ui->offset_x = width;
    ui->width = ui->x - 1 + width;
    ui->offset_y = height;
    ui->height = ui->y - 1 + height;
}

// 0x00416f50
void swrUI_OnSetElementPos(swrUI_unk* ui, int x, int y)
{
    int dx = x - ui->x;
    int dy = y - ui->y;
    ui->width = (ui->width - ui->x) + x;
    ui->x = x;
    ui->height = (ui->height - ui->y) + y;
    ui->y = y;
    for (int i = 0; i < ui->sprite_count; i++) {
        ui->ui_elements[i].screen_x1 += dx;
        ui->ui_elements[i].screen_x2 += dx;
        ui->ui_elements[i].screen_y1 += dy;
        ui->ui_elements[i].screen_y2 += dy;
    }
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

// 0x004171a0
void swrUI_SetSpriteRect(swrUI_unk* ui, int slot, int* rect)
{
    int texW;
    int texH;

    if (ui == NULL) {
        return;
    }
    swrSprite_GetTextureDimFromId(ui->ui_elements[slot].texture_id, &texW, &texH);
    ui->ui_elements[slot].texture_w = texW;
    ui->ui_elements[slot].texture_h = texH;
    if (rect != NULL) {
        // width/height become the UV scale of the dest rect over the texture
        ui->ui_elements[slot].width = (float)(rect[2] - rect[0] + 1) / (float)texW;
        ui->ui_elements[slot].height = (float)(rect[3] - rect[1] + 1) / (float)texH;
        ui->ui_elements[slot].screen_x1 = rect[0];
        ui->ui_elements[slot].screen_y1 = rect[1];
        ui->ui_elements[slot].screen_x2 = rect[2];
        ui->ui_elements[slot].screen_y2 = rect[3];
    } else {
        // no rect: span the texture from the element origin
        ui->ui_elements[slot].screen_x1 = ui->x;
        ui->ui_elements[slot].screen_y1 = ui->y;
        ui->ui_elements[slot].screen_x2 = ui->x + texW - 1;
        ui->ui_elements[slot].screen_y2 = ui->y + texH - 1;
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

// 0x00418b70
void swrUI_ClearGroupChecked(swrUI_unk* ui)
{
    int groupId;

    if (ui == NULL) {
        return;
    }
    groupId = ui->id;
    // rewind to the first member of the radio group: a marked element whose
    // preceding sibling belongs to a different group id
    while (!((ui->flags & swrUI_RADIO_GROUP_UNK) != 0 && ui->prev2->id != groupId)) {
        ui = ui->prev2;
        if (ui == NULL) {
            break;
        }
    }
    // sweep forward, unchecking every checkable FramedText member of the group
    while (ui != NULL && ui->widget_class == swrUI_CLASS_FRAMED_TEXT && ui->id == groupId) {
        swrUI_SetChecked(ui, 0);
        ui = ui->next2;
    }
}

// 0x00418bc0
void swrUI_ApplyListColors(swrUI_unk* list)
{
    swrUI_unk* item;

    if (list == NULL) {
        return;
    }
    for (item = list->next; item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
            swrUI_SetColorUnk(item, list->r, list->g, list->b, list->a);
            swrUI_SetColorUnk2(item, list->r2, list->g2, list->b2, list->a2);
            swrUI_SetColorUnk4(item, list->r4, list->g4, list->b4, list->a4);
            swrUI_SetColorUnk3(item, list->r3, list->g3, list->b3, list->a3);
            swrUI_SetColorUnk5(item, list->r5, list->g5, list->b5, list->a5);
        }
    }
}

// 0x00419030
void swrUI_SetSpriteOffset(swrUI_unk* ui, int slot, int offsetX, int offsetY)
{
    if (ui != NULL && slot >= 0 && slot < 20) {
        ui->ui_elements[slot].pos_x = offsetX;
        ui->ui_elements[slot].pos_y = offsetY;
    }
}

// 0x00419140
void swrUI_RandomizeSpriteAlpha(swrUI_unk* element)
{
    unsigned int first;
    int count;
    int alpha;
    unsigned int i;

    if (element == NULL) {
        return;
    }
    count = element->unk58;
    first = element->unk54;
    if (count == 0) {
        count = 20;
    }
    if (first > (unsigned int)element->sprite_count) {
        return;
    }
    if ((unsigned int)element->sprite_count < first + count) {
        count = element->sprite_count - first;
    }
    // roll lands in (-156, 0], so the alpha lands in [100, 255]
    alpha = 100 - (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * -156.0f);
    for (i = first; i < first + count; i++) {
        swrUI_SetSpriteColor(element, i, element->ui_elements[i].r, element->ui_elements[i].g, element->ui_elements[i].b, (uint8_t)alpha);
    }
}

// 0x004197f0
void swrUI_SetSpriteSelectionBBox_Maybe(int* bbox_out, int collapsed)
{
    if (bbox_out != NULL) {
        if (collapsed != 0) {
            bbox_out[3] = 0;
            bbox_out[2] = 0;
            bbox_out[1] = 0;
            bbox_out[0] = 0;
            return;
        }
        bbox_out[2] = 0x14;
        bbox_out[0] = 0x14;
        bbox_out[3] = 0x1a;
        bbox_out[1] = 0x1a;
    }
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
        if (((*(byte*)&ui->flags & 0x80) != 0) && (ui->prev2->id != *this_id))
            break;
        ui = ui->prev2;
    } while (ui != NULL);
    while (true)
    {
        if (ui == NULL)
        {
            return NULL;
        }
        if (((ui->widget_class == 10) && (ui->id == *this_id)) && ((*(int*)(ui->unk538 + 8)) == value))
            break;
        ui = ui->next2;
    }
    return ui;
}

// 0x0041b630
void swrUI_ApplyFocusColor(swrUI_unk* ui)
{
    if ((ui->flags & swrUI_FOCUSED) != 0) {
        swrUI_SetColorUnk(ui, ui->r5, ui->g5, ui->b5, ui->a5);
    } else {
        swrUI_SetColorUnk(ui, ui->r2, ui->g2, ui->b2, ui->a2);
    }
}

// 0x00420930
void swrUI_Front_LoadTrackFromId(swrRace_TRACK trackId, char* buffer, size_t len)
{
    char* str;
    str = swrUI_Front_GetTrackNameFromId(trackId);
    snprintf(buffer, len, "%s", str);
}

// 0x0043b0b0
void swrUI_Front_HandleCircuits(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0043fce0
void swrUI_Front_TextMenu(swrObjHang* hang, int posX, int posY, int rowSpacing, int selectedIndex, int itemIndex, char* screenText)
{
    rdVector3 color = { 163.0f, 190.0f, 17.0f };
    rdVector3 colorBase = { 163.0f, 190.0f, 17.0f };
    rdVector3 colorAlt = { 0.0f, 255.0f, 0.0f };

    if (selectedIndex == itemIndex) {
        float sin_val;
        float cos_val;
        stdMath_SinCos(swrObjHang_menuTextPulsePhase * 360.0f, &sin_val, &cos_val);
        float t = (sin_val + 1.0f) * 0.5f;
        rdVector_Scale3Add3_both(&color, t, &colorBase, 1.0f - t, &colorAlt);
    }

    if (hang->menuScreen == swrObjHang_STATE_MAIN_MENU && hang->activeMenu == 1) {
        if (selectedIndex == 0 && itemIndex == 0) {
            swrSprite_SetColor(0x82, (uint8_t)color.x, (uint8_t)color.y, (uint8_t)color.z, 0xff);
        }
        if (selectedIndex == 1 && itemIndex == 1) {
            swrSprite_SetColor(0x83, (uint8_t)color.x, (uint8_t)color.y, (uint8_t)color.z, 0xff);
        }
    }

    if (selectedIndex == itemIndex) {
        swrText_CreateTextEntry1(posX, itemIndex * rowSpacing + posY, (int)color.x, (int)color.y, (int)color.z, -1, screenText);
    } else {
        swrText_CreateTextEntry1(posX, itemIndex * rowSpacing + posY, 0x32, -1, -1, -1, screenText);
    }
}

// 0x00440150
void swrUI_Front_MenuAxisHorizontal(void* pUnused, short posY)
{
    float rateLeft = swrRace_MenuCanScrollLeft ? 838.2f : -838.2f;
    swrUI_menuArrowAlphaLeft += rateLeft * swrRace_fdeltaTimeSecs;
    if (swrUI_menuArrowAlphaLeft > 254.0f) {
        swrUI_menuArrowAlphaLeft = 254.0f;
    }
    if (swrUI_menuArrowAlphaLeft < 0.0f) {
        swrUI_menuArrowAlphaLeft = 0.0f;
    }

    float rateRight = swrRace_MenuCanScrollRight ? 838.2f : -838.2f;
    swrUI_menuArrowAlphaRight += rateRight * swrRace_fdeltaTimeSecs;
    if (swrUI_menuArrowAlphaRight > 254.0f) {
        swrUI_menuArrowAlphaRight = 254.0f;
    }
    if (swrUI_menuArrowAlphaRight < 0.0f) {
        swrUI_menuArrowAlphaRight = 0.0f;
    }

    swrSprite_SetVisible(0xae, 1);
    swrSprite_SetPos(0xae, 0x13, posY - 0xe);
    swrSprite_SetColor(0xae, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(0xad, 1);
    swrSprite_SetPos(0xad, 0x16, posY - 7);
    swrSprite_SetColor(0xad, 0x32, 0xff, 0xff, (uint8_t)swrUI_menuArrowAlphaLeft);
    swrSprite_SetVisible(0xab, 1);
    swrSprite_SetPos(0xab, 0x10b, posY - 0xe);
    swrSprite_SetColor(0xab, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(0xaa, 1);
    swrSprite_SetPos(0xaa, 0x112, posY - 7);
    swrSprite_SetColor(0xaa, 0x32, 0xff, 0xff, (uint8_t)swrUI_menuArrowAlphaRight);
    swrSprite_SetVisible(0xb0, 1);
    swrSprite_SetPos(0xb0, 0x30, posY - 4);
    swrSprite_SetColor(0xb0, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetDim(0xb0, 73.0f, 1.0f);
    if (swrRace_MenuNavRightActive != 0) {
        swrSprite_SetVisible(0xac, 1);
        swrSprite_SetPos(0xac, 0xe8, posY - 0x13);
        swrSprite_SetColor(0xac, 0x32, 0xff, 0xff, 0xfe);
    }
    if (swrRace_MenuNavLeftActive != 0) {
        swrSprite_SetVisible(0xaf, 1);
        swrSprite_SetPos(0xaf, 0xc, posY - 0x13);
        swrSprite_SetColor(0xaf, 0x32, 0xff, 0xff, 0xfe);
    }
}

// 0x004403e0
void swrUI_Front_DrawRecord(swrObjHang* hang, int param_2, int param_3, float param_4, char param_5)
{
    HANG("TODO");
}

// 0x00440620
char* swrUI_Front_GetTrackNameFromId(int trackId) // swrRace_TRACK
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
bool swrUI_Front_BeatEverything1stPlace(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00457C20
void swrUI_Front_LoadPlanetModels()
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
void swrUI_Front_LoadMapPartModels()
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
void swrUI_Front_LoadUIElements(void)
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
void swrUI_Front_LoadWindowUIElements(void)
{
    HANG("TODO");
}

// 0x004580e0
void swrUI_Front_LoadPartsUIElements(void)
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
void swrUI_Front_LoadSelectionsUIElements(void)
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
