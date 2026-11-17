#include "swrUI.h"

#include "globals.h"
#include "swrModel.h"
#include "swrObj.h"
#include "swrRace.h"
#include "swrSprite.h"
#include "swrText.h"
#include "swr.h"
#include "engine_config.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <Primitives/rdVector.h>
#include <Win95/stdConsole.h>

#include <macros.h>
#include <engine_config.h>

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

// 0x00411370
void swrUI_RefreshRoot(void)
{
    swrUI_RunCallbacks2(swrUI_GetUI1(), 0);
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

// 0x00411770
void swrUI_AddTimer(swrUI_unk* target, int interval, int param)
{
    int i;

    for (i = 0; i < SWR_UI_MAX_TIMERS; i++) {
        if (swrUI_timers[i].target == NULL) {
            swrUI_timers[i].target = target;
            swrUI_timers[i].intervalMs = interval;
            swrUI_timers[i].remainingMs = interval;
            swrUI_timers[i].id = param;
            return;
        }
    }
}

// 0x004117b0
void swrUI_RemoveTimer(int param)
{
    int i;

    for (i = 0; i < SWR_UI_MAX_TIMERS; i++) {
        if (swrUI_timers[i].id == param) {
            swrUI_timers[i].target = NULL;
            swrUI_timers[i].intervalMs = 0;
            swrUI_timers[i].remainingMs = 0;
            swrUI_timers[i].id = 0;
        }
    }
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

// 0x00412630
void swrUI_ResetAttractDemoTimer(void)
{
    swrObjHang_attractDemoTimer = 30.0f;
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

// 0x00413130
swrUI_unk* swrUI_NewWindow(swrUI_unk* parent, int* rect, int id, swrUI_unk_F2* f2)
{
    swrUI_unk* ui;
    int x0 = 0;
    int y0 = 0;
    int x1 = 0;
    int y1 = 0;

    ui = swrUI_New(parent, id, -1, NULL, 0, 0, 0, (swrUI_unk_F1)swrUI_DefaultElementProc, (swrUI_unk_F2)f2);
    if (rect != NULL) {
        y0 = rect[1];
        x0 = rect[0];
        x1 = rect[2];
        y1 = rect[3];
    }
    swrUI_SetSize(ui, x1 - x0 + 1, y1 - y0 + 1);
    swrUI_SetPos(ui, x0, y0);
    ui->widget_class = 0;
    return ui;
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

// 0x00413740
int swrUI_GetSelectedIndex(swrUI_unk* list)
{
    int index = 0;
    swrUI_unk* item;

    for (item = list->next; item != NULL; item = item->next2) {
        if (item->item_flags & swrUI_ITEM_SELECTED)
            return index;
        index++;
    }
    return -1;
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

// 0x004138f0
swrUI_unk* swrUI_AddListItem(swrUI_unk* list, char* text, int value, int id, int param5)
{
    HANG("TODO");
    return NULL;
}

// 0x00413b10
int swrUI_GetNumberValue(swrUI_unk* ui)
{
    if (ui != NULL) {
        return ui->number_value;
    }
    return 0;
}

// 0x00413b30
void swrUI_SetNumberValue(swrUI_unk* ui, int value)
{
    if (ui == NULL)
        return;
    ui->number_value = value;
    swrUI_BuildSliderSprites(ui, (ui->flags & swrUI_SLIDER_SELECTED) != 0);
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
    if (ui->has_option_value != 0) {
        return ui->option_value;
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

// 0x00414e10
swrUI_unk* swrUI_GetLastSibling(swrUI_unk* element)
{
    if (element == NULL)
        return NULL;
    while (element->next2 != NULL)
        element = element->next2;
    return element;
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

// 0x00414f10
void swrUI_FocusElement(swrUI_unk* element, int moveCursor)
{
    if (swrUI_IsFocusable(element))
        swrUI_SetFocusedElement(element);
    if (element != NULL && moveCursor != 0)
        stdConsole_SetCursorPos((element->width - element->x + 1) / 2 + element->x, (element->height - element->y + 1) / 2 + element->y);
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
    if (swrUI_IsElementVisible(swrUI_unk_ptr) == 0)
        return 0;

    swrUI_ResetAttractDemoTimer();
    if (swrUI_focusedElement != NULL)
        return swrUI_RunCallbacks(swrUI_focusedElement, pressed != 0 ? swrUI_MSG_KEY_DOWN : swrUI_MSG_KEY_UP, virtual_key_code, 0);
    if (pressed != 0)
        return pressed;

    swrUI_FocusFirstOnNav(virtual_key_code);
    // retail returns whatever swrUI_FocusFirstOnNav left in EAX; no caller reads it
    return 0;
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

// 0x004168f0
void swrUI_ClearElementRefs(swrUI_unk* element)
{
    if (element == swrUI_GetUI4())
        swrUI_SetUI4(NULL);
    if (element == swrUI_GetUI5())
        swrUI_SetUI5(NULL);
    if (element == swrUI_GetUI6())
        swrUI_SetFocusedElement(NULL);
}

// 0x00416cc0
void swrUI_QuantizeNavAxis(float x, float y, int* outX, int* outY)
{
    if (outX == NULL || outY == NULL)
        return;
    // faithful: a small deflection maps to +-2 only on the positive side
    if (x < 0.0f)
        *outX = x < -0.5f ? -2 : -1;
    else
        *outX = x > 0.5f ? 1 : 2;
    if (y < 0.0f)
        *outY = y < -0.5f ? -2 : -1;
    else
        *outY = y > 0.5f ? 1 : 2;
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
    elem->unk01_10 = (char*)&elem->unk538 + size_unk1 * 4 + 0x38;
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

// 0x004184d0
void swrUI_DrawCaret(void)
{
    unsigned int elapsedMs;
    unsigned int step;
    unsigned int bgWidth;
    unsigned int bgHeight;
    float bgW;
    float bgH;
    float width;
    float height;

    elapsedMs = (unsigned int)(int)(swrRace_deltaTimeSecs * 1000.0);
    swrSprite_SetVisible(SWR_UI_CARET_SPRITE_ID, 0);
    if (swrUI_caretEnabled == 0)
        return;

    swrSprite_GetTextureDimFromId(swrSprite_background, (int*)&bgWidth, (int*)&bgHeight);
    bgW = (float)bgWidth;
    bgH = (float)bgHeight;
    swrSprite_SetPos(SWR_UI_CARET_SPRITE_ID, (short)swrUI_caretX, (short)swrUI_caretY);
    if (swrDisplay_screenWidth == SWR_UI_CARET_WIDE_SCREEN_WIDTH) {
        width = (float)((double)(unsigned int)swrUI_caretW * 1.25 / bgW);
    } else {
        width = (float)((double)(unsigned int)swrUI_caretW / bgW);
    }
    height = (float)((double)(unsigned int)swrUI_caretH / bgH);
    swrSprite_SetDim(SWR_UI_CARET_SPRITE_ID, width, height);
    swrSprite_SetColor(SWR_UI_CARET_SPRITE_ID, 0xff, 0xff, 0xff, 0xff);

    step = swrUI_caretBlinkTimer < elapsedMs ? swrUI_caretBlinkTimer : elapsedMs;
    swrUI_caretBlinkTimer -= step;
    if (swrUI_caretBlinkTimer == 0) {
        swrUI_caretBlinkTimer = SWR_UI_CARET_BLINK_MS;
        swrUI_caretVisible = swrUI_caretVisible == 0;
    }
    swrSprite_SetVisible(SWR_UI_CARET_SPRITE_ID, swrUI_caretVisible);
    swrSprite_SetFlag(SWR_UI_CARET_SPRITE_ID, 0x800);
    swrSprite_SetFlag(SWR_UI_CARET_SPRITE_ID, 0x10000);
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

// 0x00419070
void swrUI_GetFrameTextureDim(int flags, int* outWidth, int* outHeight)
{
    if (flags == 0)
        return;
    if (flags & swrUI_FRAME_STYLE_OK_BUTTON) {
        swrSprite_GetTextureDimFromId(swrSprite_ok_button, outWidth, outHeight);
        return;
    }
    if (flags & swrUI_FRAME_STYLE_EDIT_SEGMENTED) {
        swrSprite_GetTextureDimFromId(swrSprite_editwindow_segmented, outWidth, outHeight);
        return;
    }
    if (flags & swrUI_FRAME_STYLE_SEGMENT) {
        swrSprite_GetTextureDimFromId(swrSprite_segment, outWidth, outHeight);
        return;
    }
    if (flags & swrUI_FRAME_STYLE_SETTINGS_BUTTON) {
        swrSprite_GetTextureDimFromId(swrSprite_settings_btn_strch_end, outWidth, outHeight);
        return;
    }
    if (flags & swrUI_FRAME_STYLE_SMALL_WINDOW) {
        swrSprite_GetTextureDimFromId(swrSprite_sml_window_strch, outWidth, outHeight);
        return;
    }
    swrSprite_GetTextureDimFromId((flags & swrUI_FRAME_STYLE_WINDOW_BARS) ? swrSprite_window_strchbars : (swrSprite_NAME)flags, outWidth, outHeight);
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
    count = element->rand_alpha_count;
    first = element->rand_alpha_first;
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

// 0x00419830
void swrUI_BuildPanelFrame(swrUI_unk* ui, int kind, int selected)
{
    int corner;
    int cornerW;
    int cornerH;
    int vEdgeW;
    int vEdgeH;
    int hEdgeW;
    int hEdgeH;
    int hSpan;
    int vSpan;
    swrSprite_NAME barEnd;
    swrSprite_NAME barStretch;
    int barEndW;
    int barEndH;
    int barStretchW;
    int barStretchH;
    int rect[4];

    if (ui == NULL)
        return;

    corner = kind == 1 ? swrSprite_sml_edit_box_corner : swrSprite_edit_window_corner;
    swrSprite_GetTextureDimFromId((swrSprite_NAME)(corner + 1), &vEdgeW, &vEdgeH);
    swrSprite_GetTextureDimFromId((swrSprite_NAME)corner, &cornerW, &cornerH);
    swrSprite_GetTextureDimFromId((swrSprite_NAME)(corner + 2), &hEdgeW, &hEdgeH);

    if (kind == 1) {
        rect[0] = cornerW + ui->x;
        rect[1] = ui->y + 4;
        rect[2] = ui->width - cornerW;
        rect[3] = ui->height - 3;
    } else {
        rect[0] = ui->x + 10;
        rect[1] = ui->y + 10;
        rect[2] = ui->width - 10;
        rect[3] = ui->height - 10;
    }
    swrUI_AddSprite(ui, 0, swrSprite_background, rect, 1, 0);
    swrUI_SetSpriteColor(ui, 0, 0, 0, 0, 0x96);

    rect[0] = ui->x;
    rect[1] = ui->y;
    rect[2] = cornerW + rect[0] - 1;
    rect[3] = cornerH + rect[1] - 1;
    swrUI_AddSprite(ui, 1, corner, rect, 1, swrUI_SPRITE_SLOT_MIRROR_V);

    hSpan = ui->width - cornerW * 2 - ui->x + 1;
    if (swrDisplay_screenWidth != SWR_UI_FRAME_NATIVE_SCREEN_WIDTH)
        hSpan += hEdgeW * 2;
    rect[0] = cornerW + ui->x;
    rect[1] = ui->y;
    rect[2] = cornerW + hSpan + ui->x - 1;
    rect[3] = hEdgeH + rect[1] - 1;
    swrUI_AddSprite(ui, 2, corner + 2, rect, 1, swrUI_SPRITE_SLOT_MIRROR_V);

    rect[2] = ui->width;
    rect[0] = rect[2] - cornerW + 1;
    rect[1] = ui->y;
    rect[3] = cornerH + rect[1] - 1;
    swrUI_AddSprite(ui, 3, corner, rect, 1, swrUI_SPRITE_SLOT_MIRROR_V | swrUI_SPRITE_SLOT_MIRROR_H);

    vSpan = ui->height - cornerH * 2 - ui->y + 1;
    if (swrDisplay_screenWidth != SWR_UI_FRAME_NATIVE_SCREEN_WIDTH)
        vSpan += vEdgeH * 2;
    rect[0] = ui->x;
    rect[1] = cornerH + ui->y;
    rect[2] = vEdgeW + rect[0] - 1;
    rect[3] = vSpan + cornerH + ui->y - 1;
    swrUI_AddSprite(ui, 4, corner + 1, rect, 1, 0);

    rect[0] = ui->width - cornerW + 1;
    rect[1] = cornerH + ui->y;
    rect[2] = vEdgeW + ui->width - cornerW;
    rect[3] = vSpan + cornerH + ui->y - 1;
    swrUI_AddSprite(ui, 5, corner + 1, rect, 1, swrUI_SPRITE_SLOT_MIRROR_H);

    rect[0] = ui->x;
    rect[1] = ui->height - cornerH + 1;
    rect[2] = cornerW + rect[0] - 1;
    rect[3] = ui->height;
    swrUI_AddSprite(ui, 6, corner, rect, 1, 0);

    rect[0] = cornerW + ui->x;
    rect[1] = ui->height - hEdgeH + 1;
    rect[2] = hSpan + cornerW + ui->x - 1;
    rect[3] = ui->height;
    swrUI_AddSprite(ui, 7, corner + 2, rect, 1, 0);

    // faithful: the bottom-right corner's top edge uses the horizontal edge height
    rect[2] = ui->width;
    rect[0] = rect[2] - cornerW + 1;
    rect[1] = ui->height - hEdgeH + 1;
    rect[3] = cornerH + ui->height - hEdgeH;
    swrUI_AddSprite(ui, 8, corner, rect, 1, swrUI_SPRITE_SLOT_MIRROR_H);

    if (kind != 0)
        return;

    swrUI_SetSelected(ui, selected);
    if (selected != 0) {
        barEnd = swrSprite_edit_window_bar_end_selected;
        barStretch = swrSprite_edit_windowbar_strch_selected;
    } else {
        barEnd = swrSprite_edit_window_bar_end;
        barStretch = swrSprite_edit_window_bar_strch;
    }
    swrSprite_GetTextureDimFromId(barEnd, &barEndW, &barEndH);
    swrSprite_GetTextureDimFromId(barStretch, &barStretchW, &barStretchH);
    ui->rand_alpha_first = 9;

    rect[0] = cornerW + ui->x;
    rect[1] = ui->y;
    rect[2] = barEndW + cornerW + ui->x - 1;
    rect[3] = barEndH + rect[1] - 1;
    swrUI_AddSprite(ui, 9, barEnd, rect, 1, 0);

    rect[0] = barEndW + cornerW + ui->x;
    rect[1] = ui->y;
    rect[2] = ui->width - cornerW - barEndW;
    rect[3] = barStretchH + rect[1] - 1;
    swrUI_AddSprite(ui, 10, barStretch, rect, 1, 0);

    // faithful: the top-right bar end is sized with the stretch sprite's height
    rect[2] = ui->width - cornerW;
    rect[0] = rect[2] - barEndW + 1;
    rect[1] = ui->y;
    rect[3] = barStretchH + rect[1] - 1;
    swrUI_AddSprite(ui, 11, barEnd, rect, 1, swrUI_SPRITE_SLOT_MIRROR_H);

    rect[0] = cornerW + ui->x;
    rect[1] = ui->height - barStretchH + 1;
    rect[2] = barEndW + cornerW + ui->x - 1;
    rect[3] = barEndH + ui->height - barStretchH;
    swrUI_AddSprite(ui, 12, barEnd, rect, 1, 0);

    rect[0] = barEndW + cornerW + ui->x;
    rect[1] = ui->height - barStretchH + 1;
    rect[2] = ui->width - cornerW - barEndW;
    rect[3] = ui->height;
    swrUI_AddSprite(ui, 13, barStretch, rect, 1, 0);

    rect[2] = ui->width - cornerW;
    rect[0] = rect[2] - barEndW + 1;
    rect[1] = ui->height - barStretchH + 1;
    rect[3] = ui->height;
    swrUI_AddSprite(ui, 14, barEnd, rect, 1, swrUI_SPRITE_SLOT_MIRROR_H);

    ui->rand_alpha_count = 15 - ui->rand_alpha_first;
}

// 0x00419db0
void swrUI_BuildSliderSprites(swrUI_unk* slider, int state)
{
    swrSprite_NAME endSprite;
    swrSprite_NAME stretchSprite;
    swrSprite_NAME startCap;
    swrSprite_NAME endCap;
    swrSprite_BBox startBox;
    swrSprite_BBox endBox;
    swrSprite_BBox track;
    swrSprite_BBox box;
    unsigned int w;
    int h;
    int offset;
    unsigned int fillW;
    unsigned int spread;
    int mirror;
    int slot;

    if (slider == NULL)
        return;

    if (state != 0) {
        if (slider->flags & swrUI_VERTICAL) {
            endSprite = swrSprite_vslider_end_selected;
            stretchSprite = swrSprite_vslider_strch_selected;
        } else {
            endSprite = swrSprite_sliderbar_end_selected;
            stretchSprite = swrSprite_sliderbar_strch_selected;
        }
    } else if (slider->flags & swrUI_VERTICAL) {
        endSprite = swrSprite_vsliderbar_end;
        stretchSprite = swrSprite_vsliderbar_strch;
    } else {
        endSprite = swrSprite_sliderbar_end;
        stretchSprite = swrSprite_sliderbar_strch;
    }
    if (slider->flags & swrUI_LEFT_RIGHT_UNK) {
        startCap = swrSprite_slider_plus;
        endCap = swrSprite_slider_minus;
    } else {
        startCap = swrSprite_slider_minus;
        endCap = swrSprite_slider_plus;
    }

    if (slider->flags & swrUI_VERTICAL) {
        swrSprite_GetTextureDimFromId(endSprite, (int*)&w, &h);
        startBox.x = slider->x;
        startBox.y = slider->y;
        startBox.x2 = w + startBox.x - 1;
        startBox.y2 = h + startBox.y - 1;
        swrSprite_GetTextureDimFromId(endSprite, (int*)&w, &h);
        endBox.x = slider->x;
        endBox.y = slider->slider_length + slider->y - h;
        endBox.x2 = w + endBox.x - 1;
        endBox.y2 = slider->slider_length + slider->y - 1;
        swrSprite_GetTextureDimFromId(stretchSprite, (int*)&w, &h);
        track.x = slider->x;
        track.y = startBox.y2 + 1;
        track.x2 = w + track.x - 1;
        track.y2 = endBox.y - 1;
    } else {
        swrSprite_GetTextureDimFromId(endSprite, (int*)&w, &h);
        startBox.x = slider->x;
        startBox.y = slider->y;
        startBox.x2 = w + startBox.x - 1;
        startBox.y2 = h + startBox.y - 1;
        swrSprite_GetTextureDimFromId(endSprite, (int*)&w, &h);
        endBox.x = slider->slider_length + slider->x - w;
        endBox.y = slider->y;
        endBox.x2 = slider->slider_length + slider->x - 1;
        endBox.y2 = h + endBox.y - 1;
        swrSprite_GetTextureDimFromId(stretchSprite, (int*)&w, &h);
        track.x = startBox.x2 + 1;
        track.y = slider->y;
        track.x2 = endBox.x - 1;
        track.y2 = h + track.y - 1;
    }

    if (slider->flags & swrUI_VERTICAL) {
        box.x = track.x + 15;
        box.y = track.y - 7;
        box.x2 = track.x2 - 15;
        box.y2 = track.y2 + 7;
    } else {
        box.x = track.x - 7;
        box.y = track.y + 15;
        box.x2 = track.x2 + 7;
        box.y2 = track.y2 - 15;
    }
    swrUI_AddSprite(slider, 0, swrSprite_background, (int*)&box, 1, 0);
    swrUI_SetSpriteColor(slider, 0, 0, 0, 0, 0x82);
    swrUI_AddSprite(slider, 1, endSprite, (int*)&startBox, 1, 0);
    swrUI_AddSprite(slider, 2, stretchSprite, (int*)&track, 1, 0);
    swrUI_AddSprite(slider, 3, endSprite, (int*)&endBox, 1, (slider->flags & swrUI_VERTICAL) ? swrUI_SPRITE_SLOT_MIRROR_V : swrUI_SPRITE_SLOT_MIRROR_H);
    slot = 4;

    if ((slider->flags & (swrUI_SLIDER_NO_CAPS | swrUI_DISABLED)) == 0) {
        swrSprite_GetBBoxFromId(startCap, &box);
        swrSprite_MoveBBox(&box, &startBox, 1, 1);
        swrUI_AddSprite(slider, 4, startCap, (int*)&box, 1, 0);
        swrSprite_GetBBoxFromId(endCap, &box);
        swrSprite_MoveBBox(&box, &endBox, 1, 1);
        slot = 6;
        swrUI_AddSprite(slider, 5, endCap, (int*)&box, 1, 0);
    }

    if ((slider->flags & swrUI_SLIDER_SHOW_VALUE) == 0)
        goto resize;

    if (slider->flags & swrUI_SLIDER_CENTERED) {
        swrSprite_GetTextureDimFromId(swrSprite_slider_point, (int*)&w, &h);
        offset = ((int)(track.x2 - track.x + 1) >> 1) - (int)(w >> 1);
        box.x = track.x + offset;
        box.y = track.y;
        box.x2 = w + track.x + offset - 1;
        box.y2 = h + track.y - 1;
        swrSprite_MoveBBox(&box, &track, 0, 1);
        swrSprite_TranslateBBox(&box, 0, 1);
        swrUI_AddSprite(slider, slot++, swrSprite_slider_point, (int*)&box, 1, 0);

        // faithful: the center marker reuses slider_point's dimensions
        offset = (track.x2 - track.x + 1) * (unsigned int)(slider->slider_center_value + 100) / 200 - (w >> 1);
        box.x = track.x + offset;
        box.y = track.y;
        box.x2 = w + track.x + offset - 1;
        box.y2 = h + track.y - 1;
        swrSprite_MoveBBox(&box, &track, 0, 1);
        swrSprite_TranslateBBox(&box, 0, 1);
        swrUI_AddSprite(slider, slot++, swrSprite_slider_point_center, (int*)&box, 1, 0);

        swrSprite_GetTextureDimFromId(swrSprite_slider_bracket, (int*)&w, &h);
        offset = ((int)(track.x2 - track.x + 1) >> 1) - (int)(w >> 1);
        spread = (unsigned int)slider->slider_spread * (unsigned int)(offset - 4) / 100;
        box.x = track.x + offset;
        box.y = track.y;
        box.x2 = w + track.x + offset - 1;
        box.y2 = h + track.y - 1;
        swrSprite_MoveBBox(&box, &track, 0, 1);
        swrSprite_TranslateBBox(&box, -4 - (int)spread, 0);
        swrUI_AddSprite(slider, slot++, swrSprite_slider_bracket, (int*)&box, 1, 0);

        offset = ((int)(track.x2 - track.x + 1) >> 1) + (int)(w >> 1);
        box.x = track.x + offset;
        box.y = track.y;
        box.x2 = w + track.x + offset - 1;
        box.y2 = h + track.y - 1;
        swrSprite_MoveBBox(&box, &track, 0, 1);
        swrSprite_TranslateBBox(&box, (int)spread - 15, 0);
        swrUI_AddSprite(slider, slot, swrSprite_slider_bracket, (int*)&box, 1, swrUI_SPRITE_SLOT_MIRROR_H);
        goto resize;
    }

    fillW = (track.x2 - track.x + 1) * (unsigned int)slider->slider_percent / 100;
    swrSprite_GetTextureDimFromId(swrSprite_slider_gradient, NULL, &h);
    box.x = track.x;
    box.y = 0;
    box.x2 = fillW + track.x - 1;
    box.y2 = h - 1;
    swrSprite_MoveBBox(&box, &track, 0, 1);
    swrSprite_TranslateBBox(&box, 0, 1);
    if (slider->flags & swrUI_LEFT_RIGHT_UNK)
        swrSprite_MoveBBoxTo(&box, track.x2 - box.x2 + box.x, box.y);
    mirror = (slider->flags & swrUI_LEFT_RIGHT_UNK) ? swrUI_SPRITE_SLOT_MIRROR_H : 0;
    swrUI_AddSprite(slider, slot++, swrSprite_slider_gradient, (int*)&box, 1, mirror);
    if ((slider->flags & swrUI_SLIDER_THUMB) == 0)
        goto resize;

    swrSprite_GetTextureDimFromId(swrSprite_slider_point, (int*)&w, &h);
    if (slider->flags & swrUI_LEFT_RIGHT_UNK) {
        box.x = track.x2 - fillW - (w >> 1) + 1;
        box.x2 = w - fillW + track.x2 - (w >> 1);
    } else {
        box.x = track.x + fillW - (w >> 1);
        box.x2 = w + track.x + fillW - (w >> 1) - 1;
    }
    box.y = track.y;
    box.y2 = h + track.y - 1;
    swrSprite_MoveBBox(&box, &track, 0, 1);
    swrSprite_TranslateBBox(&box, 0, 1);
    mirror = (slider->flags & swrUI_LEFT_RIGHT_UNK) ? swrUI_SPRITE_SLOT_MIRROR_H : 0;
    swrUI_AddSprite(slider, slot++, swrSprite_slider_point, (int*)&box, 1, mirror);

    swrSprite_GetTextureDimFromId(swrSprite_slider_point_center, (int*)&w, &h);
    if (slider->flags & swrUI_LEFT_RIGHT_UNK) {
        box.x = track.x2 - fillW - (w >> 1) + 1;
        box.x2 = w - fillW + track.x2 - (w >> 1);
    } else {
        box.x = track.x + fillW - (w >> 1);
        box.x2 = w + track.x + fillW - (w >> 1) - 1;
    }
    box.y = track.y;
    box.y2 = h + track.y - 1;
    swrSprite_MoveBBox(&box, &track, 0, 1);
    swrSprite_TranslateBBox(&box, 0, 1);
    mirror = (slider->flags & swrUI_LEFT_RIGHT_UNK) ? swrUI_SPRITE_SLOT_MIRROR_H : 0;
    swrUI_AddSprite(slider, slot, swrSprite_slider_point_center, (int*)&box, 1, mirror);

resize:
    if (slider->flags & swrUI_VERTICAL) {
        swrUI_SetSize(slider, startBox.x2 - startBox.x + 1, endBox.y2 - startBox.y + 1);
    } else {
        swrUI_SetSize(slider, endBox.x2 - startBox.x + 1, startBox.y2 - startBox.y + 1);
    }
}

// 0x0041a640
void swrUI_HandleSliderKey(swrUI_unk* slider, unsigned int key)
{
    unsigned int minusKey;
    unsigned int plusKey;
    unsigned int step;

    minusKey = MapVirtualKeyA(SWR_SCANCODE_MINUS, MAPVK_VSC_TO_VK);
    plusKey = MapVirtualKeyA(SWR_SCANCODE_EQUALS, MAPVK_VSC_TO_VK);
    if (key == VK_SUBTRACT || key == minusKey) {
        playUISound(0x48);
        step = (unsigned int)slider->slider_step;
        if (step < (unsigned int)slider->slider_percent) {
            slider->slider_percent -= step;
        } else {
            slider->slider_percent = 0;
        }
        if (step < (unsigned int)slider->slider_spread) {
            slider->slider_spread -= step;
        } else {
            slider->slider_spread = 0;
        }
        swrUI_RunCallbacks(slider->prev, swrUI_MSG_SLIDER_DECREASED, slider->id, (int)slider);
        swrUI_BuildSliderSprites(slider, 1);
    }
    if (key == VK_ADD || key == plusKey) {
        playUISound(0x48);
        step = (unsigned int)slider->slider_step;
        if ((unsigned int)slider->slider_percent < 100 - step) {
            slider->slider_percent += step;
        } else {
            slider->slider_percent = 100;
        }
        if ((unsigned int)slider->slider_spread < 100 - step) {
            slider->slider_spread += step;
        } else {
            slider->slider_spread = 100;
        }
        swrUI_RunCallbacks(slider->prev, swrUI_MSG_SLIDER_INCREASED, slider->id, (int)slider);
        swrUI_BuildSliderSprites(slider, 1);
    }
}

// 0x0041af00
int swrUI_LayoutRadioGroup(swrUI_unk* elem, int y, unsigned int minWidth, int count, int* outPositions)
{
    unsigned int circleW;
    int circleH;
    unsigned int partW;
    int partH;
    unsigned int totalW;
    unsigned int cellGap;
    int x;
    int cellX;
    int last;
    int rect[4];

    swrSprite_GetTextureDimFromId(swrSprite_axis_check_circ, (int*)&circleW, &circleH);
    x = elem->x;
    totalW = (circleW + 10) * count - 10;
    if (totalW < minWidth) {
        totalW = minWidth;
    } else {
        x += (minWidth >> 1) - (totalW >> 1);
    }

    swrSprite_GetTextureDimFromId(swrSprite_axis_check_strch, (int*)&partW, &partH);
    rect[0] = x;
    rect[1] = y;
    rect[2] = totalW + x - 1;
    rect[3] = partH + y - 1;
    swrUI_AddSprite(elem, 0, swrSprite_axis_check_strch, rect, 1, 0);
    swrUI_SetSpriteOffset(elem, 0, 0, 0);

    swrSprite_GetTextureDimFromId(swrSprite_axis_check_end, (int*)&partW, &partH);
    rect[0] = x - 4;
    rect[1] = y;
    rect[2] = rect[0] + partW - 1;
    rect[3] = partH + y - 1;
    swrUI_AddSprite(elem, 1, swrSprite_axis_check_end, rect, 1, 0);
    swrUI_SetSpriteOffset(elem, 1, 0, 0);
    outPositions[0] = (x - 4) - (circleW >> 1) + 2;

    last = 1;
    if (count == 4) {
        cellGap = (totalW - circleW * 3) / 3;
        swrSprite_GetTextureDimFromId(swrSprite_axis_check_center, (int*)&partW, &partH);
        cellX = cellGap + x + 5;
        rect[0] = (circleW >> 1) + cellX;
        rect[1] = y;
        rect[2] = partW - 1 + rect[0];
        rect[3] = partH + y - 1;
        swrUI_AddSprite(elem, 2, swrSprite_axis_check_center, rect, 1, 0);
        swrUI_SetSpriteOffset(elem, 2, 0, 0);
        outPositions[1] = cellX + 6;

        cellX += cellGap + circleW;
        rect[0] = (circleW >> 1) + cellX;
        rect[1] = y;
        rect[2] = partW - 1 + rect[0];
        rect[3] = partH + y - 1;
        swrUI_AddSprite(elem, 3, swrSprite_axis_check_center, rect, 1, 0);
        swrUI_SetSpriteOffset(elem, 3, 0, 0);
        outPositions[2] = cellX + 4;
        last = 3;
    } else if (count == 3) {
        swrSprite_GetTextureDimFromId(swrSprite_axis_check_center, (int*)&partW, &partH);
        rect[0] = x + (totalW >> 1) - (partW >> 1);
        rect[1] = y;
        rect[2] = rect[0] + partW - 1;
        rect[3] = partH + y - 1;
        swrUI_AddSprite(elem, 2, swrSprite_axis_check_center, rect, 1, 0);
        swrUI_SetSpriteOffset(elem, 2, 0, 0);
        last = 2;
        outPositions[1] = x - (circleW >> 1) + (totalW >> 1) - 6;
    }

    swrSprite_GetTextureDimFromId(swrSprite_axis_check_end, (int*)&partW, &partH);
    x = x - partW + totalW + 4;
    rect[0] = x;
    rect[1] = y;
    rect[2] = x + partW - 1;
    rect[3] = partH + y - 1;
    swrUI_AddSprite(elem, last + 1, swrSprite_axis_check_end, rect, 1, swrUI_SPRITE_SLOT_MIRROR_H);
    swrUI_SetSpriteOffset(elem, last + 1, 0, 0);
    outPositions[last] = (partW >> 1) - (circleW >> 1) + x;
    return partH + 4;
}

// 0x0041b380
int swrUI_IsFocusable(swrUI_unk* element)
{
    // list items (widget_class low bits 0x4|0x8) are always focusable
    if (((uint8_t)element->widget_class & 0xc) == 0xc)
        return 1;
    if ((element->flags & swrUI_STATIC) == 0 && (element->flags & swrUI_DISABLED) == 0) {
        if (swrUI_IsElementVisible(element))
            return 1;
    }
    return 0;
}

// 0x0041b3c0
swrUI_unk* swrUI_NextFocusable(swrUI_unk* element)
{
    swrUI_unk* it;

    for (it = element; it != NULL; it = it->next2) {
        if (swrUI_IsFocusable(it) && it != element)
            return it;
    }
    return it;
}

// 0x0041b420
void swrUI_FocusFirstOnNav(int vk)
{
    swrUI_unk* page;

    page = swrUI_GetCurrentPage();
    if (g_objHang2->menuScreen != swrObjHang_STATE_SPLASH)
        return;
    if (vk != VK_TAB && (vk < VK_LEFT || vk > VK_DOWN))
        return;
    if (swrUI_textEntryActive != 0 || page == NULL || page->next == NULL)
        return;
    swrUI_FocusElement(swrUI_NextFocusable(page->next), 1);
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
        if (((ui->widget_class == 10) && (ui->id == *this_id)) && (ui->option_value == value))
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
    int count = 0;

    // the Invitational circuit (index 3) only shows once unlocked
    g_CircuitIdxMax = SWR_CIRCUIT_COUNT - 1;
    swrRace_MenuMaxSelection = 0;
    if (hang->isTournamentMode != 0) {
        if (swrRace_UnlockDataBase[4] == 0)
            g_CircuitIdxMax = SWR_CIRCUIT_COUNT - 2;
        for (int track = 0; track < g_aTracksInCircuits[(int)hang->circuitIdx]; track++) {
            if ((swrRace_UnlockDataBase[hang->circuitIdx + 1] & (uint8_t)(1 << track)) != 0)
                swrRace_MenuMaxSelection = ++count;
        }
    } else {
        if (g_aBeatTracksGlobal[3] == 0)
            g_CircuitIdxMax = SWR_CIRCUIT_COUNT - 2;
        for (int track = 0; track < g_aTracksInCircuits[(int)hang->circuitIdx]; track++) {
            if ((g_aBeatTracksGlobal[(int)hang->circuitIdx] & (uint8_t)(1 << track)) != 0)
                swrRace_MenuMaxSelection = ++count;
        }
    }
    // multiplayer offers every track of the three main circuits
    if (multiplayer_enabled != 0 && hang->circuitIdx < SWR_CIRCUIT_COUNT - 1) {
        count = g_aTracksInCircuits[(int)hang->circuitIdx];
        swrRace_MenuMaxSelection = count;
    }
    if (swrRace_MenuSelectedItem > count - 1)
        swrRace_MenuSelectedItem = count - 1;
    g_bCircuitIdxInRange = 0;
    swrUI_menuScrolled = 0;
    if (hang->circuitIdx > 0)
        swrUI_menuScrolled = 1;
    if (hang->circuitIdx < g_CircuitIdxMax)
        g_bCircuitIdxInRange = 1;
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

// 0x0043b1d0
void swrUI_Front_SeekToCurrentTrack_Maybe(swrObjHang* hang)
{
    // the selection index counts only playable tracks before the current one
    swrRace_MenuSelectedItem = 0;
    for (int track = 0; track < g_aTracksInCircuits[(int)hang->circuitIdx]; track++) {
        if (g_aTrackIDs[hang->circuitIdx * SWR_TRACKS_PER_CIRCUIT + track] == hang->track_index)
            return;
        if (isTrackPlayable(hang, hang->circuitIdx, (char)track))
            swrRace_MenuSelectedItem++;
    }
}

// 0x00440550
void playUISound(int soundId)
{
    int loop = 0;
    float pitch = 0.125f;
    float gain = (float)sound_sfx_volume * (1.0f / 255.0f);

    switch (soundId) {
    case 0x4b:
        loop = 1;
        pitch = 0.5f;
        break;
    case 0x4d:
        pitch = 0.25f;
        break;
    case 0x4f:
        loop = 1;
        break;
    case 0x54:
        break;
    case 0x58:
        gain = gain * 0.75;
        pitch = 0.25f;
        break;
    default:
        pitch = 0.25f;
        loop = 0;
        break;
    }
    playASound(soundId, 6, pitch, gain, loop);
}

// 0x00440c10
void swrObjHang_SelectCreditsTracks(swrObjHang* hang)
{
    char count = 0;
    int useBeatTracks = 0;

    swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_RACE_STARTED;
    swrRace_creditsMode = 1;
    hang->flag |= swrObjHang_FLAG_CREDITS_PLAYLIST;
    // Menu input bit 0x4 is unidentified; held with the CRD profile it seeds the playlist with the current track.
    if (compare3Chars(swrRace_aProfiles[0].name, swrObjHang_creditsCheatInitials) != 0 && (swrUI_localPlayersInputDownBitset[0] & 0x4) != 0) {
        swrObjHang_creditsTracks[0] = hang->track_index;
        count = 1;
        useBeatTracks = 1;
    }
    while (count < SWR_CREDITS_TRACK_COUNT) {
        int circuit = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)SWR_CIRCUIT_COUNT);
        int track = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)(int)g_aTracksInCircuits[circuit]);
        uint8_t unlocked = useBeatTracks ? g_aBeatTracksGlobal[circuit] : (uint8_t)swrRace_UnlockDataBase[circuit + 1];
        if ((unlocked & (uint8_t)(1 << (track & 0x1f))) != 0) {
            int trackId = g_aTrackIDs[circuit * SWR_TRACKS_PER_CIRCUIT + track];
            int duplicate = 0;
            for (int i = 0; i < count; i++) {
                if (trackId == swrObjHang_creditsTracks[i]) {
                    duplicate = 1;
                    break;
                }
            }
            if (!duplicate) {
                swrObjHang_creditsTracks[(int)count] = (char)trackId;
                count++;
            }
        }
    }
}

// One track-record entry: heading, the time from the save image (or a placeholder while the
// 3599.99s default stands), and the holder's name. recordKind 0 = 3-lap, 3 = best single lap;
// records are per track + mirror.
// 0x004403e0
void swrUI_Front_DrawRecord(swrObjHang* hang, int x, int y, float alpha, char recordKind)
{
    char* text;
    char* holderName;
    float recordTime;
    int idx;

    if (recordKind == 0) {
        text = swrText_Translate("/SCREENTEXT_545/~f4~c~s3-Lap Record");
        swrText_CreateTextEntry1(x, y, 0x32, -1, -1, (int)alpha, text);
    } else if (recordKind == 3) {
        text = swrText_Translate("/SCREENTEXT_546/~f4~c~sBest Lap");
        swrText_CreateTextEntry1(x, y, 0x32, -1, -1, (int)alpha, text);
    }
    idx = hang->bMirror + hang->track_index * 2;
    if (recordKind == 3) {
        recordTime = swrRace_saveData.recordLapTimes[idx];
        holderName = swrRace_saveData.recordLapNames[idx];
    } else {
        recordTime = swrRace_saveData.record3LapTimes[idx];
        holderName = swrRace_saveData.record3LapNames[idx];
    }
    if (ELFSAVE_RECORD_TIME_EMPTY <= recordTime) {
        swrText_CreateTextEntry1(x, y + 7, 0x32, -1, -1, (int)alpha, "~c~s--:--.--- ---");
        return;
    }
    swrText_CreateTimeEntryFormat(x + 0x1e, y + 7, recordTime, 0x32, -1, -1, (int)alpha, 1);
    swrRace_DrawRecordHolderName((float)x, (float)(y + 0xf), alpha, holderName);
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
    if (!hang->isTournamentMode)
        return (swrRace_saveData.unlockFlags & swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST) != 0;

    // 2 bits of best place per track: 7 tracks x 1st in each of the 3 circuits, 4 in Invitational
    return g_aBeatTrackPlace[0] == 0x3fff && g_aBeatTrackPlace[1] == 0x3fff && g_aBeatTrackPlace[2] == 0x3fff && g_aBeatTrackPlace[3] == 0xff;
}

// 0x00440d50
void swrUI_Front_DispatchPageCallbacks_Maybe(int arg2, int arg4)
{
    swrUI_unk* page = swrUI_GetCurrentPage();
    swrUI_RunCallbacks2(swrUI_GetById(page, 2), arg2);
    swrUI_RunCallbacks2(swrUI_GetById(page, 4), arg4);
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

// 0x00417670
int swrUI_IsElementFocused(swrUI_unk* ui)
{
    return ui != NULL && ui == swrUI_focusedElement;
}

// 0x00417ca0
void swrUI_RefreshListLayout(swrUI_unk* list)
{
    HANG("TODO");
}

// 0x00417fe0
void swrUI_DrawWrappedText(swrUI_unk* ui, char* text, int flag)
{
    unsigned int len;
    unsigned int avgCharWidth;
    unsigned int maxChars;
    unsigned int n;
    char* lineStart;
    char* cursor;
    char* lastSpace;

    len = strlen(text);
    if (len == 0)
        return;

    avgCharWidth = (unsigned int)swrText_GetStringWidth(text, swrText_fontsByIndex[ui->font_index]) / len;
    swrText_GetStringHeight(text, swrText_fontsByIndex[ui->font_index]);
    maxChars = (unsigned int)(ui->content_right - ui->content_left + 1) / (avgCharWidth + 1);

    lineStart = text;
    for (;;) {
        lastSpace = NULL;
        cursor = lineStart;
        for (n = 0; *cursor != '\0' && n < maxChars; n++, cursor++) {
            if (*cursor == ' ')
                lastSpace = cursor;
        }
        if (*cursor != '\0' && lastSpace != NULL)
            *lastSpace = '\0';
        swrUI_AddListItem(ui, lineStart, flag != 0 ? swrUI_ITEM_WRAPPED_UNK : 0, 0, 0);
        // faithful: a line with no space to break at drops the rest of the text
        if (*cursor != '\0') {
            if (lastSpace == NULL)
                return;
            *lastSpace = ' ';
        }
        if (lastSpace == NULL || *cursor == '\0')
            return;
        lineStart = lastSpace + 1;
    }
}

// 0x00418680
int swrUI_GetSubstringWidth(char* text, int font, unsigned int start, int end)
{
    int count;
    int width;
    int total;
    int height;

    if (text == NULL) {
        return 0;
    }
    // Faithful: font -1 returns whatever EAX held; 0 here.
    if (font == -1) {
        return 0;
    }
    if (strlen(text) <= start) {
        return 0;
    }

    text += start;
    total = 0;
    for (count = end - start; count != 0; count--) {
        if (*text == '\0') {
            break;
        }
        swrText_GetCharSize(*text, swrText_fontsByIndex[font], &width, &height);
        total += width;
        text++;
    }
    return total;
}

// 0x004180c0
void swrUI_UpdateTimers(void)
{
    unsigned int elapsedMs;
    unsigned int step;
    int i;

    elapsedMs = (unsigned int)(int)(swrRace_deltaTimeSecs * 1000.0);
    for (i = 0; i < SWR_UI_MAX_TIMERS; i++) {
        if (swrUI_timers[i].target != NULL) {
            step = elapsedMs;
            if (swrUI_timers[i].remainingMs <= elapsedMs) {
                step = swrUI_timers[i].remainingMs;
            }
            swrUI_timers[i].remainingMs -= step;
            if (swrUI_timers[i].remainingMs == 0) {
                swrUI_timers[i].remainingMs = swrUI_timers[i].intervalMs;
                swrUI_RunCallbacks(swrUI_timers[i].target, swrUI_MSG_TIMER, swrUI_timers[i].id, 0);
            }
        }
    }
}
