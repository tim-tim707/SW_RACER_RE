#include "swrUI.h"

#include "globals.h"
#include "swrModel.h"
#include "swrMultiplayer.h"
#include "swrObj.h"
#include "swrRace.h"
#include "swrSprite.h"
#include "swrText.h"
#include "swrConfig.h"
#include "swrSound.h"
#include "swr.h"
#include "engine_config.h"

#include <General/stdFileUtil.h>
#include <General/stdFnames.h>
#include <General/stdHashTable.h>
#include <General/stdMath.h>
#include <General/stdString.h>
#include <General/utils.h>
#include <Primitives/rdVector.h>
#include <Main/swrControl.h>
#include <Main/swrMain.h>
#include <Platform/wuRegistry.h>
#include <Win95/stdComm.h>
#include <Win95/stdConsole.h>
#include <Dss/sithMessage.h>
#include <Dss/sithMulti.h>

#include <macros.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <engine_config.h>

// 0x004083d0
void swrUI_UpdateMouseState(void)
{
    int accept;
    int changed;
    int x;
    int y;

    swrUI_inputChangeFlags = 0;
    if (swrControl_acceptPressedEdge != 0 && (swrControl_menuAcceptGuard == 0 || swrControl_menuAcceptPressedEdge == 0))
        accept = 1;
    else
        accept = 0;
    // faithful: the cancel edge is tested as a 16-bit value (NEG AX)
    swrUI_menuButtonState = (accept ? swrUI_INPUT_ACCEPT : 0) | ((short)swrControl_cancelPressedEdge != 0 ? swrUI_INPUT_CANCEL : 0);
    if (swrUI_menuButtonState != swrUI_menuButtonStatePrev) {
        changed = swrUI_menuButtonState ^ swrUI_menuButtonStatePrev;
        swrUI_inputChangeFlags = swrUI_INPUT_BUTTONS_CHANGED;
        if (changed & swrUI_INPUT_ACCEPT)
            swrUI_inputChangeFlags = swrUI_INPUT_BUTTONS_CHANGED | swrUI_INPUT_ACCEPT;
        if (changed & swrUI_INPUT_CANCEL)
            swrUI_inputChangeFlags |= swrUI_INPUT_CANCEL;
    }
    swrUI_menuButtonStatePrev = swrUI_menuButtonState;

    stdConsole_GetCursorPos(&x, &y);
    g_mouse_x = x;
    g_mouse_y = y;
    if (x != g_mouse_x2 || y != g_mouse_y2)
        swrUI_inputChangeFlags |= swrUI_INPUT_CURSOR_MOVED | swrUI_INPUT_MOVED;
    g_mouse_x2 = x;
    g_mouse_y2 = y;

    swrUI_joyAxisX = swrControl_joystickAxes[0];
    swrUI_joyAxisY = swrControl_joystickAxes[1];
    if (swrControl_joystickAxes[0] != swrUI_joyAxisXPrev || swrControl_joystickAxes[1] != swrUI_joyAxisYPrev)
        swrUI_inputChangeFlags |= swrUI_INPUT_AXIS_MOVED | swrUI_INPUT_MOVED;
    swrUI_joyAxisXPrev = swrControl_joystickAxes[0];
    swrUI_joyAxisYPrev = swrControl_joystickAxes[1];
}

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

// 0x00411120
void swrUI_BroadcastToWindows(int forward2, int forward3)
{
    swrUI_BroadcastToWindowsRecurse(swrUI_unk_ptr, forward2, forward3);
}

// 0x00411140
int swrUI_IsPrevPage(int id, int flag)
{
    if (flag != 0 && swrUI_prevPage != NULL && swrUI_prevPage->id == id)
        return 1;
    return 0;
}

// 0x00411170
void swrUI_AddNavButton(swrUI_unk* page, int id, int x, int y, int kind)
{
    // faithful: retail leaves the label uninitialised for an unknown kind
    char text[256] = { 0 };

    if (kind == 0)
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0388/~sQuit"));
    else if (kind == 1)
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0034/~sCancel"));
    else if (kind == 2)
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0371/~sBack"));
    swrUI_NewButton(page, id, 6, text, x, y, 0xb4, 0x19, swrUI_FRAME_STYLE_BACK_BUTTON | swrUI_FRAME_STYLE_MIRROR_V, 0);
}

// 0x00411210
swrUI_unk* swrUI_AddOkButton(swrUI_unk* page, int x, int y)
{
    swrSprite_BBox box;

    swrSprite_GetBBoxFromId(swrSprite_ok_button, &box);
    return swrUI_NewButton(page, SWR_UI_ID_OK_BUTTON, 6, swrText_Translate("/MONDOTEXT_H_0372/~sOK"), x, y, box.x2 - box.x, box.y2 - box.y, swrUI_FRAME_STYLE_OK_BUTTON, 0);
}

// 0x00411270
void swrUI_AddRestoreButton(swrUI_unk* page, int x, int y)
{
    // faithful: the measured text size is discarded for a fixed 150x25 button
    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0390/~sRestore"), swrText_fontsByIndex[6]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0390/~sRestore"), swrText_fontsByIndex[6]);
    swrUI_NewButton(page, 0x26, 6, swrText_Translate("/MONDOTEXT_H_0390/~sRestore"), x, y, 0x96, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
}

// 0x004112f0
void swrUI_AddDefaultButton(swrUI_unk* page, int x, int y)
{
    // faithful: the measured text size is discarded for a fixed 150x25 button
    swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0389/~sDefault"), swrText_fontsByIndex[6]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0389/~sDefault"), swrText_fontsByIndex[6]);
    swrUI_NewButton(page, 0x25, 6, swrText_Translate("/MONDOTEXT_H_0389/~sDefault"), x, y, 0x96, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
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

// 0x00411910
void swrUI_ReparentElement(swrUI_unk* parent, swrUI_unk* element)
{
    if (parent == NULL || element == NULL)
        return;
    swrUI_UnlinkElement(element);
    element->fun2 = NULL;
    swrUI_RunCallbacks2(element, 1);
    element->fun2 = parent->fun2;
    swrUI_Enqueue(parent, element);
}

static const struct
{
    char* name;
    short x;
    short y;
} swrUI_devPhotoNames[] = {
    { "~c~sMark H.H.", 0x2e, 0x8a },
    { "~c~sJon", 0x55, 200 },
    { "~c~sJustin", 0x77, 0x81 },
    { "~c~sPaul T.", 0x8d, 0x59 },
    { "~c~sEric", 0x91, 0xd8 },
    { "~c~sBrett", 0xba, 0xbf },
    { "~c~sPaul Z.", 200, 0x5f },
    { "~c~sJacob", 0xdd, 0xcd },
    { "~c~sLisa", 0xee, 0x68 },
    { "~c~sSun-Inn", 0x10c, 0x91 },
    { "~c~sArmando", 0x10f, 0x5d },
    { "~c~sDuncan", 0x122, 0xd9 },
    { "~c~sChristina", 0x135, 0x6b },
    { "~c~sCamela", 0x15b, 199 },
    { "~c~sMark B.", 0x167, 0x55 },
    { "~c~sJapeth", 0x17c, 0xb2 },
    { "~c~sDino", 0x18a, 0xcb },
    { "~c~sLivia", 0x19c, 0x5d },
    { "~c~sDarren", 0x1b9, 0x77 },
    { "~c~sClint", 0x1c6, 0xc2 },
    { "~c~sAmit", 0x1d2, 0x5c },
    { "~c~sJim", 0x1fe, 0xb7 },
    { "~c~sBrad", 0x207, 0x5a },
    { "~c~sBill", 0x234, 0xd5 },
    { "~c~sNathan", 0x23c, 0x55 },
};

// 0x00411950
int swrUI_BuildMenuPages(void)
{
    swrUI_unk* page;
    int i;

    swrSprite_LoadAllSprites();
    // window 5: lone Settings + Back page
    page = swrUI_NewWindow(NULL, NULL, 5, NULL);
    if (page != NULL) {
        swrUI_NewButton(page, SWR_UI_ID_MAIN_SETTINGS, 6, swrText_Translate("/MONDOTEXT_H_0373/~sSettings"), 0, 0x15e, 200, 0x19, swrUI_FRAME_STYLE_SETTINGS_BUTTON, 0);
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x186, 2);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_NAV, NULL);
    if (page != NULL) {
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 0x1a4, 2);
        swrUI_AddOkButton(page, 0x208, 0x17c);
    }

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_SPLASH, (swrUI_unk_F2*)swrUI_Menu_Main);
    if (page != NULL) {
        swrUI_NewButton(page, SWR_UI_ID_MAIN_TOURNAMENT, 6, swrText_Translate("/MONDOTEXT_H_0374/~sSingle Player Tournament"), 0x96, 0x96, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_MAIN_FREEPLAY, 6, swrText_Translate("/MONDOTEXT_H_0375/~sSingle Player Free Play"), 0x96, 0xbe, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_MAIN_MULTIPLAYER, 6, swrText_Translate("/MONDOTEXT_H_0376/~sMultiplayer"), 0x96, 0xe6, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_MAIN_SETTINGS, 6, swrText_Translate("/MONDOTEXT_H_0373/~sSettings"), 0, 0x15e, 0xb4, 0x19, swrUI_FRAME_STYLE_SETTINGS_BUTTON, 0);
        swrUI_AddNavButton(page, SWR_UI_ID_MAIN_QUIT, 0, 0x186, 0);
        swrUI_NewLabel(page, SWR_UI_ID_MAIN_COPYRIGHT, 4, swrText_Translate("/MONDOTEXT_H_0504/~s$LucasArts Entertainment Company LLC. $Lucasfilm Ltd. and #. All Rights Reserved. Used under authorization."), 0x140, 0x1d6, swrUI_VERTICAL, 0);
        // developer-photo labels (swrUI_Menu_Main shows them instead of the menu)
        for (i = 0; i < (int)(sizeof(swrUI_devPhotoNames) / sizeof(swrUI_devPhotoNames[0])); i++)
            swrUI_NewLabel(page, SWR_UI_ID_DEV_PHOTO_NAME_FIRST + i, 4, swrUI_devPhotoNames[i].name, swrUI_devPhotoNames[i].x, swrUI_devPhotoNames[i].y, 0, 0);
        swrUI_NewLabel(page, SWR_UI_ID_DEV_PHOTO_NAME_FIRST + i, 6, swrText_Translate("/MONDOTEXT_H_0524/~sThe Team"), 0x140, 0x3c, swrUI_VERTICAL, 0);
        swrUI_NewLabel(page, SWR_UI_ID_DEV_PHOTO_NAME_FIRST + i + 1, 4, swrText_Translate("/MONDOTEXT_H_0544/~s%"), 0x12a, 0x12, 0, 0);
        swrUI_NewLabel(page, SWR_UI_ID_DEV_PHOTO_NAME_FIRST + i + 2, 4, swrText_Translate("/MONDOTEXT_H_0545/~s#"), 0x127, 0x46, 0, 0);
    }

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_PROFILE_SELECT, (swrUI_unk_F2*)swrUI_Menu_SelectProfile);
    if (page != NULL)
        swrConfig_BuildProfileListMenu(page);

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_SETTINGS, (swrUI_unk_F2*)swrUI_Menu_SettingsHub);
    if (page != NULL) {
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_VIDEO, 6, swrText_Translate("/MONDOTEXT_H_0292/~sVIDEO SETTINGS"), 0x96, 100, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_AUDIO, 6, swrText_Translate("/MONDOTEXT_H_0305/~sAUDIO SETTINGS"), 0x96, 0x8c, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_JOYSTICK, 6, swrText_Translate("/MONDOTEXT_H_0249/~sJOYSTICK SETTINGS"), 0x96, 0xbe, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_MOUSE, 6, swrText_Translate("/MONDOTEXT_H_0250/~sMOUSE SETTINGS"), 0x96, 0xe6, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_KEYBOARD, 6, swrText_Translate("/MONDOTEXT_H_0251/~sKEYBOARD SETTINGS"), 0x96, 0x10e, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_FORCE_FEEDBACK, 6, swrText_Translate("/MONDOTEXT_H_0314/~sFORCE FEEDBACK SETTINGS"), 0x96, 0x136, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_NewButton(page, SWR_UI_ID_SETTINGS_LOAD_SAVE, 6, swrText_Translate("/MONDOTEXT_H_0340/~sLOAD/SAVE SETTINGS"), 0x96, 0x168, 0x154, 0x19, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        swrUI_AddNavButton(page, SWR_UI_ID_BACK_BUTTON, 0, 400, 2);
    }

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_CONFIG_FILES, (swrUI_unk_F2*)swrUI_Menu_SaveLoadConfig);
    if (page != NULL)
        swrConfig_BuildConfigFilesMenu(page);
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_JOYSTICK_SETTINGS, (swrUI_unk_F2*)swrControl_MappingsMenu);
    if (page != NULL) {
        swrConfig_BuildJoystickMenu(page);
        swrConfig_RefreshMappingMenu(swrConfig_DEVICE_JOYSTICK, page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_MOUSE_SETTINGS, (swrUI_unk_F2*)swrControl_MappingsMenu);
    if (page != NULL) {
        swrConfig_BuildMouseMenu(page);
        swrConfig_RefreshMappingMenu(swrConfig_DEVICE_MOUSE, page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_KEYBOARD_SETTINGS, (swrUI_unk_F2*)swrControl_MappingsMenu);
    if (page != NULL) {
        swrConfig_BuildKeyboardMenu(page);
        swrConfig_RefreshMappingMenu(swrConfig_DEVICE_KEYBOARD, page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_VIDEO_SETTINGS, (swrUI_unk_F2*)swrUI_Menu_VideoSettings);
    if (page != NULL) {
        swrConfig_BuildVideoMenu(page);
        swrConfig_RefreshVideoMenu(page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_AUDIO_SETTINGS, (swrUI_unk_F2*)swrUI_Menu_AudioSettings);
    if (page != NULL) {
        swrConfig_BuildAudioMenu(page);
        swrConfig_RefreshAudioMenu(page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS, (swrUI_unk_F2*)swrUI_Menu_ForceFeedback);
    if (page != NULL) {
        swrConfig_BuildForceFeedbackMenu(page);
        swrConfig_RefreshForceFeedbackMenu(page);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_RESERVED_KEYS, (swrUI_unk_F2*)swrUI_Menu_ReservedSettings);
    if (page != NULL)
        swrConfig_BuildReservedSettingsMenu(page);

    swrMultiplayer_BuildAllMenuScreens();
    swrUI_BuildAuxPages();
    return 1;
}

// 0x004121f0
void swrUI_BuildAuxPages(void)
{
    swrUI_unk* page;
    swrUI_unk* arrow;
    int rect[4];

    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_SELECT_VEHICLE, (swrUI_unk_F2*)swrUI_Menu_HangarSelectVehicle);
    if (page != NULL) {
        rect[0] = 0x28;
        rect[1] = 0x3c;
        rect[2] = 0x5e;
        rect[3] = 0x77;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_VEHICLE_ARROW_LEFT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectVehicle, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x217;
        rect[1] = 0x3c;
        rect[2] = 0x24d;
        rect[3] = 0x77;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_VEHICLE_ARROW_RIGHT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectVehicle, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
    }
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_SELECT_PLANET, (swrUI_unk_F2*)swrUI_Menu_HangarSelectPlanet);
    if (page != NULL) {
        rect[0] = 0x28;
        rect[1] = 0x53;
        rect[2] = 0x5e;
        rect[3] = 0x8e;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_PLANET_ARROW_LEFT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectPlanet, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x217;
        rect[1] = 0x53;
        rect[2] = 0x24d;
        rect[3] = 0x8e;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_PLANET_ARROW_RIGHT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectPlanet, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x28;
        rect[1] = 0x96;
        rect[2] = 99;
        rect[3] = 0xcc;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_PLANET_ARROW_UP, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectPlanet, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x28;
        rect[1] = 0x104;
        rect[2] = 99;
        rect[3] = 0x13a;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_PLANET_ARROW_DOWN, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarSelectPlanet, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
    }
    swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_SELECT_TRACK, (swrUI_unk_F2*)swrUI_Menu_HangarSelectTrack);
    swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_MAIN_MENU, (swrUI_unk_F2*)swrUI_Menu_HangarMainMenu);
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_WATTO, (swrUI_unk_F2*)swrUI_Menu_HangarWatto);
    if (page != NULL) {
        rect[0] = 0x28;
        rect[1] = 0x1b;
        rect[2] = 0x5e;
        rect[3] = 0x56;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_WATTO_ARROW_LEFT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarWatto, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x217;
        rect[1] = 0x1b;
        rect[2] = 0x24d;
        rect[3] = 0x56;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_WATTO_ARROW_RIGHT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarWatto, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
    }
    // built under the Watto id; swrObjHang_SetMenuState looks up swrUI_WINDOW_HANGAR_JUNKYARD (0x87), which nothing creates
    page = swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_WATTO, (swrUI_unk_F2*)swrUI_Menu_HangarJunkyard);
    if (page != NULL) {
        rect[0] = 0x28;
        rect[1] = 0x1b;
        rect[2] = 0x5e;
        rect[3] = 0x56;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_JUNKYARD_ARROW_LEFT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarJunkyard, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
        rect[0] = 0x217;
        rect[1] = 0x1b;
        rect[2] = 0x24d;
        rect[3] = 0x56;
        arrow = swrUI_NewSpriteElement(page, SWR_UI_ID_HANGAR_JUNKYARD_ARROW_RIGHT, rect, 0, 0, (swrUI_unk_F2*)swrUI_Menu_HangarJunkyard, 0);
        swrUI_SetSpriteColor(arrow, 0, 0xff, 0xff, 0xff, 0);
    }
    swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_LOOK_AT_VEHICLE, (swrUI_unk_F2*)swrUI_Menu_HangarLookAtVehicle);
    swrUI_NewWindow(NULL, NULL, swrUI_WINDOW_HANGAR_UNUSED_89, (swrUI_unk_F2*)swrUI_Menu_HangarUnused89_Maybe);
}

// 0x00412630
void swrUI_ResetAttractDemoTimer(void)
{
    swrObjHang_attractDemoTimer = 30.0f;
}

// 0x00412e40
void swrUI_Shutdown(void)
{
    memset(swrUI_timers, 0, sizeof(swrUI_timers));
    if (swrUI_unk_ptr != NULL)
        swrUI_FreeElement(swrUI_unk_ptr);
    swrUI_unk_ptr = NULL;
    swrSprite_FreeSprites();
    if (swrUI_elementHashtable_Maybe != NULL) {
        stdHashTable_Free(swrUI_elementHashtable_Maybe);
        swrUI_elementHashtable_Maybe = NULL;
    }
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

// 0x004131c0
swrUI_unk* swrUI_NewLabel(swrUI_unk* parent, int id, int font, char* text, int x, int y, int flags, int param8)
{
    swrUI_unk* ui;
    int height;
    int width;

    ui = swrUI_New(parent, id, font, text, flags, param8, 0, (swrUI_unk_F1)swrUI_LabelProc, NULL);
    ui->flags |= swrUI_STATIC;
    height = swrText_GetStringHeight(text, swrText_fontsByIndex[ui->font_index]);
    width = swrText_GetStringWidth(text, swrText_fontsByIndex[ui->font_index]);
    swrUI_SetSize(ui, width, height);
    if (ui->flags & swrUI_VERTICAL)
        x = (ui->x - ui->width + (SWR_UI_DESIGN_WIDTH - 1)) >> 1;
    if (ui->flags & swrUI_LEFT_RIGHT_UNK)
        y = (ui->y - ui->height + (SWR_UI_DESIGN_HEIGHT - 1)) >> 1;
    swrUI_SetPos(ui, x, y);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_LABEL;
    ui->flags |= swrUI_NO_PAGE_TRANSITION;
    return ui;
}

// 0x004132a0
swrUI_unk* swrUI_NewButton(swrUI_unk* parent, int id, int font, char* text, int x, int y, int width, int height, int flags, int param10)
{
    swrUI_unk* ui;

    ui = swrUI_New(parent, id, font, text, flags, param10, 0, (swrUI_unk_F1)swrUI_ButtonProc, NULL);
    swrUI_SetSize(ui, width, height);
    swrUI_SetPos(ui, x, y);
    ui->text_flags = flags & SWR_UI_TEXT_FLAGS_MASK;
    swrUI_RunCallbacksScreenText(ui, text, swrUI_TEXT_ALIGN_CENTER);
    swrUI_BuildHighlightSprites(ui, 0);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_BUTTON;
    return ui;
}

// 0x00413340
swrUI_unk* swrUI_NewScreenText(swrUI_unk* parent, int id, int index, char* text, int unk5, int x, int y, int width, int height, int unk10, int flags, int sizeUnk)
{
    swrUI_unk* ui;
    int textFlags;

    ui = swrUI_New(parent, id, index, text, flags, sizeUnk, 0, (swrUI_unk_F1)swrUI_ScreenTextProc, NULL);
    swrUI_SetSize(ui, width, height);
    swrUI_SetPos(ui, x, y);
    ui->text_flags = flags & SWR_UI_TEXT_FLAGS_MASK;
    swrUI_BuildHighlightSprites(ui, 0);
    if (ui->text_flags & swrUI_SCREEN_TEXT_INDENT_1) {
        textFlags = swrUI_TEXT_ALIGN_INDENT_1;
    } else {
        textFlags = swrUI_TEXT_ALIGN_CENTER_Y;
        if ((ui->text_flags & swrUI_SCREEN_TEXT_PLAIN) == 0) {
            swrUI_SetValue(ui, swrUI_TEXT_ALIGN_CENTER_Y);
            if (ui->text_flags != 0)
                textFlags = swrUI_TEXT_ALIGN_INDENT_5 | swrUI_TEXT_ALIGN_CENTER_Y;
        }
    }
    swrUI_RunCallbacksScreenText(ui, text, textFlags);
    swrUI_SetValue2_Maybe(ui, unk10);
    swrUI_ExchangeSlotValue2_Maybe(ui, index);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_SCREEN_TEXT;
    return ui;
}

// 0x00413500
void swrUI_SetMaxLength(swrUI_unk* ui, int maxLength)
{
    if (ui != NULL)
        ui->max_length = maxLength;
}

// 0x00413430
swrUI_unk* swrUI_NewTextEntry(swrUI_unk* parent, int id, int* rect, int new_index, int flag, int size_unk2)
{
    swrUI_unk* ui;
    int left;
    int top;
    int right;
    int bottom;

    right = 0;
    bottom = 0;
    left = 0;
    top = 0;
    ui = swrUI_New(parent, id, new_index, NULL, flag, size_unk2, 0, (swrUI_unk_F1)swrUI_TextEntryProc, NULL);
    if (rect != NULL) {
        left = rect[0];
        top = rect[1];
        right = rect[2];
        bottom = rect[3];
    }
    swrUI_SetSize(ui, right - left + 1, bottom - top + 1);
    swrUI_SetPos(ui, left, top);
    swrUI_BuildPanelFrame(ui, 1, 0);
    ui->entry_style = flag & SWR_UI_TEXT_ENTRY_STYLE_MASK;
    ui->flags |= swrUI_STATIC;
    swrUI_SetMaxLength(ui, SWR_UI_TEXT_ENTRY_MAX_LENGTH);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_TEXT_ENTRY;
    return ui;
}

// 0x00413520
swrUI_unk* swrUI_NewList(swrUI_unk* parent, int id, int* rect, int new_index, int flag, int size_unk2)
{
    swrUI_unk* ui;
    int left;
    int top;
    int right;
    int bottom;
    int inset[4];

    right = 0;
    left = 0;
    top = 0;
    bottom = 0;
    ui = swrUI_New(parent, id, new_index, NULL, flag, size_unk2, 0, (swrUI_unk_F1)swrUI_ListProc, NULL);
    if (rect != NULL) {
        bottom = rect[3];
        left = rect[0];
        top = rect[1];
        right = rect[2];
    }
    swrUI_SetSize(ui, right - left + 1, bottom - top + 1);
    swrUI_SetPos(ui, left, top);
    swrUI_BuildPanelFrame(ui, 0, 0);
    swrUI_GetListFrameInsets(inset, 0);
    ui->content_left = left + inset[0];
    ui->content_top = top + inset[1];
    ui->item_flags = (swrUI_ITEM_FLAG)flag;
    ui->row_spacing = 5;
    ui->content_right = right - inset[2];
    ui->content_bottom = bottom - inset[3];
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_LIST;
    return ui;
}

// 0x00413610
void swrUI_SelectListItem(swrUI_unk* item, int bSelect)
{
    swrUI_unk* list;
    swrUI_unk* sibling;

    if (item == NULL)
        return;
    if (bSelect) {
        list = item->prev;
        for (sibling = list->next; sibling != NULL; sibling = sibling->next2) {
            if (((uint8_t)sibling->widget_class & swrUI_CLASS_LIST_ITEM) != swrUI_CLASS_LIST_ITEM)
                continue;
            swrSound_PlayUISound(0x46);
            if ((list->item_flags & swrUI_LIST_NO_SELECTION_FRAME) == 0 && ((uint8_t)sibling->widget_class & 3) != 3) {
                swrUI_AddSprite(sibling, 0, 0, NULL, 0, 0);
                swrUI_AddSprite(sibling, 1, 0, NULL, 0, 0);
                swrUI_AddSprite(sibling, 2, 0, NULL, 0, 0);
            }
            sibling->item_flags &= ~swrUI_ITEM_SELECTED;
        }
        item->item_flags |= swrUI_ITEM_SELECTED;
    } else {
        item->item_flags &= ~swrUI_ITEM_SELECTED;
    }
    swrUI_RefreshListLayout(item->prev);
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

// 0x00413770
swrUI_unk* swrUI_GetSelectableItem(swrUI_unk* list, int index)
{
    swrUI_unk* item;

    for (item = list->next; item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
            if (index == 0)
                return item;
            index--;
        }
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

// 0x00413800
void swrUI_RefreshListSelection(swrUI_unk* list)
{
    swrUI_unk* element = list->next;
    swrUI_unk* next;
    int index = 0;

    // remember the selected item's index and text, then free every list item
    list->first_visible = 0;
    while (element != NULL) {
        next = element->next2;
        if (element->item_flags & swrUI_ITEM_SELECTED) {
            list->selected_index = index;
            list->selected_text = swrUI_replaceAllocatedStr(list->selected_text, element->str_allocated);
        }
        if (((uint8_t)element->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM)
            swrUI_FreeElement(element);
        index++;
        element = next;
    }
}

// 0x00413870
void swrUI_RestoreListSelection(swrUI_unk* list)
{
    swrUI_unk* item;

    item = swrUI_GetSelectableItem(list, list->selected_index);
    if (item == NULL) {
        if (list->selected_text == NULL)
            return;
        item = swrUI_FindChildByText(list, list->selected_text);
        if (item == NULL)
            return;
    }
    swrUI_SelectListItem(item, 1);
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
    swrUI_unk* item;

    if (list == NULL || text == NULL) {
        return NULL;
    }
    item = swrUI_NewLabel(list, id, list->font_index, text, 0, 0, 0, 1);
    item->item_flags = (swrUI_ITEM_FLAG)value;
    swrUI_SetColorUnk(item, list->r, list->g, list->b, list->a);
    swrUI_SetColorUnk2(item, list->r2, list->g2, list->b2, list->a2);
    swrUI_SetColorUnk4(item, list->r4, list->g4, list->b4, list->a4);
    swrUI_SetColorUnk3(item, list->r3, list->g3, list->b3, list->a3);
    swrUI_SetColorUnk5(item, list->r5, list->g5, list->b5, list->a5);
    swrUI_SetSlotValue(item, 0, param5);
    item->widget_class = swrUI_CLASS_LIST_ITEM;
    if (swrUI_GetSelectedItem(list) == NULL) {
        swrUI_SelectListItem(item, 1);
    }
    swrUI_RefreshListLayout(list);
    return item;
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

// 0x00413b60
void swrUI_SetSliderValue(swrUI_unk* ui, int percent)
{
    if (ui == NULL)
        return;
    ui->slider_percent = percent;
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

// 0x00413c50
swrUI_unk* swrUI_NewFramedText(swrUI_unk* parent, int id, int index, char* text, int x, int y, int width, int height, int flags, int flags2)
{
    swrUI_unk* ui;
    int hasBackdrop = 0;
    int spriteW = 0;
    int spriteH;
    int tabW;
    int tabH;
    int strchW;
    int strchH;
    int explicitValue = 0;
    int sizeUnk = flags2;
    int totalW;
    int rect[4];

    if (flags2 & swrUI_FRAMED_TEXT_EXPLICIT_VALUE) {
        explicitValue = flags2 & SWR_UI_FRAMED_TEXT_VALUE_MASK;
        sizeUnk = 0;
    }
    ui = swrUI_New(parent, id, index, text, flags, sizeUnk, 0, (swrUI_unk_F1)swrUI_FramedTextProc, NULL);
    if (ui->flags & swrUI_LEFT_RIGHT_UNK) {
        swrSprite_GetTextureDimFromId(swrSprite_sml_undrline_tab, &spriteW, &spriteH);
        totalW = width + spriteW;
        swrSprite_GetTextureDimFromId(swrSprite_tiny_box_selected, &spriteW, &spriteH);
        totalW += spriteW;
        hasBackdrop = 1;
    } else if (ui->flags & swrUI_VERTICAL) {
        swrSprite_GetTextureDimFromId(swrSprite_radio_checked, &spriteW, &spriteH);
        totalW = width + spriteW;
        hasBackdrop = 1;
    } else if (ui->flags & swrUI_CHECK_CIRCLE_UNK) {
        swrSprite_GetTextureDimFromId(swrSprite_axis_check_circ, &spriteW, &spriteH);
        totalW = width;
        // unsigned compare in the EXE
        if ((unsigned int)width < (unsigned int)spriteW)
            totalW = width + ((unsigned int)spriteW >> 1);
    } else {
        totalW = width;
    }
    swrUI_SetSize(ui, totalW, height);
    swrUI_SetPos(ui, x, y);
    if (hasBackdrop) {
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = ui->width;
        rect[3] = ui->height;
        swrUI_AddSprite(ui, -1, swrSprite_background, rect, 1, 0);
        // colors slot 0, not the slot just added
        swrUI_SetSpriteColor(ui, 0, 0, 0, 0, 0x82);
    }
    swrUI_RunCallbacksScreenText(ui, text, 0);
    swrUI_SetChecked(ui, flags & swrUI_CHECKED);
    if (ui->flags & swrUI_LEFT_RIGHT_UNK) {
        swrSprite_GetTextureDimFromId(swrSprite_sml_undrline_tab, &tabW, &tabH);
        swrSprite_GetTextureDimFromId(swrSprite_sml_undrline_strch, &strchW, &strchH);
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = tabW - 1 + ui->x;
        rect[3] = tabH - 1 + ui->y;
        swrUI_AddSprite(ui, -1, swrSprite_sml_undrline_tab, rect, 1, 0);
        rect[0] = tabW + ui->x;
        rect[1] = ui->y;
        rect[2] = totalW - spriteW - 1 + ui->x;
        rect[3] = strchH - 1 + ui->y;
        swrUI_AddSprite(ui, -1, swrSprite_sml_undrline_strch, rect, 1, 0);
    }
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_FRAMED_TEXT;
    // radio groups: the first RADIO_GROUP item opens the group, the next one closes it
    if (ui->flags & swrUI_RADIO_GROUP_UNK) {
        if (swrUI_radioGroupOpen == 0) {
            swrUI_radioGroupNextValue = 0;
            ui->has_option_value = 1;
            ui->option_value = explicitValue != 0 ? explicitValue : swrUI_radioGroupNextValue;
            swrUI_radioGroupOpen++;
            swrUI_radioGroupNextValue++;
        } else {
            ui->has_option_value = 1;
            ui->option_value = explicitValue != 0 ? explicitValue : swrUI_radioGroupNextValue;
            swrUI_radioGroupOpen = 0;
            swrUI_radioGroupNextValue = 0;
        }
    } else if (swrUI_radioGroupOpen != 0) {
        ui->has_option_value = 1;
        ui->option_value = explicitValue != 0 ? explicitValue : swrUI_radioGroupNextValue;
        swrUI_radioGroupNextValue++;
    }
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

// 0x00413fc0
swrUI_unk* swrUI_New3PatchBox(swrUI_unk* parent, int id, int index, char* text, int x, int y, int width, int style, int center, int flags, int sizeUnk)
{
    swrUI_unk* ui;
    swrSprite_NAME leftId;
    swrSprite_NAME midId;
    swrSprite_NAME rightId;
    int rightFlag = 0;
    int leftW;
    int leftH;
    int midW;
    int midH;
    int rightW;
    int rightH;
    int top;
    int bottom;
    int totalW;
    int slot;
    int rect[4];

    if (style == swrUI_3PATCH_LARGE_CORNER) {
        leftId = swrSprite_undrline_tab;
        midId = swrSprite_undrline_mid_strch;
        rightId = swrSprite_undrline_corner;
    } else if (style == swrUI_3PATCH_SMALL_TAB) {
        leftId = swrSprite_sml_undrline_tab;
        midId = swrSprite_sml_undrline_strch;
        rightId = swrSprite_sml_undrline_tab;
        rightFlag = swrUI_SPRITE_SLOT_MIRROR_H;
    } else if (style == swrUI_3PATCH_LARGE_TAB) {
        leftId = swrSprite_undrline_tab;
        midId = swrSprite_undrline_mid_strch;
        rightId = swrSprite_undrline_tab;
        rightFlag = swrUI_SPRITE_SLOT_MIRROR_H;
    } else {
        leftId = swrSprite_sml_undrline_tab;
        midId = swrSprite_sml_undrline_strch;
        rightId = swrSprite_sml_undrline_corner;
    }
    ui = swrUI_New(parent, id, index, text, flags, sizeUnk, 0, (swrUI_unk_F1)swrUI_3PatchBoxProc, NULL);
    swrUI_SetPos(ui, x, y);
    top = ui->y;
    bottom = ui->height;
    swrSprite_GetTextureDimFromId(leftId, &leftW, &leftH);
    swrSprite_GetTextureDimFromId(midId, &midW, &midH);
    swrSprite_GetTextureDimFromId(rightId, &rightW, &rightH);
    if (style == swrUI_3PATCH_SMALL_CORNER || style == swrUI_3PATCH_LARGE_CORNER) {
        // width is the total width: the middle stretches between the caps
        rect[0] = x;
        rect[1] = y;
        rect[2] = leftW - 1 + x;
        rect[3] = leftH - 1 + y;
        swrUI_AddSprite(ui, -1, leftId, rect, 1, 0);
        if (rect[1] <= top)
            top = rect[1];
        if (bottom <= rect[3])
            bottom = rect[3];
        rect[0] = leftW + x;
        rect[1] = y;
        rect[2] = width - rightW - 1 + x;
        rect[3] = midH - 1 + y;
        swrUI_AddSprite(ui, -1, midId, rect, 1, 0);
        if (rect[1] <= top)
            top = rect[1];
        if (bottom <= rect[3])
            bottom = rect[3];
        rect[0] = width - rightW + x;
        rect[1] = y;
        rect[2] = width - 1 + x;
        rect[3] = rightH - 1 + y;
        swrUI_AddSprite(ui, -1, rightId, rect, 1, rightFlag);
    } else {
        // width is the middle width: the caps sit outside it
        rect[0] = x;
        rect[1] = y;
        rect[2] = leftW - 1 + x;
        rect[3] = leftH - 1 + y;
        swrUI_AddSprite(ui, -1, leftId, rect, 1, 0);
        if (rect[1] <= top)
            top = rect[1];
        if (bottom <= rect[3])
            bottom = rect[3];
        rect[0] = leftW + x;
        rect[1] = y;
        rect[2] = leftW + width - 1 + x;
        rect[3] = midH - 1 + y;
        swrUI_AddSprite(ui, -1, midId, rect, 1, 0);
        if (rect[1] <= top)
            top = rect[1];
        if (bottom <= rect[3])
            bottom = rect[3];
        rect[0] = leftW + width + x;
        rect[1] = y;
        rect[2] = rightW + leftW + width - 1 + x;
        rect[3] = rightH - 1 + y;
        swrUI_AddSprite(ui, -1, rightId, rect, 1, rightFlag);
    }
    if (rect[1] <= top)
        top = rect[1];
    if (bottom <= rect[3])
        bottom = rect[3];
    if (center != 0)
        swrUI_SetPos(ui, x - width - 2, y - rightH);
    totalW = width + rightW + leftW;
    ui->flags |= swrUI_STATIC;
    swrUI_SetSize(ui, totalW, bottom + 1 - top);
    rect[0] = ui->x;
    rect[1] = ui->y;
    rect[2] = ui->width;
    rect[3] = ui->height;
    slot = swrUI_AddSprite(ui, -1, swrSprite_background, rect, 1, 0);
    swrUI_SetSpriteColor(ui, slot, 0, 0, 0, 0x82);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_3PATCH_BOX;
    return ui;
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

// 0x004145b0
int swrUI_ShowConfirmDialog(swrUI_unk* parent, int x, int y, char* title, char* message, char* yesLabel, char* noLabel, char* thirdLabel, int modal)
{
    swrUI_unk* dialog;
    swrUI_unk* element;

    swrUI_confirmDialogDone = 0;
    swrUI_confirmDialogResult = -1;
    swrUI_RunCallbacks2(parent, 0);
    dialog = swrUI_NewDialog(NULL, x, y, title, message, yesLabel, noLabel, thirdLabel, swrUI_ConfirmDialogProc);
    swrUI_confirmDialog = dialog;
    if (dialog->next != NULL) {
        element = swrUI_NextFocusable(dialog->next);
        if (((uint8_t)element->widget_class & swrUI_CLASS_LIST) == swrUI_CLASS_LIST)
            element = element->next2;
        swrUI_FocusElement(element, 1);
    }
    swrUI_confirmDialogParent = parent;
    if (modal != 0) {
        swrUI_confirmDialogModal = 1;
        while (swrUI_confirmDialogDone == 0)
            swrMain_GuiAdvance();
        swrUI_confirmDialogModal = 0;
        swrUI_FreeElement(dialog);
        swrUI_confirmDialog = NULL;
        swrUI_RunCallbacks2(parent, 1);
        if (parent->next != NULL) {
            element = swrUI_NextFocusable(parent->next);
            if (((uint8_t)element->widget_class & swrUI_CLASS_LIST) == swrUI_CLASS_LIST)
                element = element->next2;
            swrUI_FocusElement(element, 1);
        }
        swrUI_confirmDialogParent = NULL;
    }
    return swrUI_confirmDialogResult;
}

// 0x004146c0
swrUI_unk* swrUI_NewDialog(swrUI_unk* parent, int x, int y, char* title, char* message, char* button1, char* button2, char* button3, swrUI_unk_F2 f2)
{
    swrUI_unk* dialog;
    swrUI_unk* list;
    swrSprite_BBox titleBox;
    swrSprite_BBox messageBox;
    swrSprite_BBox buttonsBox;
    int backdrop[4];
    unsigned int buttonSpacing;
    unsigned int buttonWidth;
    unsigned int labelWidth;
    int buttonHeight;
    int buttonX;
    int buttonY;
    int buttonIndex;
    int width;
    int height;
    int rowWidth;

    dialog = swrUI_New(parent, 0, 0, NULL, 0, 0, 0, (swrUI_unk_F1)swrUI_DialogProc, f2);

    swrUI_GetPaddedTextBBox((int*)&titleBox, title, 6);
    height = (int)(titleBox.y2 - titleBox.y) + 1;
    rowWidth = (int)(titleBox.x2 - titleBox.x) + 1;
    width = 0;
    if (rowWidth >= 0)
        width = rowWidth;

    swrUI_GetWrappedTextBBox((int*)&messageBox, message, 0);
    height += (int)(messageBox.y2 - messageBox.y) + 1;
    rowWidth = (int)(messageBox.x2 - messageBox.x) + 1;
    if (width <= rowWidth)
        width = rowWidth;

    buttonSpacing = swrUI_GetButtonRowBBox((int*)&buttonsBox, button1, button2, button3, 0);
    // the button row's height is counted twice
    height += ((int)(buttonsBox.y2 - buttonsBox.y) + 1) * 2;
    rowWidth = (int)(buttonsBox.x2 - buttonsBox.x) + 1;
    if (width <= rowWidth)
        width = rowWidth;

    swrUI_SetSize(dialog, width, height);
    if (x == -1)
        x = (dialog->x - dialog->width + (SWR_UI_DESIGN_WIDTH - 1)) >> 1;
    if (y == -1)
        y = (dialog->y - dialog->height + (SWR_UI_DESIGN_HEIGHT - 1)) >> 1;
    swrUI_SetPos(dialog, x, y);

    backdrop[0] = (unsigned int)(SWR_UI_DESIGN_WIDTH - width) >> 1;
    backdrop[1] = (unsigned int)(SWR_UI_DESIGN_HEIGHT - height) >> 1;
    backdrop[2] = width + backdrop[0] - 1;
    backdrop[3] = height + backdrop[1] - 1;
    swrUI_AddSprite(dialog, -1, swrSprite_background, backdrop, 1, 0);
    swrUI_SetSpriteColor(dialog, 0, 0, 0, 0, 0x82);

    swrSprite_MoveBBoxTo(&titleBox, (((int)(titleBox.x - titleBox.x2) + dialog->width - dialog->x) >> 1) + dialog->x, dialog->y + titleBox.y);
    swrSprite_MoveBBoxTo(&messageBox, (((int)(messageBox.x - messageBox.x2) + dialog->width - dialog->x) >> 1) + dialog->x, titleBox.y2);
    swrSprite_MoveBBoxTo(&buttonsBox, (((int)(buttonsBox.x - buttonsBox.x2) + dialog->width - dialog->x) >> 1) + dialog->x, messageBox.y2);

    swrUI_NewLabel(dialog, 0, 6, title, titleBox.x + 10, titleBox.y + 10, 0, 0);
    list = swrUI_NewList(dialog, 0, (int*)&messageBox, 0, swrUI_LIST_NO_SELECTION_FRAME, 0);
    swrUI_DrawWrappedText(list, message, 1);

    buttonIndex = 0;
    buttonY = buttonsBox.y + 10;
    buttonX = buttonsBox.x + 10;
    buttonWidth = 0;
    if (button1 != NULL)
        buttonWidth = swrText_GetStringWidth(button1, swrText_fontsByIndex[0]) * 3;
    if (button2 != NULL) {
        labelWidth = swrText_GetStringWidth(button2, swrText_fontsByIndex[0]) * 3;
        if (buttonWidth <= labelWidth)
            buttonWidth = labelWidth;
    }
    if (button3 != NULL) {
        labelWidth = swrText_GetStringWidth(button3, swrText_fontsByIndex[0]) * 3;
        if (buttonWidth <= labelWidth)
            buttonWidth = labelWidth;
    }
    if (buttonWidth <= SWR_UI_DIALOG_MIN_BUTTON_WIDTH)
        buttonWidth = SWR_UI_DIALOG_MIN_BUTTON_WIDTH;

    // two buttons sit side by side; with a third, the first goes on its own row above the other two
    if (button1 != NULL) {
        buttonHeight = swrText_GetStringHeight(button1, swrText_fontsByIndex[0]) * 3;
        buttonIndex = 1;
        swrUI_NewButton(dialog, 0, 0, button1, buttonX, buttonY, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        if (button3 != NULL)
            buttonY += buttonHeight + 10;
        else
            buttonX += buttonSpacing + 20;
    }
    if (button2 != NULL) {
        buttonHeight = swrText_GetStringHeight(button2, swrText_fontsByIndex[0]) * 3;
        swrUI_NewButton(dialog, buttonIndex, 0, button2, buttonX, buttonY, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
        buttonIndex++;
        buttonX += buttonSpacing + 20;
    }
    if (button3 != NULL) {
        buttonHeight = swrText_GetStringHeight(button3, swrText_fontsByIndex[0]) * 3;
        swrUI_NewButton(dialog, buttonIndex, 0, button3, buttonX, buttonY, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    }
    swrUI_RunCallbacks2(dialog, 1);
    return dialog;
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

// 0x00414b30
void swrUI_SetValue2_Maybe(swrUI_unk* ui, int value)
{
    ui->unk4f4 = value;
}

// 0x00414b40
void swrUI_SetSize(swrUI_unk* ui, int width, int height)
{
    swrUI_RunCallbacks(ui, swrUI_MSG_SET_SIZE, width, height);
}

// 0x00414b60
void swrUI_SetPos(swrUI_unk* ui, int x, int y)
{
    swrUI_RunCallbacks(ui, swrUI_MSG_SET_POS, x, y);
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

// 0x00414d00
void swrUI_FreeElement(swrUI_unk* element)
{
    swrUI_unk* child;
    swrUI_unk* next;

    for (child = element->next; child != NULL; child = next) {
        next = child->next2;
        swrUI_FreeElement(child);
    }
    if (element == swrUI_unk_ptr)
        return;
    swrUI_RunCallbacks(element, swrUI_MSG_DESTROY, 0, 0);
    swrUI_ClearAllSprites(element);
    swrUI_UnlinkElement(element);
    free(element);
}

// 0x00414d60
swrUI_unk* swrUI_FindByClass(swrUI_unk* root, int classId)
{
    swrUI_unk* found;

    if (root->widget_class == classId)
        return root;
    // only the first child's subtree is searched, never the siblings
    if (root->next != NULL) {
        found = swrUI_FindByClass(root->next, classId);
        if (found != NULL && found->widget_class == classId)
            return found;
    }
    return NULL;
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

// 0x00414df0
swrUI_unk* swrUI_GetFirstSibling(swrUI_unk* element)
{
    if (element == NULL)
        return NULL;
    while (element->prev2 != NULL)
        element = element->prev2;
    return element;
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
        swrUI_RunCallbacks(swrUI_focusedElement, swrUI_MSG_FOCUS_CHANGED, 0, 0);
        swrUI_focusedElement = element;
        if (element != NULL)
            element->flags = element->flags | swrUI_FOCUSED;
        swrUI_RunCallbacks(swrUI_focusedElement, swrUI_MSG_FOCUS_CHANGED, 1, 0);
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

// 0x00415020
void swrUI_RenderTree(swrUI_unk* node)
{
    swrUI_unk* it;
    int animating = 0;
    int stepping = 0;

    if (multiplayer_in_mp != 0)
        swrUI_ResetAttractDemoTimer();
    if (node == NULL)
        node = swrUI_unk_ptr;
    for (it = node; it != NULL; it = it->next2) {
        if ((it->flags & swrUI_VISIBLE) && (it->flags & swrUI_ANIMATING))
            animating++;
    }
    for (it = node; it != NULL; it = it->next2) {
        if (it->flags & swrUI_VISIBLE) {
            stepping |= swrUI_StepPageTransition(it);
            swrUI_RenderElementSprites(it);
            swrUI_RunCallbacks(it, swrUI_MSG_UPDATE, 0, 0);
        }
    }
    // the last sliding sibling just arrived: notify the parent page
    if (stepping == 0 && animating != 0 && node->prev != NULL)
        swrUI_RunCallbacks(node->prev, swrUI_MSG_PAGE_TRANSITION, 0, 0);
    for (; node != NULL; node = node->next2) {
        if ((node->flags & swrUI_VISIBLE) && node->next != NULL)
            swrUI_RenderTree(node->next);
    }
}

// 0x00415400
void swrUI_ProcessMouse(void)
{
    swrUI_unk* hit;
    swrUI_unk* target;
    swrUI_unk* page;
    unsigned int motion;
    int x;
    int y;

    swrUI_UpdateTimers();
    swrText_ClearEntryClipRects();
    if (swrUI_unk_ptr == NULL || !swrUI_IsElementVisible(swrUI_unk_ptr))
        return;
    swrUI_RenderTree(swrUI_unk_ptr);
    swrUI_DrawCaret();
    if (swrUI_pageTransitionActive != 0) {
        swrUI_refocusPending = 1;
        return;
    }
    if (swrUI_refocusPending != 0) {
        swrUI_FocusElement(swrUI_pageInitialFocus, 1);
        swrUI_refocusPending = 0;
    }
    if (swrSprite_IsCursorVisible()) {
        swrUI_UpdateMouseState();
        if (swrUI_inputSuppressFlags & swrUI_INPUT_SUPPRESS_MOUSE_FRAME) {
            swrUI_inputSuppressFlags &= ~swrUI_INPUT_SUPPRESS_MOUSE_FRAME;
            return;
        }
        x = g_mouse_x;
        y = g_mouse_y;
        hit = swrUI_HitTest(swrUI_unk_ptr, x, y);
        // faithful: a disabled element under the cursor also skips swrUI_ProcessPendingClose
        if (hit != NULL && (hit->flags & swrUI_DISABLED))
            return;
        if (hit != swrUI_GetUI4()) {
            swrUI_SetUI4(hit);
            if (swrUI_textEntryActive == 0)
                swrUI_SetFocusedElement(hit);
        }
        target = swrUI_GetUI5();
        if (target == NULL)
            target = hit;
        if (swrUI_inputChangeFlags & swrUI_INPUT_CURSOR_MOVED) {
            swrUI_ResetAttractDemoTimer();
            swrUI_RunCallbacks(target, swrUI_MSG_MOUSE_MOVE, x, y);
        }
        if (swrUI_inputChangeFlags & swrUI_INPUT_BUTTONS_CHANGED) {
            if (swrUI_inputChangeFlags & swrUI_INPUT_ACCEPT)
                swrUI_RunCallbacks(target, (swrUI_menuButtonState & swrUI_INPUT_ACCEPT) ? swrUI_MSG_MOUSE_DOWN : swrUI_MSG_MOUSE_UP, x, y);
            if (swrUI_inputChangeFlags & swrUI_INPUT_CANCEL)
                swrUI_RunCallbacks(target, (swrUI_menuButtonState & swrUI_INPUT_CANCEL) ? swrUI_MSG_MOUSE2_DOWN : swrUI_MSG_MOUSE2_UP, x, y);
            if (swrUI_textEntryActive == 0) {
                motion = swrUI_inputChangeFlags & (swrUI_INPUT_CURSOR_MOVED | swrUI_INPUT_UNK_40000000 | swrUI_INPUT_AXIS_MOVED);
                if (swrControl_acceptPressedEdge != 0)
                    swrUI_RunCallbacks(swrUI_GetCurrentPage(), swrUI_MSG_ACCEPT, motion, 0);
                if (swrControl_cancelPressedEdge != 0) {
                    if ((swrUI_inputSuppressFlags & swrUI_INPUT_SUPPRESS_CANCEL) == 0) {
                        if ((g_objHang2->menuScreen == swrObjHang_STATE_SELECT_VEHICLE && g_objHang2->activeMenu == -1) || g_objHang2->menuScreen == swrObjHang_STATE_SPLASH) {
                            page = swrUI_confirmDialog;
                            if (page == NULL)
                                page = swrUI_GetCurrentPage();
                            swrUI_RunCallbacks(page, swrUI_MSG_BACK, motion, 0);
                        }
                    } else {
                        swrUI_inputSuppressFlags &= ~swrUI_INPUT_SUPPRESS_CANCEL;
                    }
                }
            }
            if (swrControl_acceptPressedEdge != 0 && target != NULL && (target->flags & swrUI_EDITING) == 0)
                swrUI_RunCallbacks(target, swrUI_MSG_SET_EDITING, 1, target->id);
        }
        if (swrUI_inputChangeFlags & swrUI_INPUT_AXIS_MOVED) {
            swrUI_ResetAttractDemoTimer();
            swrUI_ProcessNavAxis();
        }
    }
    swrUI_ProcessPendingClose();
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
    // retail returns swrUI_FocusFirstOnNav's leftover EAX here
    return 0;
}

// 0x004150e0
swrUI_unk* swrUI_HitTest(swrUI_unk* root, int cursor_x, int cursor_y)
{
    swrUI_unk* hit;
    swrSprite_BBox box;

    for (; root != NULL; root = root->next2) {
        if ((root->flags & swrUI_VISIBLE) == 0 || root->widget_class == swrUI_CLASS_PANEL)
            continue;
        if (root->next != NULL) {
            hit = swrUI_HitTest(root->next, cursor_x, cursor_y);
            if (hit != NULL)
                return hit;
        }
        if ((root->flags & swrUI_CHECK_SPRITE_UNK) == 0) {
            box.x = root->x;
            box.y = root->y;
            box.x2 = root->width;
            box.y2 = root->height;
            swrSprite_BBoxFit(&box, &root->bbox);
            if (root != swrUI_unk_ptr && swrSprite_IsInsideBBox(&box, cursor_x, cursor_y) != 0)
                return root;
        }
    }
    return NULL;
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

// 0x004151f0
void swrUI_RenderElementSprites(swrUI_unk* ui)
{
    swrUI_unk2* slot;
    int i;
    uint8_t alpha;

    if (SpritesLoaded == 0 || (ui->flags & swrUI_VISIBLE) == 0)
        return;
    for (i = 0; i < ui->sprite_count; i++) {
        slot = &ui->ui_elements[i];
        if (slot->texture_id != 0 && slot->sprite_ingameId == 0)
            slot->sprite_ingameId = swrSprite_CreateFromTextureId(slot->texture_id);
        swrSprite_NewSprite((short)slot->sprite_ingameId, swrSprite_GetTextureFromId(slot->texture_id));
        swrSprite_SetPos((short)slot->sprite_ingameId, (short)(slot->pos_x + slot->screen_x1), (short)(slot->pos_y + slot->screen_y1));
        // the vertical/horizontal centering keeps the element's x/y on the other axis, not the slot's
        if (slot->flag & swrUI_SPRITE_SLOT_CENTER_V)
            swrSprite_SetPos((short)slot->sprite_ingameId, (short)ui->x, (short)(((ui->height - slot->screen_y2 + slot->screen_y1 - ui->y) >> 1) + ui->y));
        if (slot->flag & swrUI_SPRITE_SLOT_CENTER_H)
            swrSprite_SetPos((short)slot->sprite_ingameId, (short)(((ui->width - slot->screen_x2 + slot->screen_x1 - ui->x) >> 1) + ui->x), (short)ui->y);
        if (slot->flag & swrUI_SPRITE_SLOT_CENTER_BOTH)
            swrSprite_SetPos((short)slot->sprite_ingameId, (short)(((ui->width - slot->screen_x2 + slot->screen_x1 - ui->x) >> 1) + ui->x), (short)(((ui->height - slot->screen_y2 + slot->screen_y1 - ui->y) >> 1) + ui->y));
        if (slot->flag & swrUI_SPRITE_SLOT_MIRROR_V)
            swrSprite_SetFlag((short)slot->sprite_ingameId, swrSprite_FLAG_MIRROR_V);
        if (slot->flag & swrUI_SPRITE_SLOT_MIRROR_H)
            swrSprite_SetFlag((short)slot->sprite_ingameId, swrSprite_FLAG_MIRROR_H);
        if (slot->flag & swrUI_SPRITE_SLOT_FLAG_8000_UNK)
            swrSprite_SetFlag((short)slot->sprite_ingameId, swrSprite_FLAG_UNK_8000);
        if (slot->flag & swrUI_SPRITE_SLOT_ADDITIVE)
            swrSprite_SetFlag((short)slot->sprite_ingameId, swrSprite_FLAG_ADDITIVE);
        swrSprite_SetDim((short)slot->sprite_ingameId, slot->width, slot->height);
        alpha = SWR_UI_DISABLED_TEXT_ALPHA;
        if ((ui->flags & swrUI_DISABLED) == 0)
            alpha = slot->a;
        swrSprite_SetColor((short)slot->sprite_ingameId, slot->r, slot->g, slot->b, alpha);
        swrSprite_SetVisible((short)slot->sprite_ingameId, 1);
        swrSprite_SetFlag((short)slot->sprite_ingameId, swrSprite_FLAG_UNK_10000);
    }
}

// 0x004156a0
void swrUI_StartPageTransition(swrUI_unk* page, int mode)
{
    swrUI_unk* child;
    int fromLeft;
    int delay;

    if (swrUI_pageTransitionsEnabled == 0 || page == NULL)
        return;
    swrUI_pageTransitionActive = 1;
    swrUI_RunCallbacks(page, swrUI_MSG_PAGE_TRANSITION, 1, 0);
    child = page->next;
    // the page pointer doubles as the first child's side flag; a random mode reuses its stack slot
    fromLeft = (int)page;
    if (mode == -1) {
        fromLeft = swrUtils_Rand();
        mode = (int)((float)fromLeft * SWR_CTL_RAND_NORM * 2.0f);
    }
    if (mode == 1) {
        delay = 0;
        for (child = swrUI_GetLastSibling(child); child != NULL; child = child->prev2) {
            if (child->flags & swrUI_NO_PAGE_TRANSITION)
                continue;
            swrUI_RunCallbacks(child, swrUI_MSG_PAGE_TRANSITION, 1, 1);
            child->transition_home_y = child->y;
            child->transition_home_x = child->x;
            swrUI_OnSetElementPos(child, child->x, child->y - child->height - 1);
            child->transition_delay = delay;
            delay += SWR_UI_PAGE_TRANSITION_STAGGER;
            child->flags |= swrUI_ANIMATING;
        }
        return;
    }
    for (; child != NULL; child = child->next2) {
        if ((child->flags & swrUI_NO_PAGE_TRANSITION) == 0) {
            swrUI_RunCallbacks(child, swrUI_MSG_PAGE_TRANSITION, 1, 1);
            child->transition_home_x = child->x;
            child->transition_home_y = child->y;
            if (fromLeft != 0)
                swrUI_OnSetElementPos(child, child->x - child->width - 1, child->y);
            else
                swrUI_OnSetElementPos(child, SWR_UI_DESIGN_WIDTH, child->transition_home_y);
            child->flags |= swrUI_ANIMATING;
        }
        fromLeft = fromLeft == 0;
    }
}

// 0x004157d0
int swrUI_ReplaceIndex(swrUI_unk* ui, int new_index)
{
    int old_index;

    old_index = ui->font_index;
    ui->font_index = new_index;
    return old_index;
}

// 0x004157f0
int swrUI_ExchangeSlotValue2_Maybe(swrUI_unk* ui, int value)
{
    int old = ui->unk500;
    ui->unk500 = value;
    return old;
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
    switch (msg) {
    case swrUI_MSG_MOUSE_DOWN:
        swrUI_SetFocusedElement(ui);
        swrUI_SetUI5(ui);
        ui->flags |= swrUI_HIGHLIGHTED;
        return 0;
    case swrUI_MSG_MOUSE_UP:
        swrUI_ClearUI5();
        ui->flags &= ~swrUI_HIGHLIGHTED;
        break;
    case swrUI_MSG_KEY_DOWN:
        swrUI_SetUI5(ui);
        if (((int)param == VK_TAB || ((unsigned int)param >= VK_LEFT && (unsigned int)param <= VK_DOWN)) && swrUI_textEntryActive == 0) {
            swrUI_NavigateFocus(ui, (int)param);
            return 0;
        }
        break;
    case swrUI_MSG_KEY_UP:
        swrUI_ClearUI5();
        return 0;
    case swrUI_MSG_UPDATE:
        if (ui->flags & swrUI_SELECTED) {
            swrUI_RandomizeSpriteAlpha(ui);
            return 0;
        }
        break;
    case swrUI_MSG_SET_TEXT:
        ui->str_allocated = swrUI_replaceAllocatedStr(ui->str_allocated, (char*)param);
        if (param2 != -1) {
            ui->text_flags = param2;
            return 0;
        }
        break;
    case swrUI_MSG_SET_POS:
        swrUI_OnSetElementPos(ui, (int)param, param2);
        return 0;
    case swrUI_MSG_SET_SIZE:
        swrUI_OnSetElementSize(ui, (int)param, param2);
        return 0;
    case swrUI_MSG_FOCUS_CHANGED:
        if (param == NULL) {
            swrUI_RunCallbacks(ui, swrUI_MSG_SET_EDITING, 0, ui->id);
            return 0;
        }
        break;
    case swrUI_MSG_SET_ACTIVE:
        if (param != NULL) {
            ui->flags |= swrUI_VISIBLE;
            return 0;
        }
        swrUI_ClearElementRefs(ui);
        ui->flags &= ~swrUI_VISIBLE;
        swrUI_ClearAllSprites(ui);
        return 0;
    case swrUI_MSG_DESTROY:
        ui->str_allocated = swrUI_replaceAllocatedStr(ui->str_allocated, NULL);
        ui->selected_text = swrUI_replaceAllocatedStr(ui->selected_text, NULL);
        return 0;
    case swrUI_MSG_CLEAR_INTERACTION:
        ui->flags &= ~(swrUI_ANIMATING | swrUI_HIGHLIGHTED | swrUI_HOVERED | swrUI_FOCUSED);
        return 0;
    case swrUI_MSG_BACK:
        if (swrUI_suppressBackPop == 0) {
            // the EXE pushes a 0 argument here
            swrUI_PopMenuPage();
            return 0;
        }
        break;
    case swrUI_MSG_PAGE_SHOWN:
        swrUI_RunCallbacks2(ui, 1);
        if (param != NULL)
            swrUI_StartPageTransition(ui, -1);
        swrUI_pageInitialFocus = swrUI_GetById(ui, 2);
        if (swrUI_pageInitialFocus != NULL) {
            swrUI_FocusElement(swrUI_pageInitialFocus, 1);
            return 0;
        }
        if (ui->next != NULL) {
            swrUI_pageInitialFocus = ui->next;
            swrUI_FocusElement(swrUI_pageInitialFocus, 1);
            return 0;
        }
        break;
    case swrUI_MSG_PAGE_POPPED:
        swrUI_RunCallbacks2((swrUI_unk*)(&swrUI_pageStack)[(int)param], 0);
        (&swrUI_pageStack)[(int)param] = NULL;
        return 0;
    case swrUI_MSG_SET_EDITING:
        if (param != NULL) {
            ui->flags |= swrUI_EDITING;
            swrSprite_SetCursorVisibility2(0);
            return 0;
        }
        ui->flags &= ~swrUI_EDITING;
        swrSprite_SetCursorVisibility2(1);
        return 0;
    }
    return 0;
}

// 0x00415b80
int swrUI_LabelProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    switch (msg) {
    case swrUI_MSG_MOUSE_DOWN:
        swrUI_SetHighlightState(1, ui, 1, 0, 0);
        break;
    case swrUI_MSG_MOUSE_UP:
        if (swrUI_ElementContainsPoint(ui, (int)param, param2))
            swrUI_SetHighlightState(1, ui, 0, 1, 0);
        break;
    case swrUI_MSG_UPDATE:
        swrUI_DrawText(ui->font_index, ui->x, ui->y, ui->r, ui->g, ui->b, ui->a, ui->str_allocated, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        break;
    case swrUI_MSG_SET_TEXT:
        swrUI_SetSize(ui, swrText_GetStringWidth((char*)param, swrText_fontsByIndex[ui->font_index]), swrText_GetStringHeight((char*)param, swrText_fontsByIndex[ui->font_index]));
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00415ca0
int swrUI_ButtonProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    int rect[4];
    int focused;

    switch (msg) {
    case swrUI_MSG_HOVER_CHANGED:
        if (param != NULL && swrUI_muteNextButtonHoverSound == 0) {
            swrSound_PlayUISound(0x58);
            swrUI_UpdateElementColor(ui);
            return swrUI_DefaultElementProc(ui, msg, param, param2);
        }
        swrUI_muteNextButtonHoverSound = 0;
        // fallthrough
    case swrUI_MSG_FOCUS_CHANGED:
        swrUI_UpdateElementColor(ui);
        return swrUI_DefaultElementProc(ui, msg, param, param2);
    case swrUI_MSG_MOUSE_DOWN:
        swrUI_SetHighlightState(1, ui, 1, 0, 1);
        return swrUI_DefaultElementProc(ui, msg, param, param2);
    case swrUI_MSG_MOUSE_UP:
        if (swrUI_ElementContainsPoint(ui, (int)param, param2))
            swrUI_SetHighlightState(1, ui, 0, 1, 1);
        swrSound_PlayUISound(0x54);
        return swrUI_DefaultElementProc(ui, msg, param, param2);
    case swrUI_MSG_MOUSE2_DOWN:
        swrUI_SetHighlightState(2, ui, 1, 0, 1);
        return swrUI_DefaultElementProc(ui, msg, param, param2);
    case swrUI_MSG_MOUSE2_UP:
        if (swrUI_ElementContainsPoint(ui, (int)param, param2)) {
            swrUI_SetHighlightState(2, ui, 0, 1, 1);
            return swrUI_DefaultElementProc(ui, msg, param, param2);
        }
        break;
    case swrUI_MSG_UPDATE:
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = ui->width;
        rect[3] = ui->height;
        focused = swrUI_IsElementFocused(ui);
        swrUI_DrawTextAligned(ui->font_index, ui->str_allocated, (short*)rect, ui->text_flags, ui->r, ui->g, ui->b, ui->a, focused, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00415ed0
int swrUI_ScreenTextProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    swrUI_ScreenTextValue* value;
    swrUI_unk* target;
    int rect[4];
    int focused;

    switch (msg) {
    case swrUI_MSG_HOVER_CHANGED:
        if (param == NULL || ((uint8_t)ui->widget_class & swrUI_CLASS_LIST_ITEM) != 0)
            swrSound_PlayUISound(0x48);
        else
            swrSound_PlayUISound(0x58);
        // fallthrough
    case swrUI_MSG_FOCUS_CHANGED:
        swrUI_UpdateElementColor(ui);
        break;
    case swrUI_MSG_MOUSE_DOWN:
        swrUI_SetHighlightState(1, ui, 1, 0, 1);
        break;
    case swrUI_MSG_MOUSE_UP:
        if (swrUI_ElementContainsPoint(ui, (int)param, param2))
            swrUI_SetHighlightState(1, ui, 0, 1, 1);
        break;
    case swrUI_MSG_MOUSE2_DOWN:
        swrUI_SetHighlightState(2, ui, 1, 0, 1);
        break;
    case swrUI_MSG_MOUSE2_UP:
        if (swrUI_ElementContainsPoint(ui, (int)param, param2))
            swrUI_SetHighlightState(2, ui, 0, 1, 1);
        break;
    case swrUI_MSG_KEY_UP:
        if ((int)param == VK_DELETE) {
            target = ui->prev;
            if (((uint8_t)ui->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM)
                target = target->prev;
            swrUI_RunCallbacks(target, swrUI_MSG_DELETE_PRESSED, ui->id, 0);
        }
        break;
    case swrUI_MSG_UPDATE:
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = ui->width;
        rect[3] = ui->height;
        focused = swrUI_IsElementFocused(ui);
        swrUI_DrawTextAligned(ui->font_index, ui->str_allocated, (short*)rect, ui->text_flags, ui->r, ui->g, ui->b, ui->a, focused, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        value = (swrUI_ScreenTextValue*)ui->unk4f4;
        if (value->x_offset == -1)
            rect[0] = rect[0] + 1 + (ui->width - ui->x);
        else
            rect[0] += value->x_offset;
        swrUI_DrawTextAligned(value->font, value->text, (short*)rect, value->align_flags, ui->r, ui->g, ui->b, ui->a, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        break;
    case swrUI_MSG_DESTROY:
        value = (swrUI_ScreenTextValue*)ui->unk4f4;
        value->text = swrUI_replaceAllocatedStr(value->text, NULL);
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00416130
int swrUI_ListProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    swrUI_unk* item;
    swrSprite_BBox box;
    int margins[4];

    switch (msg) {
    case swrUI_MSG_HOVER_CHANGED:
        swrUI_BuildPanelFrame(ui, 0, param != NULL ? 1 : 0);
        break;
    case swrUI_MSG_KEY_DOWN:
        if (swrUI_CountSelectableItems(ui) == 0)
            break;
        swrUI_SetUI5(ui);
        if ((int)param == VK_UP) {
            item = swrUI_GetSelectedItem(ui);
            if (item == NULL)
                break;
            item = item->prev2;
        } else if ((int)param == VK_DOWN) {
            item = swrUI_GetSelectedItem(ui);
            if (item == NULL)
                break;
            item = item->next2;
        } else {
            break;
        }
        if (item != NULL)
            swrUI_SelectListItem(item, 1);
        return 1;
    case swrUI_MSG_KEY_UP:
        if (swrUI_CountSelectableItems(ui) != 0)
            swrUI_ClearUI5();
        break;
    case swrUI_MSG_SET_POS:
        box.x = ui->x;
        box.y = ui->y;
        box.x2 = ui->width;
        box.y2 = ui->height;
        swrSprite_MoveBBoxTo(&box, (int)param, param2);
        swrUI_GetListFrameInsets(margins, 0);
        ui->content_left = box.x + margins[0];
        ui->content_top = box.y + margins[1];
        ui->content_right = box.x2 - margins[2];
        ui->content_bottom = box.y2 - margins[3];
        break;
    case 0x48:
        if (param != NULL) {
            for (item = ui->next; item != NULL; item = item->next2)
                swrUI_RunCallbacks2(item, 0);
            break;
        }
        swrUI_RefreshListLayout(ui);
        break;
    case swrUI_MSG_LIST_SELECT_ITEM:
        swrUI_SelectListItem((swrUI_unk*)param2, 1);
        swrUI_RefreshListLayout(ui);
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_LIST_SELECTION_CHANGED, (int)ui, param2);
        break;
    case swrUI_MSG_SLIDER_DECREASED:
        if (ui->first_visible != 0)
            ui->first_visible--;
        swrUI_RefreshListLayout(ui);
        break;
    case swrUI_MSG_SLIDER_INCREASED:
        if ((unsigned int)ui->first_visible < (unsigned int)swrUI_CountSelectableItems(ui))
            ui->first_visible++;
        swrUI_RefreshListLayout(ui);
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00416370
int swrUI_TextEntryProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    int rect[4];
    int x;
    int caretHeight;

    switch (msg) {
    case swrUI_MSG_KEY_DOWN:
        if (ui->flags & swrUI_EDITING)
            swrUI_HandleTextEntryKey(ui, (int)param);
        break;
    case swrUI_MSG_UPDATE:
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = ui->width;
        rect[3] = ui->height;
        swrUI_DrawTextAligned(ui->font_index, ui->str_allocated, (short*)rect, swrUI_TEXT_ALIGN_CENTER_Y | swrUI_TEXT_ALIGN_INDENT_5, ui->r, ui->g, ui->b, ui->a, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        break;
    case swrUI_MSG_SET_TEXT:
        swrUI_DefaultElementProc(ui, msg, param, param2);
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_TEXT_ENTRY_CHANGED, ui->id, (int)ui->str_allocated);
        return 0;
    case swrUI_MSG_SET_POS:
        // caret left edge: text up to the caret, plus five spaces of padding
        x = swrUI_GetSubstringWidth(ui->str_allocated, ui->font_index, 0, ui->caret_pos);
        x += swrText_GetStringWidth(" ", swrText_fontsByIndex[ui->font_index]) * 5;
        caretHeight = swrText_GetStringHeight("l", swrText_fontsByIndex[ui->font_index]) * 2;
        swrUI_SetCaretRect(x + (int)param, ((ui->height - ui->y + 1) >> 1) - (caretHeight >> 1) + param2, 1, caretHeight);
        break;
    case swrUI_MSG_SET_EDITING:
        if (param != NULL) {
            swrSprite_SetCursorVisibility2(0);
            swrUI_textEntrySavedCursorCount = swrSprite_mouseVisible + 1;
            swrSprite_SetCursorVisibility(0);
            ui->caret_pos = 0;
            x = swrUI_GetSubstringWidth(ui->str_allocated, ui->font_index, 0, 0) + ui->x;
            x += swrText_GetStringWidth(" ", swrText_fontsByIndex[ui->font_index]) * 5;
            caretHeight = swrText_GetStringHeight("l", swrText_fontsByIndex[ui->font_index]) * 2;
            swrUI_SetCaretRect(x, ((ui->height - ui->y + 1) >> 1) - (caretHeight >> 1) + ui->y, 1, caretHeight);
            swrUI_SetCaretActive(1);
            swrUI_textEntryActive = 1;
            memset(swrUI_textEntryOriginalText, 0, sizeof(swrUI_textEntryOriginalText));
            if (ui->str_allocated != NULL)
                memcpy(swrUI_textEntryOriginalText, ui->str_allocated, strlen(ui->str_allocated) + 1);
        } else {
            swrSprite_SetCursorVisibility2(1);
            swrSprite_SetCursorVisibility(swrUI_textEntrySavedCursorCount);
            swrUI_SetCaretActive(0);
            swrUI_textEntryActive = 0;
        }
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00416820
int swrUI_DialogProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    return swrUI_DefaultElementProc(ui, msg, param, param2);
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

// 0x00416890
void swrUI_UnlinkElement(swrUI_unk* element)
{
    swrUI_ClearElementRefs(element);
    if (element == element->prev->next) {
        element->prev->next = element->next2;
        if (element->next2 != NULL)
            element->next2->prev2 = NULL;
    } else {
        if (element->prev2 != NULL)
            element->prev2->next2 = element->next2;
        if (element->next2 != NULL)
            element->next2->prev2 = element->prev2;
    }
    element->prev2 = NULL;
    element->next2 = NULL;
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

// 0x00416930
int swrUI_StepPageTransition(swrUI_unk* element)
{
    unsigned int elapsed;
    int dx;
    int dy;
    int stepX;
    int stepY;

    if (swrUI_pageTransitionStartTime == 0xffffffff)
        swrUI_pageTransitionStartTime = timeGetTime();
    elapsed = timeGetTime() - swrUI_pageTransitionStartTime;
    swrUI_pageTransitionActive = 0;
    if ((element->flags & swrUI_ANIMATING) == 0)
        return swrUI_pageTransitionActive;

    if (element->transition_delay != 0) {
        if ((unsigned int)element->transition_delay < elapsed)
            elapsed = element->transition_delay;
        element->transition_delay -= elapsed;
        return swrUI_pageTransitionActive;
    }

    dx = element->x - element->transition_home_x;
    dy = element->y - element->transition_home_y;
    if (dx == 0 && dy == 0) {
        element->flags &= ~swrUI_ANIMATING;
        swrUI_RunCallbacks(element, swrUI_MSG_PAGE_TRANSITION, 0, 1);
        return swrUI_pageTransitionActive;
    }

    swrUI_pageTransitionActive = 1;
    stepX = dx;
    if (dx != 0) {
        stepX = dx / 10;
        if (stepX == 0)
            stepX = dx < 0 ? -1 : 1;
    }
    stepY = dy;
    if (dy != 0) {
        stepY = dy / 10;
        if (stepY == 0)
            stepY = dy < 0 ? -1 : 1;
    }
    swrUI_SetPos(element, element->x - stepX, element->y - stepY);
    return swrUI_pageTransitionActive;
}

// 0x00416a40
void swrUI_NavigateFocus(swrUI_unk* element, int vk)
{
    swrUI_unk* target;
    swrUI_unk* cur;
    swrUI_unk* next;

    if (vk == VK_TAB) {
        // cycle forward (wrapping) to the next visible, enabled, non-static sibling
        target = NULL;
        cur = element;
        do {
            next = cur->next2;
            if (next == NULL)
                next = swrUI_GetFirstSibling(cur);
            if ((next->flags & swrUI_STATIC) == 0)
                target = next;
            if (swrUI_IsElementVisible(next) == 0)
                target = NULL;
            if (next->flags & swrUI_DISABLED)
                target = NULL;
            if (next == element)
                target = next;
            cur = next;
        } while (target == NULL);
    } else if (vk == VK_LEFT || vk == VK_RIGHT || vk == VK_UP || vk == VK_DOWN) {
        if (swrUI_IsFocusable(element) == 0)
            return;
        if (vk == VK_RIGHT || vk == VK_DOWN) {
            target = swrUI_NextFocusable(element);
            if (target == NULL) {
                if (((uint8_t)element->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
                    target = swrUI_NextFocusable(element->prev);
                } else {
                    target = swrUI_GetFirstSibling(element);
                    if (swrUI_IsFocusable(target) == 0)
                        target = swrUI_NextFocusable(target);
                }
            }
        } else {
            target = swrUI_PrevFocusable(element);
            if (target == NULL) {
                if (((uint8_t)element->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
                    target = swrUI_PrevFocusable(element->prev);
                    if (target == NULL)
                        target = swrUI_NextFocusable(element->prev);
                } else {
                    target = swrUI_GetLastSibling(element);
                    if (swrUI_IsFocusable(target) == 0)
                        target = swrUI_PrevFocusable(target);
                }
            }
        }
        // a list takes focus through its first item (no NULL check in the EXE)
        if (((uint8_t)target->widget_class & swrUI_CLASS_LIST) == swrUI_CLASS_LIST && target->next != NULL)
            target = target->next;
    } else {
        target = element;
    }
    if (target != NULL) {
        swrUI_FocusElement(target, 1);
        if (((uint8_t)target->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM)
            swrUI_SelectListItem(swrUI_FindChildByText(target->prev, target->str_allocated), 1);
    }
}

// 0x00416bd0
void swrUI_ProcessNavAxis(void)
{
    int navX;
    int navY;

    // swrUI_QuantizeNavAxis: -2 = full left/up, -1 = slight, 2 = slight right/down, 1 = full
    swrUI_QuantizeNavAxis(swrUI_joyAxisX, swrUI_joyAxisY, &navX, &navY);
    if (navX != swrUI_navAxisXPrev) {
        if (navX < 0 && swrUI_navAxisXPrev < 0)
            swrUI_HandleKeyEvent2((void*)VK_LEFT, navX == -2);
        if (navX > 0 && swrUI_navAxisXPrev > 0)
            swrUI_HandleKeyEvent2((void*)VK_RIGHT, navX == 1);
    }
    if (navY != swrUI_navAxisYPrev) {
        if (navY < 0 && swrUI_navAxisYPrev < 0)
            swrUI_HandleKeyEvent2((void*)VK_UP, navY == -2);
        if (navY > 0 && swrUI_navAxisYPrev > 0)
            swrUI_HandleKeyEvent2((void*)VK_DOWN, navY == 1);
    }
    swrUI_navAxisXPrev = navX;
    swrUI_navAxisYPrev = navY;
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
int swrUI_HandleKeyEvent2(void* forward2, int pressed)
{
    return swrUI_HandleKeyEvent((int)forward2, pressed);
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

// 0x004176f0
void swrUI_GetPaddedTextBBox(int* bbox_out, char* text, int font)
{
    int width = swrText_GetStringWidth(text, swrText_fontsByIndex[font]);
    int height = swrText_GetStringHeight(text, swrText_fontsByIndex[font]);

    bbox_out[2] = width + 0x13;
    bbox_out[1] = 0;
    bbox_out[0] = 0;
    bbox_out[3] = height + 0x1d;
}

// 0x00417740
void swrUI_GetWrappedTextBBox(int* bbox_out, char* text, int font)
{
    int width = swrText_GetStringWidth(text, swrText_fontsByIndex[font]);
    int height = swrText_GetStringHeight(text, swrText_fontsByIndex[font]);
    // roughly square box: side ~ sqrt(text area / 8)
    int side = (int)sqrt((double)((unsigned int)((height + 5) * width) >> 3));

    bbox_out[1] = 0;
    bbox_out[0] = 0;
    bbox_out[2] = side * 8 + 0x3b;
    bbox_out[3] = side + 0x4f;
}

// 0x004177b0
unsigned int swrUI_GetButtonRowBBox(int* bbox_out, char* label1, char* label2, char* label3, int font)
{
    unsigned int count = 0;
    unsigned int buttonWidth = 0x96;
    int textHeight = 0;
    int rowWidth;
    int width;

    if (label1 != NULL) {
        width = swrText_GetStringWidth(label1, swrText_fontsByIndex[font]);
        if ((unsigned int)(width * 3) > 0x95)
            buttonWidth = width * 3;
        if (swrText_GetStringHeight(label1, swrText_fontsByIndex[font]) >= 0)
            textHeight = swrText_GetStringHeight(label1, swrText_fontsByIndex[font]);
        count = 1;
    }
    if (label2 != NULL) {
        width = swrText_GetStringWidth(label2, swrText_fontsByIndex[font]);
        if ((unsigned int)(width * 3) >= buttonWidth)
            buttonWidth = width * 3;
        if (swrText_GetStringHeight(label2, swrText_fontsByIndex[font]) >= textHeight)
            textHeight = swrText_GetStringHeight(label2, swrText_fontsByIndex[font]);
        count++;
    }
    if (label3 != NULL) {
        width = swrText_GetStringWidth(label3, swrText_fontsByIndex[font]);
        if ((unsigned int)(width * 3) >= buttonWidth)
            buttonWidth = width * 3;
        if (swrText_GetStringHeight(label3, swrText_fontsByIndex[font]) >= textHeight)
            textHeight = swrText_GetStringHeight(label3, swrText_fontsByIndex[font]);
        count++;
    }
    // three buttons wrap to two columns and two rows
    if (count < 3)
        rowWidth = buttonWidth * count;
    else
        rowWidth = buttonWidth << 1;
    textHeight = textHeight + 0x14;
    if (count > 2)
        textHeight = textHeight * 2;
    bbox_out[2] = rowWidth + count * 0x14 - 1;
    bbox_out[1] = 0;
    bbox_out[0] = 0;
    bbox_out[3] = textHeight - 1;
    return buttonWidth;
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
    swrSprite_SetFlag(SWR_UI_CARET_SPRITE_ID, swrSprite_FLAG_ADDITIVE);
    swrSprite_SetFlag(SWR_UI_CARET_SPRITE_ID, swrSprite_FLAG_UNK_10000);
}

// Decodes count TGA RLE elements of elementSize bytes into dest; -1 when a packet header can't be read.
// 0x00418700
int swrSprite_ReadTgaRLEData(void* file, void* dest, int elementSize, int count)
{
    uint8_t* out = (uint8_t*)dest;
    uint8_t packet;
    uint8_t value8;
    uint16_t value16;
    uint32_t value32;
    int run;
    int i;

    if (count < 1)
        return 0;
    do {
        if (stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &packet, 1) == 0)
            return -1;
        run = (packet & SWR_TGA_RLE_COUNT_MASK) + 1;
        count -= run;
        if ((packet & SWR_TGA_RLE_RUN_PACKET) == 0) {
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, out, run * elementSize);
            out += run * elementSize;
            continue;
        }
        switch (elementSize) {
        case 1:
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &value8, 1);
            memset(out, value8, run);
            out += run;
            break;
        case 2:
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &value16, 2);
            for (i = 0; i < run; i++, out += 2)
                memcpy(out, &value16, 2);
            break;
        case 3:
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &value8, 1);
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &value16, 2);
            for (i = 0; i < run; i++, out += 3) {
                out[0] = value8;
                memcpy(out + 1, &value16, 2);
            }
            break;
        case 4:
            stdPlatform_hostServices_ptr->fileRead((stdFile_t)file, &value32, 4);
            for (i = 0; i < run; i++, out += 4)
                memcpy(out, &value32, 4);
            break;
        }
    } while (count > 0);
    return 0;
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

// 0x00418cb0
void swrUI_BuildHighlightSprites(swrUI_unk* ui, int highlighted)
{
    unsigned int style = ui->frame_style;
    unsigned int mirror = 0;
    int raised = 0;
    int leftId;
    int midId = 0; // left uninitialized by the original when no three-piece style bit is set
    int rightId;
    int leftWidth;
    int rightWidth;
    int height;
    int singleId;
    int singleOffset;
    int rect[4];

    if (style == 0)
        return;
    if (style & swrUI_FRAME_STYLE_MIRROR_V)
        mirror = swrUI_SPRITE_SLOT_MIRROR_V;
    if (style & swrUI_FRAME_STYLE_MIRROR_H)
        mirror |= swrUI_SPRITE_SLOT_MIRROR_H;

    if (style & (swrUI_FRAME_STYLE_OK_BUTTON | swrUI_FRAME_STYLE_EDIT_SEGMENTED | swrUI_FRAME_STYLE_SEGMENT)) {
        if (style & swrUI_FRAME_STYLE_OK_BUTTON) {
            singleId = swrSprite_ok_button;
            singleOffset = 0;
        } else if (style & swrUI_FRAME_STYLE_EDIT_SEGMENTED) {
            singleId = swrSprite_editwindow_segmented;
            singleOffset = -4;
        } else {
            singleId = swrSprite_segment;
            singleOffset = -4;
        }
        swrSprite_GetTextureDimFromId(singleId, &leftWidth, &height);
        rect[0] = ui->x;
        rect[1] = ui->y;
        rect[2] = leftWidth + ui->x - 1;
        rect[3] = height + ui->y - 1;
        swrUI_AddSprite(ui, 0, singleId, rect, 1, mirror);
        swrUI_SetSpriteOffset(ui, 0, 0, singleOffset);
        swrUI_SetSelected(ui, highlighted);
        return;
    }

    if (style & (swrUI_FRAME_STYLE_SETTINGS_BUTTON | swrUI_FRAME_STYLE_BACK_BUTTON)) {
        raised = (style & swrUI_FRAME_STYLE_MIRROR_V) ? -14 : -26;
        if (highlighted) {
            leftId = swrSprite_settings_btn_end_selected;
            midId = swrSprite_settings_btn_strch_selected;
            rightId = swrSprite_settings_btn_end2_selected;
        } else {
            leftId = (style & swrUI_FRAME_STYLE_BACK_BUTTON) ? swrSprite_settings_btnback_end : swrSprite_settings_btn_end;
            midId = swrSprite_settings_btn_strch_end;
            rightId = swrSprite_settings_btn_end2;
        }
    } else if (style & swrUI_FRAME_STYLE_SMALL_WINDOW) {
        raised = -7;
        leftId = rightId = highlighted ? swrSprite_sml_window_end_selected : swrSprite_sml_window_end;
        midId = highlighted ? swrSprite_sml_window_strch_selected : swrSprite_sml_window_strch;
    } else if (style & swrUI_FRAME_STYLE_WINDOW_BARS) {
        raised = -20;
        leftId = rightId = highlighted ? swrSprite_window_end_selected : swrSprite_window_end;
        midId = highlighted ? swrSprite_window_strchbars_selected : swrSprite_window_strchbars;
    } else {
        // faithful: the highlight flag itself is used as the sprite id
        leftId = rightId = highlighted;
    }

    swrSprite_GetTextureDimFromId(leftId, &leftWidth, &height);
    swrSprite_GetTextureDimFromId(rightId, &rightWidth, &height);

    rect[0] = ui->x;
    rect[1] = ui->y;
    rect[2] = leftWidth + ui->x - 1;
    rect[3] = height + ui->y - 1;
    swrUI_AddSprite(ui, 0, leftId, rect, 1, mirror);
    swrUI_SetSpriteOffset(ui, 0, 0, raised);

    rect[0] = leftWidth + ui->x;
    rect[1] = ui->y;
    rect[2] = ui->width - rightWidth;
    rect[3] = height + ui->y - 1;
    swrUI_AddSprite(ui, 1, midId, rect, 1, mirror);
    swrUI_SetSpriteOffset(ui, 1, 0, raised);

    rect[0] = ui->width - rightWidth + 1;
    rect[1] = ui->y;
    rect[2] = ui->width;
    rect[3] = height + ui->y - 1;
    swrUI_AddSprite(ui, 2, rightId, rect, 1, mirror | swrUI_SPRITE_SLOT_MIRROR_H);
    swrUI_SetSpriteOffset(ui, 2, 0, raised);
    swrUI_SetSelected(ui, highlighted);
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

// 0x004191f0
int swrUI_Menu_HangarSelectVehicle(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    swrUI_unk* button;

    switch (msg) {
    case swrUI_MSG_MOUSE_DOWN:
        if (self->id == SWR_UI_ID_HANGAR_VEHICLE_ARROW_LEFT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_LEFT;
        else if (self->id == SWR_UI_ID_HANGAR_VEHICLE_ARROW_RIGHT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_RIGHT;
        break;
    case swrUI_MSG_SET_ACTIVE:
        if (param_3 != NULL && self->id == swrUI_WINDOW_HANGAR_SELECT_VEHICLE) {
            swrUI_ReparentElement(self, swrUI_GetById(NULL, swrUI_WINDOW_HANGAR_NAV));
            swrUI_RefreshPageButtons(self, 1, multiplayer_enabled == 0);
            if (multiplayer_enabled != 0)
                swrObjHang_EnterVehicleSelect();
        }
        break;
    case swrUI_MSG_PAGE_POPPED:
        swrControl_menuAcceptGuard = 0;
        // faithful: the OK button is looked up but the back button is deactivated twice
        button = swrUI_GetById(self, SWR_UI_ID_BACK_BUTTON);
        swrUI_RunCallbacks2(button, 0);
        swrUI_GetById(self, SWR_UI_ID_OK_BUTTON);
        swrUI_RunCallbacks2(button, 0);
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0) {
                swrControl_cancelPressedEdge = 1;
                break;
            }
            swrMultiplayer_RacerPick(swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId);
            button = swrUI_GetById(self, SWR_UI_ID_BACK_BUTTON);
            swrUI_RunCallbacks2(button, 0);
            swrUI_GetById(self, SWR_UI_ID_OK_BUTTON);
            swrUI_RunCallbacks2(button, 0);
            swrUI_PopMenuPage();
        }
        break;
    }
    return 0;
}

// 0x00419390
int swrUI_Menu_HangarSelectPlanet(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    switch (msg) {
    case swrUI_MSG_MOUSE_DOWN:
        switch (self->id) {
        case SWR_UI_ID_HANGAR_PLANET_ARROW_LEFT:
            swrUI_pendingInputDown = swrUI_INPUT_MENU_LEFT;
            break;
        case SWR_UI_ID_HANGAR_PLANET_ARROW_RIGHT:
            swrUI_pendingInputDown = swrUI_INPUT_MENU_RIGHT;
            break;
        case SWR_UI_ID_HANGAR_PLANET_ARROW_UP:
            swrUI_pendingInputPressed = swrUI_INPUT_MENU_UP;
            break;
        case SWR_UI_ID_HANGAR_PLANET_ARROW_DOWN:
            swrUI_pendingInputPressed = swrUI_INPUT_MENU_DOWN;
            break;
        }
        return 1;
    case swrUI_MSG_SET_ACTIVE:
        if (param_3 != NULL && self->id == swrUI_WINDOW_HANGAR_SELECT_PLANET) {
            swrUI_ReparentElement(self, swrUI_GetById(NULL, swrUI_WINDOW_HANGAR_NAV));
            swrUI_RefreshPageButtons(self, multiplayer_enabled == 0, 1);
            if (multiplayer_enabled != 0)
                swrObjHang_EnterPlanetSelect();
        }
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() != 0)
                swrUI_PopMenuPage();
            else
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
        break;
    }
    return 0;
}

// 0x004194c0
int swrUI_Menu_HangarSelectTrack(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (param_3 != NULL && self->id == swrUI_WINDOW_HANGAR_SELECT_TRACK) {
            swrUI_suppressBackPop = 1;
            swrUI_ReparentElement(self, swrUI_GetById(NULL, swrUI_WINDOW_HANGAR_NAV));
            swrUI_RefreshPageButtons(self, 1, 1);
        }
        break;
    case swrUI_MSG_BACK:
        swrControl_cancelPressedEdge = 1;
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
        break;
    }
    return 0;
}

// 0x00419570
int swrUI_Menu_HangarMainMenu(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (param_3 != NULL && self->id == swrUI_WINDOW_HANGAR_MAIN_MENU) {
            swrUI_suppressBackPop = 1;
            swrUI_ReparentElement(self, swrUI_GetById(NULL, swrUI_WINDOW_HANGAR_NAV));
            swrUI_RefreshPageButtons(self, 1, 1);
        }
        break;
    case swrUI_MSG_BACK:
        swrControl_cancelPressedEdge = 1;
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
        break;
    }
    return 0;
}

// 0x00419620
int swrUI_Menu_HangarLookAtVehicle(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_SET_ACTIVE) {
        if (param_3 != NULL && self->id == swrUI_WINDOW_HANGAR_LOOK_AT_VEHICLE) {
            swrUI_ReparentElement(self, swrUI_GetById(NULL, swrUI_WINDOW_HANGAR_NAV));
            swrUI_RefreshPageButtons(self, 1, 0);
        }
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
    }
    return 0;
}

// 0x004196b0
int swrUI_Menu_HangarUnused89_Maybe(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
    }
    return 0;
}

// 0x00419700
int swrUI_Menu_HangarWatto(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_MOUSE_DOWN) {
        if (self->id == SWR_UI_ID_HANGAR_WATTO_ARROW_LEFT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_LEFT;
        else if (self->id == SWR_UI_ID_HANGAR_WATTO_ARROW_RIGHT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_RIGHT;
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
        }
    }
    return 0;
}

// 0x00419770
int swrUI_Menu_HangarJunkyard(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_MOUSE_DOWN) {
        if (self->id == SWR_UI_ID_HANGAR_JUNKYARD_ARROW_LEFT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_LEFT;
        else if (self->id == SWR_UI_ID_HANGAR_JUNKYARD_ARROW_RIGHT)
            swrUI_pendingInputDown = swrUI_INPUT_MENU_RIGHT;
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            if (swrMultiplayer_IsMultiplayerEnabled() == 0)
                swrControl_menuAcceptPressedEdge = 1;
        } else if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrControl_cancelPressedEdge = 1;
            swrUI_PopMenuPage();
        }
    }
    return 0;
}

// 0x004197f0
void swrUI_GetListFrameInsets(int* bbox_out, int collapsed)
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
        swrSound_PlayUISound(0x48);
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
        swrSound_PlayUISound(0x48);
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

// 0x0041a750
void swrUI_HandleSliderClick(swrUI_unk* slider, int mouseX, int mouseY)
{
    int w;
    int h;
    int decrease = 0;
    int increase = 0;
    swrSprite_BBox startCap;
    swrSprite_BBox endCap;
    swrSprite_BBox track;

    if (slider == NULL)
        return;
    if (slider->flags & swrUI_VERTICAL) {
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_end, &w, &h);
        startCap.x = slider->x;
        startCap.y = slider->y;
        startCap.x2 = w + slider->x - 1;
        startCap.y2 = h + slider->y - 1;
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_end, &w, &h);
        endCap.x = slider->x;
        endCap.y = slider->slider_length + slider->y - h;
        endCap.x2 = w + slider->x - 1;
        endCap.y2 = slider->slider_length + slider->y - 1;
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_strch, &w, &h);
        track.x = slider->x;
        track.y = startCap.y2 + 1;
        track.x2 = w + slider->x - 1;
        track.y2 = endCap.y - 1;
    } else {
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_end, &w, &h);
        startCap.x = slider->x;
        startCap.y = slider->y;
        startCap.x2 = w + slider->x - 1;
        startCap.y2 = h + slider->y - 1;
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_end, &w, &h);
        endCap.x = slider->slider_length + slider->x - w;
        endCap.y = slider->y;
        endCap.x2 = slider->slider_length + slider->x - 1;
        endCap.y2 = h + slider->y - 1;
        swrSprite_GetTextureDimFromId(swrSprite_sliderbar_strch, &w, &h);
        track.x = startCap.x2 + 1;
        track.y = slider->y;
        track.x2 = endCap.x - 1;
        track.y2 = h + slider->y - 1;
    }

    // the start cap decreases, the end cap increases; swrUI_LEFT_RIGHT_UNK swaps them
    if (swrSprite_IsInsideBBox(&startCap, mouseX, mouseY)) {
        if (slider->flags & swrUI_LEFT_RIGHT_UNK)
            increase = 1;
        else
            decrease = 1;
    }
    if (swrSprite_IsInsideBBox(&endCap, mouseX, mouseY)) {
        if (slider->flags & swrUI_LEFT_RIGHT_UNK)
            decrease = 1;
        else
            increase = 1;
    }
    // faithful: the track is hit-tested but the result is unused
    swrSprite_IsInsideBBox(&track, mouseX, mouseY);
    if (decrease)
        swrUI_HandleSliderKey(slider, VK_SUBTRACT);
    if (increase)
        swrUI_HandleSliderKey(slider, VK_ADD);
}

// 0x0041aa40
void swrUI_BroadcastToWindowsRecurse(swrUI_unk* node, int forward2, int forward3)
{
    for (; node != NULL; node = node->next2) {
        if ((node->flags & swrUI_VISIBLE) == 0)
            continue;
        if (node->next != NULL)
            swrUI_BroadcastToWindowsRecurse(node->next, forward2, forward3);
        if (node->widget_class == swrUI_CLASS_WINDOW)
            swrUI_RunCallbacks(node, swrUI_MSG_MP_UPDATE, forward2, forward3);
    }
}

// 0x0041abb0
swrUI_unk* swrUI_CreateRaceResultRow(int id)
{
    swrUI_unk* ui = swrUI_New(NULL, id, -1, NULL, 0, 0, 0, (swrUI_unk_F1)swrUI_RaceResultRowProc, NULL);
    swrUI_SetSize(ui, 500, 50);
    ui->widget_class = swrUI_CLASS_LIST_ITEM;
    ui->flags |= swrUI_STATIC | swrUI_NO_PAGE_TRANSITION;
    return ui;
}

// 0x0041ac00
int swrUI_RaceResultRowProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    if (msg == swrUI_MSG_UPDATE)
        swrUI_DrawRaceResultRow(ui);
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x0041ac30
void swrUI_DrawRaceResultRow(swrUI_unk* row)
{
    char text[256];
    int retired;
    int finished;
    int x;
    int y;
    int slot;
    char* name;

    retired = 0;
    finished = 0;
    if (row->sort_key == SWR_UI_RACE_RESULT_RETIRED)
        retired = 1;
    if (multiplayer_aPlayerQuit[row->result_player_slot] != 0)
        retired = 1;
    if (multiplayer_aPlayerFinished[row->result_player_slot] != 0)
        finished = 1;
    x = row->x;
    y = row->y;

    if (!retired) {
        sprintf(text, "%d", row->sort_key + 1);
        swrUI_DrawText(0, x + 5, y + 0x14, -1, -1, -1, -1, text, 0, 0, 0);
    }

    slot = row->result_player_slot;
    if (swrMultiplayer_IsPlayerActive(slot))
        name = swrMultiplayer_GetPlayerNameAscii(slot);
    else
        name = swrText_Translate(swrRacer_PodData[swrMultiplayer_GetRacerId(row->id)].name);
    sprintf(text, swrTextFmtString1, name);
    swrUI_DrawText(6, x + 0x19, y + 10, -1, -1, -1, -1, text, 0, 0, 0);

    name = swrText_Translate(swrRacer_PodData[swrMultiplayer_GetRacerId(row->id)].lastname);
    sprintf(text, "%s %s", swrText_Translate(swrRacer_PodData[swrMultiplayer_GetRacerId(row->id)].name), name);
    swrUI_DrawText(0, x + 0x19, y + 0x23, -1, -1, -1, -1, text, 0, 0, 0);

    if (!retired && !finished) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0548/Lap %d"), row->result_lap + 1);
        swrUI_DrawText(0, x + 0xd2, y + 0x14, -1, -1, -1, -1, text, 0, 0, 0);
    }
    if (finished)
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0531/Final"));
    else if (retired)
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0549/Retired"));
    else
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0550/Current : %s"), swrMultiplayer_FormatTimeString(row->result_current_time));
    swrUI_DrawText(0, x + 0xd2, y + 0x1e, -1, -1, -1, -1, text, 0, 0, 0);

    if (!retired) {
        sprintf(text, swrText_Translate("/MONDOTEXT_H_0551/Total : %s"), swrMultiplayer_FormatTimeString(row->result_total_time));
        swrUI_DrawText(0, x + 0x154, y + 0x1e, -1, -1, -1, -1, text, 0, 0, 0);
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

// 0x0041b260
swrUI_unk* swrUI_NewPanel(swrUI_unk* parent, int id, int* rect, int kind)
{
    swrUI_unk* ui;
    int left = 0;
    int top = 0;
    int right = 0;
    int bottom = 0;

    ui = swrUI_New(parent, id, -1, NULL, 0, 0, 0, NULL, NULL);
    ui->flags |= swrUI_STATIC;
    if (rect != NULL) {
        top = rect[1];
        left = rect[0];
        right = rect[2];
        bottom = rect[3];
    }
    swrUI_SetSize(ui, right - left + 1, bottom - top + 1);
    swrUI_SetPos(ui, left, top);
    swrUI_BuildPanelFrame(ui, kind, 0);
    swrUI_RunCallbacks2(ui, 1);
    ui->widget_class = swrUI_CLASS_PANEL;
    return ui;
}

// 0x0041b300
void swrUI_ClearListSelection(swrUI_unk* list)
{
    swrUI_unk* item;
    uint8_t cls;

    if (list == NULL || list->next == NULL)
        return;
    for (item = list->next; item != NULL; item = item->next2) {
        cls = (uint8_t)item->widget_class;
        // faithful: a mask test, so classes 13..15 pass too (15 keeps its sprites)
        if ((cls & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
            if ((cls & 3) != 3) {
                swrUI_AddSprite(item, 0, 0, NULL, 0, 0);
                swrUI_AddSprite(item, 1, 0, NULL, 0, 0);
                swrUI_AddSprite(item, 2, 0, NULL, 0, 0);
            }
            item->item_flags &= ~swrUI_ITEM_SELECTED;
        }
    }
    swrUI_RefreshListLayout(list);
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

// 0x0041b3f0
swrUI_unk* swrUI_PrevFocusable(swrUI_unk* element)
{
    swrUI_unk* it;

    for (it = element; it != NULL; it = it->prev2) {
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

// 0x0041b470
void swrUI_RefreshPageButtons(swrUI_unk* page, int backArg, int okArg)
{
    swrUI_unk* button;

    button = swrUI_GetById(page, SWR_UI_ID_BACK_BUTTON);
    if (button != NULL) {
        swrUI_RunCallbacks2(button, backArg);
        button->flags |= swrUI_STATIC;
    }
    button = swrUI_GetById(page, SWR_UI_ID_OK_BUTTON);
    if (button != NULL) {
        swrUI_RunCallbacks2(button, okArg);
        button->flags |= swrUI_STATIC;
    }
}

// 0x0041b4d0
void swrUI_SortListItems(swrUI_unk* list)
{
    swrUI_unk sorted;
    swrUI_unk* child;
    swrUI_unk* lowest;

    if (list == NULL) {
        return;
    }
    // a zeroed element on the stack collects the items in ascending sort_key order
    memset(&sorted, 0, sizeof(sorted));
    while (swrUI_CountSelectableItems(list) != 0) {
        lowest = list->next;
        // unreachable while a selectable item remains; guards the analyzer's NULL path
        if (lowest == NULL) {
            break;
        }
        for (child = list->next; child != NULL; child = child->next2) {
            if (child->widget_class == swrUI_CLASS_LIST_ITEM && (unsigned int)child->sort_key < (unsigned int)lowest->sort_key) {
                lowest = child;
            }
        }
        swrUI_UnlinkElement(lowest);
        swrUI_Enqueue(&sorted, lowest);
    }
    while (sorted.next != NULL) {
        child = sorted.next;
        swrUI_UnlinkElement(child);
        swrUI_Enqueue(list, child);
    }
    swrUI_RefreshListLayout(list);
}

// 0x0041b590
swrUI_unk* swrUI_FindCheckedGroupItem(swrUI_unk* ui)
{
    int groupId;

    if (ui == NULL)
        return NULL;
    groupId = ui->id;
    // rewind to the first member of the radio group (same walk as swrUI_ClearGroupChecked)
    do {
        if ((ui->flags & swrUI_RADIO_GROUP_UNK) != 0 && ui->prev2->id != groupId)
            break;
        ui = ui->prev2;
    } while (ui != NULL);
    // first checked FramedText from there on (not limited to the group)
    for (; ui != NULL; ui = ui->next2) {
        if (ui->widget_class == swrUI_CLASS_FRAMED_TEXT && (ui->flags & swrUI_CHECKED) != 0)
            return ui;
    }
    return NULL;
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

// 0x0041b690
void swrUI_ProcessPendingClose(void)
{
    if (swrUI_confirmDialogDone != 0 && swrUI_confirmDialogModal == 0 && swrUI_confirmDialog != NULL) {
        swrUI_FreeElement(swrUI_confirmDialog);
        swrUI_confirmDialog = NULL;
        swrUI_RunCallbacks2(swrUI_confirmDialogParent, 1);
        swrUI_RunCallbacks(swrUI_confirmDialogParent, swrUI_MSG_DIALOG_RESULT, swrUI_confirmDialogResult, 0);
        swrUI_confirmDialogParent = NULL;
        swrUI_confirmDialogDone = 0;
    }
}

// 0x0041ead0
int swrUI_Menu_MpSessionType(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_SET_ACTIVE) {
        if (param_3 != NULL)
            stdComm_Shutdown();
        if (swrUI_IsPrevPage(swrUI_WINDOW_SPLASH, (int)param_3) != 0)
            swrMultiplayer_SetInMultiplayer(1);
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((int)param_3 == SWR_UI_ID_BACK_BUTTON) {
            swrUI_PopMenuPage();
        } else if ((int)param_3 == SWR_UI_ID_MP_HOST_BUTTON) {
            stdComm_Startup();
            multiplayer_track_change_permission = 1;
            swrUI_PushMenuPage(swrUI_WINDOW_MP_CREATE_GAME);
        } else if ((int)param_3 == SWR_UI_ID_MP_JOIN_BUTTON) {
            stdComm_Startup();
            multiplayer_track_change_permission = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_MP_JOIN_GAME);
        }
    }
    return 0;
}

// Widen a text entry's string, clamped to 0x100 chars; dst holds 0x101 wchar_t.
static void swrUI_EntryTextToWchar(wchar_t* dst, char* text)
{
    int len = strlen(text);

    if (len > 0x100)
        len = 0x100;
    stdString_CharToWchar(dst, text, len);
    dst[len] = L'\0';
}

// 0x0041ede0
int swrUI_Menu_MpCreateGame(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    // the EXE's buffers are 0x100 wchar_t, one short of the clamp's terminator
    wchar_t playerName[0x101];
    wchar_t gameName[0x101];
    wchar_t password[0x101];
    swrUI_unk* element;
    char* text;

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        swrMultiplayer_Initialize();
        swrMultiplayer_FillLastPlayerName(swrUI_GetById(self, SWR_UI_ID_MP_CREATE_PLAYER_NAME));
        swrMultiplayer_FillDefaultGameName(swrUI_GetById(self, SWR_UI_ID_MP_CREATE_GAME_NAME));
        break;
    case swrUI_MSG_BACK:
    case swrUI_MSG_PAGE_POPPED:
        swrMultiplayer_Shutdown();
        break;
    case swrUI_MSG_TEXT_ENTRY_CHANGED:
        if (swrMultiplayer_ValidateGameFields(self, SWR_UI_ID_MP_CREATE_PLAYER_NAME, SWR_UI_ID_MP_CREATE_GAME_NAME, 0) == 0)
            swrUI_DisableElement(swrUI_GetById(self, SWR_UI_ID_OK_BUTTON));
        else
            swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_OK_BUTTON));
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param_3 == 3) {
            swrMultiplayer_Shutdown();
            swrUI_PopMenuPage();
        } else if ((int)param_3 == SWR_UI_ID_OK_BUTTON) {
            swrUI_EntryTextToWchar(playerName, swrUI_GetById(self, SWR_UI_ID_MP_CREATE_PLAYER_NAME)->str_allocated);
            element = swrUI_GetById(self, SWR_UI_ID_MP_CREATE_GAME_NAME);
            swrMultiplayer_SetLastGame(element->str_allocated);
            swrUI_EntryTextToWchar(gameName, element->str_allocated);
            memset(password, 0, sizeof(password));
            text = swrUI_GetById(self, SWR_UI_ID_MP_CREATE_PASSWORD)->str_allocated;
            if (text != NULL)
                swrUI_EntryTextToWchar(password, text);
            swrMultiplayer_ClearStateBuffer();
            swrMultiplayer_maxPlayers = SWR_MAX_RACERS;
            // the EXE tests DPERR 0x88770118 first, but both failure paths just return
            if (swrMultiplayer_CreateSession(playerName, gameName, password, wuRegistry_lpClass, 0xb4) != 0)
                break;
            swrMultiplayer_ResetSession();
            swrMultiplayer_InitMessaging();
            if (stdComm_SetSessionOpenState(NULL, SWR_MAX_RACERS, 1) != 0)
                break;
            swrMultiplayer_SaveLastPlayerName(swrUI_GetById(self, SWR_UI_ID_MP_CREATE_PLAYER_NAME));
            swrUI_RefreshListSelection(swrUI_GetById(NULL, SWR_UI_ID_MP_CHAT_LIST));
            swrUI_PushMenuPage(swrUI_WINDOW_MP_RACE_SETUP);
        }
        break;
    }
    return 0;
}

// 0x0041f330
int swrUI_Menu_MpJoinGame(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    // the EXE's buffers are 0x100 wchar_t, one short of the clamp's terminator
    wchar_t playerName[0x101];
    wchar_t password[0x101];
    char sessionName[SWR_MP_SESSION_NAME_LEN];
    StdCommSessionSettings settings;
    swrUI_unk* list;
    char* text;
    unsigned int numSessions;
    unsigned int i;
    int changed;
    int sel;
    HRESULT hr;

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        swrMultiplayer_Initialize();
        swrMultiplayer_FillLastPlayerName(swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PLAYER_NAME));
        if (param == NULL) {
            swrUI_RemoveTimer(SWR_UI_TIMER_MP_JOIN_REFRESH);
            return 0;
        }
        if (swrMultiplayer_bootedFromGame != 0) {
            swrMultiplayer_bootedFromGame = 0;
            swrUI_ShowConfirmDialog(self, -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0405/The host has booted you from this game"), swrText_Translate("/MONDOTEXT_H_0406/OK"), NULL, NULL, 1);
            swrMultiplayer_joinDialogReason = SWR_MP_JOIN_DIALOG_BOOTED;
        }
        swrUI_AddTimer(self, SWR_UI_TIMER_MP_JOIN_INTERVAL_MS, SWR_UI_TIMER_MP_JOIN_REFRESH);
        return 0;

    case swrUI_MSG_BACK:
    case swrUI_MSG_PAGE_POPPED:
        swrMultiplayer_Shutdown();
        return 0;

    case swrUI_MSG_DIALOG_RESULT:
        swrMultiplayer_joinDialogReason = 0;
        return 0;

    case swrUI_MSG_TIMER:
        if ((int)param != SWR_UI_TIMER_MP_JOIN_REFRESH)
            return 0;
        list = swrUI_GetById(self, SWR_UI_ID_MP_GAME_LIST);
        memset(password, 0, 0x100 * sizeof(wchar_t));
        text = swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PASSWORD)->str_allocated;
        if (text != NULL)
            swrUI_EntryTextToWchar(password, text);
        stdComm_EnumSessions(1, password);

        changed = 0;
        numSessions = stdComm_GetNumSessionSettings();
        if (numSessions == (unsigned int)swrUI_CountSelectableItems(list)) {
            for (i = 0; i < numSessions; i++) {
                if (stdComm_GetSessionSettingsByIndex(i, &settings) == 0) {
                    stdString_WcharToChar(sessionName, settings.aSessionName, SWR_MP_SESSION_NAME_LEN);
                    if (swrUI_FindChildByText(list, sessionName) != NULL)
                        continue;
                }
                changed = 1;
            }
        } else {
            changed = 1;
        }
        if (changed) {
            swrUI_RefreshListSelection(list);
            for (i = 0; i < numSessions; i++) {
                if (stdComm_GetSessionSettingsByIndex(i, &settings) == 0) {
                    stdString_WcharToChar(sessionName, settings.aSessionName, SWR_MP_SESSION_NAME_LEN);
                    swrUI_AddListItem(list, sessionName, 0, i, 0);
                }
            }
            swrUI_RestoreListSelection(list);
        }
        if (numSessions == 0)
            break;
        swrMultiplayer_sessionsFound = 1;
        if (swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PLAYER_NAME)->str_allocated == NULL)
            break;
        swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_OK_BUTTON));
        return 0;

    case swrUI_MSG_TEXT_ENTRY_CHANGED:
        if (swrMultiplayer_sessionsFound == 0)
            break;
        if (swrMultiplayer_ValidateGameFields(self, SWR_UI_ID_MP_JOIN_PLAYER_NAME, 0, 0) == 0)
            break;
        swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_OK_BUTTON));
        return 0;

    case swrUI_MSG_ELEMENT_ACTIVATED:
        if ((int)param == SWR_UI_ID_CANCEL_BUTTON) {
            swrMultiplayer_Shutdown();
            swrUI_PopMenuPage();
            return 0;
        }
        if ((int)param != SWR_UI_ID_OK_BUTTON)
            return 0;
        multiplayer_track_change_permission = 0;
        swrUI_EntryTextToWchar(playerName, swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PLAYER_NAME)->str_allocated);
        memset(password, 0, 0x100 * sizeof(wchar_t));
        text = swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PASSWORD)->str_allocated;
        if (text != NULL)
            swrUI_EntryTextToWchar(password, text);
        sel = swrUI_GetSelectedIndex(swrUI_GetById(self, SWR_UI_ID_MP_GAME_LIST));
        swrMultiplayer_joinedSessionIndex = sel;
        swrMultiplayer_ClearStateBuffer();
        swrMultiplayer_maxPlayers = SWR_MAX_RACERS;
        hr = sithMulti_JoinSessionAndCreatePlayer(sel, playerName, password);
        if (hr == DP_OK) {
            swrMultiplayer_ResetSession();
            swrMultiplayer_ClearHostState();
            swrMultiplayer_InitMessaging();
            swrMultiplayer_SendPlayerJoin(sithMulti_g_serverId);
            swrMultiplayer_SaveLastPlayerName(swrUI_GetById(self, SWR_UI_ID_MP_JOIN_PLAYER_NAME));
            swrUI_RefreshListSelection(swrUI_GetById(NULL, SWR_UI_ID_MP_CHAT_LIST));
            swrUI_PushMenuPage(swrUI_WINDOW_MP_RACE_SETUP);
        } else if (hr == DPERR_NONEWPLAYERS) {
            swrUI_ShowConfirmDialog(self, -1, -1, swrText_Translate("/MONDOTEXT_H_0407/Error"), swrText_Translate("/MONDOTEXT_H_0408/Your join request has been denied."), swrText_Translate("/MONDOTEXT_H_0406/OK"), NULL, NULL, 1);
            swrMultiplayer_joinDialogReason = DPERR_NONEWPLAYERS;
        } else if (hr == DPERR_INVALIDPASSWORD) {
            swrUI_ShowConfirmDialog(self, -1, -1, swrText_Translate("/MONDOTEXT_H_0407/Error"), swrText_Translate("/MONDOTEXT_H_0409/Your password is invalid."), swrText_Translate("/MONDOTEXT_H_0406/OK"), NULL, NULL, 1);
            swrMultiplayer_joinDialogReason = DPERR_INVALIDPASSWORD;
        } else {
            swrUI_ShowConfirmDialog(self, -1, -1, swrText_Translate("/MONDOTEXT_H_0407/Error"), swrText_Translate("/MONDOTEXT_H_0410/An unknown network error has occurred."), swrText_Translate("/MONDOTEXT_H_0406/OK"), NULL, NULL, 1);
            swrMultiplayer_joinDialogReason = SWR_MP_JOIN_DIALOG_ERROR;
        }
        return 0;

    default:
        return 0;
    }

    swrUI_DisableElement(swrUI_GetById(self, SWR_UI_ID_OK_BUTTON));
    return 0;
}

// Show the selected track's name in the race setup track label.
static void swrUI_MpSetupShowTrack(swrUI_unk* self, char* buffer)
{
    swrUI_unk* label = swrUI_GetById(self, SWR_UI_ID_MP_TRACK_NAME);

    if (label == NULL)
        return;
    swrUI_Front_LoadTrackFromId(swrRace_GetSelectedTrack(), buffer, 0x100);
    swrUI_RunCallbacksScreenText(label, buffer, 0);
}

// Ask before leaving the session; returns the dialog's result.
static int swrUI_MpSetupConfirmLeave(swrUI_unk* self)
{
    return swrUI_ShowConfirmDialog(self, -1, -1, swrText_Translate("/MONDOTEXT_H_0535/Are you sure?"), swrText_Translate("/MONDOTEXT_H_0536/That you want to leave this game"), swrText_Translate("/MONDOTEXT_H_0537/Yes"), swrText_Translate("/MONDOTEXT_H_0538/Cancel"), NULL, 1);
}

// Enable the host-only controls and mark ourselves ready.
static void swrUI_MpSetupEnableHostControls(swrUI_unk* self)
{
    swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_MP_TRACKS));
    swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_MP_LAPS));
    swrUI_EnableElement(swrUI_GetById(self, SWR_UI_ID_MP_HOST_ONLY_8C));
}

// 0x0041fc70
int swrUI_Menu_MpRaceSetup(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    // the EXE uses one 0x114-byte frame buffer; names/chat use all of it, the track label its last 0x100 bytes
    char buffer[0x114];
    swrUI_unk* element;
    wchar_t* name;
    int dirty;
    int value;
    int i;

    swrText_Translate("/MONDOTEXT_H_0422/(Error getting player name)"); // result unused

    switch (msg) {
    case swrUI_MSG_KEY_DOWN:
        swrUI_Menu_MpForwardKeyToChat(self, (int)param);
        return 0;

    case swrUI_MSG_SET_ACTIVE:
        if (param == NULL) {
            swrUI_RemoveTimer(SWR_UI_TIMER_MP_SETUP_REFRESH);
            swrMultiplayer_SendMenuEvent(0);
            multiplayer_race_button_toggle[playerNumber] = 0;
            return 0;
        }
        swrMultiplayer_playerListDirty = 1;
        swrUI_RunCallbacks2(swrUI_GetById(NULL, swrUI_WINDOW_MP_JOIN_GAME), 0);
        swrControl_menuAcceptGuard = 0;
        swrUI_RefreshListSelection(swrUI_GetById(self, SWR_UI_ID_MP_PLAYER_LIST));
        swrObjHang_SetHangar2Splash();
        element = swrUI_GetById(self, SWR_UI_ID_MP_SETUP_TAB);
        sprintf(buffer, "~s%s", swrMultiplayer_GetSessionName());
        // 0x40000 kept literal: the bit is unconfirmed on 3-patch boxes
        swrUI_RunCallbacksScreenText(element, buffer, 0x40000);
        swrMultiplayer_SetRacerListDisplay(0, 0, 0);
        swrUI_RunCallbacksScreenText(swrUI_GetById(self, SWR_UI_ID_MP_CHAT_ENTRY), NULL, 0);
        if (multiplayer_track_change_permission != 0)
            stdComm_SetSessionOpenState(NULL, SWR_MAX_RACERS, 1);
        swrUI_MpSetupShowTrack(self, buffer + 0x14);
        if (multiplayer_track_change_permission == 0) {
            swrUI_DisableElement(swrUI_GetById(self, SWR_UI_ID_MP_TRACKS));
            swrUI_DisableElement(swrUI_GetById(self, SWR_UI_ID_MP_LAPS));
            for (i = 0; i < SWR_MAX_RACERS; i++)
                multiplayer_race_button_toggle[i] = 0;
            swrMultiplayer_SendRacerSelection();
        } else {
            swrUI_MpSetupEnableHostControls(self);
            swrMultiplayer_BroadcastRaceSettings();
        }
        swrUI_RunCallbacks2(swrUI_GetById(self, swrUI_WINDOW_MP_RACE_BUTTON), multiplayer_track_change_permission);
        swrUI_AddTimer(self, SWR_UI_TIMER_MP_SETUP_INTERVAL_MS, SWR_UI_TIMER_MP_SETUP_REFRESH);
        swrMultiplayer_SendMenuEvent(1);
        multiplayer_race_button_toggle[playerNumber] = 1;
        return 0;

    case swrUI_MSG_BACK:
        if (swrUI_MpSetupConfirmLeave(self) == SWR_UI_DIALOG_RESULT_NO)
            return 1;
        sithMessage_CloseGame();
        return 0;

    case swrUI_MSG_TIMER:
        if ((int)param != SWR_UI_TIMER_MP_SETUP_REFRESH)
            return 0;
        if (multiplayer_rejoinPending != 0 && multiplayer_isHost == 0)
            swrMultiplayer_JoinGame(self);
        element = swrUI_GetById(self, SWR_UI_ID_MP_PLAYER_LIST);
        stdComm_UpdatePlayers(swrMultiplayer_joinedSessionIndex);
        dirty = swrMultiplayer_playerListDirty;
        if (stdComm_GetNumPlayers() == swrUI_CountSelectableItems(element)) {
            for (i = 0; i < SWR_MAX_RACERS; i++) {
                if (swrMultiplayer_IsPlayerActive(i) == 0)
                    continue;
                name = swrMultiplayer_GetPlayerName(i);
                if (name != NULL) {
                    stdString_WcharToChar(buffer, name, SWR_MP_LIST_NAME_LEN);
                    if (swrUI_FindChildByText(element, buffer) != NULL)
                        continue;
                }
                dirty = 1;
            }
        } else {
            dirty = 1;
        }
        if (dirty != 0) {
            swrMultiplayer_playerListDirty = 0;
            swrUI_RefreshListSelection(element);
            for (i = 0; i < SWR_MAX_RACERS; i++) {
                if (swrMultiplayer_IsPlayerActive(i) == 0)
                    continue;
                name = swrMultiplayer_GetPlayerName(i);
                if (name == NULL)
                    continue;
                stdString_WcharToChar(buffer, name, SWR_MP_LIST_NAME_LEN);
                swrUI_AddListItem(element, buffer, 0, i, 0);
            }
            swrUI_RestoreListSelection(element);
        }
        if (multiplayer_track_change_permission != 0) {
            multiplayer_numAiRacers = 0;
            swrMultiplayer_BroadcastRaceSettings();
        }
        element = swrUI_GetById(self, SWR_UI_ID_MP_PLAYER_LIST);
        if (element != NULL)
            swrMultiplayer_UpdateRacerSelectUI(self, element);
        swrMultiplayer_BroadcastMenuReset();
        swrMultiplayer_UpdateStartButtonState(self);
        return 0;

    case swrUI_MSG_MP_UPDATE:
        switch ((int)param) {
        case swrMultiplayer_MSG_PLAYER_QUIT:
            swrMultiplayer_bootedFromGame = 1;
            swrUI_PopMenuPage();
            return 0;
        case swrMultiplayer_UIEVENT_PLAYER_LEFT:
        case swrMultiplayer_UIEVENT_PLAYER_JOINED:
            swrMultiplayer_playerListDirty = 1;
            return 0;
        case swrMultiplayer_UIEVENT_BECAME_HOST:
            swrUI_MpSetupEnableHostControls(self);
            swrUI_RunCallbacks2(swrUI_GetById(self, swrUI_WINDOW_MP_RACE_BUTTON), multiplayer_track_change_permission);
            swrMultiplayer_SendMenuEvent(1);
            multiplayer_race_button_toggle[playerNumber] = 1;
            return 0;
        case swrMultiplayer_MSG_MENU_EVENT:
            swrMultiplayer_SetRaceButtonToggle(self, (int*)ui2);
            return 0;
        case swrMultiplayer_MSG_RACER_PICK:
            element = swrUI_GetById(self, SWR_UI_ID_MP_RACER_NAME);
            if (element == NULL)
                return 0;
            swrText_FormatPodName(swrMultiplayer_GetRacerId(playerNumber), buffer + 0x14, 0x100);
            swrUI_RunCallbacksScreenText(element, buffer + 0x14, 0);
            return 0;
        case swrMultiplayer_MSG_LOBBY_STATE:
            swrUI_MpSetupShowTrack(self, buffer + 0x14);
            element = swrUI_GetById(self, SWR_UI_ID_MP_LAPS);
            if (element != NULL)
                swrUI_SetNumberValue(element, multiplayer_laps);
            element = swrUI_GetById(self, SWR_UI_ID_MP_PLAYER_LIST);
            if (element != NULL)
                swrMultiplayer_UpdateRacerSelectUI(self, element);
            return 0;
        }
        return 0;

    case swrUI_MSG_ELEMENT_ACTIVATED:
        switch ((int)param) {
        case SWR_UI_ID_MP_RETIRE:
            if (swrUI_MpSetupConfirmLeave(self) == SWR_UI_DIALOG_RESULT_NO)
                return 0;
            swrMultiplayer_Shutdown();
            stdComm_Shutdown();
            swrMultiplayer_menuOverlayActive = 0;
            swrObjHang_SetHangar2State(swrObjHang_STATE_SPLASH);
            swrUI_RunCallbacks2(self, 0);
            swrUI_ResetPageStack();
            swrUI_PushMenuPage(swrUI_WINDOW_SPLASH);
            return 0;
        case swrUI_WINDOW_MP_RACE_BUTTON:
            swrControl_menuAcceptGuard = 1;
            swrUI_RemoveTimer(SWR_UI_TIMER_MP_SETUP_REFRESH);
            if (multiplayer_track_change_permission != 0)
                stdComm_SetSessionOpenState(NULL, SWR_MAX_RACERS, 0);
            swrUI_RefreshListSelection(swrUI_GetById(NULL, SWR_UI_ID_MP_CHAT_LIST));
            swrMultiplayer_BroadcastRaceReset();
            swrObjHang_ReturnToMultiplayerLobby();
            return 0;
        case SWR_UI_ID_MP_TRACKS:
            swrControl_menuAcceptGuard = 1;
            swrMultiplayer_SetRacerListDisplay(1, 10, 0x78);
            swrUI_PushMenuPage(swrUI_WINDOW_HANGAR_SELECT_PLANET);
            return 0;
        case SWR_UI_ID_MP_PODRACER:
            swrControl_menuAcceptGuard = 1;
            swrMultiplayer_SetRacerListDisplay(1, 10, 0x78);
            swrUI_PushMenuPage(swrUI_WINDOW_HANGAR_SELECT_VEHICLE);
            return 0;
        case SWR_UI_ID_MP_BOOT:
            value = swrUI_GetSelectedIndex(swrUI_GetById(NULL, SWR_UI_ID_MP_PLAYER_LIST));
            if (value == -1 || value == playerNumber)
                return 0;
            swrMultiplayer_DropPlayer(value);
            return 0;
        }
        return 0;

    case swrUI_MSG_SLIDER_DECREASED:
    case swrUI_MSG_SLIDER_INCREASED:
        value = swrUI_GetNumberValue(ui2);
        if ((int)param == SWR_UI_ID_MP_LAPS) {
            if (msg == swrUI_MSG_SLIDER_DECREASED) {
                if (value > SWR_MP_LAPS_MIN)
                    value--;
            } else if (value < SWR_MP_LAPS_MAX) {
                value++;
            }
            swrUI_SetNumberValue(ui2, value);
            multiplayer_laps = value;
        }
        swrMultiplayer_BroadcastRaceSettings();
        return 0;

    case swrUI_MSG_TEXT_ENTRY_COMMITTED:
        if ((int)param != SWR_UI_ID_MP_CHAT_ENTRY || ui2 == NULL)
            return 0;
        sprintf(buffer, swrText_Translate("/MONDOTEXT_H_0393/%s says '%s'"), swrMultiplayer_GetPlayerNameAscii(playerNumber), (char*)ui2);
        swrMultiplayer_PostChatMessage(buffer);
        return 0;

    case swrUI_MSG_LIST_SELECTION_CHANGED:
        if (((swrUI_unk*)param)->id != SWR_UI_ID_MP_PLAYER_LIST)
            return 0;
        swrMultiplayer_UpdateRacerSelectUI(self, (swrUI_unk*)param);
        return 0;
    }
    return 0;
}

// 0x004206b0
int swrUI_Menu_MpRacerList(swrUI_unk* self, unsigned int msg, void* param_3, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_SET_ACTIVE) {
        if (param_3 != NULL) {
            swrUI_RefreshListSelection(swrUI_GetById(NULL, SWR_UI_ID_MP_CHAT_LIST));
            swrMultiplayer_SetRacerListDisplay(1, 10, 0x78);
            swrMultiplayer_racerListPageActive = 1;
            swrMultiplayer_PopulateRacerList();
        } else {
            swrMultiplayer_SetRacerListDisplay(0, 0, 0);
            swrMultiplayer_racerListPageActive = 0;
        }
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED && (int)param_3 == SWR_UI_ID_BACK_BUTTON) {
        swrUI_PopMenuPage();
    }
    return 0;
}

// 0x00420930
void swrUI_Front_LoadTrackFromId(swrRace_TRACK trackId, char* buffer, size_t len)
{
    char* str;
    str = swrUI_Front_GetTrackNameFromId(trackId);
    snprintf(buffer, len, "%s", str);
}

// 0x00410fd0
int swrUI_Initialize(void)
{
    volatile float score;
    volatile int rounded;
    uint32_t start;
    uint32_t tick;

    swrUI_elementHashtable_Maybe = stdHashTable_New(SWR_UI_ELEMENT_HASH_BUCKETS);
    if (swrUI_elementHashtable_Maybe == NULL)
        return 0;

    memset(swrUI_rootElementStorage, 0, sizeof(swrUI_rootElementStorage));
    memset(swrSpriteTexItems, 0, sizeof(swrSpriteTexItems));
    swrUI_unk_ptr = (swrUI_unk*)swrUI_rootElementStorage;
    memset(swrUI_timers, 0, sizeof(swrUI_timers));
    swrUI_ResetPageStack();
    swrUI_initJoyAxisX = swrControl_joystickAxes[0];
    swrUI_initJoyAxisY = swrControl_joystickAxes[1];
    swrUI_QuantizeNavAxis(swrControl_joystickAxes[0], swrControl_joystickAxes[1], &swrUI_navAxisXPrev, &swrUI_navAxisYPrev);
    for (int id = SWR_SPRITE_DYNAMIC_FIRST; id < SWR_SPRITE_DYNAMIC_END; id++)
        swrSprite_array[id].texture = NULL;
    swrUI_unk_ptr->fun = (swrUI_unk_F1)swrUI_DefaultElementProc;
    swrUI_RunCallbacks2(swrUI_unk_ptr, 1);

    score = 0.0f;
    start = stdPlatform_hostServices_ptr->getTimerTick();
    do {
        tick = stdPlatform_hostServices_ptr->getTimerTick();
    } while (tick == start);
    start = stdPlatform_hostServices_ptr->getTimerTick();
    do {
        for (int i = 0; i < SWR_UI_BENCH_INNER_LOOPS; i++) {
            rounded = (int)score; // the original FRNDINT/FISTPs into a dead local each pass
            score = score - -1.0f;
        }
    } while (stdPlatform_hostServices_ptr->getTimerTick() - start <= SWR_UI_BENCH_TICKS);
    if (score * SWR_UI_BENCH_SCALE < SWR_UI_BENCH_MIN_SCORE)
        swrUI_pageTransitionsEnabled = 0;
    return 1;
}

// 0x00420960
void swrUI_Menu_MpForwardKeyToChat(swrUI_unk* page, int key)
{
    swrUI_unk* chat = swrUI_GetById(page, SWR_UI_ID_MP_CHAT_ENTRY);
    swrUI_RunCallbacks(chat, swrUI_MSG_KEY_DOWN, key, 0);
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
void swrUI_Front_SyncTrackSelection(swrObjHang* hang)
{
    // the selection index counts only playable tracks before the current one
    swrRace_MenuSelectedItem = 0;
    for (int track = 0; track < g_aTracksInCircuits[(int)hang->circuitIdx]; track++) {
        if (g_aTrackIDs[hang->circuitIdx * SWR_TRACKS_PER_CIRCUIT + track] == hang->track_index)
            return;
        if (swrObjHang_IsTrackPlayable(hang, hang->circuitIdx, (char)track))
            swrRace_MenuSelectedItem++;
    }
}

// 0x00440550
void swrSound_PlayUISound(int soundId)
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
    swrSound_Play2D(soundId, 6, pitch, gain, loop);
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
    if (swrUtils_Compare3Chars(swrRace_aProfiles[0].name, swrObjHang_creditsCheatInitials) != 0 && (swrUI_localPlayersInputDownBitset[0] & 0x4) != 0) {
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
void swrUI_Front_SetOkBackActive(int arg2, int arg4)
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

    tex = swrSprite_LoadTextureById(swrSprite_whitesquare_rgb);
    spriteId = swrUISprite_newflare1_rgb_49;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0x90);
    tex = swrSprite_LoadTextureById(swrSprite_whitesquare_rgb);
    spriteId = swrUISprite_lightstar_glowstreak_rgb_3;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        swrSprite_SetFlag((short)spriteId, 0x2000);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0xa2);
    tex = swrSprite_LoadTextureById(swrSprite_window1_yellow_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_6, tex);
    tex = swrSprite_LoadTextureById(swrSprite_rectangle_blue_rgb);
    spriteId = swrUISprite_newflare1_rgb_7;
    do
    {
        swrSprite_NewSprite(spriteId, tex);
        spriteId = spriteId + swrUISprite_dial_lap_pos_rgb_1;
    } while ((short)spriteId < 0x5f);
    tex = swrSprite_LoadTextureById(swrSprite_btm_light_blue_rgb);
    swrSprite_NewSprite(swrUISprite_btm_light_blue_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_bluehalf_rgb);
    swrSprite_NewSprite(swrUISprite_bluehalf_rgb_0, tex);
    tex = swrSprite_LoadTextureById(swrSprite_window1_select_blue_rgb);
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
    swrSpriteTexture* tex;
    int id;

    tex = swrSprite_LoadTextureById(swrSprite_whitesquare_rgb);
    for (id = 0x90; id < 0xa2; id++) {
        swrSprite_NewSprite((short)id, tex);
        swrSprite_SetFlag((short)id, 0x2000);
    }
    tex = swrSprite_LoadTextureById(swrSprite_sml_wdw_blue_rgb);
    for (id = 0x62; id < 0x69; id++)
        swrSprite_NewSprite((short)id, tex);
    tex = swrSprite_LoadTextureById(swrSprite_sml_window_ylw_rgb);
    for (id = 0x6a; id < 0x71; id++)
        swrSprite_NewSprite((short)id, tex);
    tex = swrSprite_LoadTextureById(swrSprite_lrg_wdw_blue_rgb);
    swrSprite_NewSprite(0x69, tex);
    tex = swrSprite_LoadTextureById(swrSprite_lrg_window_ylw_rgb);
    swrSprite_NewSprite(0x71, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_sml_rgb);
    swrSprite_NewSprite(0x72, tex);
    tex = swrSprite_LoadTextureById(swrSprite_lrg_wdw_select_blue_rgb);
    swrSprite_NewSprite(0x73, tex);
    for (id = 0x62; id < 0x74; id++) {
        swrSprite_SetFlag((short)id, 0x2000);
        swrSprite_SetFlag((short)id, swrSprite_FLAG_UNK_8000);
    }
}

// 0x004580e0
void swrUI_Front_LoadPartsUIElements(void)
{
    swrSpriteTexture* tex;
    int id;

    tex = swrSprite_LoadTextureById(swrSprite_ui_buy_dnt_buy_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_35, tex);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_36, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_costvalue_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_37, tex);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_38, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_nw_part_name_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_39, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_nw_part_price_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_40, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_nw_part_window_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_41, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_nw_part_ylw_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_42, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_old_part_name_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_43, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_old_part_replace_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_44, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_old_part_window_blue_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_45, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_old_part_ylw_rgb);
    swrSprite_NewSprite(swrUISprite_newflare1_rgb_46, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ui_vert_light_blue_rgb);
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

    tex = swrSprite_LoadTextureById(swrSprite_ctrl_A_rgb);
    swrSprite_NewSprite(swrUISprite_symbol_2_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_B_rgb);
    swrSprite_NewSprite(swrUISprite_symbol_3_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_C_up_rgb);
    swrSprite_NewSprite(swrUISprite_award_third, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_C_down_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_down_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_C_left_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_left_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_C_right_rgb);
    swrSprite_NewSprite(swrUISprite_ctrl_C_right_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_Z_rgb);
    swrSprite_NewSprite(swrUISprite_award_second_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_ctrl_stick_rgb);
    swrSprite_NewSprite(swrUISprite_award_first_rgb, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_arrow_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_arrow_lit_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_circle_rgb);
    swrSprite_NewSprite(swrUISprite_select_circle_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_circle_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_bars_rgb);
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
    tex = swrSprite_LoadTextureById(swrSprite_select_arrow_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_v_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_arrow_lit_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_arrow_lit_v_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_circle_v_rgb);
    swrSprite_NewSprite(swrUISprite_select_circle_v_rgb_0, tex);
    swrSprite_NewSprite(swrUISprite_select_circle_v_rgb_1, tex);
    tex = swrSprite_LoadTextureById(swrSprite_select_bars_v_rgb);
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

// 0x00417690
void swrUI_SetHighlightState(int mode, swrUI_unk* ui, int highlighted, int fireCallback, int refreshColor)
{
    if (highlighted == 0)
        ui->flags &= ~swrUI_HIGHLIGHTED;
    else
        ui->flags |= swrUI_HIGHLIGHTED;
    if (refreshColor != 0)
        swrUI_UpdateElementColor(ui);
    if (fireCallback != 0)
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_ELEMENT_ACTIVATED + (mode != 1), ui->id, (int)ui);
}

// 0x00417940
int swrUI_FramedTextProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    swrUI_unk* check;
    int rect[4];
    int focused;
    int spriteW;
    int textH;

    if (msg == swrUI_MSG_MOUSE_UP) {
        if (swrSprite_IsInsideBBox((swrSprite_BBox*)&ui->x, (int)param, param2) && (ui->has_option_value == 0 || swrUI_FindCheckedGroupItem(ui) != ui)) {
            swrUI_ToggleChecked(ui);
            swrUI_SetHighlightState(1, ui, 0, 1, 1);
            swrSound_PlayUISound(0x54);
        }
    } else if (msg == swrUI_MSG_UPDATE) {
        if (ui->flags & swrUI_CHECK_CIRCLE_UNK) {
            check = ui->next;
            rect[0] = check->x;
            rect[1] = check->y;
            rect[2] = check->width;
            rect[3] = check->height;
            focused = swrUI_IsElementFocused(ui);
            swrUI_DrawTextAligned(ui->font_index, ui->str_allocated, (short*)rect, ui->text_flags | swrUI_TEXT_ALIGN_CENTER, ui->r, ui->g, ui->b, ui->a, focused, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
            return swrUI_DefaultElementProc(ui, swrUI_MSG_UPDATE, param, param2);
        }
        if ((ui->flags & swrUI_VERTICAL) == 0) {
            swrSprite_GetTextureDimFromId((swrSprite_NAME)ui->ui_elements[1].texture_id, &spriteW, NULL);
            textH = swrText_GetStringHeight(ui->str_allocated, swrText_fontsByIndex[ui->font_index]);
            swrUI_DrawText(ui->font_index, ui->x + spriteW + 2, ((ui->height - textH - ui->y + 1) >> 1) + ui->y, ui->r, ui->g, ui->b, ui->a, ui->str_allocated, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
            return swrUI_DefaultElementProc(ui, swrUI_MSG_UPDATE, param, param2);
        }
        swrSprite_GetTextureDimFromId((swrSprite_NAME)ui->next->ui_elements[0].texture_id, &spriteW, NULL);
        textH = swrText_GetStringHeight(ui->str_allocated, swrText_fontsByIndex[ui->font_index]);
        swrUI_DrawText(ui->font_index, ui->x + spriteW + 5, ((ui->height - textH - ui->y + 1) >> 1) + ui->y, ui->r, ui->g, ui->b, ui->a, ui->str_allocated, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        return swrUI_DefaultElementProc(ui, swrUI_MSG_UPDATE, param, param2);
    } else if (msg == swrUI_MSG_FOCUS_CHANGED) {
        swrUI_ApplyFocusColor(ui);
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00417be0
int swrUI_3PatchBoxProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    int capW;
    int capH;
    int textH;

    if (msg == swrUI_MSG_UPDATE) {
        // label sits on the left cap, 8px above its bottom edge
        swrSprite_GetTextureDimFromId((swrSprite_NAME)ui->ui_elements[0].texture_id, &capW, &capH);
        textH = swrText_GetStringHeight(ui->str_allocated, swrText_fontsByIndex[ui->font_index]);
        swrUI_DrawText(ui->font_index, ui->x + capW, ui->y + capH - textH - 8, ui->r, ui->g, ui->b, ui->a, ui->str_allocated, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x00417ca0
void swrUI_RefreshListLayout(swrUI_unk* list)
{
    swrUI_unk* item;
    swrUI_unk* next;
    swrUI_unk* scrollbar;
    unsigned int index = 0;
    int overflow = 0;
    int skip;
    int y;
    int rowHeight;
    int highlight[4];
    int needScrollbar = 0;

    for (item = list->next; item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM) {
            swrUI_RunCallbacks2(item, 0);
            item->sort_key = index;
            index++;
            if (index > SWR_UI_LIST_MAX_ITEMS)
                overflow++;
        }
    }
    // drop the oldest children so at most SWR_UI_LIST_MAX_ITEMS remain
    item = list->next;
    while (overflow-- != 0) {
        next = item->next2;
        swrUI_FreeElement(item);
        item = next;
    }

    skip = list->first_visible;
    item = list->next;
    if (skip != 0)
        needScrollbar = 1;
    if (item == NULL)
        return;
    for (; skip != 0 && item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM)
            skip--;
    }
    if (item == NULL)
        return;

    y = list->content_top;
    for (; y < list->height + 0x14 && item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) != swrUI_CLASS_LIST_ITEM)
            continue;
        rowHeight = item->height - item->y + 1;
        if (rowHeight + y >= list->content_bottom)
            needScrollbar = 1;
        if (y < list->content_bottom) {
            if ((item->item_flags & swrUI_ITEM_NO_AUTO_POS) == 0) {
                if (item->item_flags & swrUI_ITEM_CENTERED)
                    swrUI_SetPos(item, ((item->x - item->width + list->content_right - list->content_left) >> 1) + list->content_left, y);
                else
                    swrUI_SetPos(item, list->content_left, y);
            }
            if ((item->item_flags & swrUI_ITEM_SELECTED) && (list->item_flags & swrUI_LIST_NO_SELECTION_FRAME) == 0) {
                highlight[0] = list->content_left - 10;
                highlight[1] = item->y - 10;
                highlight[2] = list->content_right + 10;
                highlight[3] = item->height - 10;
                swrUI_BuildEditSelectionSprites((int)list, item, highlight);
            }
            swrUI_RunCallbacks2(item, 1);
        }
        y += list->row_spacing + rowHeight;
    }

    if (needScrollbar && (list->item_flags & swrUI_LIST_NO_SCROLLBAR) == 0) {
        scrollbar = swrUI_FindByClass(list, swrUI_CLASS_NUMBER_FIELD);
        if (scrollbar == NULL) {
            int top = list->content_top - 0xf;
            swrUI_NewNumberField(list, 0, list->content_right - 0x20, top, list->content_bottom - top + 0x10, swrUI_VERTICAL, 0);
        }
        // faithful: a freshly created scrollbar is not the one shown here (scrollbar is still NULL)
        swrUI_RunCallbacks2(scrollbar, 1);
    }

    for (item = list->next; item != NULL; item = item->next2) {
        if (((uint8_t)item->widget_class & swrUI_CLASS_LIST_ITEM) == swrUI_CLASS_LIST_ITEM)
            swrUI_SetBBox(item, list->content_left, list->content_top - 2, list->content_right, list->content_bottom + 2);
    }
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
        swrUI_AddListItem(ui, lineStart, flag != 0 ? swrUI_ITEM_CENTERED : 0, 0, 0);
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

// 0x00418120
void swrUI_HandleTextEntryKey(swrUI_unk* ui, int key)
{
    char buffer[SWR_UI_TEXT_ENTRY_MAX_LENGTH];
    unsigned int limit;
    int textWidth;
    int caretHeight;

    if (ui == NULL)
        return;
    memset(buffer, 0, sizeof(buffer));
    if (ui->str_allocated != NULL) {
        strncpy(buffer, ui->str_allocated, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\0';
    }

    switch (key) {
    case VK_BACK:
        if (ui->caret_pos == 0)
            break;
        // overlapping copy (memmove semantics)
        memmove(buffer + ui->caret_pos - 1, buffer + ui->caret_pos, sizeof(buffer) - ui->caret_pos);
        buffer[sizeof(buffer) - 1] = '\0';
        ui->caret_pos--;
        swrUI_RunCallbacksScreenText(ui, buffer, 0);
        break;
    case VK_RETURN:
        swrSound_PlayUISound(0x46);
        swrUI_inputSuppressFlags |= swrUI_INPUT_SUPPRESS_MOUSE_FRAME;
        swrUI_RunCallbacks(ui, swrUI_MSG_SET_EDITING, 0, ui->id);
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_TEXT_ENTRY_COMMITTED, ui->id, (int)ui->str_allocated);
        if (ui->entry_style & swrUI_TEXT_ENTRY_CLEAR_ON_COMMIT) {
            ui->str_allocated = swrUI_replaceAllocatedStr(ui->str_allocated, NULL);
            break;
        }
        if (ui->str_allocated != NULL && (ui->entry_style & swrUI_TEXT_ENTRY_CARET_TO_END))
            ui->caret_pos = strlen(ui->str_allocated);
        break;
    case VK_ESCAPE:
        swrSound_PlayUISound(0x47);
        swrUI_RunCallbacksScreenText(ui, swrUI_textEntryOriginalText, ui->text_flags);
        swrUI_inputSuppressFlags |= swrUI_INPUT_SUPPRESS_MOUSE_FRAME;
        swrUI_RunCallbacks(ui->prev, swrUI_MSG_TEXT_ENTRY_CANCELLED, ui->id, (int)ui->str_allocated);
        break;
    case VK_END:
        if (ui->str_allocated != NULL)
            ui->caret_pos = strlen(ui->str_allocated);
        break;
    case VK_HOME:
        ui->caret_pos = 0;
        break;
    case VK_LEFT:
        if (ui->caret_pos != 0)
            ui->caret_pos--;
        break;
    case VK_RIGHT:
        if (ui->str_allocated != NULL && (unsigned int)ui->caret_pos < strlen(ui->str_allocated))
            ui->caret_pos++;
        break;
    case VK_DELETE:
        // Delete clears the whole field, unless it is already empty with the caret at the start
        if (ui->caret_pos == 0 && (ui->str_allocated == NULL || ui->str_allocated[0] == '\0'))
            break;
        ui->caret_pos = 0;
        swrUI_RunCallbacksScreenText(ui, NULL, 0);
        break;
    default:
        // the original tests the CRT ctype table with _ALPHA | _DIGIT (0x107)
        if (!isalnum(key) && key != ' ')
            break;
        limit = (unsigned int)ui->max_length;
        if (limit > SWR_UI_TEXT_ENTRY_MAX_LENGTH - 1)
            limit = SWR_UI_TEXT_ENTRY_MAX_LENGTH;
        if ((unsigned int)ui->caret_pos >= limit || (key == ' ' && ui->caret_pos == 0))
            break;
        memmove(buffer + ui->caret_pos + 1, buffer + ui->caret_pos, sizeof(buffer) - 1 - ui->caret_pos);
        buffer[ui->caret_pos] = (char)key;
        ui->caret_pos++;
        swrUI_RunCallbacksScreenText(ui, buffer, 0);
        break;
    }

    textWidth = swrUI_GetSubstringWidth(ui->str_allocated, ui->font_index, 0, ui->caret_pos);
    caretHeight = swrText_GetStringHeight("l", swrText_fontsByIndex[ui->font_index]) * 2;
    swrUI_SetCaretRect(swrText_GetStringWidth(" ", swrText_fontsByIndex[ui->font_index]) * 5 + textWidth + ui->x, ((ui->height - ui->y + 1) >> 1) - (caretHeight >> 1) + ui->y, 1, caretHeight);
}

// 0x00413a30
swrUI_unk* swrUI_AddListElement(swrUI_unk* list, swrUI_unk* element)
{
    if (list == NULL || element == NULL)
        return NULL;
    element->widget_class |= swrUI_CLASS_LIST_ITEM;
    swrUI_UnlinkElement(element);
    swrUI_Enqueue(list, element);
    if (swrUI_GetSelectedItem(list) == NULL)
        swrUI_SelectListItem(element, 1);
    swrUI_RefreshListLayout(list);
    return element;
}

// 0x00413a90
swrUI_unk* swrUI_NewNumberField(swrUI_unk* parent, int id, int x, int y, int param_5, int flag, int size_unk2)
{
    swrUI_unk* ui = swrUI_New(parent, id, -1, NULL, flag, size_unk2, 0, (swrUI_unk_F1)swrUI_NumberFieldProc, NULL);

    swrUI_SetPos(ui, x, y);
    ui->slider_length = param_5;
    ui->slider_step = 10;
    ui->slider_style = flag;
    ui->widget_class = swrUI_CLASS_NUMBER_FIELD;
    swrUI_BuildSliderSprites(ui, 0);
    swrUI_RunCallbacks2(ui, 1);
    return ui;
}

// 0x00416690
int swrUI_NumberFieldProc(swrUI_unk* ui, unsigned int msg, void* param, int param2)
{
    int rect[4];
    char text[256];

    switch (msg) {
    case swrUI_MSG_HOVER_CHANGED:
        if (param != NULL) {
            swrSound_PlayUISound(0x58);
            swrUI_BuildSliderSprites(ui, 1);
        } else {
            swrUI_BuildSliderSprites(ui, 0);
        }
        break;
    case swrUI_MSG_MOUSE_DOWN:
        swrUI_sliderClickX = (int)param;
        swrUI_sliderClickY = param2;
        swrUI_AddTimer(ui, 100, (int)ui);
        swrUI_HandleSliderClick(ui, swrUI_sliderClickX, swrUI_sliderClickY);
        break;
    case swrUI_MSG_MOUSE_UP:
        swrUI_RemoveTimer((int)ui);
        break;
    case swrUI_MSG_KEY_DOWN:
        swrUI_HandleSliderKey(ui, (unsigned int)param);
        break;
    case swrUI_MSG_UPDATE:
        if (ui->slider_style & swrUI_SLIDER_SHOW_NUMBER) {
            rect[0] = ui->x;
            rect[1] = ui->y;
            rect[2] = ui->width;
            rect[3] = ui->height;
            sprintf(text, "%d", ui->number_value);
            swrUI_DrawTextAligned(ui->font_index, text, (short*)rect, swrUI_TEXT_ALIGN_CENTER, ui->r, ui->g, ui->b, ui->a, 0, (int)&ui->bbox, ui->flags & swrUI_DISABLED);
        }
        break;
    }
    return swrUI_DefaultElementProc(ui, msg, param, param2);
}

// 0x004172a0
int swrUI_ElementContainsPoint(swrUI_unk* ui, int x, int y)
{
    // x/y/width/height are laid out as a swrSprite_BBox
    return swrSprite_IsInsideBBox((swrSprite_BBox*)&ui->x, x, y);
}

// 0x004173c0
void swrUI_DrawText(int font, int x, int y, int color0, int color1, int color2, int color3, char* text, int unk9, int unk10, int disabled)
{
    char buffer[1024];
    int prefixLength;

    if (text == NULL)
        return;
    if (disabled)
        color3 = (color3 & ~0xff) | SWR_UI_DISABLED_TEXT_ALPHA;
    // "~F<n>" selects the font for swrText
    prefixLength = sprintf(buffer, "~F%d", font);
    memcpy(buffer + prefixLength, text, strlen(text) + 1);
    if (font == SWR_UI_FONT_LOW_BASELINE)
        y += SWR_UI_FONT_LOW_BASELINE;
    swrText_CreateTextEntry1(x, y, color0, color1, color2, color3, buffer);
    swrText_SetEntryClipRect((int*)unk10);
    // write-only pulse, nothing reads it
    swrUI_textPulse = swrUI_textPulseStep + swrUI_textPulse;
    if (swrUI_textPulse > 255.0f)
        swrUI_textPulseStep = -1.0f;
    if (swrUI_textPulse < 40.0f)
        swrUI_textPulseStep = 0.5f;
}

// 0x00417540
void swrUI_DrawTextAligned(int font, char* text, short* bbox, unsigned int alignFlags, int color0, int color1, int color2, int color3, int unk9, int unk10, int unk11)
{
    // bbox is really an int[4] box; x/y are 16-bit here (swrText_CreateEntry takes shorts)
    int* box = (int*)bbox;
    int textWidth;
    int textHeight;
    short x;
    short y;

    if (text == NULL)
        return;
    textWidth = swrText_GetStringWidth(text, swrText_fontsByIndex[font]);
    textHeight = swrText_GetStringHeight(text, swrText_fontsByIndex[font]);
    x = (short)box[0];
    y = (short)box[1];
    if (alignFlags & swrUI_TEXT_ALIGN_CENTER) {
        x += (unsigned int)(box[2] - textWidth - box[0] + 1) >> 1;
        y += (unsigned int)(box[3] - textHeight - box[1] + 1) >> 1;
    } else if (alignFlags & swrUI_TEXT_ALIGN_CENTER_X) {
        x += (unsigned int)(box[2] - textWidth - box[0] + 1) >> 1;
    } else if (alignFlags & swrUI_TEXT_ALIGN_CENTER_Y) {
        y += (unsigned int)(box[3] - textHeight - box[1] + 1) >> 1;
    } else if (alignFlags & swrUI_TEXT_ALIGN_RIGHT) {
        x = (short)box[2] - (short)textWidth;
    }
    if (alignFlags & swrUI_TEXT_ALIGN_INDENT_5)
        x += swrText_GetStringWidth(" ", swrText_fontsByIndex[font]) * 5;
    else if (alignFlags & swrUI_TEXT_ALIGN_INDENT_1)
        x += swrText_GetStringWidth(" ", swrText_fontsByIndex[font]);
    swrUI_DrawText(font, x, y, color0, color1, color2, color3, text, unk9, unk10, unk11);
}

// 0x0041aa90
void swrUI_BuildEditSelectionSprites(int a1, swrUI_unk* ui, int* rect)
{
    int endWidth;
    int endHeight;
    int box[4];

    if (a1 == 0 || ui == NULL)
        return;
    swrSprite_GetTextureDimFromId(swrSprite_edit_window_selected_end, &endWidth, &endHeight);

    box[0] = rect[0];
    box[1] = rect[1];
    box[2] = endWidth + rect[0] - 1;
    box[3] = endHeight + rect[1] - 1;
    swrUI_AddSprite(ui, 0, swrSprite_edit_window_selected_end, box, 1, 0);

    box[0] = rect[0] + endWidth;
    box[1] = rect[1];
    box[2] = rect[2] - endWidth;
    box[3] = endHeight + rect[1] - 1;
    swrUI_AddSprite(ui, 1, swrSprite_edit_window_selected_strch, box, 1, 0);

    box[0] = rect[2] - endWidth + 1;
    box[1] = rect[1];
    box[2] = rect[2];
    box[3] = endHeight + rect[1] - 1;
    swrUI_AddSprite(ui, 2, swrSprite_edit_window_selected_end, box, 1, swrUI_SPRITE_SLOT_MIRROR_H);

    swrUI_SetSelected(ui, 1);
    ui->rand_alpha_first = 0;
    ui->rand_alpha_count = 3;
}

// 0x004172f0
void swrUI_UpdateElementColor(swrUI_unk* ui)
{
    if ((ui->flags & swrUI_HIGHLIGHTED) != 0) {
        swrUI_SetColorUnk(ui, ui->r4, ui->g4, ui->b4, ui->a4);
        swrUI_BuildHighlightSprites(ui, 0);
    } else if ((ui->flags & swrUI_FOCUSED) != 0) {
        swrUI_SetColorUnk(ui, ui->r5, ui->g5, ui->b5, ui->a5);
        swrUI_BuildHighlightSprites(ui, 1);
    } else if ((ui->flags & swrUI_HOVERED) != 0) {
        swrUI_SetColorUnk(ui, ui->r3, ui->g3, ui->b3, ui->a3);
        swrUI_BuildHighlightSprites(ui, 1);
    } else {
        swrUI_SetColorUnk(ui, ui->r2, ui->g2, ui->b2, ui->a2);
        swrUI_BuildHighlightSprites(ui, 0);
    }
}

// 0x00417f50
int swrUI_ConfirmDialogProc(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    unsigned int key;

    switch (msg) {
    case swrUI_MSG_BACK:
        swrUI_confirmDialogResult = SWR_UI_DIALOG_RESULT_CANCEL;
        swrUI_confirmDialogDone = 1;
        return 1;
    case swrUI_MSG_KEY_DOWN:
        swrUI_SetUI5(self);
        key = (unsigned int)param;
        if ((key == VK_TAB || (key >= VK_LEFT && key <= VK_DOWN)) && swrUI_textEntryActive == 0) {
            swrUI_NavigateFocus(self, key);
            return 0;
        }
        break;
    case swrUI_MSG_KEY_UP:
        swrUI_ClearUI5();
        return 0;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        // param = index of the pressed button
        if ((unsigned int)param <= 2) {
            swrUI_confirmDialogResult = (int)param;
            swrUI_confirmDialogDone = 1;
        }
        break;
    }
    return 0;
}

// 0x00401000
int swrUI_Menu_Main(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    swrUI_unk* page;
    int i;

    // the developer photo swaps the menu buttons for the team name labels
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_FREEPLAY), g_objHang2->showDeveloperPhoto == 0);
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_TOURNAMENT), g_objHang2->showDeveloperPhoto == 0);
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_MULTIPLAYER), g_objHang2->showDeveloperPhoto == 0);
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_SETTINGS), g_objHang2->showDeveloperPhoto == 0);
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_QUIT), g_objHang2->showDeveloperPhoto == 0);
    swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_MAIN_COPYRIGHT), g_objHang2->showDeveloperPhoto == 0);
    for (i = 0; i < SWR_UI_DEV_PHOTO_NAME_COUNT; i++)
        swrUI_RunCallbacks2(swrUI_GetById(self, SWR_UI_ID_DEV_PHOTO_NAME_FIRST + i), g_objHang2->showDeveloperPhoto);

    switch (msg) {
    case swrUI_MSG_BACK:
        return 1;
    case swrUI_MSG_SET_ACTIVE:
        if (param != NULL) {
            swrControl_uiInputActive = 0;
            swrControl_menuAcceptGuard = 0;
            swrMultiplayer_SetInMultiplayer(0);
        }
        return 0;
    case swrUI_MSG_DIALOG_RESULT:
        if (swrUI_mainMenuDialog != SWR_UI_ID_MAIN_MULTIPLAYER) {
            if (swrUI_mainMenuDialog != SWR_UI_ID_MAIN_QUIT)
                return 0;
            if (param == NULL) {
                Main_Shutdown();
                exit(0);
            }
        }
        swrUI_mainMenuDialog = 0;
        return 0;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        switch ((int)param) {
        case SWR_UI_ID_MAIN_FREEPLAY:
            page = swrUI_GetById(NULL, swrUI_WINDOW_PROFILE_SELECT);
            swrConfig_RefreshProfileListMenu(page);
            swrUI_RunCallbacksScreenText(swrUI_GetById(page, 1), swrText_Translate("/MONDOTEXT_H_0000/SINGLE-PLAYER FREEPLAY ~nRACER ROSTER"), 0);
            swrObjHang_pendingTournamentMode = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_PROFILE_SELECT);
            return 0;
        case SWR_UI_ID_MAIN_MULTIPLAYER:
            swrObjHang_pendingTournamentMode = 0;
            if (swrMultiplayer_IsAvailable() == 0) {
                swrUI_ShowConfirmDialog(self, -1, -1, swrText_Translate("/MONDOTEXT_H_0519/~sMultiplayer"), swrText_Translate("/MONDOTEXT_H_0520/~sYou must have IPX installed to play multiplayer"), swrText_Translate("/MONDOTEXT_H_0521/~sOK"), NULL, NULL, 0);
                swrUI_mainMenuDialog = SWR_UI_ID_MAIN_MULTIPLAYER;
                return 0;
            }
            swrUI_PushMenuPage(swrUI_WINDOW_MP_START);
            return 0;
        case SWR_UI_ID_MAIN_TOURNAMENT:
            page = swrUI_GetById(NULL, swrUI_WINDOW_PROFILE_SELECT);
            swrConfig_RefreshProfileListMenu(page);
            swrUI_RunCallbacksScreenText(swrUI_GetById(page, 1), swrText_Translate("/MONDOTEXT_H_0001/SINGLE-PLAYER TOURNAMENT ~nRACER ROSTER"), 0);
            swrObjHang_pendingTournamentMode = 1;
            swrUI_PushMenuPage(swrUI_WINDOW_PROFILE_SELECT);
            return 0;
        case SWR_UI_ID_MAIN_SETTINGS:
            swrUI_PushMenuPage(swrUI_WINDOW_SETTINGS);
            return 0;
        case SWR_UI_ID_MAIN_QUIT:
            swrUI_ShowConfirmDialog(swrUI_GetById(NULL, swrUI_WINDOW_SPLASH), -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0523/Are you sure you want to quit the game?"), swrText_Translate("/MONDOTEXT_H_0032/~sYes"), swrText_Translate("/MONDOTEXT_H_0033/~sNo"), NULL, 0);
            swrUI_mainMenuDialog = SWR_UI_ID_MAIN_QUIT;
            return 0;
        }
        break;
    }
    return 0;
}

// 0x00401960
int swrUI_Menu_SettingsHub(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    if (msg == swrUI_MSG_SET_ACTIVE) {
        if (param != NULL)
            swrMultiplayer_SetInMultiplayer(0);
    } else if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        switch ((int)param) {
        case SWR_UI_ID_BACK_BUTTON:
            swrUI_PopMenuPage();
            return 0;
        case SWR_UI_ID_SETTINGS_VIDEO:
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_VIDEO_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_AUDIO:
            swrUI_audioSettingsSnapshotPending = 1;
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_AUDIO_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_JOYSTICK:
            swrControl_bindingCaptureActive = 1;
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_JOYSTICK_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_MOUSE:
            swrControl_bindingCaptureActive = 1;
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_MOUSE_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_KEYBOARD:
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_KEYBOARD_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_FORCE_FEEDBACK:
            swrConfig_RefreshForceFeedbackMenu(swrUI_GetById(NULL, swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS));
            swrUI_settingsDirty = 0;
            swrUI_PushMenuPage(swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS);
            return 0;
        case SWR_UI_ID_SETTINGS_LOAD_SAVE:
            swrConfig_RefreshConfigFilesMenu(swrUI_GetById(NULL, swrUI_WINDOW_CONFIG_FILES));
            swrUI_PushMenuPage(swrUI_WINDOW_CONFIG_FILES);
            return 0;
        }
    }
    return 0;
}

// 0x00401af0
int swrUI_Menu_SaveLoadConfig(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* item)
{
    unsigned int id = (unsigned int)param;
    swrUI_unk* focus;
    char* notice;
    char name[128];
    char path[256];

    memset(name, 0, sizeof(name));
    name[0] = wuRegistry_lpClass[0];
    if (msg != swrUI_MSG_DESTROY) {
        if (swrUI_configFilesPage == NULL) {
            swrUI_configFilesPage = swrUI_GetById(NULL, swrUI_WINDOW_CONFIG_FILES);
        } else {
            if (swrUI_configNameEntry == NULL)
                swrUI_configNameEntry = swrUI_GetById(swrUI_configFilesPage, SWR_UI_ID_FILE_NAME_ENTRY);
            if (swrUI_configFileList != NULL || (swrUI_configFileList = swrUI_GetById(swrUI_configFilesPage, SWR_UI_ID_FILE_LIST)) != NULL) {
                swrUI_configPrevSelectedFile = swrUI_configSelectedFile;
                swrUI_configSelectedFile = swrUI_GetSelectedItem(swrUI_configFileList);
                if (swrUI_configSelectedFile == NULL) {
                    swrUI_configSelectedIsPreset = 0;
                } else {
                    sprintf(name, "%s", swrUI_configSelectedFile->str_allocated);
                    swrUI_configSelectedIsPreset = swrUI_GetSlotValue(swrUI_configSelectedFile, 0);
                }
            }
        }
    }

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (id != 0) {
            swrMultiplayer_SetInMultiplayer(0);
            swrUI_RunCallbacksScreenText(swrUI_configNameEntry, wuRegistry_lpClass, 0);
        }
        return 0;
    case swrUI_MSG_DIALOG_RESULT:
        // "delete this configuration?" answered yes
        if (id == 0) {
            sprintf(path, "%s%s", ".\\data\\config\\", name);
            stdFileUtil_DelTree(path);
            swrConfig_RefreshConfigFilesMenu(swrUI_configFilesPage);
            swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0541/                       Removed settings file."), 2.0f);
        }
        return 0;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if (id == 3) { // nav button (swrConfig_BuildConfigFilesMenu)
            swrUI_PopMenuPage();
            return 0;
        }
        if (id == SWR_UI_ID_FILE_SAVE) {
            swrUI_RunCallbacks2(swrUI_configNameEntry, 1);
            swrUI_SetFocusedElement(swrUI_configNameEntry);
            swrUI_RunCallbacks(swrUI_configNameEntry, swrUI_MSG_SET_EDITING, 1, swrUI_configNameEntry->id);
            swrUI_RunCallbacksScreenText(swrUI_configNameEntry, wuRegistry_lpClass, 0);
            return 0;
        }
        if (id == SWR_UI_ID_FILE_LOAD) {
            if (name[0] == '\0') {
                if (swrUI_configSelectedFile != NULL)
                    swrUI_GetAllocatedString(swrUI_configNameEntry, name, sizeof(name));
                if (name[0] == '\0') {
                    swrSound_PlayUISound(-1);
                    swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0542/                       No file selected."), 2.0f);
                    return 0;
                }
            }
            if (swrUI_configSelectedIsPreset == 0) {
                stdConfFile_readAndApplyConf(-1, name, 0);
                swrConfig_RefreshMappingMenu(swrConfig_DEVICE_JOYSTICK, swrUI_GetById(NULL, swrUI_WINDOW_JOYSTICK_SETTINGS));
                swrConfig_RefreshMappingMenu(swrConfig_DEVICE_MOUSE, swrUI_GetById(NULL, swrUI_WINDOW_MOUSE_SETTINGS));
                swrConfig_RefreshMappingMenu(swrConfig_DEVICE_KEYBOARD, swrUI_GetById(NULL, swrUI_WINDOW_KEYBOARD_SETTINGS));
            } else {
                // pre-installed files only carry joystick mappings
                stdFnames_ChangeExt(name, "map");
                stdConfFile_readAndApplyConf(0, name, 1);
                swrConfig_RefreshMappingMenu(swrConfig_DEVICE_JOYSTICK, swrUI_GetById(NULL, swrUI_WINDOW_JOYSTICK_SETTINGS));
            }
            if (swrUI_configSelectedIsPreset == 0) {
                stdConfFile_readAndApplyConf(-1, name, 0);
                swrConfig_ReadVideoConfig(name);
                swrConfig_RefreshVideoMenu(swrUI_GetById(NULL, swrUI_WINDOW_VIDEO_SETTINGS));
                swrConfig_ReadAudioConfig(name);
                swrConfig_RefreshAudioMenu(swrUI_GetById(NULL, swrUI_WINDOW_AUDIO_SETTINGS));
                swrConfig_ReadForceFeedbackConfig(name);
                swrConfig_RefreshForceFeedbackMenu(swrUI_GetById(NULL, swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS));
            }
            swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0539/                       Loaded settings file."), 2.0f);
            return 0;
        }
        if (id == SWR_UI_ID_FILE_REMOVE) {
            if (swrUI_configSelectedIsPreset != 0) {
                swrSound_PlayUISound(-1);
                notice = "/MONDOTEXT_H_0010/This is a pre-installed, non-writable ~nfile.  Use another name.";
            } else if (swrUI_configSelectedFile == NULL) {
                swrSound_PlayUISound(-1);
                notice = "/MONDOTEXT_H_0542/                       No file selected.";
            } else {
                swrUI_ShowConfirmDialog(swrUI_configFilesPage, -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0533/Are you sure you want to delete this configuration?"), swrText_Translate("/MONDOTEXT_H_0032/~sYes"), swrText_Translate("/MONDOTEXT_H_0033/~sNo"), NULL, 0);
                return 0;
            }
            swrText_ShowTimedMessage(swrText_Translate(notice), 2.0f);
            swrUI_noticeDurationUnused = 2.1f;
            return 0;
        }
        return 0;
    case swrUI_MSG_TEXT_ENTRY_COMMITTED:
        if (swrUI_configNameEntry->str_allocated[0] == '\0') {
            swrSound_PlayUISound(-1);
            swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0008/\t            Enter a filename or press ESC."), 2.0f);
            swrUI_noticeDurationUnused = 2.1f;
            swrUI_SetFocusedElement(swrUI_configNameEntry);
            swrUI_RunCallbacks(swrUI_configNameEntry, swrUI_MSG_SET_EDITING, 1, swrUI_configNameEntry->id);
            return 0;
        }
        swrUI_configSelectedFile = swrUI_FindChildByText(swrUI_configFileList, swrUI_configNameEntry->str_allocated);
        if (swrUI_configSelectedFile != NULL) {
            swrSound_PlayUISound(-1);
            swrUI_configSelectedIsPreset = swrUI_GetSlotValue(swrUI_configSelectedFile, 0);
            swrText_ShowTimedMessage(swrText_Translate(swrUI_configSelectedIsPreset != 0 ? "/MONDOTEXT_H_0010/This is a pre-installed, non-writable ~nfile.  Use another name." : "/MONDOTEXT_H_0534/                     Filename already exists."), 2.0f);
            swrUI_noticeDurationUnused = 2.1f;
            swrUI_SetFocusedElement(swrUI_configNameEntry);
            swrUI_RunCallbacks(swrUI_configNameEntry, swrUI_MSG_SET_EDITING, 1, swrUI_configNameEntry->id);
            return 0;
        }
        sprintf(path, "%s%s", ".\\data\\config\\", swrUI_configNameEntry->str_allocated);
        stdFileUtil_MkDir(path);
        swrConfig_WriteMappings(swrUI_configNameEntry->str_allocated);
        swrConfig_WriteVideoConfig(swrUI_configNameEntry->str_allocated);
        swrConfig_WriteAudioConfig(swrUI_configNameEntry->str_allocated);
        swrConfig_WriteForceFeedbackConfig(swrUI_configNameEntry->str_allocated);
        swrConfig_RefreshConfigFilesMenu(swrUI_configFilesPage);
        swrUI_SelectListItem(swrUI_FindChildByText(swrUI_configFileList, swrUI_configNameEntry->str_allocated), 1);
        swrUI_RunCallbacks2(swrUI_configNameEntry, 0);
        swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0540/                       Saved settings file."), 2.0f);
        return 0;
    case swrUI_MSG_TEXT_ENTRY_CANCELLED:
        swrUI_RunCallbacks2(swrUI_configNameEntry, 0);
        focus = swrUI_configFileList;
        if (focus == NULL)
            focus = swrUI_GetById(swrUI_configFilesPage, 3);
        swrUI_FocusElement(focus, 1);
        return 0;
    case swrUI_MSG_LIST_SELECTION_CHANGED:
        swrUI_RunCallbacksScreenText(swrUI_configNameEntry, item->str_allocated, 0);
        swrUI_configLoadButton = swrUI_GetById(swrUI_configFilesPage, SWR_UI_ID_FILE_LOAD);
        swrUI_FocusElement(swrUI_configLoadButton, 1);
        return 0;
    }
    return 0;
}

// 0x004030f0
int swrUI_Menu_VideoSettings(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    unsigned int id = (unsigned int)param;

    if (self->id == swrUI_WINDOW_VIDEO_SETTINGS) {
        swrUI_videoSettingsPageId = swrUI_WINDOW_VIDEO_SETTINGS;
        swrUI_videoSettingsPage = self;
    }
    if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        switch (id) {
        case 0x62:
            swrConfig_VIDEO_REFLECTIONS = swrConfig_VIDEO_REFLECTIONS == 0;
            break;
        case 0x63:
            swrConfig_VIDEO_ZEFFECTS = swrConfig_VIDEO_ZEFFECTS == 0;
            break;
        case 0x64:
            swrConfig_VIDEO_DYNAMIC_LIGHTING = swrConfig_VIDEO_DYNAMIC_LIGHTING == 0;
            break;
        case 0x65:
            swrConfig_VIDEO_VSYNC = swrConfig_VIDEO_VSYNC == 0;
            break;
        case 0x66:
            swrConfig_VIDEO_TEXTURE_RES = swrUI_GetValue(ui2);
            break;
        case 0x67:
            swrConfig_VIDEO_MODEL_DETAIL = swrUI_GetValue(ui2);
            break;
        case 0x273b:
            if (direct3d_LensFlareCompatible == 0)
                swrConfig_VIDEO_LENSFLARE = 0;
            else
                swrConfig_VIDEO_LENSFLARE = swrConfig_VIDEO_LENSFLARE == 0;
            break;
        case 0x273c:
            if (direct3d_LensFlareCompatible == 0)
                swrConfig_VIDEO_ENGINEEXHAUST = 0;
            else
                swrConfig_VIDEO_ENGINEEXHAUST = swrConfig_VIDEO_ENGINEEXHAUST == 0;
            break;
        case 0x273d:
            swrConfig_VIDEO_DRAWDISTANCE = swrUI_GetValue(ui2);
            break;
        }
    }

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (param != NULL)
            swrMultiplayer_SetInMultiplayer(0);
        return 0;
    case swrUI_MSG_BACK:
        if (swrUI_settingsDirty != 0) {
            swrUI_ShowConfirmDialog(swrUI_videoSettingsPage, -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0031/~sSave any changes?"), swrText_Translate("/MONDOTEXT_H_0032/~sYes"), swrText_Translate("/MONDOTEXT_H_0033/~sNo"), swrText_Translate("/MONDOTEXT_H_0034/~sCancel"), 0);
            if (ui2 != NULL)
                swrUI_videoSettingsClosePending++;
            return 1;
        }
        break;
    case swrUI_MSG_DIALOG_RESULT:
        if (id == 0) {
            // faithful: "save changes? yes" writes the force feedback config, not the video one
            swrConfig_WriteForceFeedbackConfig("current");
            if (swrUI_videoSettingsClosePending == 0)
                return 0;
            swrUI_PopMenuPage();
            swrUI_videoSettingsClosePending = 0;
            return 0;
        }
        if (id != 1)
            return 0;
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if (id == 0x25) {
            swrConfig_SetDefaultVideo();
            swrConfig_RefreshVideoMenu(swrUI_videoSettingsPage);
            swrUI_settingsDirty = 1;
            return 0;
        }
        if (id == 0x26) {
            swrConfig_ReadVideoConfig("current");
            swrConfig_RefreshVideoMenu(swrUI_videoSettingsPage);
            swrUI_settingsDirty = 1;
            return 0;
        }
        if (id == SWR_UI_ID_OK_BUTTON) {
            swrConfig_WriteVideoConfig("current");
            swrUI_PopMenuPage();
            return 0;
        }
        if (id == SWR_UI_ID_BACK_BUTTON) {
            swrUI_RunCallbacks(self, swrUI_MSG_BACK, 0, 1);
            return 0;
        }
        if (id == 1 || (id >= 0x2710 && id <= 0x2713))
            return 0;
        swrUI_settingsDirty = 1;
        return 1;
    default:
        return 0;
    }

    // back without changes, or "save changes? no": revert and leave
    swrConfig_ReadVideoConfig("current");
    swrConfig_RefreshVideoMenu(swrUI_videoSettingsPage);
    swrUI_PopMenuPage();
    return 1;
}

// 0x004039a0
int swrUI_Menu_ForceFeedback(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    unsigned int id = (unsigned int)param;

    if (self->id == swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS) {
        swrUI_forceFeedbackPageId = swrUI_WINDOW_FORCE_FEEDBACK_SETTINGS;
        swrUI_forceFeedbackPage = self;
    }
    if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        switch (id) {
        case 0x5a:
            swrConfig_FORCE_STRENGTH = swrUI_GetValue(ui2);
            break;
        case 0x5b:
            swrConfig_FORCE_AUTOCENTER = swrUI_GetValue(ui2);
            break;
        case 0x5c:
            swrConfig_FORCE_COLLISIONS = swrUI_GetValue(ui2);
            break;
        case 0x5d:
            swrConfig_FORCE_DAMAGE = swrUI_GetValue(ui2);
            break;
        case 0x5e:
            swrConfig_FORCE_TERRAIN = swrUI_GetValue(ui2);
            break;
        case 0x5f:
            swrConfig_FORCE_PODACTIONS = swrUI_GetValue(ui2);
            break;
        case 0x60:
            swrConfig_FORCE_GFORCES = swrConfig_FORCE_GFORCES == 0;
            break;
        case 0x61:
            swrConfig_FORCE_ENGINERUMBLE = swrConfig_FORCE_ENGINERUMBLE == 0;
            break;
        }
    }

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (param != NULL)
            swrMultiplayer_SetInMultiplayer(0);
        return 0;
    case swrUI_MSG_BACK:
        if (swrUI_settingsDirty != 0) {
            swrUI_ShowConfirmDialog(swrUI_forceFeedbackPage, -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0031/~sSave any changes?"), swrText_Translate("/MONDOTEXT_H_0032/~sYes"), swrText_Translate("/MONDOTEXT_H_0033/~sNo"), swrText_Translate("/MONDOTEXT_H_0034/~sCancel"), 0);
            if (ui2 != NULL)
                swrUI_forceFeedbackClosePending++;
            return 1;
        }
        swrConfig_ReadForceFeedbackConfig("current");
        swrConfig_RefreshForceFeedbackMenu(swrUI_forceFeedbackPage);
        swrControl_StopForceEffect(swrForceEffect_AUTO_CENTER);
        swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
        swrUI_PopMenuPage();
        return 1;
    case swrUI_MSG_DIALOG_RESULT:
        if (id == 0) {
            swrConfig_WriteForceFeedbackConfig("current");
            if (swrUI_forceFeedbackClosePending == 0)
                return 0;
            swrUI_PopMenuPage();
            swrUI_forceFeedbackClosePending = 0;
            return 0;
        }
        if (id == 1) {
            swrConfig_ReadForceFeedbackConfig("current");
            swrConfig_RefreshForceFeedbackMenu(swrUI_forceFeedbackPage);
            swrUI_PopMenuPage();
            return 1;
        }
        return 0;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if (id == 1 || (id >= 0x2710 && id <= 0x2713))
            return 0;
        if (id == 0x25 || id == 0x26) {
            if (id == 0x25)
                swrConfig_SetDefaultForce();
            else
                swrConfig_ReadForceFeedbackConfig("current");
            swrConfig_RefreshForceFeedbackMenu(swrUI_forceFeedbackPage);
            swrUI_settingsDirty = 1;
            return 0;
        }
        if (id == SWR_UI_ID_OK_BUTTON) {
            swrConfig_AssignForceValues();
            swrConfig_WriteForceFeedbackConfig("current");
            swrUI_PopMenuPage();
            return 0;
        }
        if (id == SWR_UI_ID_BACK_BUTTON) {
            swrUI_RunCallbacks(self, swrUI_MSG_BACK, 0, 1);
            return 0;
        }
        if (id == 0x59) {
            if (Main_force_feedback != 0 && swrControl_forceFeedbackAvailable != 0)
                swrConfig_FORCE_ENABLED = swrConfig_FORCE_ENABLED == 0;
            else
                swrConfig_FORCE_ENABLED = 0;
            if (swrControl_forceFeedbackAvailable == 0) {
                swrUI_forceFeedbackMissingShown = 1;
                swrUI_noticeDurationUnused = 2.1f;
                swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0042/~nNo Force Feedback device detected."), 2.0f);
                swrSound_PlayUISound(-1);
                swrUI_SetChecked(ui2, swrControl_forceFeedbackAvailable);
            }
            return 0;
        }
        // any slider / checkbox: apply and preview the change
        swrConfig_AssignForceValues();
        swrControl_StopForceEffect(swrForceEffect_AUTO_CENTER);
        swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
        swrUI_settingsDirty = 1;
        return 1;
    }
    return 0;
}

// 0x00403d70
int swrUI_Menu_ReservedSettings(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    swrUI_unk* label;

    if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        if ((unsigned int)param == 3) // nav button (swrConfig_BuildReservedSettingsMenu)
            swrUI_PopMenuPage();
    } else if (swrMain_moneyHintUnlocked != 0 && msg != swrUI_MSG_DESTROY && swrUI_moneyHintShown == 0) {
        label = swrUI_NewLabel(swrUI_GetById(NULL, swrUI_WINDOW_RESERVED_KEYS), 1, 0, swrText_Translate("/MONDOTEXT_H_0334/~s  SHIFT, 4 and F4 shows you the money!, where?  You figure it out!"), 0x28, 400, 0, 0);
        swrUI_SetColorUnk(label, 0xb4, 0xb4, 0, 0xff);
        swrUI_moneyHintShown++;
    }
    return 0;
}

// 0x00403430
int swrUI_Menu_AudioSettings(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* ui2)
{
    swrUI_unk* slider;
    unsigned int id = (unsigned int)param;

    if (swrUI_audioSettingsSnapshotPending != 0) {
        swrUI_audioSnapshotHiResSound = Main_hiRes_sound;
        swrUI_audioSnapshotSound = Main_sound;
        swrUI_audioSettingsSnapshotPending = 0;
    }
    if (self->id == swrUI_WINDOW_AUDIO_SETTINGS) {
        swrUI_audioSettingsPageId = swrUI_WINDOW_AUDIO_SETTINGS;
        swrUI_audioSettingsPage = self;
    }

    // slider changes are applied on the next message, after the slider has updated
    if (swrUI_sfxVolumeChanged != 0) {
        swrSound_StopVoiceById(0x6d);
        slider = swrUI_GetById(swrUI_audioSettingsPage, 0x273e);
        sound_sfx_volume = (unsigned int)(slider->slider_percent * 255) / 100;
        swrSound_Play2D(0x6d, 6, 0.25f, 1.0f, 0);
        swrUI_sfxVolumeChanged = 0;
    }
    if (swrUI_musicVolumeChanged != 0) {
        slider = swrUI_GetById(swrUI_audioSettingsPage, 0x273f);
        swrUI_musicVolumeChanged = 0;
        *(uint8_t*)&sound_music_volume = (unsigned int)(slider->slider_percent * 255) / 100;
    }
    if (swrUI_soundGainChanged != 0) {
        slider = swrUI_GetById(swrUI_audioSettingsPage, 0x2740);
        Main_sound_gain_adjust = (float)(unsigned int)slider->slider_percent * 0.01f;
        slider->number_value = slider->slider_percent;
        swrSound_PlayLayeredStream_Maybe(1, Main_sound_gain_adjust, "sfx_crash_wood.wav", "sfx_crash_wood.wav");
        swrUI_soundGainChanged = 0;
    }

    if (msg == swrUI_MSG_ELEMENT_ACTIVATED) {
        switch (id) {
        case 0x2741:
            if (swrSound_Ready == 0)
                Main_sound = 0;
            else
                Main_sound = Main_sound == 0;
            break;
        case 0x2742:
            Sound_enabled_3d = Sound_enabled_3d == 0;
            break;
        case 0x2743:
            Main_doppler_sound = Main_doppler_sound == 0;
            break;
        case 0x2744:
            swrUI_hiResSoundToggled = 1;
            Main_hiRes_sound = Main_hiRes_sound == 0;
            swrUI_noticeDurationUnused = 2.1f;
            break;
        case 0x2745:
            Main_sound_reverb = Main_sound_reverb == 0;
            break;
        case 0x2746:
            swrRace_voices_enabled = swrRace_voices_enabled == 0;
            break;
        case 0x2747:
            swrRace_music_enabled = swrRace_music_enabled == 0;
            break;
        }
    }

    switch (msg) {
    case swrUI_MSG_SET_ACTIVE:
        if (param != NULL)
            swrMultiplayer_SetInMultiplayer(0);
        return 0;
    case swrUI_MSG_BACK:
        swrSound_PlayLayeredStream_Maybe(0, Main_sound_gain_adjust, wuRegistry_lpClass, wuRegistry_lpClass);
        if (swrUI_settingsDirty != 0) {
            swrUI_ShowConfirmDialog(swrUI_audioSettingsPage, -1, -1, wuRegistry_lpClass, swrText_Translate("/MONDOTEXT_H_0031/~sSave any changes?"), swrText_Translate("/MONDOTEXT_H_0032/~sYes"), swrText_Translate("/MONDOTEXT_H_0033/~sNo"), swrText_Translate("/MONDOTEXT_H_0034/~sCancel"), 0);
            if (ui2 != NULL)
                swrUI_audioSettingsClosePending++;
            return 1;
        }
        break;
    case swrUI_MSG_DIALOG_RESULT:
        if (id == 0) {
            // faithful: "save changes? yes" writes the force feedback config, not the audio one
            swrConfig_WriteForceFeedbackConfig("current");
            if (swrUI_audioSettingsClosePending == 0)
                return 0;
            swrUI_PopMenuPage();
            swrUI_audioSettingsClosePending = 0;
            return 0;
        }
        if (id != 1)
            return 0;
        break;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        if (id == 0x25) {
            swrSound_SetDefaultConfig();
            swrConfig_RefreshAudioMenu(swrUI_audioSettingsPage);
            swrUI_settingsDirty = swrSound_Initted;
            return 0;
        }
        if (id == 0x26) {
            swrConfig_ReadAudioConfig("current");
            swrRace_LoadGameData();
            swrConfig_RefreshAudioMenu(swrUI_audioSettingsPage);
            swrUI_settingsDirty = swrSound_Initted;
            return 0;
        }
        if (id == SWR_UI_ID_OK_BUTTON) {
            swrSound_PlayLayeredStream_Maybe(0, Main_sound_gain_adjust, wuRegistry_lpClass, wuRegistry_lpClass);
            swrConfig_WriteAudioConfig("current");
            // restart the sound system if it was switched on/off or its sample rate changed
            if (swrUI_audioSnapshotSound != Main_sound) {
                if (Main_sound != 0) {
                    swrSound_Startup();
                } else {
                    swrSound_RewindChannels();
                    swrSound_Teardown(0);
                }
            }
            if (Main_sound != 0 && swrUI_audioSnapshotHiResSound != Main_hiRes_sound) {
                swrSound_RewindChannels();
                swrSound_Teardown(0);
                swrSound_Startup();
            }
            swrUI_PopMenuPage();
            return 0;
        }
        if (id == SWR_UI_ID_BACK_BUTTON) {
            swrUI_RunCallbacks(self, swrUI_MSG_BACK, 0, 1);
            return 0;
        }
        if (id == 1 || (id >= 0x2710 && id <= 0x2713))
            return 0;
        swrConfig_RefreshAudioMenu(swrUI_audioSettingsPage);
        swrUI_settingsDirty = swrSound_Initted;
        return 1;
    case swrUI_MSG_SLIDER_DECREASED:
    case swrUI_MSG_SLIDER_INCREASED:
        if (id == 0x273e)
            swrUI_sfxVolumeChanged = 1;
        else if (id == 0x273f)
            swrUI_musicVolumeChanged = 1;
        else if (id == 0x2740)
            swrUI_soundGainChanged = 1;
        return 0;
    default:
        return 0;
    }

    // back without changes, or "save changes? no": reload and leave
    swrConfig_ReadAudioConfig("current");
    swrRace_LoadGameData();
    swrConfig_RefreshAudioMenu(swrUI_audioSettingsPage);
    swrUI_PopMenuPage();
    return 1;
}
