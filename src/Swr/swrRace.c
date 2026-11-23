#include "swrRace.h"

#include "swrObj.h"
#include "swrModel.h"
#include "swrSpline.h"
#include "swrEvent.h"
#include "swrText.h"
#include "swrSound.h"
#include "swrSprite.h"
#include "swrUI.h"
#include "swrMultiplayer.h"
#include "swrConfig.h"
#include "swr.h"
#include <Main/swrControl.h>
#include <Main/swrMain.h>
#include <Engine/sithRender.h>
#include <Platform/stdControl.h>
#include "macros.h"
#include "swrRender.h"
#include "engine_config.h"
#include "globals.h"
#include "engine_config.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <General/stdFileUtil.h>
#include <General/stdFnames.h>
#include <Primitives/rdVector.h>
#include <Primitives/rdMatrix.h>
#include <Unknown/rdMatrixStack.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 0x00401340
int swrUI_Menu_SelectProfile(swrUI_unk* self, unsigned int msg, void* param, swrUI_unk* item)
{
    unsigned int id = (unsigned int)param;
    char* notice;
    char* noLabel;
    char* yesLabel;
    char label[128];
    char question[256];

    if (swrUI_profileLoadCooldown > 0.0f) {
        swrUI_profileLoadCooldown -= swrRace_deltaTimeSecs;
    } else if (swrUI_profileLoadCooldown < 0.0f) {
        swrUI_profileLoadCooldown = 0.0f;
    }

    if (msg != swrUI_MSG_DESTROY) {
        if (swrUI_profileSelectPage == NULL) {
            swrUI_profileSelectPage = swrUI_GetById(NULL, swrUI_WINDOW_PROFILE_SELECT);
        } else {
            if (swrUI_profileNameEntry == NULL)
                swrUI_profileNameEntry = swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_FILE_NAME_ENTRY);
            if (swrUI_profileList != NULL || (swrUI_profileList = swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_FILE_LIST)) != NULL) {
                swrUI_profilePrevSelectedItem = swrUI_profileSelectedItem;
                swrUI_profileSelectedItem = swrUI_GetSelectedItem(swrUI_profileList);
                if (swrUI_profileSelectedItem != NULL)
                    sprintf(swrUI_profileName, "%s", swrUI_profileSelectedItem->str_allocated);
            }
            if (swrUI_profileCurrentPlayerLabel == NULL) {
                swrUI_profileCurrentPlayerLabel = swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_CURRENT_PLAYER_LABEL);
            } else if (swrUI_profileShowLabelPending != 0) {
                swrUI_RunCallbacks2(swrUI_profileCurrentPlayerLabel, 1);
                swrUI_profileShowLabelPending = 0;
            }
        }
    }

    switch (msg) {
    case swrUI_MSG_DIALOG_RESULT:
        // "delete player?" answered yes
        if (id == 0) {
            swrRace_DeleteProfile(swrUI_profileName);
            swrConfig_RefreshProfileListMenu(swrUI_profileSelectPage);
        }
        return 0;
    case swrUI_MSG_SET_ACTIVE:
        if (id != 0) {
            swrMultiplayer_SetInMultiplayer(0);
            swrUI_RunCallbacksScreenText(swrUI_profileNameEntry, wuRegistry_lpClass, 0);
            swrObjHang_SetHangar2Splash();
        }
        return 0;
    case swrUI_MSG_TEXT_ENTRY_COMMITTED:
        if (strlen(swrUI_profileNameEntry->str_allocated) == 0) {
            swrSound_PlayUISound(-1);
            notice = "/MONDOTEXT_H_0006/Please enter a racer name or ~npress ESC to cancel.";
        } else if (swrUI_FindChildByText(swrUI_profileList, swrUI_profileNameEntry->str_allocated) == NULL) {
            // passes 0x80, larger than swrUI_profileName (faithful)
            swrUI_GetAllocatedString(swrUI_profileNameEntry, swrUI_profileName, 0x80);
            swrRace_CreateProfile(swrUI_profileName);
            sprintf(label, swrText_Translate("/MONDOTEXT_H_0002/Current Player:  %s"), swrUI_profileName);
            swrUI_RunCallbacksScreenText(swrUI_profileCurrentPlayerLabel, label, 0);
            swrConfig_RefreshProfileListMenu(swrUI_profileSelectPage);
            swrUI_RunCallbacks2(swrUI_profileNameEntry, 0);
            swrUI_FocusElement(swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_OK_BUTTON), 1);
            swrUI_profileShowLabelPending = 1;
            return 0;
        } else {
            swrSound_PlayUISound(-1);
            notice = "/MONDOTEXT_H_0007/Racer already exists.  ~nUse another name.";
        }
        swrText_ShowTimedMessage(swrText_Translate(notice), 2.0f);
        swrUI_noticeDurationUnused = 2.1f;
        swrUI_SetFocusedElement(swrUI_profileNameEntry);
        swrUI_RunCallbacks(swrUI_profileNameEntry, swrUI_MSG_SET_EDITING, 1, swrUI_profileNameEntry->id);
        return 0;
    case swrUI_MSG_TEXT_ENTRY_CANCELLED:
        swrUI_RunCallbacks2(swrUI_profileNameEntry, 0);
        swrUI_FocusElement(swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_PROFILE_CREATE), 1);
        swrUI_RunCallbacks2(swrUI_profileCurrentPlayerLabel, 1);
        return 0;
    case swrUI_MSG_ELEMENT_ACTIVATED:
        switch (id) {
        case SWR_UI_ID_PROFILE_CREATE:
            swrUI_RunCallbacks2(swrUI_profileCurrentPlayerLabel, 0);
            swrUI_RunCallbacks2(swrUI_profileNameEntry, 1);
            swrUI_SetFocusedElement(swrUI_profileNameEntry);
            swrUI_RunCallbacks(swrUI_profileNameEntry, swrUI_MSG_SET_EDITING, 1, swrUI_profileNameEntry->id);
            swrUI_RunCallbacksScreenText(swrUI_profileNameEntry, wuRegistry_lpClass, 0);
            return 0;
        case SWR_UI_ID_OK_BUTTON:
        case SWR_UI_ID_PROFILE_SELECT_UNUSED:
            break;
        case SWR_UI_ID_FILE_REMOVE:
            if (swrRace_profileLoaded < 0)
                goto no_profile;
            sprintf(question, swrText_Translate("/MONDOTEXT_H_0512/~sAre you sure you want to delete player %s ?"), swrUI_profileName);
            noLabel = swrText_Translate("/MONDOTEXT_H_0033/~sNo");
            yesLabel = swrText_Translate("/MONDOTEXT_H_0032/~sYes");
            swrUI_ShowConfirmDialog(swrUI_profileSelectPage, -1, -1, wuRegistry_lpClass, question, yesLabel, noLabel, NULL, 0);
            return 0;
        case SWR_UI_ID_PROFILE_NAV:
            swrUI_PopMenuPage();
            return 0;
        default:
            return 0;
        }
        break;
    case swrUI_MSG_LIST_SELECTION_CHANGED:
        if (swrUI_profileLoadCooldown == 0.0f) {
            swrUI_profileLoadCooldown = 0.5f;
            sprintf(swrUI_profileName, "%s", item->str_allocated);
            sprintf(label, swrText_Translate("/MONDOTEXT_H_0002/Current Player:  %s"), swrUI_profileName);
            swrUI_RunCallbacksScreenText(swrUI_profileCurrentPlayerLabel, label, 0);
            if (!swrRace_LoadProfile(swrUI_profileName)) {
                swrSound_PlayUISound(-1);
                swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0003/Error loading file."), 2.0f);
                swrUI_noticeDurationUnused = 2.1f;
            }
            swrUI_FocusElement(swrUI_GetById(swrUI_profileSelectPage, SWR_UI_ID_OK_BUTTON), 1);
            return 0;
        }
        // picking the already-selected racer again during the cooldown acts as SELECT
        if (swrUI_profileSelectedItem == NULL || swrUI_profileSelectedItem != swrUI_profilePrevSelectedItem)
            return 0;
        break;
    default:
        return 0;
    }

    if (swrRace_profileLoaded >= 0) {
        swrObjHang_splashSkipToVehicleIntro = 1;
        swrUI_PushMenuPage(swrUI_WINDOW_HANGAR_SELECT_VEHICLE);
        return 0;
    }
no_profile:
    swrSound_PlayUISound(-1);
    swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0004/Please select or create racer."), 2.0f);
    swrUI_noticeDurationUnused = 2.1f;
    return 0;
}

// 0x0040fb50
void swrConfig_BuildReservedSettingsMenu(swrUI_unk* page)
{
    static char* const keyLines[] = {
        "/MONDOTEXT_H_0326/~sCAPSLOCK       Cycle Map Indicator",
        "/MONDOTEXT_H_0327/~sF1             Camera View 1",
        "/MONDOTEXT_H_0328/~sF2             Camera View 2",
        "/MONDOTEXT_H_0329/~sF3             Camera View 3",
        "/MONDOTEXT_H_0330/~sF4             Camera View 4",
        "/MONDOTEXT_H_0331/~sF5             Cyle Taunts and Send",
        "/MONDOTEXT_H_0332/~sF6             Random Taunt and Send",
        "/MONDOTEXT_H_0333/~sF7             Enable Chat Prompt",
        "/MONDOTEXT_H_0335/~sF12            Save Screenshot",
        "/MONDOTEXT_H_0336/~sCTRL-F         Toggle Force Feedback On/Off",
        "/MONDOTEXT_H_0337/~sCTRL-J         Toggle Joystick On/Off",
        "/MONDOTEXT_H_0338/~sCTRL-M         Toggle Mouse On/Off",
        "/MONDOTEXT_H_0522/Net play: Press CTRL-Q to quit race.",
    };
    swrUI_unk* element;
    char title[256];
    int padding[4];
    int rect[4];
    unsigned int backWidth;
    unsigned int panelWidth;
    int titleWidth;
    int lineHeight;
    int x;
    int y;
    int i;

    backWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0324/~sBack to Keyboard Settings"), swrText_fontsByIndex[0]);
    swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0324/~sBack to Keyboard Settings"), swrText_fontsByIndex[0]);
    sprintf(title, swrText_Translate("/MONDOTEXT_H_0325/~sRESERVED KEYS"));
    titleWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0325/~sRESERVED KEYS"), swrText_fontsByIndex[6]);
    element = swrUI_New3PatchBox(page, 1, 6, title, (((backWidth >> 1) + backWidth) >> 2) + 0x104, 0x7d, titleWidth, swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);
    lineHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0325/~sRESERVED KEYS"), swrText_fontsByIndex[0]) + 5;
    swrUI_AddNavButton(page, 3, 0, 0x1a4, 2);

    swrUI_GetListFrameInsets(padding, 0);
    panelWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0522/Net play: Press CTRL-Q to quit race."), swrText_fontsByIndex[0]);
    panelWidth += (panelWidth >> 1) + padding[0];
    rect[0] = SWR_UI_DESIGN_WIDTH / 2 - (panelWidth >> 1);
    rect[1] = 0x8c;
    rect[2] = rect[0] + panelWidth - 1;
    rect[3] = lineHeight * 15 + padding[1] + 0x8b;
    swrUI_NewPanel(page, 1, rect, 0);

    x = rect[0] + padding[0];
    y = padding[1] + 0x8c;
    for (i = 0; i < (int)(sizeof(keyLines) / sizeof(keyLines[0])); i++) {
        element = swrUI_NewLabel(page, 1, -1, swrText_Translate(keyLines[i]), x, y, 0, 0);
        swrUI_SetColorUnk(element, 0, 0xb4, 0, 0xff);
        y += lineHeight;
    }
}

// 0x0040ffe0
void swrConfig_BuildConfigFilesMenu(swrUI_unk* page)
{
    swrUI_unk* element;
    char title[256];
    int listRect[4];
    int entryRect[4];
    int buttonWidth;
    int textHeight;
    int buttonHeight;

    buttonWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0339/~sRemove"), swrText_fontsByIndex[0]) * 3;
    textHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0339/~sRemove"), swrText_fontsByIndex[0]);
    buttonHeight = textHeight * 3;
    swrUI_AddNavButton(page, 3, 0, 0x1a9, 1);
    listRect[0] = 0xc3;
    listRect[1] = 0x8c;
    listRect[2] = 0x1bc;
    listRect[3] = 0x153;

    sprintf(title, swrText_Translate("/MONDOTEXT_H_0340/~sLOAD/SAVE SETTINGS"));
    element = swrUI_New3PatchBox(page, 1, 6, title, 500, 0x3c, swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0340/~sLOAD/SAVE SETTINGS"), swrText_fontsByIndex[6]), swrUI_3PATCH_LARGE_TAB, 1, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0, 0, 0xff);

    element = swrUI_NewList(page, SWR_UI_ID_FILE_LIST, listRect, 0, 0, 0);
    swrUI_SetListHighlightColor(element, 0xff, 100, 0, 0xff);

    entryRect[0] = listRect[0];
    entryRect[1] = listRect[3] + 0x14;
    entryRect[2] = listRect[2];
    entryRect[3] = listRect[3] + 0x13 + textHeight * 6;
    element = swrUI_NewTextEntry(page, SWR_UI_ID_FILE_NAME_ENTRY, entryRect, 0, swrUI_TEXT_ENTRY_CARET_TO_END, 0);
    swrUI_SetMaxLength(element, SWR_UI_CONFIG_NAME_MAX_LENGTH);
    swrUI_SetColorUnk2(element, 0xff, 100, 0, 0xff);
    swrUI_RunCallbacks2(element, 0);

    swrUI_NewButton(page, SWR_UI_ID_FILE_LOAD, -1, swrText_Translate("/MONDOTEXT_H_0341/~sLoad"), listRect[0] - 0x96, listRect[1] + 0x28, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, SWR_UI_ID_FILE_REMOVE, -1, swrText_Translate("/MONDOTEXT_H_0339/~sRemove"), listRect[0] - 0x96, listRect[1] + 0x46, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, SWR_UI_ID_FILE_SAVE, -1, swrText_Translate("/MONDOTEXT_H_0342/~sSave"), listRect[0] - 0x96, listRect[1] + 100, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
}

// 0x00410230
void swrConfig_BuildProfileListMenu(swrUI_unk* page)
{
    swrUI_unk* element;
    int listRect[4];
    int entryRect[4];
    unsigned int buttonWidth;
    int textHeight;
    int buttonHeight;

    buttonWidth = swrText_GetStringWidth(swrText_Translate("/MONDOTEXT_H_0343/~sREMOVE RACER"), swrText_fontsByIndex[0]);
    buttonWidth += buttonWidth >> 1;
    textHeight = swrText_GetStringHeight(swrText_Translate("/MONDOTEXT_H_0343/~sREMOVE RACER"), swrText_fontsByIndex[0]);
    buttonHeight = textHeight * 3;
    listRect[0] = 0xc3;
    listRect[1] = 0x8c;
    listRect[2] = 0x1bc;
    listRect[3] = 0x153;
    element = swrUI_NewList(page, SWR_UI_ID_FILE_LIST, listRect, 0, 0, 0);
    swrUI_SetListHighlightColor(element, 0xff, 100, 0, 0xff);

    entryRect[0] = listRect[0];
    entryRect[1] = listRect[3] + 0x14;
    entryRect[2] = listRect[2];
    entryRect[3] = listRect[3] + 0x13 + textHeight * 6;
    element = swrUI_NewTextEntry(page, SWR_UI_ID_FILE_NAME_ENTRY, entryRect, 0, swrUI_TEXT_ENTRY_CARET_TO_END, 0);
    swrUI_SetMaxLength(element, SWR_UI_CONFIG_NAME_MAX_LENGTH);
    swrUI_SetColorUnk2(element, 0xff, 100, 0, 0xff);
    swrUI_RunCallbacks2(element, 0);

    element = swrUI_NewLabel(page, SWR_UI_ID_CURRENT_PLAYER_LABEL, 6, swrText_Translate("/MONDOTEXT_H_0345/Current Player:  -none-"), listRect[0], listRect[3] + 0x19, 0, 0);
    swrUI_SetColorUnk(element, 0xff, 0xe1, 0, 0xfa);
    swrUI_NewButton(page, SWR_UI_ID_PROFILE_CREATE, -1, swrText_Translate("/MONDOTEXT_H_0347/~sCREATE RACER"), listRect[0] - 0x96, listRect[1] + 0x28, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_NewButton(page, SWR_UI_ID_FILE_REMOVE, -1, swrText_Translate("/MONDOTEXT_H_0343/~sREMOVE RACER"), listRect[0] - 0x96, listRect[1] + 0x46, buttonWidth, buttonHeight, swrUI_FRAME_STYLE_WINDOW_BARS, 0);
    swrUI_AddNavButton(page, SWR_UI_ID_PROFILE_NAV, 0, 0x1a4, 2);
    swrUI_AddOkButton(page, 0x208, 0x17c);
}

// 0x0041c4e0
swrRace_TRACK swrRace_GetSelectedTrack(void)
{
    return swrMultiplayer_trackSelect;
}

// 0x00421810
void swrRace_InitGameData(void)
{
    if (!swrRace_LoadGameData()) {
        swrRace_ResetGameData(1);
        if (!swrRace_SaveGameData())
            (*stdPlatform_hostServices_ptr->assert)("elfSaveLoad_SaveThisGameStruct()", "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Source\\elfSaveLoad.c", 0x4f);
    }
    swrRace_CopyProfileFromSave(0, 0);
}

// 0x00421850
bool swrRace_LoadProfile(char* playerName)
{
    FILE* stream;
    int failed;
    int version;
    swrSaveProfile profile;
    char path[256];

    version = 0;
    failed = 0;
    sprintf(path, "%s%s", ".\\data\\player\\", playerName);
    stdFnames_ChangeExt(path, "sav");
    stream = fopen(path, "rb");
    if (stream == NULL) {
        failed = 1;
    } else {
        if (fread(&version, 1, 4, stream) == 0 || version != ELFSAVE_VERSION_MAGIC || fread(&profile, 1, sizeof(swrSaveProfile), stream) == 0)
            failed = 1;
        fclose(stream);
    }
    if (failed == 0) {
        swrRace_saveData.profiles[0] = profile;
        swrRace_profileLoaded = 0;
        swrRace_saveData.profiles[0].planetIntrosSeen = 0;
        sprintf(swrRace_playerName, "%s", profile.name);
        swrRace_CopyProfileFromSave(0, 0);
    }
    return failed == 0;
}

// 0x00421950
int swrRace_DeleteProfile(char* playerName)
{
    char path[256];

    sprintf(path, "%s%s", ".\\data\\player\\", playerName);
    stdFnames_ChangeExt(path, "sav");
    stdFileUtil_DeleteFile(path);
    swrRace_playerName[0] = wuRegistry_lpClass[0];
    swrRace_profileLoaded = -1;
    swrRace_GenerateDefaultDataSAV(1, 0);
    swrRace_CopyProfileFromSave(0, 0);
    return 1;
}

// 0x004219d0
bool swrRace_SaveProfile(char* playerName)
{
    FILE* stream;
    size_t wroteMagic;
    size_t wroteProfile;
    int version;
    swrSaveProfile profile;
    char path[256];

    version = ELFSAVE_VERSION_MAGIC;
    profile = swrRace_saveData.profiles[0];
    if (swrRace_profileLoaded < 0)
        return false;
    sprintf(path, "%s%s", ".\\data\\player\\", playerName);
    stdFnames_ChangeExt(path, "sav");
    stream = fopen(path, "wb");
    if (stream == NULL)
        return false;
    wroteMagic = fwrite(&version, 1, 4, stream);
    wroteProfile = fwrite(&profile, 1, sizeof(swrSaveProfile), stream);
    fclose(stream);
    return wroteProfile != 0 && wroteMagic != 0;
}

// 0x00421ac0
void swrRace_CreateProfile(char* playerName)
{
    sprintf(swrRace_playerName, "%s", playerName);
    swrRace_profileLoaded = 0;
    swrRace_GenerateDefaultDataSAV(0, 0);
    sprintf(swrRace_aProfiles[0].name, "%s", playerName);
    swrRace_CopyProfileToSave(0, 0);
    swrRace_SaveProfile(playerName);
}

// 0x00421b20
int swrRace_ResetGameData(int resetCurrentPlayer)
{
    swrSaveProfile profile;

    profile = swrRace_saveData.profiles[0];
    swrRace_InitDefaultGameData(&swrRace_saveData);
    if (resetCurrentPlayer == 0) {
        swrRace_saveData.profiles[0] = profile;
        return 1;
    }
    swrRace_playerName[0] = wuRegistry_lpClass[0];
    swrRace_profileLoaded = -1;
    return 1;
}

// 0x00421b90
bool swrRace_LoadGameData(void)
{
    FILE* stream;
    int failed;
    int version;
    char path[256];

    version = 0;
    failed = 0;
    sprintf(path, "%s%s", ".\\data\\player\\", "tgfd.dat");
    stream = fopen(path, "rb");
    if (stream == NULL) {
        failed = 1;
    } else {
        if (fread(&version, 1, 4, stream) == 0 || version != ELFSAVE_VERSION_MAGIC || fread(&swrRace_saveData, 1, sizeof(swrSaveData), stream) == 0)
            failed = 1;
        fclose(stream);
    }
    if (failed == 0) {
        sprintf(swrRace_playerName, "%s", swrRace_saveData.profiles[0].name);
        swrRace_profileLoaded = (swrRace_playerName[0] != '\0') ? 0 : -1;
        swrRace_saveData.profiles[0].planetIntrosSeen = 0;
        if (swrRace_IsGameDataUninitialized()) {
            swrRace_CopyProfileToSave(0, 0);
            swrRace_ResetGameData(0);
        }
    }
    return failed == 0;
}

// 0x00421c90
bool swrRace_SaveGameData(void)
{
    FILE* stream;
    size_t wroteMagic;
    size_t wroteImage;
    int version;
    char path[256];

    version = ELFSAVE_VERSION_MAGIC;
    if (swrRace_IsGameDataUninitialized()) {
        swrRace_CopyProfileToSave(0, 0);
        swrRace_ResetGameData(0);
    }
    stdFileUtil_MkDir(".\\data\\player\\");
    sprintf(path, "%s%s", ".\\data\\player\\", "tgfd.dat");
    stream = fopen(path, "wb");
    if (stream == NULL)
        return false;
    wroteMagic = fwrite(&version, 1, 4, stream);
    wroteImage = fwrite(&swrRace_saveData, 1, sizeof(swrSaveData), stream);
    fclose(stream);
    return wroteImage != 0 && wroteMagic != 0;
}

// 0x00421d80
bool swrRace_IsGameDataUninitialized(void)
{
    return swrRace_saveData.pilotsUnlockedGlobal == 0;
}

// 0x00429cd0
void swrRace_PushDebugMenuState(int state)
{
    swrRace_inRaceMenuSavedCursor[DebugMenuState] = swrRace_inRaceMenuCursor;
    swrRace_inRaceMenuStackDepth++;
    DebugMenuState = state;
    swrRace_inRaceMenuCursor = swrRace_inRaceMenuSavedCursor[state];
    swrRace_inRaceMenuStateStack[swrRace_inRaceMenuStackDepth] = state;
}

// 0x00429d10
void swrRace_PopDebugMenuState(void)
{
    swrRace_inRaceMenuSavedCursor[DebugMenuState] = swrRace_inRaceMenuCursor;
    if (swrRace_inRaceMenuStackDepth > 0)
        swrRace_inRaceMenuStackDepth--;
    DebugMenuState = swrRace_inRaceMenuStateStack[swrRace_inRaceMenuStackDepth];
    swrRace_inRaceMenuCursor = swrRace_inRaceMenuSavedCursor[DebugMenuState];
}

// 0x00429dc0
int swrRace_GetDebugVehicleStatEntry(int index, char* nameOut, char* unk, int* c, float* d)
{
    swrRace* player;
    swrRacerData* racer;

    *unk = '\0';
    player = (swrRace*)swrEvent_FindObjectById('Test', swrRace_debugStatRacerId);
    if (player == NULL)
        return 0;
    *c = -10000;
    switch (index) {
    case 0:
        racer = (swrRacerData*)player->score_ptr->pilotId;
        sprintf(nameOut, "Name: %s %s", swrText_Translate(racer->name), swrText_Translate(racer->lastname));
        *d = -99999.0f;
        return 1;
    case 1:
        sprintf(nameOut, "Anti Skid");
        *d = player->podStats.antiSkid;
        return 1;
    case 2:
        sprintf(nameOut, "Turn Response");
        *d = player->podStats.turnResponse;
        return 1;
    case 3:
        sprintf(nameOut, "Max Turn Rate");
        *d = player->podStats.maxTurnRate;
        return 1;
    case 4:
        sprintf(nameOut, "Acceleration");
        *d = player->podStats.acceleration;
        return 1;
    case 5:
        sprintf(nameOut, "Max Speed");
        *d = player->podStats.maxSpeed;
        return 1;
    case 6:
        sprintf(nameOut, "AirBrake Inv");
        *d = player->podStats.airBrakeInv;
        return 1;
    case 7:
        sprintf(nameOut, "Decel Inv");
        *d = player->podStats.deceleration_interval;
        return 1;
    case 8:
        sprintf(nameOut, "Boost Thrust");
        *d = player->podStats.boost_thrust;
        return 1;
    case 9:
        sprintf(nameOut, "Heat Rate");
        *d = player->podStats.heatRate;
        return 1;
    case 10:
        sprintf(nameOut, "Cool Rate");
        *d = player->podStats.coolRate;
        return 1;
    case 11:
        sprintf(nameOut, "Hover Height");
        *d = player->podStats.hoverHeight;
        return 1;
    case 12:
        sprintf(nameOut, "Repair Rate");
        *d = player->podStats.repairRate;
        return 1;
    case 13:
        sprintf(nameOut, "Bump Mass");
        *d = player->podStats.bumpMass;
        return 1;
    case 14:
        sprintf(nameOut, "Dmg Immunity");
        *d = player->podStats.damageImmunity;
        return 1;
    case 15:
        sprintf(nameOut, "ISect Radius");
        *d = player->collisionWidth;
        return 1;
    case 16:
        sprintf(nameOut, "AI Look Ahead");
        *d = stdMath_Sqrt(player->aiLookAheadDistSq);
        return 1;
    default:
        sprintf(nameOut, "Unimplemented");
        *d = 0.0f;
        return 0;
    }
}

// Case 0 cycles the edited pod; the rest nudge one stat on the pod and mirror it into its score.
// 0x0042a110
void swrRace_DebugSetVehicleStat(unsigned int id, float value)
{
    swrRace* player;
    swrRace* next;
    float lookAhead;

    swrRace_debugVehicleStatsEdited = 1;
    player = (swrRace*)swrEvent_FindObjectById('Test', swrRace_debugStatRacerId);
    if (player == NULL)
        return;
    switch (id) {
    case 0:
        value = (value <= 0.0f) ? -1.0f : 1.0f;
        swrRace_debugStatRacerId = (int)((float)swrRace_debugStatRacerId + value);
        next = (swrRace*)swrEvent_FindObjectById('Test', swrRace_debugStatRacerId);
        if (next != NULL && (next->obj.flags & swrObj_FLAG_FREED) == 0)
            return;
        if (value >= 0.0f) {
            swrRace_debugStatRacerId = 0;
            return;
        }
        // stepped below the first pod: walk forward to the last live one
        do {
            swrRace_debugStatRacerId++;
            next = (swrRace*)swrEvent_FindObjectById('Test', swrRace_debugStatRacerId);
            if (next == NULL || (next->obj.flags & swrObj_FLAG_FREED) != 0) {
                value = 0.0f;
                swrRace_debugStatRacerId--;
            }
        } while (value < 0.0f);
        return;
    case 1:
        stdMath_MultiplyAddClamped(&player->podStats.antiSkid, value, 0.01f, 0.05f, 1.0f);
        player->score_ptr->podStats.antiSkid = player->podStats.antiSkid;
        return;
    case 2:
        stdMath_MultiplyAddClamped(&player->podStats.turnResponse, value, 1.0f, 10.0f, 1000.0f);
        player->score_ptr->podStats.turnResponse = player->podStats.turnResponse;
        return;
    case 3:
        stdMath_MultiplyAddClamped(&player->podStats.maxTurnRate, value, 1.0f, 10.0f, 1000.0f);
        player->score_ptr->podStats.maxTurnRate = player->podStats.maxTurnRate;
        return;
    case 4:
        stdMath_MultiplyAddClamped(&player->podStats.acceleration, value, 0.01f, 0.02f, 10.0f);
        player->score_ptr->podStats.acceleration = player->podStats.acceleration;
        return;
    case 5:
        stdMath_MultiplyAddClamped(&player->podStats.maxSpeed, value, 1.0f, 100.0f, 2000.0f);
        player->score_ptr->podStats.maxSpeed = player->podStats.maxSpeed;
        return;
    case 6:
        stdMath_MultiplyAddClamped(&player->podStats.airBrakeInv, value, 0.5f, 2.0f, 1000.0f);
        player->score_ptr->podStats.airBrakeInv = player->podStats.airBrakeInv;
        return;
    case 7:
        stdMath_MultiplyAddClamped(&player->podStats.deceleration_interval, value, 0.5f, 2.0f, 1000.0f);
        player->score_ptr->podStats.deceleration_interval = player->podStats.deceleration_interval;
        return;
    case 8:
        stdMath_MultiplyAddClamped(&player->podStats.boost_thrust, value, 1.0f, 10.0f, 1000.0f);
        player->score_ptr->podStats.boost_thrust = player->podStats.boost_thrust;
        return;
    case 9:
        stdMath_MultiplyAddClamped(&player->podStats.heatRate, value, 0.1f, 0.1f, 30.0f);
        player->score_ptr->podStats.heatRate = player->podStats.heatRate;
        return;
    case 10:
        stdMath_MultiplyAddClamped(&player->podStats.coolRate, value, 0.1f, 0.1f, 20.0f);
        player->score_ptr->podStats.coolRate = player->podStats.coolRate;
        return;
    case 11:
        stdMath_MultiplyAddClamped(&player->podStats.hoverHeight, value, 0.05f, 3.0f, 30.0f);
        player->score_ptr->podStats.hoverHeight = player->podStats.hoverHeight;
        return;
    case 12:
        stdMath_MultiplyAddClamped(&player->podStats.repairRate, value, 0.01f, 0.0f, 1.0f);
        player->score_ptr->podStats.repairRate = player->podStats.repairRate;
        return;
    case 13:
        stdMath_MultiplyAddClamped(&player->podStats.bumpMass, value, 0.1f, 1.0f, 100.0f);
        player->score_ptr->podStats.bumpMass = player->podStats.bumpMass;
        return;
    case 14:
        stdMath_MultiplyAddClamped(&player->podStats.damageImmunity, value, 0.01f, 0.0f, 1.0f);
        player->score_ptr->podStats.damageImmunity = player->podStats.damageImmunity;
        return;
    case 15:
        stdMath_MultiplyAddClamped(&player->collisionWidth, value, 0.05f, 0.05f, 20.0f);
        player->score_ptr->podStats.intersectRadius = player->collisionWidth;
        return;
    case 16:
        lookAhead = stdMath_Sqrt(player->aiLookAheadDistSq);
        stdMath_MultiplyAddClamped(&lookAhead, value, 1.0f, 10.0f, 500.0f);
        player->aiLookAheadDistSq = lookAhead * lookAhead;
        return;
    }
}

// 0x0042a580
int swrRace_GetDebugGameValueEntry(int index, char* nameOut, char* unk, int* c, float* d)
{
    swrRace* player;

    *unk = '\0';
    *c = -10000;
    *d = -10000.0f;
    switch (index) {
    case 0:
        sprintf(nameOut, "Debug Level");
        *c = swrRace_DebugLevel;
        return 1;
    case 1:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_INVINCIBILITY) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, swrRace_IsInvincible != 0 ? "Invincibility On" : "Invincibility Off");
        return 1;
    case 2:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_AI_TUNING) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, "AI Level x10");
        *d = swrRace_AILevel * 10.0f;
        return 1;
    case 3:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_AI_TUNING) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, "AI SPREAD");
        *d = ai_spread;
        return 1;
    case 4:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_AI_TUNING) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, "Death SpeedMin");
        *d = swrRace_DeathSpeedMin;
        return 1;
    case 5:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_AI_TUNING) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, "Death SpeedDrop");
        *d = swrRace_DeathSpeedDrop;
        return 1;
    case 6:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_SPLINE_MARKERS) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, debug_showSplineMarkers != 0 ? "Spline Markers On" : "Spline Markers Off");
        *d = -99999.0f;
        return 1;
    case 7:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_MIRROR_TOGGLE) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        sprintf(nameOut, (GameSettingFlags & GAME_SETTING_MIRROR) != 0 ? "Mirrored Mode On" : "Mirrored Mode Off");
        *d = -99999.0f;
        return 1;
    case 8:
        if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_EDIT_VEHICLE_STATS) == 0) {
            sprintf(nameOut, "------");
            return 1;
        }
        player = (swrRace*)swrEvent_FindObjectById('Test', swrRace_debugStatRacerId);
        if (player == NULL || (player->obj.flags & swrObj_FLAG_FREED) != 0)
            return 0;
        sprintf(nameOut, "Edit Vehicle Stats");
        return 1;
    default:
        sprintf(nameOut, "Unimplemented");
        return 0;
    }
}

// While a quit/restart confirmation is pending, rows 0-3 become the
// "Are you sure?" / Yes / No / blank prompt.
// 0x0042a840
int swrRace_InRace_EscMenu(int textIndex, char* textBuffer, char* unk, int* c, float* d)
{
    *unk = '\0';
    *c = -10000;
    *d = -10000.0f;
    switch (textIndex) {
    case 0:
        sprintf(textBuffer, swrText_Translate("/SCREENTEXT_535/~cContinue"));
        if (swrRace_escMenuConfirmPending != 0)
            sprintf(textBuffer, "~c%s", swrText_Translate("/SCREENTEXT_366/~~Are you sure?"));
        return 1;
    case 1:
        sprintf(textBuffer, swrText_Translate("/SCREENTEXT_536/~cRestart Race"));
        if (swrRace_escMenuConfirmPending != 0)
            sprintf(textBuffer, "~c%s", swrText_Translate("/SCREENTEXT_367/~~Yes"));
        return 1;
    case 2:
        sprintf(textBuffer, swrText_Translate("/SCREENTEXT_657/~cQuit Race"));
        if (swrRace_escMenuConfirmPending != 0)
            sprintf(textBuffer, "~c%s", swrText_Translate("/SCREENTEXT_368/~~No"));
        return 1;
    case 3:
        sprintf(textBuffer, swrText_Translate("/SCREENTEXT_658/~cQuit Game"));
        if (swrRace_escMenuConfirmPending != 0)
            textBuffer[0] = '\0'; // EXE sprintf's the empty string at 0x4d55cc
        return 1;
    case 4:
        if (swrRace_DebugMenu >= 1) {
            sprintf(textBuffer, "~cGame Cheats");
            return 1;
        }
        // fall through
    default:
        sprintf(textBuffer, "Unimplemented");
        return 0;
    }
}

// 0x0042a9f0
void swrRace_DebugSetGameValue(int id, float value)
{
    switch (id)
    {
    case 0:
        stdMath_AddScaledValueAndClamp_i32(&swrRace_DebugLevel, value, 1.0, 0, 6);
        return;
    case 1:
        if ((swrRace_DebugFlag & 4U) != 0)
        {
            swrRace_IsInvincible = (unsigned int)(swrRace_IsInvincible == 0);
            return;
        }
        break;
    case 2:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped((float*)&swrRace_AILevel, value, 0.001, 0.2, 2.0);
            return;
        }
        break;
    case 3:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&ai_spread, value, 0.5, 2.0, 200.0);
            return;
        }
        break;
    case 4:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&swrRace_DeathSpeedMin, value, 1.0, 20.0, 1000.0);
            return;
        }
        break;
    case 5:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&swrRace_DeathSpeedDrop, value, 1.0, 20.0, 500.0);
            return;
        }
        break;
    case 6:
        if ((swrRace_DebugFlag & 0x10U) != 0)
        {
            debug_showSplineMarkers = (unsigned int)(debug_showSplineMarkers == 0);
            return;
        }
        break;
    case 7:
        if ((swrRace_DebugFlag & 0x20U) != 0)
        {
            if ((GameSettingFlags & 0x4000) != 0)
            {
                GameSettingFlags = GameSettingFlags & 0xffffbfff;
                return;
            }
            GameSettingFlags = GameSettingFlags | 0x4000;
        }
    }
}

// 0x0042ab60
void swrRace_ActivateDebugGameValueEntry(int index)
{
    if (index == 8 && (swrRace_DebugFlag & swrRace_DEBUGFLAG_EDIT_VEHICLE_STATS) != 0)
        swrRace_PushDebugMenuState(swrRace_INRACEMENU_VEHICLE_STATS);
}

// 0x0042ab80
void swrRace_ActivateEscMenuEntry(int index)
{
    if (index == 0) {
        swrRace_inRaceMenuResult = swrRace_INRACEMENU_RESULT_CONTINUE;
        swrControl_uiInputActive = 1;
        swrRace_RequestUnpause();
    }
    if (index == 2) {
        if (swrRace_escMenuConfirmPending == 0) {
            swrRace_escMenuConfirmPending = 1;
            swrRace_escMenuConfirmAction = index;
            swrRace_inRaceMenuCursor = 1;
        } else {
            swrRace_escMenuConfirmPending = 0;
            swrRace_inRaceMenuCursor = swrRace_escMenuConfirmAction;
        }
    }
    if (index == 1) {
        if (swrRace_escMenuConfirmPending == 0) {
            swrControl_uiInputActive = 1;
            swrRace_inRaceMenuResult = swrRace_INRACEMENU_RESULT_RESTART;
            swrRace_RequestUnpause();
        } else if (swrRace_escMenuConfirmAction == 2) {
            swrControl_uiInputActive = 1;
            swrRace_inRaceMenuResult = swrRace_INRACEMENU_RESULT_QUIT_RACE;
            swrRace_RequestUnpause();
        } else if (swrRace_escMenuConfirmAction == 3) {
            Main_Shutdown();
            exit(0);
        }
    }
    if (index == 3 && swrRace_escMenuConfirmPending == 0) {
        swrRace_escMenuConfirmPending = 1;
        swrRace_escMenuConfirmAction = index;
        swrRace_inRaceMenuCursor = 1;
    }
    if (index == 4)
        swrRace_PushDebugMenuState(swrRace_INRACEMENU_DEBUG_VALUES);
}

// 0x0042ac70
int swrRace_GetInRaceMenuEntry(int index, char* nameOut, char* unk, int* c, float* d)
{
    if (DebugMenuState == swrRace_INRACEMENU_DEBUG_VALUES)
        return swrRace_GetDebugGameValueEntry(index, nameOut, unk, c, d);
    if (DebugMenuState == swrRace_INRACEMENU_VEHICLE_STATS)
        return swrRace_GetDebugVehicleStatEntry(index, nameOut, unk, c, d);
    if (DebugMenuState == swrRace_INRACEMENU_ESC)
        return swrRace_InRace_EscMenu(index, nameOut, unk, c, d);
    return (int)d; // EAX still holds d on this path in the EXE
}

// 0x0042acf0
void swrRace_AdjustDebugValue(unsigned int id, float delta)
{
    if (DebugMenuState == swrRace_INRACEMENU_DEBUG_VALUES)
        swrRace_DebugSetGameValue(id, delta);
    else if (DebugMenuState == swrRace_INRACEMENU_VEHICLE_STATS)
        swrRace_DebugSetVehicleStat(id, delta);
}

// 0x0042ad30
void swrRace_ActivateInRaceMenuEntry(int index)
{
    if (DebugMenuState == swrRace_INRACEMENU_DEBUG_VALUES) {
        swrRace_ActivateDebugGameValueEntry(index);
        return;
    }
    if (DebugMenuState == swrRace_INRACEMENU_ESC)
        swrRace_ActivateEscMenuEntry(index);
}

// 0x0042ad60
void swrRace_OpenInRaceMenu(void)
{
    swrObjJdge* jdge;

    // EXE loops 3x storing -1 to DebugMenuState (meant to reset the saved cursors)
    if (swrRace_inRaceMenuSavedCursor[0] == -2)
        DebugMenuState = -1;
    swrRace_inRaceMenuCursor = swrRace_inRaceMenuSavedCursor[0];
    swrRace_inRaceMenuResult = swrRace_INRACEMENU_RESULT_CONTINUE;
    swrRace_inRaceMenuStackDepth = 0;
    jdge = (swrObjJdge*)swrEvent_GetItem('Jdge', 0);
    if ((jdge->obj.flags & swrObj_FLAG_SLEEPING) != 0) {
        DebugMenuState = swrRace_INRACEMENU_DEBUG_VALUES;
        swrRace_inRaceMenuStateStack[swrRace_inRaceMenuStackDepth] = swrRace_INRACEMENU_DEBUG_VALUES;
        return;
    }
    swrRace_escMenuConfirmPending = 0;
    swrRace_inRaceMenuCursor = 0;
    DebugMenuState = swrRace_INRACEMENU_ESC;
    swrRace_inRaceMenuStateStack[swrRace_inRaceMenuStackDepth] = swrRace_INRACEMENU_ESC;
}

// 0x004376b0
int swrRace_GetLensFlareEnabled(void)
{
    return swrConfig_VIDEO_LENSFLARE;
}

// 0x0042adf0
int swrRace_GetInRaceMenuResult(void)
{
    return swrRace_inRaceMenuResult;
}

// 0x0042ae00
void swrRace_UpdateInRaceMenu(void)
{
    float scroll;
    float pulse;
    float floatValue = 0.0f;
    float r, g, b, a;
    int intValue = 0;
    int index;
    int row;
    int rowY;
    int x, y;
    char label[64] = { 0 };
    char help[256] = { 0 };
    char text[256];
    char line[256];

    // debug viewport test: step through the four 320x240 quadrants, 10 frames each
    if (swrViewport_force320x240 != 0) {
        if (--swrViewport_force320x240Timer > 0)
            return;
        swrViewport_force320x240Timer = 10;
        if (++swrViewport_force320x240Quadrant > 3)
            swrViewport_force320x240 = 0;
        return;
    }

    if (DebugMenuState != 2 && swrObjJdge_singleLocalViewport == 0)
        swrRace_blankWorldForMenu = 1;
    scroll = swrRace_GetPauseMenuScrollInOut();
    pulse = (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 0.25 + 0.75;

    // dev builds: input bits 0x1000, 0x800, 0x2000, 0x400 in order unlock the debug menu
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_DEV) && swrRace_DebugMenu <= 0 && inRaceLocalPlayerInputBitset1[0] != 0) {
        if (swrRace_DebugMenu == 0 && inRaceLocalPlayerInputBitset1[0] == 0x1000) {
            swrRace_DebugMenu = -1;
        } else if (swrRace_DebugMenu == -1 && inRaceLocalPlayerInputBitset1[0] == 0x800) {
            swrRace_DebugMenu = -2;
        } else if (swrRace_DebugMenu == -2 && inRaceLocalPlayerInputBitset1[0] == 0x2000) {
            swrRace_DebugMenu = -3;
        } else if (swrRace_DebugMenu == -3) {
            swrRace_DebugMenu = 1;
            if (inRaceLocalPlayerInputBitset1[0] != 0x400)
                swrRace_DebugMenu = 0;
        } else {
            swrRace_DebugMenu = 0;
        }
    }

    if (scroll >= 1.0f) {
        if (DebugMenuState == 2) {
            if (swrObjJdge_KeyDownForPlayer1Or2(0x4000)) {
                if (--swrRace_inRaceMenuCursor < 0)
                    swrRace_inRaceMenuCursor = 0;
                else
                    swrSound_Play2D(0x55, 6, 0.25f, 1.0f, 0);
            }
            if (swrObjJdge_KeyDownForPlayer1Or2(0x8000)) {
                swrRace_inRaceMenuCursor++;
                if (!swrRace_GetInRaceMenuEntry(swrRace_inRaceMenuCursor, label, help, &intValue, &floatValue))
                    swrRace_inRaceMenuCursor--;
                else
                    swrSound_Play2D(0x55, 6, 0.25f, 1.0f, 0);
            }
            swrControl_uiInputActive = 0;
            if (swrControl_acceptPressedEdge != 0) {
                swrControl_menuAcceptPressedEdge = 0;
                swrControl_acceptPressedEdge = 0;
                swrRace_ActivateInRaceMenuEntry(swrRace_inRaceMenuCursor);
            }
            if (swrControl_cancelPressedEdge != 0) {
                if (DebugMenuState == 2)
                    swrRace_inRaceMenuCursor = 0;
                swrRace_ActivateInRaceMenuEntry(swrRace_inRaceMenuCursor);
            }
        } else {
            // up past the top wraps to the last row
            if (((inRaceLocalPlayerInputBitset1[0] & 4) || (inRaceLocalPlayerInputBitset1[0] & 0x4000)) && --swrRace_inRaceMenuCursor < 0) {
                swrRace_inRaceMenuCursor = 0;
                while (swrRace_GetInRaceMenuEntry(swrRace_inRaceMenuCursor, label, help, &intValue, &floatValue))
                    swrRace_inRaceMenuCursor++;
                swrRace_inRaceMenuCursor--;
            }
            if ((inRaceLocalPlayerInputBitset1[0] & 8) || (inRaceLocalPlayerInputBitset1[0] & 0x8000)) {
                swrRace_inRaceMenuCursor++;
                if (!swrRace_GetInRaceMenuEntry(swrRace_inRaceMenuCursor, label, help, &intValue, &floatValue))
                    swrRace_inRaceMenuCursor = 0;
            }
            if (inRaceLocalPlayerInputBitset1[0] & 0x20)
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, 1.0f);
            if (inRaceLocalPlayerInputBitset1[0] & 0x10)
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, -1.0f);
            if (inRaceLocalPlayerInputBitset1[0] & 0x1000)
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, -1.0f);
            if ((inRaceLocalPlayerInputBitset1[0] & 0x2000) || (inRaceLocalPlayerInputBitset1[0] & 1))
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, 1.0f);
            if (inRaceLocalPlayerInputBitset1[0] & 0x400)
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, 10.0f);
            if (inRaceLocalPlayerInputBitset1[0] & 0x800)
                swrRace_AdjustDebugValue(swrRace_inRaceMenuCursor, -10.0f);
            if (inRaceLocalPlayerInputBitset1[0] & 1)
                swrRace_ActivateInRaceMenuEntry(swrRace_inRaceMenuCursor);
            if (inRaceLocalPlayerInputBitset1[0] & 0x200)
                swrRace_RequestUnpause();
            if (inRaceLocalPlayerInputBitset1[0] & 2)
                swrRace_PopDebugMenuState();
        }
    }

    // the "Are you sure?" prompt only has rows 1 and 2
    if (swrRace_escMenuConfirmPending != 0) {
        if (swrRace_inRaceMenuCursor < 1)
            swrRace_inRaceMenuCursor = 1;
        if (swrRace_inRaceMenuCursor > 2)
            swrRace_inRaceMenuCursor = 2;
    }

    for (index = 0, row = 0x42, rowY = 0; row < 0x162; index++, row += 0xc, rowY += 0xe) {
        if (!swrRace_GetInRaceMenuEntry(index, label, help, &intValue, &floatValue))
            continue;
        // value sentinels: float <= -9999.99 means "no float", int < -9999 means "no int"
        if (floatValue < -9999.99 && intValue < -9999)
            sprintf(text, swrText_Translate("~s%s\n"), label);
        else if (floatValue > -9999.99)
            sprintf(text, swrText_Translate("~s%s: %.2f\n"), label, (double)floatValue);
        else
            sprintf(text, swrText_Translate("~s%s: %d\n"), label, intValue);

        if (row < 0xd2) {
            x = 0x19;
            y = rowY + 0x14;
        } else {
            x = 0xa5;
            y = rowY - 0x78;
        }
        r = 255.0f;
        b = 255.0f;
        if (index == swrRace_inRaceMenuCursor) {
            r = 0.0f;
            b = 55.0f;
        }

        if (DebugMenuState == 2) {
            x = 0xa0;
            y = row;
            scroll = swrRace_GetPauseMenuScrollInOut();
            if (scroll > 0.0f) {
                a = scroll * 255.0f;
                if (index == swrRace_inRaceMenuCursor) {
                    r = pulse * 255.0f;
                    g = pulse * 250.0f;
                    b = pulse * 50.0f;
                } else {
                    r = 170.0f;
                    g = 160.0f;
                    b = 0.0f;
                }
                sprintf(line, "%s", text);
                swrText_CreateEntry2(0xa0, row, (int)r, (int)g, (int)b, (int)a, line);
            }
        } else {
            sprintf(line, swrText_Translate("~f4%s"), text);
            swrText_CreateTextEntry1(x, y, (int)r, -1, (int)b, -1, line);
            if (index != swrRace_inRaceMenuCursor)
                continue;
            if (help[0] != '\0') {
                sprintf(line, swrText_Translate("~s%s\n"), help);
                swrText_CreateTextEntry1(x + 0x82, y - 0x1e, 0, -1, -0x80, -1, line);
            }
        }
        // faithful: on the debug pages the help line was already queued above, so it is drawn twice
        if (index == swrRace_inRaceMenuCursor && help[0] != '\0') {
            sprintf(line, swrText_Translate("~s%s\n"), help);
            swrText_CreateTextEntry1(x + 0x82, y - 0x1e, 0, -1, -0x80, -1, line);
        }
    }
    swrRace_inRaceMenuSavedCursor[DebugMenuState] = swrRace_inRaceMenuCursor;
}

// 0x00435700
void swrRace_SelectVehicle(swrObjHang* hang)
{
    char text[256];
    rdMatrix44 m;
    rdVector3 unusedEye;
    int reload;
    int i;
    int prevItem;
    int width;
    int pick;
    float animTime;
    float pitch;
    float yaw;
    float roll;
    char* lastname;
    char* name;

    reload = 0;
    if (swrObjHang_menuJustEntered) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_UpdateUICameraPlacements(157.0f);
        swrRace_vehicleSelectEntered = 0;
        swrRace_vehicleSelectStep = 0;
        swrObjHang_settledMenuItem = 0;
        swrRace_vehicleSelectLoadedRacer = -1;
        swrRace_vehicleSelectShowStats = 1;
        swrObjHang_FocusMenuItem(hang, 0x24, ~swrObjHang_STATE_LEGAL, 0);
        swrRace_BuildPartMenuList(hang);
        swrRace_MenuSelectedItem = 0;
        for (i = 0; i < swrRace_MenuMaxSelection; i++) {
            if (swrRace_SelectIndex[i].racerId == (signed char)swrRace_aProfiles[hang->current_player_for_vehicle_selection].pilotId) {
                swrRace_MenuSelectedItem = i;
                break;
            }
        }
        swrObjHang_ComputeUpgradedStats(swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId, -1, 0, -1);
        swrObjHang_InitTrackSprites(hang, 0);
        swrRace_PodRotationAnimation = 360.0f;
    }

    if (swrObjHang_cameraMoveMode != 0)
        return;

    swrRace_SelectedRacer = swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId;
    if (swrRace_Transition > 0.0f) {
        animTime = 0.025f - (float)swrRace_SelectIndex[swrObjHang_settledMenuItem].racerId * -0.05f;
        swrModel_AnimationsSetSettings(swr_sceneAnimations[INGAME_MODELID_flag2_part], animTime, animTime, animTime, false, 0.0f, 0.0f);
        // the EXE pushes swrObjHang_settledMenuItem, which the callee ignores
        swrObjHang_AnimateTransitionNode();
    } else if (swrRace_SelectedRacer != -1) {
        animTime = 0.025f - (float)swrRace_SelectedRacer * -0.05f;
        swrModel_AnimationsSetSettings(swr_sceneAnimations[INGAME_MODELID_flag2_part], animTime, animTime, animTime, false, 0.0f, 0.0f);
    }

    if (swrRace_vehicleSelectStep == 5 && swrObjHang_StepTransition(-3.3f) == 0.0f) {
        swrObjElmo_SetAnimStateById(SWR_SCENE_SLOT_PILOT_PUPPETS, 0);
        swrRace_SaveCurrentProfile();
        if (swrMultiplayer_enabled != 0) {
            swrUI_PopMenuPage();
            return;
        }
        swrObjHang_SetMenuState(hang, swrObjHang_state2);
        return;
    }

    if (swrRace_vehicleSelectStep == 0) {
        swrObjHang_vehicleStatsFade = swrObjHang_vehicleStatsFade - swrRace_fdeltaTimeSecs * 3.3f;
        if (swrObjHang_vehicleStatsFade < 0.0f)
            swrObjHang_vehicleStatsFade = 0.0f;
        if (swrRace_vehicleSelectShowStats != 0)
            swrObjHang_VehicleStatisticsSubMenu(hang, 105.0f, 135.0f);
    }

    swrText_CreateColorlessEntry1(0xa0, 0x19, swrText_Translate("/SCREENTEXT_525/~c~sSelect Vehicle"));
    lastname = swrText_Translate(swrRacer_PodData[swrRace_SelectedRacer].lastname);
    name = swrText_Translate(swrRacer_PodData[swrRace_SelectedRacer].name);
    sprintf(text, swrText_Translate("~c~s%s %s"), name, lastname);
    swrText_CreateTextEntry1(0xa0, 0x2a, 0, -1, 0, -1, text);
    swrText_GetStringWidthByFont(text, 0);
    width = swrText_GetStringWidthByFont(text, 0);
    swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - (double)width * 0.5), 0x2b);
    hang->flag |= 4;

    if (swrObjHang_menuRepeatCount == 0 && swrRace_vehicleSelectLoadedRacer != swrRace_SelectIndex[swrObjHang_settledMenuItem].racerId)
        reload = 1;
    if (swrRace_SelectedRacer != -1 && (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS] == NULL || reload)) {
        swrModel_ClearSceneAnimations();
        swrObjHang_CullElmoAssets(3);
        swrRace_PodRotationAnimation = 0.0f;
        swrModel_LoadModelIntoScene(swrRacer_PodData[swrRace_SelectedRacer].pod_modelID, swrRacer_PodData[swrRace_SelectedRacer].pod_alt_modelID, (INGAME_MODELID)SWR_SCENE_SLOT_POD_MODELS, false);
        if (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS] != NULL) {
            swrObjHang_RequestDisplayPodReset();
            swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[0x3c].value = swrRace_SelectedRacer;
            swrModel_LoadPuppet(swrRacer_PodData[swrRace_SelectedRacer].puppet_modelId, (INGAME_MODELID)SWR_SCENE_SLOT_PILOT_PUPPETS, swrObjElmo_KIND_PILOT, swrRacer_PodData[swrRace_SelectedRacer].float20);
        }
        swrRace_vehicleSelectLoadedRacer = swrRace_SelectedRacer;
        swrModel_ReloadAnimations();
        swrObjHang_UpdatePitDroidAnims(hang);
        swrObjHang_ComputeUpgradedStats(swrRace_SelectedRacer, -1, -1, -1);
    }

    if (swrRace_vehicleSelectEntered == 0)
        swrRace_vehicleSelectEntered = 1;
    swrRace_PodRotationAnimation = swrRace_PodRotationAnimation - swrRace_fdeltaTimeSecs * -90.0f;
    if (swrRace_PodRotationAnimation > 1800.0f)
        swrRace_PodRotationAnimation = swrRace_PodRotationAnimation - 1800.0f;
    if (swrRace_vehicleSelectStep == 1 && swrObjHang_StepTransition(-3.3f) == 0.0f)
        swrRace_vehicleSelectStep = 2;

    swrRace_vehicleSelectPodScale = swrRace_Transition * 4.0f;
    if (swrRace_vehicleSelectPodScale < 0.001f)
        swrRace_vehicleSelectPodScale = 0.001f;

    if (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS] != NULL && swrRace_Transition > 0.0f) {
        swrObjHang_UpdateHoloBillboardMatrix();
        if (swrRace_PodRotationAnimation < 540.0f) {
            pitch = 100.08f - swrObjHang_CosineEase(swrRace_PodRotationAnimation, 540.0f);
            yaw = 0.0f;
            roll = 0.0f;
        } else if (swrRace_PodRotationAnimation < 900.0f) {
            pitch = 100.08f;
            yaw = 180.0f;
            roll = 180.0f - swrObjHang_CosineEase(swrRace_PodRotationAnimation - 540.0f, 360.0f);
        } else if (swrRace_PodRotationAnimation < 1440.0f) {
            pitch = 280.08002f - swrObjHang_CosineEase(swrRace_PodRotationAnimation - 900.0f, 540.0f);
            yaw = 0.0f;
            roll = 0.0f;
        } else {
            pitch = 100.08f;
            yaw = 0.0f;
            roll = -swrObjHang_CosineEase(swrRace_PodRotationAnimation - 1440.0f, 360.0f);
        }
        rdMatrix_SetRotation44(&m, pitch, yaw, roll);
        rdVector_Copy3((rdVector3*)&m.vD, &swrObjHang_cameraPlacements[0x24].position2);
        swrRace_vehicleSelectPodScale = swrRace_vehicleSelectPodScale * 0.5f;
        rdVector_Scale3Add3_both((rdVector3*)&m.vD, 0.5f, &swrObjHang_cameraPlacements[0x24].position2, 0.5f, &swrObjHang_cameraPlacements[0x24].position1);
        swrRace_AnimateDisplayPod((swrModel_Node**)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS], &m, 1, swrRace_vehicleSelectPodScale, swrRace_vehicleSelectPodScale, swrRace_vehicleSelectPodScale, -1157.0f, 0, 1.0f, 1.0f);
        if (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[0x3b].node != NULL)
            swrModel_NodeModifyFlags(swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[0x3b].node, 2, 3, 0x10, 2);
    }

    if (swrRace_vehicleSelectStep != 0) {
        if (swrRace_Transition == 0.0f)
            swrRace_vehicleSelectStep++;
        return;
    }

    for (i = hang->current_player_for_vehicle_selection; i < hang->current_player_for_vehicle_selection + 1; i++) {
        if (swrObjHang_cameraMoveMode != 0)
            break;
        prevItem = swrRace_MenuSelectedItem;
        swrObjHang_NavigateVehicleSelect(i, 1.0f, 1);
        if (prevItem != swrRace_MenuSelectedItem)
            swrObjHang_ComputeUpgradedStats(swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId, -1, 0, -1);
        if (swrRace_Transition >= 1.0f && swrControl_cancelPressedEdge != 0) {
            swrUI_PopMenuPage();
            swrSound_PlayUISound(0x4d);
            if (hang->menuScreenPrev == swrObjHang_STATE_MAIN_MENU) {
                swrObjHang_state2 = swrObjHang_STATE_MAIN_MENU;
                swrRace_vehicleSelectStep = 1;
                return;
            }
            swrSound_PlayUISound(0x4d);
            if (hang->current_player_for_vehicle_selection > 0) {
                swrRace_vehicleSelectStep = 1;
                hang->current_player_for_vehicle_selection--;
                swrObjHang_state2 = swrObjHang_STATE_SELECT_VEHICLE;
                return;
            }
            swrRace_vehicleSelectSaveSlot = 0;
            swrRace_vehicleSelectStep = 1;
            swrRace_vehicleSelectLoadedRacer = -1;
            swrObjHang_state2 = swrObjHang_STATE_SPLASH;
            swrObjHang_fadeState = -1;
            swrRace_SaveCurrentProfile();
            return;
        }
        if (swrRace_Transition >= 1.0f && swrControl_menuAcceptPressedEdge != 0) {
            swrSound_PlayUISound(0x54);
            swrRace_vehicleSelectStep = 1;
        }
        if (swrUI_localPlayersInputPressedBitset[i] & 8) {
            swrSound_PlayUISound(0x54);
            swrRace_vehicleSelectShowStats = swrRace_vehicleSelectShowStats == 0;
        }
    }

    if (swrRace_vehicleSelectStep == 1) {
        swrObjHang_UpdateUICameraPlacements(swrRacer_PodData[swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId].float20);
        for (i = hang->current_player_for_vehicle_selection; i < hang->current_player_for_vehicle_selection + 1; i++) {
            (&hang->vehiclePlayer)[i] = (char)swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId;
            pick = swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId;
            swrRace_aProfiles[i].pilotId = (uint8_t)pick;
            if (swrRace_vehicleSelectSaveSlot < ELFSAVE_NB_PROFILE_SLOTS) {
                if (swrRace_saveData.profiles[swrRace_vehicleSelectSaveSlot].name[0] == 0) {
                    swrRace_aProfiles[i].nbPitDroids = 1;
                    swrRace_aProfiles[i].truguts = ELFSAVE_DEFAULT_TRUGUTS;
                } else {
                    swrRace_saveData.profiles[swrRace_vehicleSelectSaveSlot].pilotId = (uint8_t)pick;
                }
            }
            if (swrMultiplayer_IsMultiplayerEnabled())
                swrMultiplayer_RacerPick(swrRace_SelectIndex[swrRace_MenuSelectedItem].racerId);
        }
        swrObjHang_GenerateJunkyardStock(hang);
        if (hang->menuScreenPrev == swrObjHang_STATE_MAIN_MENU) {
            swrObjHang_state2 = swrObjHang_STATE_MAIN_MENU;
            return;
        }
        // faithful: the slot's name is read before the bounds check
        if (swrRace_saveData.profiles[swrRace_vehicleSelectSaveSlot].name[0] == 0 && swrRace_vehicleSelectSaveSlot < ELFSAVE_NB_PROFILE_SLOTS) {
            swrObjHang_state2 = swrObjHang_STATE_ENTER_NAME;
            return;
        }
        if (hang->current_player_for_vehicle_selection < hang->num_local_players - 1) {
            hang->current_player_for_vehicle_selection++;
            swrObjHang_state2 = swrObjHang_STATE_SELECT_VEHICLE;
            return;
        }
        swrObjHang_state2 = swrObjHang_STATE_SELECT_PLANET;
        // dead copy, but the swrUtils_Rand draw advances the RNG
        rdVector_Copy3(&unusedEye, &swrObjElmo_waypoints[9 + hang->unk50]);
        swrUtils_Rand();
        return;
    }
    if (swrRace_vehicleSelectStep == 2)
        swrRace_vehicleSelectStep = 3;
}

// 0x004368a0
void swrObjHang_MainMenu(swrObjHang* hang)
{
    HangRoom targetRoom = HangRoom_None;
    rdVector3 toEye;
    rdMatrix44 orbit;
    char text[32];
    char* label;
    float distance;
    int moved;
    char count;
    char i;
    char player;

    swrObjHang_mainMenuChangeVehicle = 0;
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_TRACK)
            hang->mainMenuSelection = 0;
        // recover the orbit angles/distance from the current camera
        rdVector_Sub3(&toEye, (rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        swrObjHang_orbitDistance = rdVector_Len3(&toEye);
        rdVector_Normalize3Acc(&toEye);
        swrObjHang_orbitYaw = stdMath_ArcTan2(-toEye.x, toEye.y);
        swrObjHang_orbitPitch = stdMath_ArcSin(toEye.z);
        if (swrObjHang_orbitYaw < 0.0f)
            swrObjHang_orbitYaw = swrObjHang_orbitYaw - -360.0f;
        if (swrObjHang_orbitYaw > 360.0f)
            swrObjHang_orbitYaw = swrObjHang_orbitYaw - 360.0f;
        if (swrObjHang_orbitPitch < -90.0f)
            swrObjHang_orbitPitch = swrObjHang_orbitPitch - -180.0f;
        if (swrObjHang_orbitPitch > 90.0f)
            swrObjHang_orbitPitch = swrObjHang_orbitPitch - 180.0f;

        memset(swrObjHang_mainMenuItems, -1, sizeof(swrObjHang_mainMenuItems));
        swrObjHang_mainMenuItems[0] = swrObjHang_MAINMENU_START_RACE;
        count = 1;
        swrObjHang_mainMenuItemCount = count;
        if (hang->num_local_players == 1) {
            swrObjHang_mainMenuItems[1] = swrObjHang_MAINMENU_INSPECT_VEHICLE;
            count = 2;
            swrObjHang_mainMenuItemCount = count;
        }
        if (hang->isTournamentMode != 0) {
            swrObjHang_mainMenuItems[count++] = swrObjHang_MAINMENU_VEHICLE_UPGRADES;
            swrObjHang_mainMenuItems[count++] = swrObjHang_MAINMENU_BUY_PARTS;
            swrObjHang_mainMenuItems[count++] = swrObjHang_MAINMENU_JUNKYARD;
            if ((unsigned char)swrRace_nbPitDroids < SWR_MAX_PIT_DROIDS)
                swrObjHang_mainMenuItems[count++] = swrObjHang_MAINMENU_BUY_PIT_DROIDS;
        }
        swrObjHang_mainMenuItems[count++] = swrObjHang_MAINMENU_CHANGE_VEHICLE;
        swrObjHang_mainMenuItemCount = count;
    }

    swrText_CreateColorlessEntry1(0xa0, 0x19, swrText_Translate(g_pTxtMainMenu));
    for (i = 0; i < swrObjHang_mainMenuItemCount; i++) {
        label = NULL;
        switch (swrObjHang_mainMenuItems[i]) {
        case swrObjHang_MAINMENU_START_RACE:
            label = g_pTxtStartRace;
            break;
        case swrObjHang_MAINMENU_INSPECT_VEHICLE:
            label = g_pTxtInspectVehicle;
            break;
        case swrObjHang_MAINMENU_VEHICLE_UPGRADES:
            label = g_pTxtVehicleUpgrades;
            break;
        case swrObjHang_MAINMENU_BUY_PARTS:
            label = g_pTxtBuyParts;
            break;
        case swrObjHang_MAINMENU_JUNKYARD:
            label = g_pTxtJunkyard;
            break;
        case swrObjHang_MAINMENU_BUY_PIT_DROIDS:
            label = g_pTxtBuyPitDroids;
            break;
        case swrObjHang_MAINMENU_CHANGE_VEHICLE:
            label = g_pTxtChangeVehicle;
            break;
        case swrObjHang_MAINMENU_OPTIONS:
            label = g_pTxtOptions;
            break;
        }
        // faithful: an unknown item keeps the previous row's text (the buffer is not cleared)
        if (label != NULL)
            sprintf(text, swrText_Translate(label));
        swrUI_Front_TextMenu(hang, 0x3c, 0x50, 10, hang->mainMenuSelection, i, text);
    }

    for (player = 0; player < hang->num_local_players; player++) {
        if (swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_DOWN) {
            hang->mainMenuSelection++;
            if (hang->mainMenuSelection > swrObjHang_mainMenuItemCount - 1)
                hang->mainMenuSelection = 0;
            swrSound_PlayUISound(0x58);
        }
        if (swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_UP) {
            hang->mainMenuSelection--;
            if (hang->mainMenuSelection < 0)
                hang->mainMenuSelection = swrObjHang_mainMenuItemCount - 1;
            swrSound_PlayUISound(0x58);
        }

        // Alt/Shift + stick orbits the camera around the pod
        if (stdControl_ReadKey(DIK_LMENU, NULL) != 0 || stdControl_ReadKey(DIK_RMENU, NULL) != 0 || stdControl_ReadKey(DIK_LSHIFT, NULL) != 0 || stdControl_ReadKey(DIK_RSHIFT, NULL) != 0) {
            distance = swrObjHang_orbitDistance;
            moved = 0;
            swrObjHang_cameraMoveMode = 0;
            if (swrControl_aPlayerAxisX[player] > 0.1f || swrControl_aPlayerAxisX[player] < -0.1f) {
                moved = 1;
                swrObjHang_orbitYaw = swrObjHang_orbitYaw - swrControl_aPlayerAxisX[player] * swrRace_fdeltaTimeSecs * 105.0f;
            }
            if (swrControl_aPlayerAxisY[player] > 0.1f || swrControl_aPlayerAxisY[player] < -0.1f) {
                swrObjHang_orbitPitch = swrObjHang_orbitPitch - swrControl_aPlayerAxisY[player] * swrRace_fdeltaTimeSecs * -67.5f;
                if (swrObjHang_orbitPitch > 45.0f)
                    swrObjHang_orbitPitch = 45.0f;
                if (swrObjHang_orbitPitch < -45.0f)
                    swrObjHang_orbitPitch = -45.0f;
                moved = 1;
            }
            if (moved) {
                rdMatrix_SetRotation44(&orbit, swrObjHang_orbitYaw, swrObjHang_orbitPitch, 0.0f);
                rdVector_Scale3Add3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD, -swrObjHang_orbitDistance, (rdVector3*)&orbit.vB);
                // faithful: the distance is never changed above, so this never recomputes
                if (swrObjHang_orbitDistance != distance)
                    swrObjHang_orbitDistance = rdVector_Dist3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
                rdMatrix_Copy44(&swrObjHang_cameraMatrixStart, &swrObjHang_cameraMatrix);
            }
        }

        if (swrControl_cancelPressedEdge != 0) {
            swrSound_PlayUISound(0x4d);
            targetRoom = Cantina;
            swrObjHang_state2 = swrObjHang_STATE_SELECT_TRACK;
        }
        if (swrControl_menuAcceptPressedEdge == 0)
            continue;

        swrSound_PlayUISound(0x54);
        if (hang->mainMenuSelection == 0) {
            targetRoom = HangRoom_None;
            swrControl_StopAllForceEffects(0);
            swrControl_LoadForceEffects(-1);
            swrControl_LoadForceEffects(0);
            swrSound_PreloadSoundSet(g_aTrackInfos[hang->track_index].PlanetIdx, g_aTrackInfos[hang->track_index].planetTrackNumber);
            if (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) {
                if (hang->isTournamentMode != 0 && (uint8_t)swrRace_UnlockDataBase[0] != g_aTrackInfos[hang->track_index].FavoritePilot && swrControl_slideButton != 0.0f && swrObjHang_skipTournamentIntro == 0)
                    swrObjHang_state2 = swrObjHang_STATE_TAUNT_SCENE;
                swrObjHang_fadeState = -1;
                if (swrUtils_Compare3Chars(swrRace_aProfiles[0].name, swrObjHang_creditsCheatInitials) != 0 && (swrUI_localPlayersInputDownBitset[0] & 0x4) != 0)
                    swrObjHang_SelectCreditsTracks(hang);
                swrMultiplayer_BroadcastRaceReset();
                return;
            }
            continue;
        }

        switch (swrObjHang_mainMenuItems[hang->mainMenuSelection]) {
        case swrObjHang_MAINMENU_INSPECT_VEHICLE:
            swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
            targetRoom = Hangar;
            hang->activeMenu = 0;
            swrUI_ResetMenuInputBitsets();
            break;
        case swrObjHang_MAINMENU_VEHICLE_UPGRADES:
            swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
            targetRoom = Hangar;
            hang->activeMenu = 1;
            swrUI_ResetMenuInputBitsets();
            break;
        case swrObjHang_MAINMENU_BUY_PARTS:
            swrObjHang_state2 = swrObjHang_STATE_WATTO;
            targetRoom = Shop;
            hang->activeMenu = 0;
            break;
        case swrObjHang_MAINMENU_JUNKYARD:
            targetRoom = Junkyard;
            swrObjHang_state2 = swrObjHang_STATE_JUNKYARD;
            break;
        case swrObjHang_MAINMENU_BUY_PIT_DROIDS:
            swrObjHang_state2 = swrObjHang_STATE_WATTO;
            targetRoom = Shop;
            hang->activeMenu = 1;
            break;
        case swrObjHang_MAINMENU_CHANGE_VEHICLE:
            swrObjHang_state2 = swrObjHang_STATE_SELECT_VEHICLE;
            hang->current_player_for_vehicle_selection = player;
            targetRoom = Cantina;
            swrObjHang_mainMenuChangeVehicle = 1;
            break;
        case swrObjHang_MAINMENU_OPTIONS:
            hang->activeMenu = 1;
            return;
        }
    }

    if (targetRoom != HangRoom_None) {
        if (hang->room == targetRoom) {
            swrObjHang_SetMenuState(hang, swrObjHang_state2);
            return;
        }
        swrObjHang_fadeState = -1;
    }
}

// Held left/right slides a 0..255 volume at 255 per second
static uint8_t stepMenuVolume(uint8_t volume, int held)
{
    double level;

    if ((held & swrUI_INPUT_MENU_RIGHT) != 0 && volume < 0xff) {
        level = volume + swrRace_fdeltaTimeSecs * 255.0;
        volume = level > 255.0 ? 0xff : (uint8_t)(int)level;
    }
    if ((held & swrUI_INPUT_MENU_LEFT) != 0 && volume > 0) {
        level = volume - swrRace_fdeltaTimeSecs * 255.0;
        volume = level < 0.0 ? 0 : (uint8_t)(int)level;
    }
    return volume;
}

// 0x00436fa0
void swrRace_AudioVideoSettings(swrObjHang* hang)
{
    uint8_t* musicVolume = (uint8_t*)&sound_music_volume; // the page only ever touches the low byte
    int done;
    int player;
    short id;

    done = 0;
    id = swrRace_menuSpriteCount + 0x82;
    swrRace_menuSpriteCount++;
    swrRace_audioVideoMenuX = 165.0f;
    swrRace_audioVideoMenuY = 70.0f;
    if (*musicVolume == 0) {
        swrUI_Front_TextMenu(hang, 0xa5, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 0, swrText_Translate("/SCREENTEXT_91/~sOFF"));
    } else {
        swrSprite_SetVisible(id, 1);
        swrSprite_SetPos(id, (short)(int)swrRace_audioVideoMenuX, (short)(int)swrRace_audioVideoMenuY);
        swrSprite_SetDim(id, 0.125f - (float)*musicVolume * -0.039215688f, 1.0f);
        swrSprite_SetColor(id, 0x32, 0xff, 0xff, 0xff);
        swrSprite_AddDirtyRect((short)(int)(swrRace_audioVideoMenuX - 2.0f), (short)(int)(swrRace_audioVideoMenuY - 2.0f), (short)(int)(swrRace_audioVideoMenuX - -84.0f), (short)(int)(swrRace_audioVideoMenuY - -12.0f));
    }
    swrUI_Front_TextMenu(hang, 0x9b, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 0, swrText_Translate("/SCREENTEXT_81/~r~sMusic:"));

    id = swrRace_menuSpriteCount + 0x82;
    swrRace_menuSpriteCount++;
    if (sound_sfx_volume == 0) {
        swrUI_Front_TextMenu(hang, 0xa5, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 1, swrText_Translate("/SCREENTEXT_91/~sOFF"));
    } else {
        swrSprite_SetVisible(id, 1);
        swrSprite_SetPos(id, (short)(int)swrRace_audioVideoMenuX, (short)(int)(swrRace_audioVideoMenuY - -15.0f));
        swrSprite_SetDim(id, 0.125f - (float)sound_sfx_volume * -0.039215688f, 1.0f);
        swrSprite_SetColor(id, 0x32, 0xff, 0xff, 0xff);
        swrSprite_AddDirtyRect((short)(int)(swrRace_audioVideoMenuX - 2.0f), (short)(int)(swrRace_audioVideoMenuY - -15.0f - 2.0f), (short)(int)(swrRace_audioVideoMenuX - -84.0f), (short)(int)(swrRace_audioVideoMenuY - -27.0f));
    }
    swrUI_Front_TextMenu(hang, 0x9b, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 1, swrText_Translate("/SCREENTEXT_82/~r~sSound:"));

    swrUI_Front_TextMenu(hang, 0x9b, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 2, swrText_Translate("/SCREENTEXT_83/~r~sAudio:"));
    swrUI_Front_TextMenu(hang, 0xa5, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 2, swrText_Translate((swrRace_saveData.unlockFlags & swrSaveData_OPTION_STEREO) != 0 ? "/SCREENTEXT_84/~sSTEREO" : "/SCREENTEXT_85/~sMONO"));
    swrUI_Front_TextMenu(hang, 0x9b, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 3, swrText_Translate("/SCREENTEXT_89/~r~sLens flares:"));
    swrUI_Front_TextMenu(hang, 0xa5, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 3, swrText_Translate((swrRace_saveData.unlockFlags & swrSaveData_OPTION_LENS_FLARES) != 0 ? "/SCREENTEXT_90/~sON" : "/SCREENTEXT_91/~sOFF"));
    swrUI_Front_TextMenu(hang, 0x9b, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 4, swrText_Translate("/SCREENTEXT_467/~r~sResolution:"));
    swrUI_Front_TextMenu(hang, 0xa5, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 4, swrText_Translate((swrRace_saveData.unlockFlags & swrSaveData_OPTION_HIRES) != 0 ? "/SCREENTEXT_468/~sHi-res" : "/SCREENTEXT_469/~sLo-res"));
    swrUI_Front_TextMenu(hang, 0xa0, (int)swrRace_audioVideoMenuY, 0xf, swrRace_audioVideoMenuRow, 5, swrText_Translate("/SCREENTEXT_92/~c~sExit"));

    for (player = 0; player < hang->num_local_players; player++) {
        if (swrControl_menuAcceptPressedEdge != 0) {
            swrSound_PlayUISound(0x4d);
            done = 1;
        }
        if (swrControl_cancelPressedEdge != 0) {
            swrSound_PlayUISound(0x4d);
            done = 1;
        }
        if (done) {
            swrRace_SaveCurrentProfile();
            hang->activeMenu = 0;
            return;
        }
        if ((swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_DOWN) != 0) {
            swrRace_audioVideoMenuRow++;
            if (swrRace_audioVideoMenuRow > swrRace_audioVideoMenuLastRow) {
                swrRace_audioVideoMenuRow = 0;
            }
            swrSound_PlayUISound(0x58);
        }
        if ((swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_UP) != 0) {
            swrRace_audioVideoMenuRow--;
            if (swrRace_audioVideoMenuRow < 0) {
                swrRace_audioVideoMenuRow = swrRace_audioVideoMenuLastRow;
            }
            swrSound_PlayUISound(0x58);
        }
        if ((swrUI_localPlayersInputPressedBitset[player] & (swrUI_INPUT_MENU_LEFT | swrUI_INPUT_MENU_RIGHT)) != 0) {
            if (swrRace_audioVideoMenuRow == 2) {
                swrRace_saveData.unlockFlags ^= swrSaveData_OPTION_STEREO;
            }
            if (swrRace_audioVideoMenuRow == 3) {
                swrRace_saveData.unlockFlags ^= swrSaveData_OPTION_LENS_FLARES;
            }
            if (swrRace_audioVideoMenuRow == 4) {
                swrRace_saveData.unlockFlags ^= swrSaveData_OPTION_HIRES;
            }
            if (swrRace_audioVideoMenuRow >= 2 && swrRace_audioVideoMenuRow != 5) {
                swrSound_PlayUISound(0x58);
            }
        }
        if (swrRace_audioVideoMenuRow == 0) {
            *musicVolume = stepMenuVolume(*musicVolume, swrUI_localPlayersInputDownBitset[player]);
            swrSound_Play2D(0x9b, 6, 0.25f, 1.0f, 1);
        } else if (swrRace_audioVideoMenuRow == 1) {
            sound_sfx_volume = stepMenuVolume(sound_sfx_volume, swrUI_localPlayersInputDownBitset[player]);
            swrSound_Play2D(0x4f, 6, 0.125f, 1.0f, 1);
        }
    }
}

// 0x004396d0
void swrObjHang_LookAtVehicleMenu(swrObjHang* hang)
{
    char text[48];
    rdMatrix44 m;
    HangCameraState item;
    swrModel_Header* pod;

    if (swrRace_hangarMenuReinit != 0 || swrObjHang_menuJustEntered != 0) {
        swrRace_hangarMenuFrame = 0;
        if (swrObjHang_menuJustEntered == 0)
            swrObjHang_hangarUpgradeType = 0;
        swrObjHang_LayoutVehicleSelectIcons(hang);
        swrObjHang_ComputeUpgradedStats(hang->vehiclePlayer, (signed char)upgradeInfos[(signed char)uiUpgradeInfos[swrObjHang_hangarUpgradeType].index].type, 0, -1);
        swrRace_SetupStatsMenuLighting();
        swrRace_UpdatePartNodeSelection();
        swrObjHang_cameraMoveMode = 0;
        swrObjHang_menuJustEntered = 0;
        swrRace_hangarMenuReinit = 0;
    }

    if (swrRace_hangarMenuFrame == 1) {
        swrRace_hangarMenuFrame = 2;
        pod = swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS];

        swrModel_NodeGetTransform((swrModel_NodeTransformed*)pod->entries[swrObjHang_displayPodEngineREntry].node, &m);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x1f].position2, (rdVector3*)&m.vD);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x1f].position1, (rdVector3*)&m.vD);
        swrObjHang_cameraPlacements[0x1f].position2.x = 0.0f;
        swrObjHang_cameraPlacements[0x1f].position1.x = swrObjHang_displayPodBoundsEngineR[3] + 200.0f;
        swrObjHang_cameraPlacements[0x1f].position1.y = swrObjHang_displayPodBoundsEngineR[4] + 300.0f;
        swrObjHang_cameraPlacements[0x1f].position1.z = swrObjHang_cameraPlacements[0x1f].position1.z + 200.0f;

        swrModel_NodeGetTransform((swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[5].node, &m);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x20].position2, (rdVector3*)&m.vD);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x20].position1, (rdVector3*)&m.vD);
        swrObjHang_cameraPlacements[0x20].position1.z = -152.0f;
        swrObjHang_cameraPlacements[0x20].position1.x = swrObjHang_cameraPlacements[0x20].position1.x + 50.0f;
        swrObjHang_cameraPlacements[0x20].position1.y = swrObjHang_cameraPlacements[0x20].position1.y - 300.0f;

        swrModel_NodeGetTransform((swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[5].node, &m);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x21].position2, (rdVector3*)&m.vD);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x21].position1, (rdVector3*)&m.vD);
        swrObjHang_cameraPlacements[0x21].position1.x = swrObjHang_cameraPlacements[0x21].position1.x - 100.0f;
        swrObjHang_cameraPlacements[0x21].position1.y = swrObjHang_cameraPlacements[0x21].position1.y - 500.0f;
        swrObjHang_cameraPlacements[0x21].position1.z = swrObjHang_cameraPlacements[0x21].position1.z + 100.0f;

        swrModel_NodeGetTransform((swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[swrObjHang_displayPodEngineLEntry].node, &m);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x22].position2, (rdVector3*)&m.vD);
        rdVector_Copy3(&swrObjHang_cameraPlacements[0x22].position1, (rdVector3*)&m.vD);
        swrObjHang_cameraPlacements[0x22].position1.z = -152.0f;
        swrObjHang_cameraPlacements[0x22].position1.x = swrObjHang_displayPodBoundsEngineL[0] - 300.0f;
        swrObjHang_cameraPlacements[0x22].position1.y = swrObjHang_displayPodBoundsEngineL[4] + 300.0f;

        if (swrObjHang_hangarUpgradeType < SWR_UPGRADE_CATEGORY_COUNT)
            swrObjHang_FocusMenuItem(hang, swrObjHang_hangarUpgradeType % 4 + HangCameraState_InspectUpgrades1, ~swrObjHang_STATE_LEGAL, 0);
        else
            swrRace_hangarSelectionDirty = 1;
    }

    sprintf(text, swrText_Translate("~s%s"), swrText_Translate((char*)upgradeInfos[(signed char)uiUpgradeInfos[swrObjHang_hangarUpgradeType].index].name));
    if (swrObjHang_hangarUpgradeType == SWR_UPGRADE_CATEGORY_COUNT) {
        if ((uint8_t)swrRace_nbPitDroids < 4)
            sprintf(text, swrText_Translate("/SCREENTEXT_588/~sPit Droid Management"));
        else
            sprintf(text, swrText_Translate("/SCREENTEXT_99/~sNo more pit droids!"));
    }
    swrText_CreateTextEntry1(0x1e, 0x2c, -1, -1, -1, (int)(swrObjHang_lookAtMenuFade * 2.5f * 255.0f), text);

    if (swrRace_hangarFirstVisit != 0) {
        swrRace_hangarSelectionDirty = 1;
        swrRace_hangarVisited = 1;
        swrRace_hangarFirstVisit = 0;
    }

    if (swrMultiplayer_menuOverlayActive == 0 && swrControl_cancelPressedEdge != 0) {
        swrSound_PlayUISound(0x4d);
        swrRace_hangarMenuReinit = 1;
        swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
        return;
    }

    if ((swrUI_localPlayersInputPressedBitset[hang->current_player_for_vehicle_selection] & swrUI_INPUT_MENU_LEFT) && swrObjHang_hangarUpgradeType > 0) {
        swrRace_hangarSelectionDirty = 1;
        swrObjHang_hangarUpgradeType = swrObjHang_hangarUpgradeType - 1;
        swrSound_PlayUISound(0x58);
    }
    if ((swrUI_localPlayersInputPressedBitset[hang->current_player_for_vehicle_selection] & swrUI_INPUT_MENU_RIGHT) && swrObjHang_hangarUpgradeType < SWR_UPGRADE_CATEGORY_COUNT) {
        swrRace_hangarSelectionDirty = 1;
        swrObjHang_hangarUpgradeType = swrObjHang_hangarUpgradeType + 1;
        swrSound_PlayUISound(0x58);
    }
    if ((swrUI_localPlayersInputPressedBitset[hang->current_player_for_vehicle_selection] & swrUI_INPUT_MENU_UP) && swrObjHang_hangarUpgradeType > 1) {
        swrRace_hangarSelectionDirty = 1;
        swrObjHang_hangarUpgradeType = swrObjHang_hangarUpgradeType - 2;
        swrSound_PlayUISound(0x58);
    }
    if ((swrUI_localPlayersInputPressedBitset[hang->current_player_for_vehicle_selection] & swrUI_INPUT_MENU_DOWN) && swrObjHang_hangarUpgradeType <= 5) {
        swrRace_hangarSelectionDirty = 1;
        swrObjHang_hangarUpgradeType = swrObjHang_hangarUpgradeType + 2;
        swrSound_PlayUISound(0x58);
    }

    if (swrRace_hangarSelectionDirty != 0 && swrObjHang_hangarUpgradeType != -1) {
        swrRace_hangarSelectionDirty = 0;
        swrRace_UpdatePartNodeSelection();
        if (swrObjHang_hangarUpgradeType < SWR_UPGRADE_CATEGORY_COUNT) {
            swrObjHang_ComputeUpgradedStats(hang->vehiclePlayer, (signed char)upgradeInfos[(signed char)uiUpgradeInfos[swrObjHang_hangarUpgradeType].index].type, 0, -1);
            item = swrObjHang_hangarUpgradeType % 4 + HangCameraState_InspectUpgrades1;
            if (item != hang->cameraState)
                swrObjHang_FocusMenuItem(hang, item, ~swrObjHang_STATE_LEGAL, 0);
        } else {
            swrObjHang_ComputeUpgradedStats(hang->vehiclePlayer, swrObjHang_hangarUpgradeType, 0, -1);
            swrObjHang_cameraMoveMode = 1;
            hang->cameraState = HangCameraState_InspectPT01;
            swrObjHang_AimHoloCamera(hang, HangCameraState_InspectPT01, 0);
        }
    }

    if (swrMultiplayer_menuOverlayActive == 0 && swrControl_menuAcceptPressedEdge != 0 && (swrObjHang_hangarUpgradeType != SWR_UPGRADE_CATEGORY_COUNT || swrRace_nbPitDroids != 4)) {
        swrSound_PlayUISound(0x54);
        swrObjHang_state2 = swrObjHang_STATE_WATTO;
        swrObjHang_shopFocusTypePending = 1;
        if (swrObjHang_hangarUpgradeType == SWR_UPGRADE_CATEGORY_COUNT) {
            swrObjHang_shopFocusTypePending = 2;
            hang->activeMenu = 1;
        }
        swrObjHang_fadeState = -1;
        swrObjHang_lookAtMenuFade = 0.4f;
    }

    if (swrRace_hangarMenuFrame < 2)
        swrRace_hangarMenuFrame++;
}

// The stored name field is 32 chars with NO guaranteed NUL (a fresh save holds 32 'A's); the
// original sprintf's the raw copy and relies on whatever follows it on the stack.
// 0x00439c70
void swrRace_DrawRecordHolderName(float x, float y, float alpha, char* recordName)
{
    char name[33];
    char buffer[64];

    memcpy(name, recordName, 32);
    name[32] = '\0';
    sprintf(buffer, "~f4~c~s%s", name);
    swrText_CreateTextEntry1((int)x, (int)y, 0x32, -1, -1, (int)alpha, buffer);
}

// Post-race results screen. On entry it sanitizes and sorts the scores, routes record-setting
// guest players through name entry, commits new records into the save image, and in tournament mode
// applies the whole progression step (prizes, unlocks, beat-place bits, podium), then autosaves.
// 0x00439ce0
void swrObjHang_ResultsMenu(swrObjHang* hang)
{
    swrScore* scores[20]; // race order: local players first
    float bestLap[2];
    swrScore* score;
    char* text;
    float rowYf;
    float alphaF;
    float lapTime;
    int rowY;
    int textY;
    int alpha;
    int spriteId;
    int pilot;
    int recordIdx;
    int lap;
    int i;
    int k;
    char effLaps;
    char newCircuitIdx;
    char minLocalPlace;
    char required;
    uint8_t favoritePilot;
    int storedPlaceBits;
    int gain;
    swrObjHang_STATE state2;
    char buffer[256];

    newCircuitIdx = hang->circuitIdx;
    bestLap[0] = ELFSAVE_RECORD_TIME_EMPTY;
    bestLap[1] = ELFSAVE_RECORD_TIME_EMPTY;
    g_CircuitIdxMax = (int)(150.0f - (float)hang->num_players * 30.0f); // scroll floor (see DrawScrollbar)
    effLaps = hang->numLaps;
    if (hang->isTournamentMode != 0)
        effLaps = 3;
    text = swrText_Translate("/SCREENTEXT_189/~c~sResults");
    swrText_CreateColorlessEntry1(0xa0, 0x14, text);
    for (i = 0; i < 20; i++)
        scores[i] = NULL;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrRace_resultsFanfareDelay = 2.0f;
        for (i = 0; i < g_aTracksInCircuits[(int)hang->circuitIdx]; i++) {
            if ((int)hang->track_index == g_aTrackIDs[hang->circuitIdx * 7 + i]) {
                swrObjHang_trackInCircuitIdx = (uint8_t)i;
                break;
            }
        }
        swrRace_resultsScrollY = 0.0f;
        swrRace_TournamentTrugutGain = 0;
        for (i = 0; i < 20; i++)
            swrRace_resultsSortedScores[i] = NULL;
        // collect + sanitize: out-of-range totals and lap times become the empty-record value
        for (i = 0; i < hang->num_players; i++) {
            score = &swrScores[i];
            scores[i] = score;
            if (score == NULL) {
                hang->num_players = (char)i;
                break;
            }
            if (ELFSAVE_RECORD_TIME_EMPTY < score->results_P1_total_time || score->results_P1_total_time < 0.0f)
                score->results_P1_total_time = ELFSAVE_RECORD_TIME_EMPTY;
            for (lap = 0; lap < effLaps; lap++) {
                if (ELFSAVE_RECORD_TIME_EMPTY < (&score->results_P1_Lap1)[lap] || (&score->results_P1_Lap1)[lap] < 0.0f)
                    (&score->results_P1_Lap1)[lap] = ELFSAVE_RECORD_TIME_EMPTY;
            }
            swrRace_resultsSortedScores[i] = score;
        }
        // sort by finishing position (bubble)
        for (i = 1; i < hang->num_players; i++) {
            for (k = 0; k < i; k++) {
                if ((short)swrRace_resultsSortedScores[i]->results_P1_Position < (short)swrRace_resultsSortedScores[k]->results_P1_Position) {
                    score = swrRace_resultsSortedScores[i];
                    swrRace_resultsSortedScores[i] = swrRace_resultsSortedScores[k];
                    swrRace_resultsSortedScores[k] = score;
                }
            }
        }
        // best single lap per local player (a non-positive lap time ends the scan)
        for (k = 0; k < hang->num_local_players; k++) {
            bestLap[k] = (&scores[k]->results_P1_Lap1)[0];
            for (lap = 1; lap < effLaps; lap++) {
                lapTime = (&scores[k]->results_P1_Lap1)[lap];
                if (lapTime <= 0.0f)
                    break;
                if (lapTime < bestLap[k])
                    bestLap[k] = lapTime;
            }
        }
        // a record-setting guest profile (not linked to a save slot) gets sent to name entry
        recordIdx = hang->bMirror + hang->track_index * 2;
        if ((swrRace_resultsStateFlags & swrRace_RESULTSFLAG_NAME_ENTRY_P1) == 0 && swrRace_aProfiles[0].linkedToSave == 0 && ((effLaps == 3 && scores[0]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx] && (hang->num_local_players == 1 || scores[0]->results_P1_total_time < scores[1]->results_P1_total_time)) || (bestLap[0] < swrRace_saveData.recordLapTimes[recordIdx] && (hang->num_local_players == 1 || bestLap[0] < bestLap[1])))) {
            swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_NAME_ENTRY_P1;
            hang->current_player_for_vehicle_selection = 0;
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_ENTER_NAME);
            return;
        }
        if (1 < hang->num_local_players && (swrRace_resultsStateFlags & swrRace_RESULTSFLAG_NAME_ENTRY_P2) == 0 && swrRace_aProfiles[1].linkedToSave == 0 && ((effLaps == 3 && scores[1]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx] && scores[1]->results_P1_total_time < scores[0]->results_P1_total_time) || (bestLap[1] < swrRace_saveData.recordLapTimes[recordIdx] && bestLap[1] < bestLap[0]))) {
            swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_NAME_ENTRY_P2;
            hang->current_player_for_vehicle_selection = 1;
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_ENTER_NAME);
            return;
        }
        // commit new records: time + holder name + holder pilot from the live profile
        if ((swrRace_resultsStateFlags & swrRace_RESULTSFLAG_RECORDS_COMMITTED) == 0) {
            for (k = 0; k < hang->num_local_players; k++) {
                recordIdx = hang->bMirror + hang->track_index * 2;
                if (effLaps == 3 && scores[k]->results_P1_total_time < ELFSAVE_RECORD_TIME_EMPTY && scores[k]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx]) {
                    swrRace_saveData.record3LapTimes[recordIdx] = scores[k]->results_P1_total_time;
                    for (i = 0; i < 32; i++)
                        swrRace_saveData.record3LapNames[recordIdx][i] = swrRace_aProfiles[k].name[i];
                    swrRace_saveData.record3LapPilots[recordIdx] = swrRace_aProfiles[k].pilotId;
                }
                if (bestLap[k] < ELFSAVE_RECORD_TIME_EMPTY && bestLap[k] < swrRace_saveData.recordLapTimes[recordIdx]) {
                    swrRace_saveData.recordLapTimes[recordIdx] = bestLap[k];
                    for (i = 0; i < 32; i++)
                        swrRace_saveData.recordLapNames[recordIdx][i] = swrRace_aProfiles[k].name[i];
                    swrRace_saveData.recordLapPilots[recordIdx] = swrRace_aProfiles[k].pilotId;
                }
            }
        }
        swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_RECORDS_COMMITTED;

        swrRace_resultsPlaceP1 = *(char*)&scores[0]->results_P1_Position;
        swrRace_resultsPlaceP2 = -1;
        minLocalPlace = swrRace_resultsPlaceP1;
        if (1 < hang->num_local_players) {
            swrRace_resultsPlaceP2 = *(char*)&scores[1]->results_P1_Position;
            if (swrRace_resultsPlaceP2 < swrRace_resultsPlaceP1)
                minLocalPlace = swrRace_resultsPlaceP2;
        }
        if (3 < minLocalPlace) {
            // start the list scrolled so the local player's row is visible
            swrRace_resultsScrollY = (float)(minLocalPlace - 3) * -30.0f;
            if (swrRace_resultsScrollY < 150.0f - (float)hang->num_players * 30.0f)
                swrRace_resultsScrollY = 150.0f - (float)hang->num_players * 30.0f;
        }
        if (hang->num_local_players == 1 && hang->isTournamentMode != 0 && 3 < hang->num_players) {
            // equal totals share a finishing position
            for (i = 1; i < hang->num_players; i++) {
                if (swrRace_resultsSortedScores[i]->results_P1_total_time == swrRace_resultsSortedScores[i - 1]->results_P1_total_time)
                    *(short*)&swrRace_resultsSortedScores[i]->results_P1_Position = *(short*)&swrRace_resultsSortedScores[i - 1]->results_P1_Position;
            }
            // winning a track can unlock its favorite pilot (cutaway state)
            if (swrRace_resultsPlaceP1 == 1 && hang->isTournamentMode != 0 && (swrRace_resultsStateFlags & swrRace_RESULTSFLAG_PILOT_UNLOCK_SHOWN) == 0) {
                favoritePilot = g_aTrackInfos[(int)hang->track_index].FavoritePilot;
                if (favoritePilot == 2 && hang->track_index != 1)
                    favoritePilot = 0;
                if (0 < (char)favoritePilot && (swrRace_aProfiles[0].pilotsUnlocked & (1u << (favoritePilot & 0x1f))) == 0) {
                    swrRace_aProfiles[0].pilotsUnlocked |= 1u << (favoritePilot & 0x1f);
                    swrRace_saveData.pilotsUnlockedGlobal |= swrRace_aProfiles[0].pilotsUnlocked;
                    swrRace_SaveCurrentProfile();
                    swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_PILOT_UNLOCK_SHOWN;
                    swrObjHang_SetMenuState(hang, swrObjHang_STATE_RESULTS_INTRO);
                    return;
                }
            }
            required = swrObjHang_GetRequiredPlaceToProceed(hang->circuitIdx, (char)swrObjHang_trackInCircuitIdx);
            if (swrRace_resultsPlaceP1 <= required) {
                storedPlaceBits = (swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] >> ((swrObjHang_trackInCircuitIdx & 0xf) * 2)) & 3;
                if (swrObjHang_IsTrackUnlocked(hang->circuitIdx, (char)swrObjHang_trackInCircuitIdx) != 0) {
                    // prize scales with the circuit: x1.0 / x1.5 / x2.0 / x2.5
                    gain = (int)hang->winnings.truguts[hang->WinningsID - 1][swrRace_resultsPlaceP1 - 1];
                    gain = (int)((1.0 - (double)(int)hang->circuitIdx * -0.5) * (double)gain);
                    swrRace_TournamentTrugutGain = gain;
                    swrRace_truguts += gain;
                    if (hang->circuitIdx < 3) {
                        if ((int)swrObjHang_trackInCircuitIdx == g_aTracksInCircuits[(int)hang->circuitIdx] - 1 && (swrRace_aProfiles[0].circuitsCompleted & (1 << (hang->circuitIdx & 0x1f))) == 0) {
                            // circuit finished for the first time: jump to its invitational track
                            newCircuitIdx = 3;
                            swrRace_aProfiles[0].circuitsCompleted |= 1 << (hang->circuitIdx & 0x1f);
                            hang->track_index = (char)g_aTrackIDs[hang->circuitIdx + 0x15];
                        } else if ((int)swrObjHang_trackInCircuitIdx < g_aTracksInCircuits[(int)hang->circuitIdx] - 1 && (swrRace_aProfiles[0].tracksUnlocked[(int)hang->circuitIdx] & (1 << ((swrObjHang_trackInCircuitIdx + 1) & 0x1f))) == 0) {
                            hang->track_index = (char)g_aTrackIDs[hang->circuitIdx * 7 + swrObjHang_trackInCircuitIdx + 1];
                        }
                        swrRace_aProfiles[0].tracksUnlocked[(int)hang->circuitIdx] |= 1 << ((swrObjHang_trackInCircuitIdx + 1) & 0x1f);
                    }
                    swrRace_UpdatePartsHealth();
                }
                if ((int)swrObjHang_trackInCircuitIdx == g_aTracksInCircuits[(int)hang->circuitIdx] - 1 && hang->circuitIdx == 2)
                    swrObjHang_SelectCreditsTracks(hang);
                // best finishing place per track, 2 bits each (stored as 4 - place)
                if (storedPlaceBits < 4 - swrRace_resultsPlaceP1) {
                    swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] &= (uint16_t)~(3 << (swrObjHang_trackInCircuitIdx * 2));
                    swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] |= (uint16_t)((4 - swrRace_resultsPlaceP1) << (swrObjHang_trackInCircuitIdx * 2));
                    if (swrRace_aProfiles[0].beatTrackPlace[0] == 0x3fff && swrRace_aProfiles[0].beatTrackPlace[1] == 0x3fff && swrRace_aProfiles[0].beatTrackPlace[2] == 0x3fff) {
                        if ((swrRace_aProfiles[0].circuitsCompleted & 8) == 0) {
                            swrRace_aProfiles[0].circuitsCompleted |= 8;
                            newCircuitIdx = 3;
                            hang->track_index = (char)g_aTrackIDs[0x18];
                        } else if (swrRace_aProfiles[0].beatTrackPlace[3] == 0xff && (swrRace_saveData.unlockFlags & swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST) == 0) {
                            swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST;
                        }
                    }
                }
            }
            // fold the profile's unlock progress into the machine-global unlocks
            // (UnlockDataBase[1..4] = tracksUnlocked[0..2] + circuitsCompleted)
            for (i = 0; i < 4; i++) {
                if (g_aBeatTracksGlobal[i] < (uint8_t)swrRace_UnlockDataBase[i + 1])
                    g_aBeatTracksGlobal[i] = (uint8_t)swrRace_UnlockDataBase[i + 1];
            }
        }
        hang->circuitIdx = newCircuitIdx;
        swrRace_SaveCurrentProfile();
    }

    if (0.0f < swrRace_resultsFanfareDelay) {
        swrRace_resultsFanfareDelay -= swrRace_fdeltaTimeSecs;
        if (swrRace_resultsFanfareDelay <= 0.0f)
            swrSound_Play2D(0xb6, 7, 0.25f, 1.0f, 0);
    }

    // standings rows (30px apart, faded near the top/bottom edges)
    rowY = 0x1e;
    for (i = 0; i < hang->num_players; i++) {
        score = swrRace_resultsSortedScores[i];
        rowYf = ((float)rowY + swrRace_resultsScrollY) + 15.0f;
        alphaF = 255.0f;
        if (rowYf < 45.0f)
            alphaF = (float)(255.0 - (45.0 - (double)rowYf) * 8.0);
        if (160.0f < rowYf)
            alphaF = (float)(255.0 - ((double)rowYf - 160.0) * 8.0);
        if (alphaF < 0.0f)
            alphaF = 0.0f;
        if (255.0f < alphaF)
            alphaF = 255.0f;
        alpha = (int)alphaF;
        // duplicate pods use the mirrored sprite bank (+0x17 per prior appearance)
        pilot = *score->pilotId;
        spriteId = pilot;
        for (k = 0; k < i; k++) {
            if (pilot == *swrRace_resultsSortedScores[k]->pilotId)
                spriteId += 0x17;
        }
        swrSprite_SetVisible((short)spriteId, 1);
        swrSprite_SetPos((short)spriteId, 0x1e, (short)(int)rowYf);
        swrSprite_SetDim((short)spriteId, 0.5f, 0.5f);
        swrSprite_SetColor((short)spriteId, 0xff, 0xff, 0xff, (uint8_t)alpha);
        rowYf += 10.0f;
        textY = (int)rowYf;
        if (i == swrRace_resultsPlaceP1 - 1 || i == swrRace_resultsPlaceP2 - 1) {
            // local player's row: highlighted, with the profile name underneath
            text = swrText_Translate("~r~s%d:");
            sprintf(buffer, text, (int)(short)score->results_P1_Position);
            swrText_CreateTextEntry1(0x58, textY, -0x5d, -0x42, 0x11, alpha, buffer);
            text = swrText_Translate("~f4~s%s %s");
            sprintf(buffer, text, swrText_Translate(swrRacer_PodData[pilot].name), swrText_Translate(swrRacer_PodData[pilot].lastname));
            swrText_CreateTextEntry1(0x5c, (int)(rowYf + 1.0f), -0x5d, -0x42, 0x11, alpha, buffer);
            swrText_CreateTimeEntryFormat(0x109, textY, score->results_P1_total_time, -0x5d, -0x42, 0x11, alpha, 1);
            text = swrText_Translate("~f4~s%s");
            sprintf(buffer, text, (i == swrRace_resultsPlaceP1 - 1) ? swrRace_aProfiles[0].name : swrRace_aProfiles[1].name);
            swrText_CreateTextEntry1(100, (int)(rowYf + 9.0f), -0x5d, -0x42, 0x11, alpha, buffer);
        } else {
            text = swrText_Translate("~r~s%d:");
            sprintf(buffer, text, (int)(short)score->results_P1_Position);
            swrText_CreateTextEntry1(0x58, textY, 0x32, -1, -1, alpha, buffer);
            text = swrText_Translate("~f4~s%s %s");
            sprintf(buffer, text, swrText_Translate(swrRacer_PodData[pilot].name), swrText_Translate(swrRacer_PodData[pilot].lastname));
            swrText_CreateTextEntry1(0x5c, (int)(rowYf + 1.0f), 0x32, -1, -1, alpha, buffer);
            swrText_CreateTimeEntryFormat(0x109, textY, score->results_P1_total_time, 0x32, -1, -1, alpha, 1);
        }
        rowY += 0x1e;
    }
    if (4 < hang->num_players)
        swrRace_DrawScrollbar(0x122, 0x1e, 0x90);
    if (0 < swrRace_TournamentTrugutGain) {
        text = swrText_Translate("/SCREENTEXT_575/~c~sYou won %d Truguts!");
        sprintf(buffer, text, swrRace_TournamentTrugutGain);
        swrText_CreateColorlessEntry1(0x87, 0xcd, buffer);
        swrObjHang_PositionHoloNode(0, 7.0f, -7.0f, 1.0f);
    }

    state2 = swrObjHang_state2;
    for (k = 0; k < hang->num_local_players; k++) {
        if (swrControl_acceptPressedEdge != 0 || swrControl_cancelPressedEdge != 0) {
            swrUI_RunCallbacks2(swrUI_GetUI1(), 1);
            swrSound_PlayUISound(0x54);
            if (hang->isTournamentMode == 0) {
                // multiplayer results return to the lobby flow (SELECT_PLANET - 11)
                state2 = swrMultiplayer_IsMultiplayerEnabled() != 0 ? (swrObjHang_STATE)(swrObjHang_STATE_SELECT_PLANET - 11) : swrObjHang_STATE_SELECT_PLANET;
                swrObjHang_state2 = state2;
            } else if (swrRace_resultsPlaceP1 < 4 && swrObjHang_trackInCircuitIdx == 6) {
                // circuit final won: podium ceremony with the top three pilots
                for (i = 0; i < 3; i++)
                    hang->podiumCharacters[i] = *(char*)swrRace_resultsSortedScores[i]->pilotId;
                state2 = swrObjHang_STATE_PLANET_SELECT_INTRO;
                swrObjHang_state2 = state2;
            } else {
                state2 = swrObjHang_STATE_SELECT_PLANET;
                swrObjHang_state2 = state2;
            }
        }
        g_bCircuitIdxInRange = 0;
        swrUI_menuScrolled = 0;
        if (4 < hang->num_players) {
            // analog scroll through the standings
            if (swrControl_aPlayerAxisY[k] < -0.1f || 0.1f < swrControl_aPlayerAxisY[k]) {
                swrRace_resultsScrollY -= swrControl_aPlayerAxisY[k] * swrRace_fdeltaTimeSecs * -300.0f;
                if (0.0f < swrRace_resultsScrollY)
                    swrRace_resultsScrollY = 0.0f;
                if (swrRace_resultsScrollY < 150.0f - (float)hang->num_players * 30.0f)
                    swrRace_resultsScrollY = 150.0f - (float)hang->num_players * 30.0f;
            }
            swrUI_menuScrolled = (uint32_t)(swrRace_resultsScrollY < 0.0f);
            if ((float)g_CircuitIdxMax < swrRace_resultsScrollY)
                g_bCircuitIdxInRange = 1;
        }
    }
    if (state2 != ~swrObjHang_STATE_LEGAL) {
        // a state transition is pending: reset the one-shot latches for the next results screen
        swrRace_resultsStateFlags = 0;
        swrObjHang_fadeState = -1;
    }
}

// 0x0043b240
void swrObjHang_CourseSelectionMenu(void)
{
    char text[256];
    swrObjHang* hang = g_objHang2;
    char* label;
    int r;
    int g;
    int b;
    int width;
    int labelWidth;
    int planetSprite;
    int selected;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_FocusMenuItem(hang, 0x25, -1, 0);
        swrObjHang_courseTrackChosen = 0;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_PLANET)
            swrRace_Transition = 1.0f;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_VEHICLE || hang->menuScreenPrev == swrObjHang_STATE_SPLASH)
            hang->circuitIdx = 0;
        swrUI_Front_HandleCircuits(hang);
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_VEHICLE || hang->menuScreenPrev == swrObjHang_STATE_SPLASH) {
            swrRace_MenuSelectedItem = 0;
            // tournament: start on the circuit's last track when it is already unlocked
            if (hang->isTournamentMode != 0 && swrObjHang_IsTrackUnlocked(hang->circuitIdx, swrRace_MenuMaxSelection - 1) != 0)
                swrRace_MenuSelectedItem = swrRace_MenuMaxSelection - 1;
        } else {
            swrUI_Front_SyncTrackSelection(hang);
        }
        swrObjHang_InitTrackSprites(hang, 1);
        swrObjHang_courseShownPlanet = g_aTrackInfos[hang->track_index].PlanetIdx;
        swrObjHang_courseShownCircuit = hang->circuitIdx;
    }

    if (swrObjHang_courseTrackChosen != 0) {
        swrObjHang_StepTransition(-3.3f);
    } else if (swrObjHang_settledMenuItem == swrRace_MenuSelectedItem) {
        swrObjHang_courseShownPlanet = g_aTrackInfos[hang->track_index].PlanetIdx;
        swrObjHang_courseShownCircuit = hang->circuitIdx;
        swrObjHang_StepTransition(3.3f);
    }

    selected = swrObjHang_VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
    hang->track_index = (char)g_aTrackIDs[hang->circuitIdx * 7 + selected];
    if (swrRace_Transition > 0.0f)
        swrObjHang_DrawHoloPlanet(hang, swrObjHang_courseShownPlanet, swrRace_Transition * 0.5);
    if (swrObjHang_courseTrackChosen != 0)
        return;

    if (g_aTrackInfos[hang->track_index].trackID == -1 || g_aTrackInfos[hang->track_index].splineID == -1) {
        sprintf(text, swrText_Translate(g_pTxtPlanetNotLoaded));
        b = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        g = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        r = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        swrText_CreateTextEntry1(0xa0, 0xcd, r, g, b, -1, text);
    }
    sprintf(text, swrText_Translate(g_pTxtPartNameFormat), swrUI_Front_GetTrackNameFromId(hang->track_index));
    swrText_CreateTextEntry1(0xa0, 0x36, 0, -1, 0, -1, text);
    labelWidth = swrText_GetStringWidthByFont(text, 0);
    width = swrText_GetStringWidthByFont(text, 0);
    // faithful: the original also pushes labelWidth as a third argument the callee never reads
    swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - width * 0.5), 0x37);
    (void)labelWidth;

    switch (hang->circuitIdx) {
    case 0:
        swrText_CreateTextEntry1(0xa0, 0x22, 0x32, -1, -1, -1, swrText_Translate(g_pTxtCircuitAmateur));
        break;
    case 1:
        swrText_CreateTextEntry1(0xa0, 0x22, 0x44, -1, 0x3e, -1, swrText_Translate(g_pTxtCircuitSemiPro));
        break;
    case 2:
        swrText_CreateTextEntry1(0xa0, 0x22, -0x5d, -0x42, 0x11, -1, swrText_Translate(g_pTxtCircuitGalactic));
        break;
    case 3:
        swrText_CreateTextEntry1(0xa0, 0x22, -0x63, 0x59, 0x20, -1, swrText_Translate(g_pTxtCircuitInvitational));
        break;
    }

    if (hang->isTournamentMode != 0)
        label = swrText_Translate(g_pTxtTournament);
    else if (hang->timeAttackMode != 0)
        label = swrText_Translate(g_pTxtTimeAttack);
    else if (hang->num_local_players == 2)
        label = swrText_Translate(g_pTxt2Player);
    else
        label = swrText_Translate(g_pTxtFreePlay);
    sprintf(text, label);
    swrText_CreateTextEntry1(0xa0, 0x18, 0x32, -1, -1, -1, text);

    swrObjHang_DrawTracks(hang, swrObjHang_courseShownCircuit);
    planetSprite = (char)g_aTrackInfos[hang->track_index].PlanetIdx + 0x45;
    swrSprite_SetVisible(planetSprite, 1);
    swrSprite_SetPos(planetSprite, 0xa0, 0x91);
    swrSprite_SetDim(planetSprite, 1.0f, 1.0f);
    swrSprite_SetColor(planetSprite, 0xff, 0xff, 0xff, 0xff);
    swrText_CreateTextEntry1(0xe0, 0x8a, 0, -1, 0, -1, swrPlanetTable[(char)g_aTrackInfos[hang->track_index].PlanetIdx].name);
    swrRace_DrawScrollbar(0x2d, 0x54, 0x1e);
    if (swrObjHang_courseTrackChosen != 0)
        return;

    swrObjHang_NavigateVehicleSelect(0, 1.0f, 1);
    // faithful: the original's per-player loop bound stops after player 1
    if (swrMultiplayer_menuOverlayActive == 0) {
        if (swrControl_menuAcceptPressedEdge != 0 && (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0)) {
            if (swrMultiplayer_enabled != 0) {
                swrUI_PopMenuPage();
                return;
            }
            if (swrObjHang_menuAcceptLock != 0)
                return;
            swrSound_PlayUISound(0x54);
            swrObjHang_InitTrackSprites(hang, 0);
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_TRACK);
            swrObjHang_courseTrackChosen = 1;
            return;
        }
        if (swrControl_cancelPressedEdge != 0 && swrObjHang_menuAcceptLock == 0) {
            if (swrMultiplayer_enabled != 0) {
                swrUI_PopMenuPage();
                return;
            }
            swrSound_PlayUISound(0x4d);
            if (swrMultiplayer_IsMultiplayerEnabled() != 0 && swrMultiplayer_IsHost() != 0)
                return;
            swrObjHang_InitTrackSprites(hang, 0);
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_VEHICLE);
            return;
        }
    }
    if (swrObjHang_courseShownCircuit == hang->circuitIdx) {
        if ((swrUI_localPlayersInputPressedBitset[0] & swrUI_INPUT_MENU_DOWN) != 0) {
            if (hang->circuitIdx < g_CircuitIdxMax) {
                hang->circuitIdx++;
                swrObjHang_settledMenuItem = -1;
                swrSound_PlayUISound(0x58);
                swrUI_Front_HandleCircuits(hang);
            } else {
                swrSound_PlayUISound(0x4b);
            }
        }
        if ((swrUI_localPlayersInputPressedBitset[0] & swrUI_INPUT_MENU_UP) != 0) {
            if (hang->circuitIdx > 0) {
                hang->circuitIdx--;
                swrObjHang_settledMenuItem = -1;
                swrSound_PlayUISound(0x58);
                swrUI_Front_HandleCircuits(hang);
            } else {
                swrSound_PlayUISound(0x4b);
            }
        }
    }

    swrMultiplayer_trackSelect = hang->track_index;
    if (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) {
        g_LoadTrackModel = g_aTrackInfos[hang->track_index].trackID;
        swrMultiplayer_BroadcastPlayerState();
    }
}

// Course info screen (after track select): builds the option-row list on entry (which rows depend
// on the mode), draws the rows plus the hologram, preview, both save-image records and the
// favorite pilot, then handles option cycling and the start/back transitions.
// 0x0043b880
void swrObjHang_CourseInfoMenu(swrObjHang* hang)
{
    char* text;
    char* valueText;
    int rowY;
    int prizeY;
    int recordIdx;
    int trackInCircuit;
    int prize;
    int width;
    int colR;
    int colG;
    int colB;
    int i;
    char itemCount;
    char required;
    char pilot;
    uint8_t favoritePilot;
    char buffer[64];

    if ((uint8_t)nb_AI_racers == 0)
        nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
    if (swrObjHang_splitscreenRacerCount == 0)
        swrObjHang_splitscreenRacerCount = 2;

    itemCount = swrObjHang_courseInfoItemCount;
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_FocusMenuItem(hang, 0x25, ~swrObjHang_STATE_LEGAL, 0);
        swrObjHang_courseInfoSelectedRow = 0;
        swrObjHang_courseInfoLeaving = 0;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_PLANET)
            swrRace_Transition = 1.0f;
        swrUI_Front_HandleCircuits(hang);
        if (hang->menuScreenPrev != swrObjHang_STATE_SELECT_PLANET)
            swrUI_Front_SyncTrackSelection(hang);
        for (i = 0; i < 12; i++)
            swrObjHang_courseInfoItemKinds[i] = -1;
        swrObjHang_courseInfoItemCount = 0;
        if (swrUI_Front_BeatEverything1stPlace(hang)) {
            swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 0; // mirror toggle
            swrObjHang_courseInfoItemCount++;
        }
        if (hang->isTournamentMode == 0) {
            itemCount = swrObjHang_courseInfoItemCount + 1;
            swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 2; // laps
            if (hang->timeAttackMode == 0) {
                swrObjHang_courseInfoItemCount += 2;
                swrObjHang_courseInfoItemKinds[itemCount] = 3; // racers
                swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 4; // AI speed
                itemCount = swrObjHang_courseInfoItemCount + 1;
            }
        } else {
            trackInCircuit = swrObjHang_VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
            if (swrObjHang_IsTrackUnlocked(hang->circuitIdx, (char)trackInCircuit) != 0) {
                swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 1; // winnings
                itemCount = swrObjHang_courseInfoItemCount + 1;
            } else {
                itemCount = swrObjHang_courseInfoItemCount;
            }
        }
    }
    swrObjHang_courseInfoItemCount = itemCount;

    trackInCircuit = swrObjHang_VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
    required = swrObjHang_GetRequiredPlaceToProceed(hang->circuitIdx, (char)trackInCircuit);

    rowY = 0xa0;
    if (swrObjHang_courseInfoLeaving == 0 && 0 < swrObjHang_courseInfoItemCount) {
        for (i = 0; i < swrObjHang_courseInfoItemCount; i++) {
            valueText = NULL;
            switch (swrObjHang_courseInfoItemKinds[i]) {
            case 0: // mirror
                text = swrText_Translate(g_pTxtMirror);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = swrText_Translate(hang->bMirror == 0 ? g_pTxtOff : g_pTxtOn);
                break;
            case 1: // tournament winnings + prize table
                if (hang->WinningsID == 1)
                    text = swrText_Translate(g_pTxtFair);
                else if (hang->WinningsID == 2)
                    text = swrText_Translate(g_pTxtSkilled);
                else
                    text = swrText_Translate(g_pTxtWinnerTakesAll);
                sprintf(buffer, text);
                text = swrText_Translate(g_pTxtWinnings);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                swrUI_Front_TextMenu(hang, 0x55, rowY, 10, swrObjHang_courseInfoSelectedRow, i, buffer);
                prizeY = rowY + 10;
                text = swrText_Translate(g_pTxt1st);
                swrUI_Front_TextMenu(hang, 0x2d, prizeY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                text = swrText_Translate(g_pTxt2nd);
                swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x14, 10, swrObjHang_courseInfoSelectedRow, i, text);
                text = swrText_Translate(g_pTxt3rd);
                swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x1e, 10, swrObjHang_courseInfoSelectedRow, i, text);
                if (required == 4) {
                    text = swrText_Translate(g_pTxt4th);
                    swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x28, 10, swrObjHang_courseInfoSelectedRow, i, text);
                }
                for (prize = 0; prize < required; prize++) {
                    // prize scales with the circuit: x1.0 / x1.5 / x2.0 / x2.5
                    int truguts = (int)((1.0 - (double)(int)hang->circuitIdx * -0.5) * (double)(int)hang->winnings.truguts[hang->WinningsID - 1][prize]);
                    text = swrText_Translate("~f0~r~s%d");
                    sprintf(buffer, text, truguts);
                    swrUI_Front_TextMenu(hang, 0x69, prizeY, 10, swrObjHang_courseInfoSelectedRow, i, buffer);
                    prizeY += 10;
                }
                continue;
            case 2: // laps
                text = swrText_Translate("~f0~s%d");
                sprintf(buffer, text, (int)hang->numLaps);
                text = swrText_Translate(g_pTxtLaps);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 3: // racer count
                text = swrText_Translate("~f0~s%d");
                sprintf(buffer, text, (int)(uint8_t)nb_AI_racers);
                if (1 < hang->num_local_players) {
                    text = swrText_Translate("~f0~s%d");
                    sprintf(buffer, text, (int)(uint8_t)swrObjHang_splitscreenRacerCount);
                }
                text = swrText_Translate(g_pTxtRacers);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 4: // AI speed
                if (hang->AISpeed == 1)
                    text = swrText_Translate(g_pTxtSlow);
                else if (hang->AISpeed == 2)
                    text = swrText_Translate(g_pTxtAverage);
                else
                    text = swrText_Translate(g_pTxtFast);
                sprintf(buffer, text);
                text = swrText_Translate(g_pTxtAISpeed);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 5: // demo mode
                rowY += 10;
                text = swrText_Translate(g_pTxtDemoMode);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = swrText_Translate(hang->demo_mode == 0 ? g_pTxtOff : g_pTxtOn);
                break;
            case 6: // cutscene selector
                if (hang->unk68_type < 0) {
                    text = swrText_Translate(g_pTxtOff2);
                    sprintf(buffer, text);
                } else {
                    text = swrText_Translate("~s%d");
                    sprintf(buffer, text, hang->unk68_type + 1);
                }
                text = swrText_Translate(g_pTxtCutscene);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            default:
                continue;
            }
            swrUI_Front_TextMenu(hang, 0x55, rowY, 10, swrObjHang_courseInfoSelectedRow, i, valueText);
        }
    }

    swrObjHang_StepTransition(swrObjHang_courseInfoLeaving == 0 ? 3.3f : -3.3f);
    if (0.0f < swrRace_Transition)
        swrObjHang_DrawHoloPlanet(hang, (int)(char)g_aTrackInfos[(int)hang->track_index].PlanetIdx, swrRace_Transition * 0.5f);
    if (swrObjHang_courseInfoLeaving != 0)
        return;
    swrObjHang_DrawTrackPreview(hang, (int)hang->track_index, 0.5f);
    if (swrObjHang_courseInfoLeaving != 0)
        return;

    if (g_aTrackInfos[(int)hang->track_index].trackID == (INGAME_MODELID)~INGAME_MODELID_loc_watto_part || g_aTrackInfos[(int)hang->track_index].splineID == (SPLINEID)~SPLINEID_planetd_track) {
        // no model/spline assigned: flashing "planet not loaded" warning
        text = swrText_Translate(g_pTxtPlanetNotLoaded);
        sprintf(buffer, text);
        colB = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        colG = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        swrText_CreateTextEntry1(0xa0, 0xcd, colR, colG, colB, -1, buffer);
    }
    text = swrUI_Front_GetTrackNameFromId((int)hang->track_index);
    valueText = swrText_Translate("~c~s%s");
    sprintf(buffer, valueText, text);
    swrText_CreateTextEntry1(0xa0, 0x25, 0, -1, 0, -1, buffer);
    swrText_GetStringWidthByFont(buffer, 0); // result unused in the original too
    width = swrText_GetStringWidthByFont(buffer, 0);
    swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - (double)width * 0.5), 0x26);

    swrUI_Front_DrawRecord(hang, 100, 0x37, 255.0f, 0);
    swrUI_Front_DrawRecord(hang, 0xdc, 0x37, 255.0f, 3);
    // 3-lap record holder: pilot name + pod sprite
    recordIdx = hang->bMirror + hang->track_index * 2;
    if (swrRace_saveData.record3LapTimes[recordIdx] < ELFSAVE_RECORD_TIME_EMPTY) {
        pilot = swrRace_saveData.record3LapPilots[recordIdx];
        text = swrText_Translate("~f4~c~s%s %s");
        sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(int)pilot].name), swrText_Translate(swrRacer_PodData[(int)pilot].lastname));
        swrText_CreateTextEntry1(100, 0x4e, -0x5d, -0x42, 0x11, -1, buffer);
        swrSprite_SetVisible((short)(pilot + 0x17), 1);
        swrSprite_SetPos((short)(pilot + 0x17), 0x54, 0x55);
        swrSprite_SetDim((short)(pilot + 0x17), 0.5f, 0.5f);
        swrSprite_SetColor((short)(pilot + 0x17), 0xff, 0xff, 0xff, 0xff);
    }
    // best-lap record holder
    if (swrRace_saveData.recordLapTimes[recordIdx] < ELFSAVE_RECORD_TIME_EMPTY) {
        pilot = swrRace_saveData.recordLapPilots[recordIdx];
        text = swrText_Translate("~f4~c~s%s %s");
        sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(int)pilot].name), swrText_Translate(swrRacer_PodData[(int)pilot].lastname));
        swrText_CreateTextEntry1(0xdc, 0x4e, -0x5d, -0x42, 0x11, -1, buffer);
        swrSprite_SetVisible((short)(pilot + 0x2e), 1);
        swrSprite_SetPos((short)(pilot + 0x2e), 0xcc, 0x55);
        swrSprite_SetDim((short)(pilot + 0x2e), 0.5f, 0.5f);
        swrSprite_SetColor((short)(pilot + 0x2e), 0xff, 0xff, 0xff, 0xff);
    }
    // track favorite
    favoritePilot = g_aTrackInfos[(int)hang->track_index].FavoritePilot;
    text = swrText_Translate(g_pTxtTrackFavorite);
    swrText_CreateTextEntry1(0xf0, 0x82, 0x32, -1, -1, -1, text);
    text = swrText_Translate("~f4~c~s%s %s");
    sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(char)favoritePilot].name), swrText_Translate(swrRacer_PodData[(char)favoritePilot].lastname));
    swrText_CreateTextEntry1(0xf0, 0x89, -0x5d, -0x42, 0x11, -1, buffer);
    swrSprite_SetVisible((short)(char)favoritePilot, 1);
    swrSprite_SetPos((short)(char)favoritePilot, 0xd0, 0x91);
    swrSprite_SetDim((short)(char)favoritePilot, 1.0f, 1.0f);
    swrSprite_SetColor((short)(char)favoritePilot, 0xff, 0xff, 0xff, 0xff);
    if (hang->isTournamentMode != 0) {
        trackInCircuit = swrObjHang_VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
        if (swrObjHang_IsTrackUnlocked(hang->circuitIdx, (char)trackInCircuit) != 0) {
            text = swrText_Translate(required == 3 ? g_pTxtMinPlace3rd : g_pTxtMinPlace4th);
            swrText_CreateTextEntry1(0xa0, 0x73, -0x5d, -0x42, 0x11, -1, text);
        }
    }

    if (swrObjHang_courseInfoLeaving == 0 && 1.0f <= swrRace_Transition) {
        // the original iterates a single element: only player 1's pressed bitset
        int* pressed = swrUI_localPlayersInputPressedBitset;
        if (swrMultiplayer_menuOverlayActive == 0) {
            if (swrControl_menuAcceptPressedEdge != 0 && (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) && swrObjHang_menuAcceptLock == 0) {
                swrSound_PlayUISound(0x54);
                if (hang->isTournamentMode == 0) {
                    if (hang->timeAttackMode != 0) {
                        hang->num_players = 1;
                    } else if (hang->num_local_players < 2) {
                        if (hang->demo_mode != 0 && (uint8_t)nb_AI_racers == 2)
                            hang->num_players = 1;
                        else
                            hang->num_players = (uint8_t)nb_AI_racers;
                    } else {
                        hang->num_players = swrObjHang_splitscreenRacerCount;
                    }
                } else {
                    hang->num_players = 12;
                }
                swrObjHang_InitTrackSprites(hang, 0);
                swrObjHang_FocusMenuItem(hang, 0x24, swrObjHang_STATE_MAIN_MENU, 0);
                swrObjHang_courseInfoLeaving = 1;
                return;
            }
            if (swrControl_cancelPressedEdge != 0 && swrObjHang_menuAcceptLock == 0) {
                swrSound_PlayUISound(0x4d);
                swrObjHang_InitTrackSprites(hang, 0);
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_PLANET);
                return;
            }
        }
        if (1 < swrObjHang_courseInfoItemCount) {
            if ((*pressed & swrUI_INPUT_MENU_UP) != 0) {
                swrObjHang_courseInfoSelectedRow--;
                swrSound_PlayUISound(0x58);
            }
            if ((*pressed & swrUI_INPUT_MENU_DOWN) != 0) {
                swrObjHang_courseInfoSelectedRow++;
                swrSound_PlayUISound(0x58);
            }
            if (swrObjHang_courseInfoSelectedRow < 0)
                swrObjHang_courseInfoSelectedRow = swrObjHang_courseInfoItemCount - 1;
            if (swrObjHang_courseInfoItemCount - 1 < swrObjHang_courseInfoSelectedRow)
                swrObjHang_courseInfoSelectedRow = 0;
        }
        if (0 < swrObjHang_courseInfoItemCount) {
            if ((*pressed & swrUI_INPUT_MENU_RIGHT) != 0) {
                switch (swrObjHang_courseInfoItemKinds[swrObjHang_courseInfoSelectedRow]) {
                case 0:
                    hang->bMirror = hang->bMirror == 0;
                    break;
                case 1:
                    hang->WinningsID++;
                    break;
                case 2:
                    hang->numLaps++;
                    break;
                case 3:
                    if (hang->num_local_players < 2) {
                        // 1 <-> 2 <-> 4 <-> 8 <-> 12 racers
                        if ((uint8_t)nb_AI_racers == 8)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
                        else if ((uint8_t)nb_AI_racers == 0xc)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 1;
                        else
                            nb_AI_racers = (nb_AI_racers & ~0xff) | (uint8_t)((uint8_t)nb_AI_racers << 1);
                    } else {
                        swrObjHang_splitscreenRacerCount += 2;
                        if (swrObjHang_splitscreenRacerCount == 8)
                            swrObjHang_splitscreenRacerCount = 2;
                    }
                    break;
                case 4:
                    hang->AISpeed++;
                    break;
                case 5:
                    hang->demo_mode = hang->demo_mode == 0;
                    break;
                case 6:
                    hang->unk68_type++;
                    break;
                }
                swrSound_PlayUISound(0x58);
            }
            if ((*pressed & swrUI_INPUT_MENU_LEFT) != 0) {
                switch (swrObjHang_courseInfoItemKinds[swrObjHang_courseInfoSelectedRow]) {
                case 0:
                    hang->bMirror = hang->bMirror == 0;
                    break;
                case 1:
                    hang->WinningsID--;
                    break;
                case 2:
                    hang->numLaps--;
                    break;
                case 3:
                    if (hang->num_local_players < 2) {
                        if ((uint8_t)nb_AI_racers == 0xc)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 8;
                        else if ((uint8_t)nb_AI_racers == 1)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
                        else
                            nb_AI_racers = (nb_AI_racers & ~0xff) | (uint8_t)((uint8_t)nb_AI_racers >> 1);
                    } else {
                        swrObjHang_splitscreenRacerCount -= 2;
                        if (swrObjHang_splitscreenRacerCount == 0)
                            swrObjHang_splitscreenRacerCount = 6;
                    }
                    break;
                case 4:
                    hang->AISpeed--;
                    break;
                case 5:
                    hang->demo_mode = hang->demo_mode == 0;
                    break;
                case 6:
                    hang->unk68_type--;
                    break;
                }
                swrSound_PlayUISound(0x58);
            }
        }
        // wrap the cycling options
        if (hang->numLaps < 1)
            hang->numLaps = 5;
        if (5 < hang->numLaps)
            hang->numLaps = 1;
        if (hang->AISpeed < 1)
            hang->AISpeed = 3;
        if (3 < hang->AISpeed)
            hang->AISpeed = 1;
        if (hang->WinningsID < 1)
            hang->WinningsID = 3;
        if (3 < hang->WinningsID)
            hang->WinningsID = 1;
        if (hang->unk68_type < -1)
            hang->unk68_type = 0x14;
        if (0x14 < hang->unk68_type)
            hang->unk68_type = -1;

        if (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) {
            g_LoadTrackModel = g_aTrackInfos[(int)hang->track_index].trackID;
            swrMultiplayer_BroadcastPlayerState();
        }
    }
}

// Post-race: spend the race's damage as random 25..76-point hits on installed parts, then
// let the pit droids (255 points each) repair random parts the same way.
// 0x0043d720
void swrRace_UpdatePartsHealth(void)
{
    swrSaveProfile* profile = &swrRace_aProfiles[0];
    int damage;
    int repair;
    int missing;
    int installed;
    int part;
    uint8_t wear;
    uint8_t health;
    int i;

    damage = (int)(swrScores[0].lastRaceDamage * 255.0f);
    if (damage > SWR_PART_DAMAGE_MAX)
        damage = SWR_PART_DAMAGE_MAX;
    installed = 0;
    for (i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++) {
        if (profile->upgradeLevels[i] != 0)
            installed++;
    }
    if (installed == 0)
        return;

    wear = (uint8_t)(25 - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -52.0f));
    while (wear <= damage) {
        part = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 7.0f);
        if (profile->upgradeLevels[part] != 0) {
            health = (uint8_t)profile->upgradeHealths[part];
            profile->upgradeHealths[part] = (health > wear) ? (char)(health - wear) : 0;
        }
        damage -= wear;
        wear = (uint8_t)(25 - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -52.0f));
    }
    for (i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++) {
        if (profile->upgradeLevels[i] == 0)
            profile->upgradeHealths[i] = (char)0xff;
    }

    missing = 0;
    for (i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++)
        missing += 0xff - (uint8_t)profile->upgradeHealths[i];
    repair = (uint8_t)profile->nbPitDroids * 0xff;
    if (repair >= missing) {
        for (i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++)
            profile->upgradeHealths[i] = (char)0xff;
        swrRace_SaveCurrentProfile();
        return;
    }

    wear = (uint8_t)(25 - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -52.0f));
    while (wear <= repair) {
        part = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 7.0f);
        health = (uint8_t)profile->upgradeHealths[part];
        if (health != 0xff) {
            if (0xff - health < wear) {
                profile->upgradeHealths[part] = (char)0xff;
                wear = (uint8_t)(wear + health + 1); // EXE charges wear + health + 1 (byte), not 255 - health
            } else {
                profile->upgradeHealths[part] = (char)(wear + health);
            }
            repair -= wear;
        }
        wear = (uint8_t)(25 - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -52.0f));
    }
    swrRace_SaveCurrentProfile();
}

// 0x0043d970
void swrRace_ResetAllProfiles(void)
{
    int i;

    for (i = 0; i < 20; i++)
        swrRace_GenerateDefaultDataSAV(0, i);
    for (i = 0; i < 4; i++)
        swrRace_GenerateDefaultDataSAV(1, i);
}

// 0x0043d9a0
void swrRace_CheatUnlockAll(void)
{
    if (swrRace_cheatUnlockAllDone == 0) {
        swrText_ShowTimedMessage("All Pods, tracks unlocked!!!", 3.0f);
        if (swrRace_cheatUnlockAllDone == 0) {
            swrRace_cheatUnlockAllDone = 1;
            swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST;
            g_aBeatTracksGlobal[3] = 0xf;
            swrRace_saveData.pilotsUnlockedGlobal = 0xfffffff;
            swrRace_aProfiles[0].pilotsUnlocked = 0xfffffff;
            swrRace_saveData.profiles[0].pilotsUnlocked = 0xfffffff;
            g_aBeatTracksGlobal[0] = 0xff;
            g_aBeatTracksGlobal[1] = 0xff;
            g_aBeatTracksGlobal[2] = 0xff;
            swrRace_SaveCurrentProfile();
        }
    }
}

// 0x0043ea00
void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot)
{
    swrSaveProfile* profile;
    int i;

    if (user_tgfd == 0)
        profile = &swrRace_aProfiles[slot];
    else if (user_tgfd == 1)
        profile = &swrRace_saveData.profiles[slot];
    else
        return;

    profile->unk20 = 0;
    profile->truguts = ELFSAVE_DEFAULT_TRUGUTS;
    profile->nbPitDroids = 1;
    profile->unk23 = 0;
    profile->pilotsUnlocked = ELFSAVE_DEFAULT_PILOTS;
    profile->planetIntrosSeen = 0;
    profile->linkedToSave = 1;
    profile->pilotId = 0;
    profile->saveSlot = (uint8_t)slot;
    profile->beatTrackPlace[0] = 0;
    profile->beatTrackPlace[1] = 0;
    profile->beatTrackPlace[2] = 0;
    profile->beatTrackPlace[3] = 0;
    profile->tracksUnlocked[0] = 1;
    profile->tracksUnlocked[1] = 1;
    profile->tracksUnlocked[2] = 1;
    profile->circuitsCompleted = 0;
    for (i = 0; i < 7; i++) {
        profile->upgradeLevels[i] = 0;
        profile->upgradeHealths[i] = -1;
    }
    memset(profile->name, 0, sizeof(profile->name));
    if (user_tgfd == 1)
        profile->unk4f = 0;
}

// swrObjHang_cameraMatrix.vD + swrObjElmo_waypoints[7] along the camera's axes
static void partDetailPosition(rdVector3* out)
{
    swrObjHang_UpdateHoloBillboardMatrix();
    rdVector_Copy3(out, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Scale3Add3(out, out, swrObjElmo_waypoints[7].x, (rdVector3*)&swrObjHang_cameraMatrix.vA);
    rdVector_Scale3Add3(out, out, swrObjElmo_waypoints[7].y, (rdVector3*)&swrObjHang_cameraMatrix.vB);
    rdVector_Scale3Add3(out, out, swrObjElmo_waypoints[7].z, (rdVector3*)&swrObjHang_cameraMatrix.vC);
}

static void pullTowardEye(rdVector3* v)
{
    rdVector_Scale3Add3_both(v, 0.2f, v, 0.8f, (rdVector3*)&swrObjHang_cameraMatrix.vD);
}

static float shopIconTilt(void)
{
    float s;
    float c;

    stdMath_SinCos((float)((1.5 - swrObjHang_shopSwingPhase) * 360.0), &s, &c);
    return (float)(c * swrObjHang_shopSwingLean * 45.0);
}

// 0x0043da10
void swrRace_BuildPartMenuList(swrObjHang* hang)
{
    uint32_t unlocked;
    int racer;
    int count;

    unlocked = swrRace_aProfiles[hang->current_player_for_vehicle_selection].pilotsUnlocked | ELFSAVE_DEFAULT_PILOTS;
    count = 0;
    for (racer = 0; racer < SWR_PILOT_COUNT; racer++) {
        if ((unlocked & (1 << racer)) != 0 || swrMultiplayer_enabled != 0) {
            swrRace_SelectIndex[count].racerId = racer;
            swrRace_SelectIndex[count].unk4 = 0xff;
            swrRace_SelectIndex[count].unk5 = 0;
            count++;
        }
    }
    for (racer = count; racer < SWR_PILOT_COUNT; racer++) {
        swrRace_SelectIndex[racer].racerId = -1;
        swrRace_SelectIndex[racer].unk4 = 0xff;
        swrRace_SelectIndex[racer].unk5 = 0;
    }
    swrRace_MenuMaxSelection = count;
}

// 0x0043dba0
void swrRace_UpdatePartMenuLayout(swrObjHang* hang)
{
    float duration = SWR_PART_LERP_TIME;
    float s;
    float c;
    rdVector3 detailPos;

    // let the shop ring's swing settle
    if (swrObjHang_shopSwingLean < 0.0f) {
        swrObjHang_shopSwingLean = swrObjHang_shopSwingLean + swrRace_fdeltaTimeSecs;
        if (0.0f < swrObjHang_shopSwingLean)
            swrObjHang_shopSwingLean = 0.0f;
    }
    if (0.0f < swrObjHang_shopSwingLean) {
        swrObjHang_shopSwingLean = swrObjHang_shopSwingLean - swrRace_fdeltaTimeSecs;
        if (swrObjHang_shopSwingLean < 0.0f)
            swrObjHang_shopSwingLean = 0.0f;
    }
    if (0.0f < swrObjHang_shopSwingPhase) {
        swrObjHang_shopSwingPhase = swrObjHang_shopSwingPhase - swrRace_fdeltaTimeSecs;
        if (swrObjHang_shopSwingPhase < 0.0f)
            swrObjHang_shopSwingPhase = 0.0f;
    }
    for (int i = 0; i < swrRace_MenuMaxSelection; i++) {
        swrUIUpgradeInfo* icon = &uiUpgradeInfos2[i];
        if (hang->room != Shop)
            continue;
        if (i != swrRace_MenuSelectedItem)
            icon->yawDegrees = stdMath_ArcTan2(icon->vector1.x - 12.0f, -116.0f - icon->vector1.y) - 90.0f;
        if (icon->vector1.z == 106.0f)
            icon->tiltDegrees = shopIconTilt();
    }

    if (swrObjHang_partLayoutDirty != 0) {
        if (hang->room == Shop) {
            for (int i = 0; i < swrRace_MenuMaxSelection; i++) {
                swrUIUpgradeInfo* icon = &uiUpgradeInfos2[i];
                stdMath_SinCos((float)(((swrRace_MenuSelectedItem - i) + 9) * 10), &s, &c);
                icon->vector3.x = 12.0f - c * -256.0f;
                icon->vector3.y = -116.0f - s * -256.0f;
                icon->vector3.z = 106.0f;
                if (i != swrRace_MenuSelectedItem)
                    icon->yawDegrees = stdMath_ArcTan2(icon->vector1.x - 12.0f, -116.0f - icon->vector1.y) - 90.0f;
                icon->tiltDegrees = shopIconTilt();
                if (i == swrRace_MenuSelectedItem) {
                    if (swrObjHang_partDetailActive != 0) {
                        partDetailPosition(&detailPos);
                        rdVector_Copy3(&icon->vector3, &detailPos);
                        pullTowardEye(&icon->vector1);
                    } else {
                        rdVector_Copy3(&icon->vector3, &swrObjElmo_waypoints[6]);
                        icon->tiltDegrees = 0.0f;
                        icon->yawDegrees = stdMath_ArcTan2(swrObjElmo_waypoints[6].x - 12.0f, -116.0f - swrObjElmo_waypoints[6].y) - 90.0f;
                        if (swrObjHang_partDetailClosing != 0)
                            pullTowardEye(&icon->vector3);
                    }
                }
                rdVector_Copy3(&icon->vector2, &icon->vector1);
            }
        } else if (hang->room == Junkyard) {
            int slot = hang->cameraState - SWR_JUNKYARD_PLACEMENT_FIRST;
            swrRace_MenuSelectedItem = swrObjHang_junkyardStock[slot].partType;
            if (swrRace_MenuSelectedItem < 0 || slot < 0) {
                swrObjHang_partLayoutDirty = 0;
                return;
            }
            swrUIUpgradeInfo* icon = &uiUpgradeInfos2[swrRace_MenuSelectedItem];
            if (swrObjHang_partDetailActive != 0) {
                partDetailPosition(&detailPos);
                rdVector_Copy3(&icon->vector3, &detailPos);
                pullTowardEye(&icon->vector1);
            } else {
                rdVector_Copy3(&icon->vector3, &swrObjHang_cameraPlacements[hang->cameraState].position2);
                if (swrObjHang_partDetailClosing != 0)
                    pullTowardEye(&icon->vector3);
            }
            rdVector_Copy3(&icon->vector2, &icon->vector1);
        }
        swrObjHang_partLayoutDirty = 0;
        swrObjHang_partLerpActive = 1;
        swrObjHang_partLerpTime = 0.0f;
    }

    if (swrObjHang_cameraMoveActive != 0)
        duration = SWR_PART_LERP_TIME_CAMERA_MOVE;
    if (swrObjHang_partLerpActive == 0 || !(swrObjHang_partLerpTime < duration))
        return;
    swrObjHang_partLerpTime = swrObjHang_partLerpTime + swrRace_fdeltaTimeSecs;
    if (!(swrObjHang_partLerpTime < duration)) {
        swrObjHang_partLerpTime = duration;
        swrObjHang_partLerpActive = 0;
    }
    for (int i = 0; i < swrRace_MenuMaxSelection; i++) {
        swrUIUpgradeInfo* icon = &uiUpgradeInfos2[i];
        if (hang->room != Junkyard || swrRace_MenuSelectedItem == i) {
            float t = swrObjHang_partLerpTime / duration;
            icon->vector1.x = (icon->vector3.x - icon->vector2.x) * t + icon->vector2.x;
            icon->vector1.y = (icon->vector3.y - icon->vector2.y) * t + icon->vector2.y;
            icon->vector1.z = (icon->vector3.z - icon->vector2.z) * t + icon->vector2.z;
        }
    }
    if (swrObjHang_partLerpActive == 0 && swrObjHang_partDetailClosing != 0) {
        swrObjHang_partDetailClosing = 0;
        rdVector_Copy3(&uiUpgradeInfos2[swrRace_MenuSelectedItem].vector1, hang->room == Shop ? &swrObjElmo_waypoints[6] : (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        uiUpgradeInfos2[swrRace_MenuSelectedItem].tiltDegrees = 0.0f;
    }
}

// 0x0043eb50
void swrRace_ComputeUpgradePrices(void)
{
    int selected = swrRace_MenuSelectedItem;
    char offered = (char)uiUpgradeInfos2[selected].index;
    char type = (char)upgradeInfos[offered].type;
    char installed = (char)uiUpgradeInfos[type].index;
    int tradeIn;

    // faithful: 1 - (int)(price * health * -1/255)
    tradeIn = 1 - (int)((float)(int)(upgradeInfos[installed].price * (uint8_t)(&swrRace_traction_upgrade_health)[type]) * SWR_UPGRADE_PRICE_HEALTH_SCALE);
    swrRace_upgradeTradeInValue = tradeIn;
    swrRace_upgradePrice = 1 - (int)((float)(int)(upgradeInfos[offered].price * uiUpgradeInfos2[selected].health) * SWR_UPGRADE_PRICE_HEALTH_SCALE);
    swrRace_upgradeUnaffordable = (uint16_t)(tradeIn + swrRace_truguts < swrRace_upgradePrice);
}

// 0x0043ec10
void swrRace_DrawPartShopScreen(swrObjHang* hang)
{
    char text[32];
    char line[32];
    char* name;
    char* format;
    int topY;
    int bottomY;
    int i;
    int type;
    int player;

    if ((swrObjHang_partDetailActive == 0 && swrObjHang_partDetailClosing == 0) || swrObjHang_cameraMoveParity == 0) {
        return;
    }

    topY = (int)(swrObjHang_screenSlideOffset - 3.0f);
    swrSprite_SetColor(0x7b, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(0x7b, 1);
    swrSprite_SetPos(0x7b, 0x1e, topY);
    swrSprite_SetColor(0x78, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x78, 1);
    swrSprite_SetPos(0x78, 0x22, topY + 4);
    name = swrText_Translate((char*)upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index].name);
    format = swrText_Translate("~f4~c~s%s");
    sprintf(text, format, name);
    swrText_CreateTextEntry1(0x56, topY + 6, 0x32, -1, -1, -2, text);
    swrSprite_SetColor(0x80, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x80, 1);
    swrSprite_SetPos(0x80, 0x21, topY + 0x13);
    swrRace_DrawStatBar(hang, 0x88, (short)topY + 0x11, (float)uiUpgradeInfos2[swrRace_MenuSelectedItem].health * 0.0039215684f, -2.0f, 10.0f, 41.0f);
    swrSprite_SetColor(0x79, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x79, 1);
    swrSprite_SetPos(0x79, 0x2a, topY + 0x10);
    swrText_CreateTextEntry1(0x2c, topY + 0x12, 0x32, -1, -1, -2, swrText_Translate("/SCREENTEXT_246/~sPrice"));
    sprintf(text, swrText_Translate("~r~s%d"), swrRace_upgradePrice);
    swrText_CreateTextEntry1(0x87, topY + 0x12, 0x32, -1, -1, -2, text);
    swrSprite_SetColor(0x7a, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x7a, 1);
    swrSprite_SetPos(0x7a, 0x29, topY + 0x1b);

    bottomY = (int)(swrObjHang_screenSlideOffset - 5.0f);
    swrSprite_SetColor(0x7f, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(0x7f, 1);
    swrSprite_SetPos(0x7f, 0xae, bottomY);
    swrSprite_SetColor(0x7d, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x7d, 1);
    swrSprite_SetPos(0x7d, 0xb3, bottomY + 5);
    swrText_CreateTextEntry1(0xb6, bottomY + 6, 0x32, -1, -1, -2, swrText_Translate("/SCREENTEXT_248/~sReplace"));
    swrSprite_SetColor(0x81, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x81, 1);
    swrSprite_SetPos(0x81, 0xb2, bottomY + 0x14);
    swrSprite_SetColor(0x7c, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x7c, 1);
    swrSprite_SetPos(0x7c, 0xbe, bottomY + 0x17);

    // the installed part of the offered part's type
    type = (char)upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index].type;
    name = swrText_Translate((char*)upgradeInfos[(char)uiUpgradeInfos[type].index].name);
    format = swrText_Translate("~f4~c~s%s");
    sprintf(text, format, name);
    swrText_CreateTextEntry1(0xee, bottomY + 0x1a, 0x32, -1, -1, -2, text);
    swrSprite_SetColor(0x7e, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x7e, 1);
    swrSprite_SetPos(0x7e, 0xd6, bottomY + 0x28);
    swrRace_DrawStatBar(hang, 0xff, (short)bottomY + 0x30, (float)(uint8_t)(&swrRace_traction_upgrade_health)[type] * 0.0039215684f, -2.0f, 7.0f, 26.0f);

    for (i = 0; i < 2; i++) {
        swrSprite_SetColor(0x76 + i, 0x32, 0xff, 0xff, 0xfe);
        swrSprite_SetVisible(0x76 + i, 1);
        swrSprite_SetPos(0x76 + i, 0xc2, bottomY + i * 0xb + 0x5d);
        swrSprite_SetColor(0x74 + i, 0x32, 0xff, 0xff, 0xfe);
        swrSprite_SetVisible(0x74 + i, 1);
        swrSprite_SetPos(0x74 + i, 0xdb, bottomY + i * 0xd + 0x7c);
    }

    sprintf(text, "~f4%s", swrText_Translate("/SCREENTEXT_250/~sTrade"));
    swrText_CreateTextEntry1(0xc4, bottomY + 0x60, 0x32, -1, -1, -2, text);
    sprintf(text, "~f4%s", swrText_Translate("/SCREENTEXT_251/~sCost"));
    swrText_CreateTextEntry1(0xc4, bottomY + 0x6b, 0x32, -1, -1, -2, text);
    sprintf(text, swrText_Translate("~r~s%d"), swrRace_upgradeTradeInValue);
    sprintf(line, "~f4%s", text);
    swrText_CreateTextEntry1(0x114, bottomY + 0x60, 0x32, -1, -1, -2, line);
    sprintf(text, swrText_Translate("~r~s%d"), swrRace_upgradePrice - swrRace_upgradeTradeInValue);
    sprintf(line, "~f4%s", text);
    swrText_CreateTextEntry1(0x114, bottomY + 0x6b, 0x32, -1, -1, -2, line);

    // swrRace_upgradeUnaffordable doubles as the BUY(0)/CANCEL(1) cursor; short of truguts pins it to CANCEL
    if (swrRace_truguts < swrRace_upgradePrice - swrRace_upgradeTradeInValue) {
        swrRace_upgradeUnaffordable = 1;
    }
    swrUI_Front_TextMenu(hang, 0xfc, (short)bottomY + 0x7e, 0xd, (short)swrRace_upgradeUnaffordable, 0, swrText_Translate("/SCREENTEXT_254/~c~sBUY"));
    swrUI_Front_TextMenu(hang, 0xfc, (short)bottomY + 0x7e, 0xd, (short)swrRace_upgradeUnaffordable, 1, swrText_Translate("/SCREENTEXT_257/~c~sCANCEL"));
    swrText_CreateTextEntry1(0xfe, bottomY + 0xa5, -0x5d, -0x42, 0x11, -2, swrText_Translate("/SCREENTEXT_599/~c~sTruguts"));
    // faithful: the binary also subtracts a 0.0 double here
    swrObjHang_PositionHoloNode(0, 5.0f, (float)((double)(swrObjHang_screenSlideOffset - 6.0f) - 0.0), 1.0f);
    sprintf(text, swrText_Translate("~r~sX %d"), swrRace_truguts);
    swrText_CreateTextEntry1(0x122, bottomY + 0xb4, 0x32, -1, -1, -2, text);
    if (swrRace_truguts < swrRace_upgradePrice - swrRace_upgradeTradeInValue) {
        swrText_CreateTextEntry1(0x122, bottomY + 0xb4, -1, 0, 0, -2, text);
    }

    for (player = 0; player < 4; player++) {
        if (swrObjHang_partDetailActive != 0 && (swrUI_localPlayersInputPressedBitset[player] & (swrUI_INPUT_MENU_UP | swrUI_INPUT_MENU_DOWN)) != 0) {
            if (swrRace_truguts < swrRace_upgradePrice - swrRace_upgradeTradeInValue) {
                swrSound_PlayUISound(0x4b);
            } else {
                swrRace_upgradeUnaffordable = (uint16_t)(swrRace_upgradeUnaffordable == 0);
                swrSound_PlayUISound(0x58);
            }
        }
    }
}

// spin a part about the camera's forward axis, tilt it 45 degrees about the up axis, spin back
static void spinPartTowardCamera(rdMatrix44* m, const rdMatrix44* cam)
{
    rdMatrix_AddRotationFromVectorAngle44After(m, m, swrObjHang_partSpinAngle * 4.0f, cam->vC.x, cam->vC.y, cam->vC.z);
    rdMatrix_AddRotationFromVectorAngle44After(m, m, 45.0f, cam->vB.x, cam->vB.y, cam->vB.z);
    rdMatrix_AddRotationFromVectorAngle44After(m, m, swrObjHang_partSpinAngle * -1.0f, cam->vC.x, cam->vC.y, cam->vC.z);
}

// 0x004557e0
void swrRace_DrawStatBar(swrObjHang* hang, short x, short y, float fill, float alpha, float width, float height)
{
    short id;
    float empty;
    float barWidth;
    float barHeight;
    uint8_t a;

    if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
        barWidth = 0.375f;
        barHeight = 3.75f;
    } else {
        barHeight = height * 0.125f;
        barWidth = (width - 2.0f) * 0.125f;
        x = x + 3;
        y = y + 1;
    }

    // dark backing for the unfilled part, then the filled part shaded red -> green
    id = (short)swrRace_statBarSpriteCount + SWR_STAT_BAR_SPRITE_BASE;
    swrRace_statBarSpriteCount++;
    swrSprite_SetVisible(id, 1);
    swrSprite_SetPos(id, x, y);
    empty = 1.0f - fill;
    swrSprite_SetDim(id, barWidth, barHeight * empty);
    a = (uint8_t)(int)alpha;
    swrSprite_SetColor(id, 0, 0, 0, a);

    id = (short)swrRace_statBarSpriteCount + SWR_STAT_BAR_SPRITE_BASE;
    swrRace_statBarSpriteCount++;
    swrSprite_SetVisible(id, 1);
    // the original offsets by the unscaled height arg here
    swrSprite_SetPos(id, x, (short)(int)(height * empty + (float)y));
    swrSprite_SetDim(id, barWidth, barHeight * fill);
    swrSprite_SetColor(id, (uint8_t)(int)(empty * 255.0f), (uint8_t)(int)(fill * 255.0f), 0, a);
}

// 0x00455930
void swrRace_DrawUpgradesPanel(swrObjHang* hang)
{
    float alpha;
    float x;
    float y;
    uint8_t a;
    short id;
    short px;
    int i;
    swrModel_Header* model;
    swrModel_NodeTransformed* node;
    swrUIUpgradeInfo* info;
    rdVector3 pos;
    rdMatrix44 billboard;
    rdMatrix44 transform;

    alpha = swrObjHang_lookAtMenuFade * 2.5f * 255.0f;
    if (alpha > 254.0f)
        alpha = 254.0f;
    swrObjHang_VehicleStatisticsSubMenu(hang, 20.0f, 135.0f);

    if (swrRace_MenuMaxSelection + 1 > 0) {
        a = (uint8_t)(int)alpha;
        for (i = 0; i < swrRace_MenuMaxSelection + 1; i++) {
            id = 0x62 + i;
            x = (float)((i % 2) * 40 + 210) + 5.0f;
            y = (float)((i / 2) * 35 + 20);
            swrSprite_SetVisible(id, 1);
            px = (short)(int)(x + 2.0f);
            swrSprite_SetPos(id, px, (short)(int)(y + 1.0f));
            if (i == swrRace_MenuMaxSelection)
                swrSprite_SetPos(id, px, (short)(int)(y + 2.0f));
            swrSprite_SetColor(id, 0x32, 0xff, 0xff, a);

            id = 0x6a + i;
            swrSprite_SetVisible(id, 1);
            swrSprite_SetPos(id, (short)(int)x, (short)(int)y);
            swrSprite_SetColor(id, 0xa3, 0xbe, 0x11, a);

            if (i == swrObjHang_hangarUpgradeType) {
                id = 0x72 + (i >= swrRace_MenuMaxSelection);
                swrSprite_SetVisible(id, 1);
                px = (short)(int)(x - 5.0f);
                swrSprite_SetPos(id, px, (short)(int)(y - 7.0f));
                if (i == swrRace_MenuMaxSelection)
                    swrSprite_SetPos(id, px, (short)(int)(y - 4.0f));
                swrSprite_SetColor(id, 0x32, 0xff, 0xff, a);
            }

            if (i < swrRace_MenuMaxSelection)
                swrRace_DrawStatBar(hang, (short)(int)(x + 36.0f), (short)(int)(y + 2.0f), (float)(uint8_t)(&swrRace_traction_upgrade_health)[i] * 0.003921569f, alpha, 3.0f, 30.0f);
        }
    }

    for (i = 0; i < swrRace_MenuMaxSelection + 1; i++) {
        model = swr_sceneModels[SWR_SCENE_SLOT_INSTALLED_PARTS + i];
        node = (swrModel_NodeTransformed*)model->entries[0].node;
        if (node == NULL)
            continue;
        info = &uiUpgradeInfos[i];
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        if (i == swrRace_MenuMaxSelection && model->entries[3].node != NULL)
            swrModel_NodeModifyFlags(model->entries[3].node, 2, -4, 0x10, 3);

        swrObjHang_UpdateHoloBillboardMatrix();
        rdMatrix_Copy44(&billboard, &swrObjHang_cameraMatrix);
        rdVector_Copy3(&pos, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        rdVector_Scale3Add3(&pos, &pos, info->vector1.x, (rdVector3*)&swrObjHang_cameraMatrix.vA);
        rdVector_Scale3Add3(&pos, &pos, info->vector1.y, (rdVector3*)&swrObjHang_cameraMatrix.vB);
        rdVector_Scale3Add3(&pos, &pos, info->vector1.z, (rdVector3*)&swrObjHang_cameraMatrix.vC);
        rdVector_Copy3((rdVector3*)&billboard.vD, &pos);
        rdMatrix_Copy44(&transform, &billboard);

        if (i == swrObjHang_hangarUpgradeType && i != swrRace_MenuMaxSelection) {
            rdMatrix_AddRotationFromVectorAngle44After(&transform, &transform, swrObjHang_partSpinAngle * 4.0f, billboard.vC.x, billboard.vC.y, billboard.vC.z);
            rdMatrix_AddRotationFromVectorAngle44After(&transform, &transform, 45.0f, billboard.vB.x, billboard.vB.y, billboard.vB.z);
            rdMatrix_AddRotationFromVectorAngle44After(&transform, &transform, swrObjHang_partSpinAngle * -1.0f, billboard.vC.x, billboard.vC.y, billboard.vC.z);
        }

        alpha = swrObjHang_lookAtMenuFade * 2.5f * 0.003;
        if (i == swrRace_MenuMaxSelection)
            alpha = alpha * 5.5;
        rdMatrix_ScaleBasis44(&transform, alpha, alpha, alpha, &transform);
        rdVector_Copy3((rdVector3*)&transform.vD, &pos);
        swrModel_NodeSetTransform(node, &transform);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }
}

// 0x00455dc0
void swrRace_UpdateStatPartModels(void)
{
    swrModel_NodeTransformed* node;
    swrTranslationRotation xf;
    rdMatrix44 m;
    rdMatrix44 cam;
    rdVector3 previewPos;
    float scale;

    for (int i = 0; i < swrRace_MenuMaxSelection; i++) {
        swrUIUpgradeInfo* icon = &uiUpgradeInfos2[i];
        node = (swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_SHOP_PARTS + i]->entries[0].node;
        if (node == NULL)
            continue;
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        scale = SWR_PART_ICON_SCALE;
        rdVector_Copy3(&xf.translation, &icon->vector1);
        rdVector_Set3(&xf.yaw_roll_pitch, icon->yawDegrees, icon->tiltDegrees, 0.0f);
        rdMatrix_SetTransform44(&m, &xf);
        if (i == swrRace_MenuSelectedItem && (swrObjHang_partDetailActive != 0 || swrObjHang_partDetailClosing != 0)) {
            rdMatrix_Copy44(&cam, &swrObjHang_cameraMatrix);
            rdMatrix_Copy44(&m, &swrObjHang_cameraMatrix);
            rdVector_Copy3((rdVector3*)&m.vD, &icon->vector1);
            if (swrObjHang_partDetailActive != 0 && swrObjHang_partDetailClosing == 0)
                spinPartTowardCamera(&m, &cam);
            else
                rdMatrix_SetRotation44(&m, icon->yawDegrees, 0.0f, 0.0f);
            scale = SWR_PART_DETAIL_SCALE;
            rdVector_Copy3((rdVector3*)&m.vD, &icon->vector1);
        }
        rdMatrix_ScaleBasis44(&m, scale, scale, scale, &m);
        swrModel_NodeSetTransform(node, &m);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }

    // the installed part of the same type floats beside the camera for comparison
    if (swrObjHang_partDetailActive == 0 || swrObjHang_cameraMoveParity == 0 || swrObjHang_screenTransitionDir != 0)
        return;
    node = (swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_INSTALLED_PARTS + (char)upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index].type]->entries[0].node;
    if (node == NULL)
        return;
    swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
    swrObjHang_UpdateHoloBillboardMatrix();
    rdMatrix_Copy44(&cam, &swrObjHang_cameraMatrix);
    rdVector_Copy3(&previewPos, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Scale3Add3(&previewPos, &previewPos, 6.0f, (rdVector3*)&swrObjHang_cameraMatrix.vA);
    rdVector_Scale3Add3(&previewPos, &previewPos, 30.0f, (rdVector3*)&swrObjHang_cameraMatrix.vB);
    rdVector_Scale3Add3(&previewPos, &previewPos, 3.5f, (rdVector3*)&swrObjHang_cameraMatrix.vC);
    rdVector_Copy3(&xf.translation, &previewPos);
    rdVector_Set3(&xf.yaw_roll_pitch, 0.0f, 0.0f, 0.0f);
    rdMatrix_SetTransform44(&m, &xf);
    spinPartTowardCamera(&m, &cam);
    rdMatrix_ScaleBasis44(&m, SWR_PART_INSTALLED_PREVIEW_SCALE, SWR_PART_INSTALLED_PREVIEW_SCALE, SWR_PART_INSTALLED_PREVIEW_SCALE, &m);
    rdVector_Copy3((rdVector3*)&m.vD, &previewPos);
    swrModel_NodeSetTransform(node, &m);
    swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
}

// 0x00456200
void swrRace_UpdatePitDroidModels(void)
{
    swrModel_NodeTransformed* node;
    swrObjElmo* droid;
    rdVector3 ambient;
    rdVector3 lightColor;
    rdVector3 lightPos;
    rdVector3 droidPos;
    rdMatrix44 m;
    float camYaw;
    float sparkScale;
    float animTime;
    int i;

    camYaw = stdMath_ArcTan2(swrObjHang_cameraMatrix.vD.x - swrObjHang_holoCameraMatrix.vD.x, swrObjHang_holoCameraMatrix.vD.y - swrObjHang_cameraMatrix.vD.y);
    ambient.x = 80.0f;
    ambient.y = 75.0f;
    ambient.z = 50.0f;
    for (i = 0; i < swrRace_nbPitDroids; i++) {
        sparkScale = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 2.5 - -2.0;
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PIT_DROIDS + i], &droidPos);
        if (droidPos.z <= -157.0f)
            continue;
        if (swr_sceneModels[INGAME_MODELID_sparky_part_0 + i] == NULL)
            return; // skips the light update below too
        node = (swrModel_NodeTransformed*)swr_sceneModels[INGAME_MODELID_sparky_part_0 + i]->entries[0].node;
        if (node != NULL) {
            swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
            swrModel_NodeSetColorsOnAllMaterials(&node->node, 0, 0, 200, 200, 0xff, 0xff);
            droid = (swrObjElmo*)swrEvent_GetItem('Elmo', SWR_SCENE_SLOT_PIT_DROIDS + i);
            // the spark shows only during the welding animation; the ambient light flickers with it
            animTime = swrModel_GetAnimListTime((swrModel_Animation**)droid->unk34);
            if ((float)swrObjElmo_animFramesPitDroid[SWR_ELMO_PIT_DROID_ANIM_WELD].start * 0.0666f <= animTime && swrModel_GetAnimListTime((swrModel_Animation**)droid->unk34) <= (float)swrObjElmo_animFramesPitDroid[SWR_ELMO_PIT_DROID_ANIM_WELD].end * 0.0666f) {
                ambient.x = 80.0f;
                ambient.y = 75.0f;
                ambient.z = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 120.0 - 30.0 - -50.0f;
                rdMatrix_SetRotation44(&m, camYaw, 0.0f, -90.0f);
                rdVector_Copy3((rdVector3*)&m.vD, &droidPos);
                if (m.vD.x < 0.0f)
                    m.vD.x -= -30.0f;
                else
                    m.vD.x -= 30.0f;
                m.vD.z -= -13.0f;
                rdMatrix_ScaleBasis44(&m, sparkScale, sparkScale, sparkScale, &m);
                swrModel_NodeSetTransform(node, &m);
                swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
            }
        }
        node = (swrModel_NodeTransformed*)swr_sceneModels[INGAME_MODELID_hovcart_part_0 + i]->entries[0].node;
        if (node == NULL)
            continue;
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, 0.0f);
        rdVector_Copy3((rdVector3*)&m.vD, &droidPos);
        rdMatrix_ScaleBasis44(&m, 0.3f, 0.3f, 0.3f, &m);
        m.vD.z -= 30.000002f;
        swrModel_NodeSetTransform(node, &m);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);

        node = (swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_SHADOW_SQUARES + i]->entries[0].node;
        if (node == NULL)
            continue;
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, 0.0f);
        rdVector_Copy3((rdVector3*)&m.vD, &droidPos);
        rdMatrix_ScaleBasis44(&m, 0.3f, 0.3f, 0.3f, &m);
        m.vD.z = -157.0f;
        swrModel_NodeSetTransform(node, &m);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }
    lightColor.x = 255.0f;
    lightColor.y = 255.0f;
    lightColor.z = 200.0f;
    lightPos.x = 0.0f;
    lightPos.y = 0.0f;
    lightPos.z = -40000.0f;
    swrRender_SetLight1FromFloats(-1, &ambient, &lightColor, &lightPos);
}

// 0x0043f380
void swrObjHang_BuyPitDroidsMenu(swrObjHang* hang)
{
    char price[32];
    char line[32];
    int top = (int)(swrObjHang_screenSlideOffset - 5.0f);
    short y = (short)top;
    int i;

    swrSprite_SetColor(0x7f, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(0x7f, 1);
    swrSprite_SetPos(0x7f, 0xae, y);
    swrSprite_SetColor(0x81, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x81, 1);
    swrSprite_SetPos(0x81, 0xb2, y + 0x14);
    swrSprite_SetColor(0x7c, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x7c, 1);
    swrSprite_SetPos(0x7c, 0xbe, y + 0x17);
    swrText_CreateTextEntry1(0xc1, top + 0x1a, 0x32, -1, -1, -2, swrText_Translate("/SCREENTEXT_589/~f4~sBuy Pit Droid?"));
    swrText_CreateTextEntry1(99, top + 0x1e, 0x32, -1, -1, -1, swrText_Translate("/SCREENTEXT_590/~f4~c~sBuy more pit droids to"));
    swrText_CreateTextEntry1(99, top + 0x26, 0x32, -1, -1, -1, swrText_Translate("/SCREENTEXT_591/~f4~c~smake faster repairs to"));
    swrText_CreateTextEntry1(99, top + 0x2e, 0x32, -1, -1, -1, swrText_Translate("/SCREENTEXT_592/~f4~c~syour damaged upgrade parts."));

    swrSprite_SetColor(0x76, 0x32, 0xff, 0xff, 0xfe);
    swrSprite_SetVisible(0x76, 1);
    swrSprite_SetPos(0x76, 0xc2, y + 0x68);
    sprintf(price, swrText_Translate("~r~s%d"), SWR_PITDROID_PRICE);
    sprintf(line, "~f4%s", price);
    swrText_CreateTextEntry1(0x114, top + 0x6b, 0x32, -1, -1, -2, line);
    for (i = 0; i < 2; i++) {
        swrSprite_SetColor(i + 0x74, 0x32, 0xff, 0xff, 0xfe);
        swrSprite_SetVisible(i + 0x74, 1);
        swrSprite_SetPos(i + 0x74, 0xdb, y + i * 0xd + 0x7c);
    }
    sprintf(price, "~f4%s", swrText_Translate("/SCREENTEXT_251/~sCost"));
    swrText_CreateTextEntry1(0xc4, top + 0x6b, 0x32, -1, -1, -2, price);
    swrUI_Front_TextMenu(hang, 0xfc, y + 0x7e, 0xd, (short)swrRace_upgradeUnaffordable, 0, swrText_Translate("/SCREENTEXT_254/~c~sBUY"));
    swrUI_Front_TextMenu(hang, 0xfc, y + 0x7e, 0xd, (short)swrRace_upgradeUnaffordable, 1, swrText_Translate("/SCREENTEXT_257/~c~sCANCEL"));
    swrText_CreateTextEntry1(0xfe, top + 0xa5, -0x5d, -0x42, 0x11, -2, swrText_Translate("/SCREENTEXT_599/~c~sTruguts"));
    if (swrObjHang_screenSlideOffset == 20.0f && swrObjHang_cameraMoveMode != 1)
        swrObjHang_PositionHoloNode(0, 5.0f, (swrObjHang_screenSlideOffset - 6.0f) - 20.5, 1.0f);

    sprintf(price, swrText_Translate("~r~sX %d"), swrRace_truguts);
    swrText_CreateTextEntry1(0x122, top + 0xb4, 0x32, -1, -1, -2, price);
    if (swrRace_truguts < SWR_PITDROID_PRICE)
        swrText_CreateTextEntry1(0x122, top + 0xb4, -1, 0, 0, -2, price);

    // swrRace_upgradeUnaffordable doubles as the BUY(0)/CANCEL(1) cursor; it is pinned to CANCEL when broke
    for (i = 0; i < hang->num_local_players; i++) {
        if ((swrUI_localPlayersInputPressedBitset[i] & (swrUI_INPUT_MENU_UP | swrUI_INPUT_MENU_DOWN)) == 0)
            continue;
        if (swrRace_truguts < SWR_PITDROID_PRICE) {
            swrSound_PlayUISound(0x4b);
        } else {
            swrRace_upgradeUnaffordable = swrRace_upgradeUnaffordable == 0;
            swrSound_PlayUISound(0x58);
        }
    }
    if (swrRace_truguts < SWR_PITDROID_PRICE)
        swrRace_upgradeUnaffordable = 1;
}

// 0x0043fe90
void swrRace_DrawScrollbar(short x, short y, int height)
{
    float rate = swrUI_menuScrolled != 0 ? SWR_SCROLLBAR_ARROW_FADE_RATE : -SWR_SCROLLBAR_ARROW_FADE_RATE;
    swrRace_scrollbarUpArrowAlpha = rate * swrRace_fdeltaTimeSecs + swrRace_scrollbarUpArrowAlpha;
    if (SWR_SCROLLBAR_ARROW_ALPHA_MAX < swrRace_scrollbarUpArrowAlpha)
        swrRace_scrollbarUpArrowAlpha = SWR_SCROLLBAR_ARROW_ALPHA_MAX;
    if (swrRace_scrollbarUpArrowAlpha < 0.0f)
        swrRace_scrollbarUpArrowAlpha = 0.0f;

    rate = g_bCircuitIdxInRange != 0 ? SWR_SCROLLBAR_ARROW_FADE_RATE : -SWR_SCROLLBAR_ARROW_FADE_RATE;
    swrRace_scrollbarDownArrowAlpha = rate * swrRace_fdeltaTimeSecs + swrRace_scrollbarDownArrowAlpha;
    if (SWR_SCROLLBAR_ARROW_ALPHA_MAX < swrRace_scrollbarDownArrowAlpha)
        swrRace_scrollbarDownArrowAlpha = SWR_SCROLLBAR_ARROW_ALPHA_MAX;
    if (swrRace_scrollbarDownArrowAlpha < 0.0f)
        swrRace_scrollbarDownArrowAlpha = 0.0f;

    swrSprite_SetVisible(swrUISprite_select_circle_v_rgb_0, 1);
    swrSprite_SetPos(swrUISprite_select_circle_v_rgb_0, x - 0x1b, y - 0xb);
    swrSprite_SetColor(swrUISprite_select_circle_v_rgb_0, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(swrUISprite_select_arrow_v_rgb_0, 1);
    swrSprite_SetPos(swrUISprite_select_arrow_v_rgb_0, x - 0x14, y - 7);
    swrSprite_SetColor(swrUISprite_select_arrow_v_rgb_0, 0x32, 0xff, 0xff, (uint8_t)(int)swrRace_scrollbarUpArrowAlpha);

    swrSprite_SetVisible(swrUISprite_select_circle_v_rgb_1, 1);
    swrSprite_SetPos(swrUISprite_select_circle_v_rgb_1, x - 0x1b, (short)height + 0xf + y);
    swrSprite_SetColor(swrUISprite_select_circle_v_rgb_1, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetVisible(swrUISprite_select_arrow_v_rgb_1, 1);
    swrSprite_SetPos(swrUISprite_select_arrow_v_rgb_1, x - 0x14, (short)height + 0x17 + y);
    swrSprite_SetColor(swrUISprite_select_arrow_v_rgb_1, 0x32, 0xff, 0xff, (uint8_t)(int)swrRace_scrollbarDownArrowAlpha);

    swrSprite_SetVisible(swrUISprite_select_bars_v_rgb, 1);
    swrSprite_SetPos(swrUISprite_select_bars_v_rgb, x - 0x11, y + 0x12);
    swrSprite_SetColor(swrUISprite_select_bars_v_rgb, 0xa3, 0xbe, 0x11, 0xfe);
    swrSprite_SetDim(swrUISprite_select_bars_v_rgb, 1.0f, (float)height * 0.3333f);

    if (g_bCircuitIdxInRange != 0 && (swrUI_localPlayersInputDownBitset[0] & swrUI_INPUT_MENU_DOWN) != 0) {
        swrSprite_SetVisible(swrUISprite_select_arrow_lit_v_rgb_1, 1);
        swrSprite_SetPos(swrUISprite_select_arrow_lit_v_rgb_1, x - 0x20, (short)height - 0x13 + y);
        swrSprite_SetColor(swrUISprite_select_arrow_lit_v_rgb_1, 0x32, 0xff, 0xff, 0xfe);
    }
    if (swrUI_menuScrolled != 0 && (swrUI_localPlayersInputDownBitset[0] & swrUI_INPUT_MENU_UP) != 0) {
        swrSprite_SetVisible(swrUISprite_select_arrow_lit_v_rgb_0, 1);
        swrSprite_SetPos(swrUISprite_select_arrow_lit_v_rgb_0, x - 0x20, y - 0x11);
        swrSprite_SetColor(swrUISprite_select_arrow_lit_v_rgb_0, 0x32, 0xff, 0xff, 0xfe);
    }
}

// Sets up the global ray-collision query state from `ray` (= {origin.xyz, dir.xyz, maxDist}),
// installs the per-face callbacks, resets the matrix stack, then recursively ray-tests the model's
// node tree (CollideNodeRecursiveRay, which latches the closest hit into the query globals). On a hit
// (closest <= maxDist) it fills outHit/outNormal and returns the hit distance; -1.0 on a miss. The hit
// node is published to swrRace_collisionHitNode.
// 0x00444d10
float swrRace_RaycastModel(swrModel_Node* model, float* ray, rdVector3* outHit, rdVector3* outNormal)
{
    if (model == NULL) {
        swrModel_collisionResultDist = -1.0;
    } else {
        swrModel_collisionResultDist = ray[6] + 200.0f;// closest-hit accumulator, init past maxDist
        swrModel_collisionResultNode = NULL;
        swrModel_collisionRayMaxDist = ray[6];
        swrModel_collisionRayDir.x = ray[3];
        swrModel_collisionRayDir.y = ray[4];
        swrModel_collisionRayDir.z = ray[5];
        swrModel_collisionRayOrigin.x = ray[0];
        swrModel_collisionRayOrigin.y = ray[1];
        swrModel_collisionRayOrigin.z = ray[2];
        swrModel_collisionUnkE1c = 1;
        swrModel_meshCollisionFaceCallback = swrModel_MeshCollisionFaceCallback;
        swrModel_meshCollisionFaceCallbackIndexed = swrModel_MeshCollisionFaceCallbackIndexed;
        swrModel_collisionUnkE70 = 0;
        swrModel_collisionUnk250 = 0;
        rdMatrixStack44_Init();
        swrModel_CollideNodeRecursiveRay((swrModel_NodeTransformed*) model, ray, 0);
        if (swrModel_collisionResultDist <= ray[6]) {
            outHit->x = swrModel_collisionHitPoint.x;
            outHit->y = swrModel_collisionHitPoint.y;
            outHit->z = swrModel_collisionHitPoint.z;
            outNormal->x = swrModel_collisionHitNormal.x;
            outNormal->y = swrModel_collisionHitNormal.y;
            outNormal->z = swrModel_collisionHitNormal.z;
        } else {
            swrModel_collisionResultDist = -1.0;
        }
    }
    if (swrModel_collisionResultNode != NULL)
        swrRace_collisionHitNode = swrModel_collisionResultNode;
    return swrModel_collisionResultDist;
}

// 0x00441010
void swrModel_SetRaycastIgnoreFacing(int value)
{
    swrModel_collisionForceBothFaces = value;
}

// Clears the collision-query "hit node" result before a ray query (the query latches it on hit).
// 0x00441020
void swrRace_ResetCollisionHit(void)
{
    swrRace_collisionHitNode = NULL;
}

// Returns the node hit by the most recent ray query (NULL if none).
// 0x00441030
swrModel_Node* swrRace_GetCollisionHit(void)
{
    return swrRace_collisionHitNode;
}

// TODO: look at 0x0045cf60

// Convert a pod's raw handling stats into the normalized 0..1 garage display bars
// (consumed by swrObjHang_VehicleStatisticsSubMenu and swrObjHang_ComputeUpgradedStats).
// Display only: the flight model reads the raw podStats directly, never this output.
// 0x00449330
RETAIL_FP void swrRace_ComputeStatBars(PodHandlingData* out_stats, PodHandlingData* stats)
{
    int i;
    float* bar;

    // Every constant is a float32.
    out_stats->antiSkid = stats->antiSkid;
    out_stats->turnResponse = stats->turnResponse * (float)0.001f;
    out_stats->maxTurnRate = 1.0f - stdMath_Sqrt(stats->acceleration) * (float)0.4761905f;
    out_stats->acceleration = (stats->maxSpeed - 450.0f) * (float)0.005f;
    out_stats->maxSpeed = 8.0f / stdMath_Sqrt(stats->airBrakeInv * 0.5f) - (float)1.68f;
    out_stats->airBrakeInv = stats->coolRate * (float)0.05f;
    out_stats->deceleration_interval = stats->repairRate;

    // The seven bars are the first seven fields, each clamped to [0.05, 1].
    bar = &out_stats->antiSkid;
    for (i = 0; i < 7; i++) {
        if (bar[i] < (float)0.05f)
            bar[i] = (float)0.05f;
        if (1.0f < bar[i])
            bar[i] = 1.0f;
    }
}

// 0x00449d00
RETAIL_FP void swrRace_ApplyUpgradesToStats(PodHandlingData* pActiveStats, PodHandlingData* pBaseStats, char* pUpgradeLevels, char* pUpgradeHealths)
{
    int i;
    memcpy(pActiveStats, pBaseStats, 0x3Cu);

    i = 0;
    do
    {
        swrRace_CalculateUpgradedStat(pActiveStats, i, (int)pUpgradeLevels[i], (float)(unsigned int)(uint8_t)(pUpgradeLevels + i)[(int)pUpgradeHealths - (int)pUpgradeLevels] * (float)0.003921569f);
        i = i + 1;
    } while (i < 7);
}

// 0x004493f0
RETAIL_FP void swrRace_CalculateUpgradedStat(PodHandlingData* podHandlingData, int upgradeCategory, int upgradeLevel, float upgradeHealth)
{
    // Retail tests the unrounded sum against the upper bound, then the stored float against the lower.
    long double tmp;

    switch (upgradeCategory)
    {
    case 0:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * (float)0.05f + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->antiSkid = 1.0f;
            }
            if (podHandlingData->antiSkid < (float)0.01f)
            {
                podHandlingData->antiSkid = (float)0.01f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * (float)0.1f + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->antiSkid = 1.0f;
            }
            if (podHandlingData->antiSkid < (float)0.01f)
            {
                podHandlingData->antiSkid = (float)0.01f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * (float)0.15f + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->antiSkid = 1.0f;
            }
            if (podHandlingData->antiSkid < (float)0.01f)
            {
                podHandlingData->antiSkid = (float)0.01f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * (float)0.2f + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->antiSkid = 1.0f;
            }
            if (podHandlingData->antiSkid < (float)0.01f)
            {
                podHandlingData->antiSkid = (float)0.01f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 0.25f + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->antiSkid = 1.0f;
            }
            if (podHandlingData->antiSkid < (float)0.01f)
            {
                podHandlingData->antiSkid = (float)0.01f;
                return;
            }
        }
        break;
    case 1:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 116.0f + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->turnResponse = 1000.0f;
            }
            if (podHandlingData->turnResponse < 50.0f)
            {
                podHandlingData->turnResponse = 50.0f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 232.0f + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->turnResponse = 1000.0f;
            }
            if (podHandlingData->turnResponse < 50.0f)
            {
                podHandlingData->turnResponse = 50.0f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 348.0f + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->turnResponse = 1000.0f;
            }
            if (podHandlingData->turnResponse < 50.0f)
            {
                podHandlingData->turnResponse = 50.0f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 464.0f + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->turnResponse = 1000.0f;
            }
            if (podHandlingData->turnResponse < 50.0f)
            {
                podHandlingData->turnResponse = 50.0f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 578.0f + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->turnResponse = 1000.0f;
            }
            if (podHandlingData->turnResponse < 50.0f)
            {
                podHandlingData->turnResponse = 50.0f;
                return;
            }
        }
        break;
    case 2:
        if (upgradeLevel == 1)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.13999999f - -(float)0.86f) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0f < tmp)
            {
                podHandlingData->acceleration = 5.0f;
            }
            if (podHandlingData->acceleration < (float)0.1f)
            {
                podHandlingData->acceleration = (float)0.1f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.27999997f - -(float)0.72f) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0f < tmp)
            {
                podHandlingData->acceleration = 5.0f;
            }
            if (podHandlingData->acceleration < (float)0.1f)
            {
                podHandlingData->acceleration = (float)0.1f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.42000002f - -(float)0.58f) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0f < tmp)
            {
                podHandlingData->acceleration = 5.0f;
            }
            if (podHandlingData->acceleration < (float)0.1f)
            {
                podHandlingData->acceleration = (float)0.1f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.56f - -(float)0.44f) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0f < tmp)
            {
                podHandlingData->acceleration = 5.0f;
            }
            if (podHandlingData->acceleration < (float)0.1f)
            {
                podHandlingData->acceleration = (float)0.1f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.7f - -(float)0.3f) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0f < tmp)
            {
                podHandlingData->acceleration = 5.0f;
            }
            if (podHandlingData->acceleration < (float)0.1f)
            {
                podHandlingData->acceleration = (float)0.1f;
                return;
            }
        }
        break;
    case 3:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 40.0f + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0f < tmp)
            {
                podHandlingData->maxSpeed = 650.0f;
            }
            if (podHandlingData->maxSpeed < 450.0f)
            {
                podHandlingData->maxSpeed = 450.0f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 80.0f + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0f < tmp)
            {
                podHandlingData->maxSpeed = 650.0f;
            }
            if (podHandlingData->maxSpeed < 450.0f)
            {
                podHandlingData->maxSpeed = 450.0f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 120.0f + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0f < tmp)
            {
                podHandlingData->maxSpeed = 650.0f;
            }
            if (podHandlingData->maxSpeed < 450.0f)
            {
                podHandlingData->maxSpeed = 450.0f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 160.0f + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0f < tmp)
            {
                podHandlingData->maxSpeed = 650.0f;
            }
            if (podHandlingData->maxSpeed < 450.0f)
            {
                podHandlingData->maxSpeed = 450.0f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 200.0f + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0f < tmp)
            {
                podHandlingData->maxSpeed = 650.0f;
            }
            if (podHandlingData->maxSpeed < 450.0f)
            {
                podHandlingData->maxSpeed = 450.0f;
                return;
            }
        }
        break;
    case 4:
        if (upgradeLevel == 1)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.07999998f - -(float)0.92f) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0f;
            }
            if (podHandlingData->airBrakeInv < 1.0f)
            {
                podHandlingData->airBrakeInv = 1.0f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.17000002f - -(float)0.83f) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0f;
            }
            if (podHandlingData->airBrakeInv < 1.0f)
            {
                podHandlingData->airBrakeInv = 1.0f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.26f - -(float)0.74f) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0f;
            }
            if (podHandlingData->airBrakeInv < 1.0f)
            {
                podHandlingData->airBrakeInv = 1.0f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.35000002f - -(float)0.65f) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0f;
            }
            if (podHandlingData->airBrakeInv < 1.0f)
            {
                podHandlingData->airBrakeInv = 1.0f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = ((1.0f - upgradeHealth) * (float)0.44f - -(float)0.56f) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0f < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0f;
            }
            if (podHandlingData->airBrakeInv < 1.0f)
            {
                podHandlingData->airBrakeInv = 1.0f;
                return;
            }
        }
        break;
    case 5:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * (float)1.6f + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0f < tmp)
            {
                podHandlingData->coolRate = 20.0f;
            }
            if (podHandlingData->coolRate < 1.0f)
            {
                podHandlingData->coolRate = 1.0f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * (float)3.2f + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0f < tmp)
            {
                podHandlingData->coolRate = 20.0f;
            }
            if (podHandlingData->coolRate < 1.0f)
            {
                podHandlingData->coolRate = 1.0f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * (float)4.8f + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0f < tmp)
            {
                podHandlingData->coolRate = 20.0f;
            }
            if (podHandlingData->coolRate < 1.0f)
            {
                podHandlingData->coolRate = 1.0f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * (float)6.4f + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0f < tmp)
            {
                podHandlingData->coolRate = 20.0f;
            }
            if (podHandlingData->coolRate < 1.0f)
            {
                podHandlingData->coolRate = 1.0f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 8.0f + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0f < tmp)
            {
                podHandlingData->coolRate = 20.0f;
            }
            if (podHandlingData->coolRate < 1.0f)
            {
                podHandlingData->coolRate = 1.0f;
                return;
            }
        }
        break;
    case 6:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * (float)0.1f + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->repairRate = 1.0f;
            }
            if (podHandlingData->repairRate < 0.0f)
            {
                podHandlingData->repairRate = 0.0f;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * (float)0.2f + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->repairRate = 1.0f;
            }
            if (podHandlingData->repairRate < 0.0f)
            {
                podHandlingData->repairRate = 0.0f;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * (float)0.3f + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->repairRate = 1.0f;
            }
            if (podHandlingData->repairRate < 0.0f)
            {
                podHandlingData->repairRate = 0.0f;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * (float)0.4f + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->repairRate = 1.0f;
            }
            if (podHandlingData->repairRate < 0.0f)
            {
                podHandlingData->repairRate = 0.0f;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * (float)0.45f + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0f < tmp)
            {
                podHandlingData->repairRate = 1.0f;
            }
            if (podHandlingData->repairRate < 0.0f)
            {
                podHandlingData->repairRate = 0.0f;
            }
        }
    }
}

// Eases a turn rate (*turnRate) toward targetRate at rateAccel/sec, then integrates it
// (plus steer and bias) into a heading angle (*heading) wrapped to [-180, 180] degrees.
// Both clamps test the unrounded result before it is stored to float.
// 0x0044ae40
RETAIL_FP void swrRace_UpdateTurn(float* turnRate, float* heading, float targetRate, float rateAccel, float steer, float bias)
{
    long double step = rateAccel;
    long double next;

    if (*turnRate <= targetRate) {
        // Accelerate the rate; 5x faster while still on the wrong side of zero.
        if (*turnRate < 0.0f)
            step = rateAccel * 5.0f;
        next = *turnRate + step * swrRace_deltaTimeSecs;
        *turnRate = next;
        if (targetRate < next)
            *turnRate = targetRate;
    } else {
        if (0.0f < *turnRate)
            step = rateAccel * 5.0f;
        next = *turnRate - step * swrRace_deltaTimeSecs;
        *turnRate = next;
        if (next < targetRate)
            *turnRate = targetRate;
    }

    // Snap to zero when the steering input opposes the current rate's sign.
    if (0.0f < steer && *turnRate < 0.0f)
        *turnRate = 0.0f;
    if (steer < 0.0f && 0.0f < *turnRate)
        *turnRate = 0.0f;

    // Integrate into the heading angle and wrap to [-180, 180].
    next = *heading + ((*turnRate + bias) + steer) * swrRace_deltaTimeSecs;
    *heading = next;
    if (180.0f < next)
        *heading = next - 360.0f;
    if (*heading < -180.0f)
        *heading += 360.0f;
}

// 0x0044af50
RETAIL_FP void swrRace_SetAngleFromTurnRate(float* out_tilt, float cur_turnrate, void* unused, float max_turnrate, float max_angle)
{
    long double tilt;

    tilt = -(cur_turnrate / max_turnrate) * max_angle;
    if (80.0f < tilt)
    {
        tilt = 80.0f;
    }
    if (tilt < -80.0f)
    {
        tilt = -80.0f;
    }
    *out_tilt = *out_tilt - (tilt - *out_tilt) * swrRace_deltaTimeSecs * -5.0;
}

// 0x0044afb0
void swrRace_GetEngineNodeOffsetPos(void** nodePair, rdVector3* outPos)
{
    if (nodePair == NULL) {
        rdVector_Set3(outPos, 0.0f, 0.0f, 0.0f);
        return;
    }
    swrModel_NodeTransformed* node = (swrModel_NodeTransformed*) nodePair[0];
    swrModel_NodeTransformed* offsetNode = (swrModel_NodeTransformed*) nodePair[1];
    if (node == NULL) {
        rdVector_Set3(outPos, 0.0f, 0.0f, 0.0f);
        return;
    }
    rdMatrix44 nodeMat;
    swrModel_NodeGetTransform(node, &nodeMat);
    outPos->x = nodeMat.vD.x;
    outPos->y = nodeMat.vD.y;
    outPos->z = nodeMat.vD.z;
    if (offsetNode != NULL) {
        rdMatrix44 offsetMat;
        swrModel_NodeGetTransform(offsetNode, &offsetMat);
        // offset the node position along the node's own second axis by the offset node's height
        rdVector_Scale3Add3(outPos, outPos, offsetMat.vD.y, (rdVector3*) &nodeMat.vB);
    }
}

// 0x0044b180
void swrRace_SetEngineNodeRotScale(void** nodePair, float scale, float angle)
{
    rdMatrix44 rotScale;
    rdMatrix44 current;
    rdMatrix44 partner;
    rdVector3 pos;
    swrModel_NodeTransformed* node;
    swrModel_NodeTransformed* partnerNode;

    if (nodePair == NULL)
        return;
    node = (swrModel_NodeTransformed*)nodePair[0];
    partnerNode = (swrModel_NodeTransformed*)nodePair[1];
    if (node == NULL)
        return;
    rdMatrix_SetRotation44(&rotScale, angle, 0.0f, 0.0f);
    rdMatrix_ScaleBasis44(&rotScale, scale, scale, scale, &rotScale);
    swrModel_NodeGetTransform(node, &current);
    // the original computes this offset position and never uses it
    rdVector_Copy3(&pos, (rdVector3*)&current.vD);
    if (partnerNode != NULL) {
        swrModel_NodeGetTransform(partnerNode, &partner);
        rdVector_Scale3Add3(&pos, &pos, partner.vD.y, (rdVector3*)&current.vB);
        rdVector_Scale3Add3(&pos, &pos, -partner.vD.y, (rdVector3*)&rotScale.vB);
    }
    swrModel_NodeSetTransform(node, &rotScale);
}

// 0x0044b270
void swrRace_SetEngineNodeTranslation(void** nodePair, rdVector3* pos)
{
    if (nodePair == NULL)
        return;
    swrModel_NodeTransformed* node = (swrModel_NodeTransformed*) nodePair[0];
    swrModel_NodeTransformed* offsetNode = (swrModel_NodeTransformed*) nodePair[1];
    if (node == NULL)
        return;

    rdMatrix44 nodeMat;
    swrModel_NodeGetTransform(node, &nodeMat);
    rdMatrix44 out;
    rdMatrix_Copy44(&out, &nodeMat);
    rdVector_Copy3((rdVector3*) &out.vD, pos);
    if (offsetNode == NULL) {
        swrModel_NodeSetTransform(node, &out);
        return;
    }
    rdMatrix44 offsetMat;
    swrModel_NodeGetTransform(offsetNode, &offsetMat);
    // remove the engine-height offset applied by swrRace_GetEngineNodeOffsetPos
    rdVector_Scale3Add3((rdVector3*) &out.vD, (rdVector3*) &out.vD, -offsetMat.vD.y, (rdVector3*) &out.vB);
    swrModel_NodeSetTransform(node, &out);
}

// 0x0044B530
void swrRace_ReplaceMarsGuoWithJinnReeso(void)
{
    swrRacerData* pod = &swrRacer_PodData[SWR_PILOT_MARS_GUO];
    swrRacerVisualData* vis = &swrRacer_PodVisualData[SWR_PILOT_MARS_GUO];

    pod->pod_modelID = MODELID_jinn_reeso_pod;
    pod->pod_alt_modelID = MODELID_alt_jinn_reeso_pod;
    pod->pod_lod_modelID = MODELID_mid_jinn_reeso_part;
    pod->name = "Jinn";
    pod->lastname = "Reeso";
    pod->puppet_modelId = MODELID_char_jinn_reeso_puppet;

    vis->hoverPadOffsetB.x = 4.43f;
    vis->sweepEngineOffset.x = 2.22f;
    vis->sweepEngineOffset.y = 2.78f;
    vis->sweepEngineOffset.z = 0.0f;
    vis->cableCockpitAnchor.x = 1.26f;
    vis->cableCockpitAnchor.y = 0.24f;
    vis->cableCockpitAnchor.z = -0.46f;
    vis->cableEngineAnchor.x = 0.26f;
    vis->cableEngineAnchor.y = -3.64f;
    vis->cableEngineAnchor.z = -0.31f;
}

// 0x0044B5E0
void swrRace_ReplaceBullseyeWithCyYunga(void)
{
    swrRacerData* pod = &swrRacer_PodData[SWR_PILOT_BULLSEYE];
    swrRacerVisualData* vis = &swrRacer_PodVisualData[SWR_PILOT_BULLSEYE];

    pod->pod_modelID = MODELID_cy_yunga_pod;
    pod->pod_alt_modelID = MODELID_alt_cy_yunga_pod;
    pod->pod_lod_modelID = MODELID_mid_cy_yunga_part;
    pod->name = "Cy";
    pod->lastname = "Yunga";
    pod->puppet_modelId = MODELID_char_cy_yunga_puppet;

    vis->sweepEngineOffset.x = 1.04f;
    vis->sweepEngineOffset.y = 2.08f;
    vis->sweepEngineOffset.z = -1.08f;
    vis->cableEngineAnchor.x = -0.08f;
    vis->cableEngineAnchor.y = -1.66f;
    vis->cableEngineAnchor.z = 2.15f;
}

// Rebuild the save image from scratch. Record defaults are 3599.99s times, all-'A' holder names,
// and each track's favorite pilot as holder.
// 0x0044e320
void swrRace_InitDefaultGameData(void* saveImage)
{
    swrSaveData* save;
    int track;
    int mirror;
    int idx;
    int i;

    save = (swrSaveData*)saveImage;
    memset(save, 0, sizeof(swrSaveData));
    save->unk4 = 1;
    save->sfxVolume = 225;
    save->musicVolume = 200;
    save->unlockFlags = swrSaveData_UNLOCK_DEFAULT_Maybe;
    swrRace_saveDefaultsUnk = 0;
    swr_noop2();
    save->pilotsUnlockedGlobal = ELFSAVE_DEFAULT_PILOTS;
    save->beatTracksGlobal[0] = 7;
    save->beatTracksGlobal[1] = 3;
    save->beatTracksGlobal[2] = 1;
    save->beatTracksGlobal[3] = 0;
    for (track = 0; track < ELFSAVE_NB_TRACKS; track++) {
        for (mirror = 0; mirror < 2; mirror++) {
            idx = track * 2 + mirror;
            save->record3LapTimes[idx] = ELFSAVE_RECORD_TIME_EMPTY;
            save->recordLapTimes[idx] = ELFSAVE_RECORD_TIME_EMPTY;
            for (i = 0; i < 32; i++) {
                save->record3LapNames[idx][i] = 'A';
                save->recordLapNames[idx][i] = 'A';
            }
            save->record3LapPilots[idx] = g_aTrackInfos[track].FavoritePilot;
            save->recordLapPilots[idx] = g_aTrackInfos[track].FavoritePilot;
        }
    }
    for (i = 0; i < 4; i++)
        swrRace_GenerateDefaultDataSAV(1, i);
    // the original hardcodes the global image here, ignoring saveImage
    swrRace_saveData.checksum = swrRace_ComputeSaveChecksum(&swrRace_saveData);
}

// 0x0044e440
unsigned int swrRace_ComputeSaveChecksum(void* saveImage)
{
    return swrRace_Crc32((char*)saveImage + 4, sizeof(swrSaveData) - 4);
}

// 0x0044e460
unsigned int swrRace_Crc32(void* data, int length)
{
    unsigned char* bytes;
    unsigned int crc;

    if (swrRace_aCrc32Table[1] == 0)
        swrRace_InitCrc32Table();
    crc = 0xffffffff;
    bytes = (unsigned char*)data;
    for (; length > 0; length--) {
        crc = (crc << 8) ^ swrRace_aCrc32Table[(crc >> 24) ^ *bytes];
        bytes++;
    }
    return ~crc;
}

// 0x0044e4a0
void swrRace_InitCrc32Table(void)
{
    unsigned int value;
    int i;
    int bit;

    for (i = 0; i < 256; i++) {
        value = i << 24;
        for (bit = 8; bit != 0; bit--) {
            if ((value & 0x80000000) == 0)
                value = value << 1;
            else
                value = (value << 1) ^ 0x4c11db7;
        }
        swrRace_aCrc32Table[i] = value;
    }
}

// 0x0044e4e0
void swrRace_BackupGameData(void)
{
    swrRace_saveDataBackup = swrRace_saveData;
}

// 0x0044e500
void swrRace_CopyProfileFromSave(int workingSlot, int savedSlot)
{
    swrRace_aProfiles[workingSlot] = swrRace_saveData.profiles[savedSlot];
}

// 0x0044e530
void swrRace_CopyProfileToSave(int savedSlot, int workingSlot)
{
    swrRace_saveData.profiles[savedSlot] = swrRace_aProfiles[workingSlot];
}

// 0x0044e560
void swrRace_SaveCurrentProfile(void)
{
    if (swrRace_aProfiles[0].linkedToSave == 1)
        swrRace_CopyProfileToSave(swrRace_aProfiles[0].saveSlot, 0);
    swrRace_CopyProfileToSave(0, 0);
    swrRace_SaveGameData();
    swrRace_SaveProfile(swrRace_saveData.profiles[0].name);
}

// 0x004550d0
void swrObjHang_VehicleStatisticsSubMenu(swrObjHang* hang, float x, float y)
{
    static char* const labels[] = {
        "/SCREENTEXT_403/~f4~sTraction", "/SCREENTEXT_404/~f4~sTurning", "/SCREENTEXT_405/~f4~sAccel.", "/SCREENTEXT_406/~f4~sTop Speed", "/SCREENTEXT_407/~f4~sAir Brake", "/SCREENTEXT_408/~f4~sCooling", "/SCREENTEXT_409/~f4~sRepair",
    };
    static const float labelOffsets[] = { -7.0f, -16.5f, -26.0f, -35.5f, -45.0f, -54.5f, -64.0f };
    float fade;
    float alphaF;
    float firstRowY;
    float barX;
    uint8_t alpha;
    short textX;
    short barXs;
    short rowY;
    short id;
    int changed;
    int i;

    changed = -1;
    fade = 1.0f;
    if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
        fade = swrObjHang_lookAtMenuFade * 2.5f;
    }
    alphaF = fade * 255.0f;
    if (alphaF > 254.0f) {
        alphaF = 254.0f;
    }
    // last stat the candidate upgrade moves
    for (i = 0; i < 7; i++) {
        if (swrRace_statBarChanged[i] != 0) {
            changed = i;
        }
    }

    swrSprite_SetVisible(0x57, 1);
    swrSprite_SetPos(0x57, (short)(int)x, (short)(int)y);
    alpha = (uint8_t)(int)alphaF;
    swrSprite_SetColor(0x57, 0xa3, 0xbe, 0x11, alpha);
    textX = (short)(int)(x - -5.0f);
    swrText_CreateTextEntry1(textX, (int)(y - 4.0f), 0x32, -1, -1, alpha, swrText_Translate("/SCREENTEXT_475/~f4~sVehicle Statistics"));
    for (i = 0x58; i < 0x5f; i++) {
        swrSprite_SetVisible(i, 1);
        swrSprite_SetPos(i, textX, (short)(int)(y - (float)(i - 0x58) * -9.5f - -5.0f));
        swrSprite_SetColor(i, 0x32, 0xff, 0xff, alpha);
    }

    firstRowY = y - -7.0f;
    for (i = 0; i < 7; i++) {
        swrText_CreateTextEntry1(textX, (int)(y - labelOffsets[i]), 0x32, -1, -1, alpha, swrText_Translate(labels[i]));
    }

    swrSprite_SetVisible(0x5f, 1);
    swrSprite_SetPos(0x5f, (short)(int)(x - -65.0f), (short)(int)(y - -69.0f));
    swrSprite_SetColor(0x5f, 0x32, 0xff, 0xff, alpha);
    swrSprite_SetVisible(0x60, 1);
    swrSprite_SetPos(0x60, (short)(int)(x - -167.0f), (short)(int)(y - -5.0f));
    swrSprite_SetColor(0x60, 0x32, 0xff, 0xff, alpha);
    if (changed > -1) {
        swrSprite_SetVisible(0x61, 1);
        swrSprite_SetPos(0x61, (short)(int)(x - 6.0f), (short)(int)(y - (float)changed * -9.5f));
        swrSprite_SetColor(0x61, 0x32, 0xff, 0xff, alpha);
    }

    barX = x - -67.0f;
    barXs = (short)(int)barX;
    for (i = 0; i < 7; i++) {
        float current = swrRace_statBarsCurrent[i];
        float preview = swrRace_statBarsPreview[i];

        id = swrRace_menuSpriteCount + 0x82;
        swrRace_menuSpriteCount++;
        swrSprite_SetVisible(id, 1);
        rowY = (short)(int)(firstRowY - (float)i * -9.5f);
        swrSprite_SetPos(id, barXs, rowY);
        if (current == preview) {
            swrSprite_SetDim(id, current * 12.0f, 0.625f);
            swrSprite_SetColor(id, 0x32, 0xff, 0xff, alpha);
        } else if (current < preview) {
            // gain: white bar to the current value, flickering yellow segment up to the preview
            swrSprite_SetDim(id, current * 12.0f, 0.625f);
            swrSprite_SetColor(id, 0x32, 0xff, 0xff, alpha);
            id = swrRace_menuSpriteCount + 0x82;
            swrRace_menuSpriteCount++;
            swrSprite_SetVisible(id, 1);
            swrSprite_SetPos(id, (short)(int)(barX - current * -96.0f), rowY);
            swrSprite_SetDim(id, (preview - current) * 12.0f, 0.625f);
            swrSprite_SetColor(id, 0xa3, 0xbe, 0x11, (uint8_t)(int)(((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 155.0f - -100.0f) * fade));
        } else {
            // loss: white bar to the preview value, flickering red segment up to the current one
            swrSprite_SetDim(id, preview * 12.0f, 0.625f);
            swrSprite_SetColor(id, 0x32, 0xff, 0xff, alpha);
            id = swrRace_menuSpriteCount + 0x82;
            swrRace_menuSpriteCount++;
            swrSprite_SetVisible(id, 1);
            swrSprite_SetPos(id, (short)(int)(barX - preview * -96.0f), rowY);
            swrSprite_SetDim(id, (current - preview) * 12.0f, 0.625f);
            swrSprite_SetColor(id, 0xff, 0x64, 0x64, (uint8_t)(int)(((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 155.0f - -100.0f) * fade));
            // faithful: in the look-at-vehicle screen the loss segment is repainted solid yellow
            if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
                swrSprite_SetColor(id, 0xa3, 0xbe, 0x11, alpha);
            }
        }
    }
}

// In-race HUD for one local racer: frame sprites, speed readout, the ~4s post-lap time popup
// (flicker, "New Record" blink, fanfare guard, FINAL LAP banner), the running TIME when no popup
// is up, the LAP and POS counters, and the speed dial.
// 0x00460950
void swrRace_InRaceTimer(swrScore* score, swrObjJdge* jdge)
{
    swrRace* pod;
    char* text;
    float x;
    float y;
    float speed;
    float lastLapTime;
    float fade;
    float flicker;
    int numLocal;
    int isPlayer2;
    int dialY;
    int lap;
    int lapShown;
    int colR;
    int colG;
    int colB;
    int alpha;
    int lapTimeShown;
    int blinkLapCounter;
    char buffer[256];

    dialY = 0xa4;
    numLocal = swrObjJdge_NumLocalPlayers();
    pod = score->obj_test_ptr;
    isPlayer2 = (score == secondLocalPlayer) ? 1 : 0;
    if (swrRace_GetPauseState() == 0) {
        pod->vibrationMagnitude -= (float)swrRace_deltaTimeSecs;
        if (pod->vibrationMagnitude < 0.0f)
            pod->vibrationMagnitude = 0.0f;
    }
    swrObjJdge_LayoutHudFrameSprites(jdge->hud_mode == swrObjJdge_HUDMODE_PROGRESS_RING ? 5 : (jdge->hud_mode == swrObjJdge_HUDMODE_GAP_ARROWS ? 2 : 0));

    // speed readout
    x = 254.0f;
    y = 190.0f;
    if (numLocal == 2) {
        x = 277.0f;
        y = (float)(isPlayer2 * 0x6e + 0x60);
    }
    speed = pod->speedValue;
    if (speed <= 0.0f)
        speed = 0.0f;
    text = swrText_Translate("~f2~c~s%.0f");
    sprintf(buffer, text, (double)speed);
    swrText_CreateTextEntry1((int)x, (int)y, 0, -0x3d, -2, -2, buffer);

    // lap-time popup panel position (the progress ring occupies the default spot)
    if (jdge->hud_mode == swrObjJdge_HUDMODE_PROGRESS_RING) {
        x = 240.0f;
        y = 30.0f;
    } else {
        x = 160.0f;
        y = 23.0f;
        if (numLocal == 2)
            y = (float)(isPlayer2 * 0x6e + 0x14);
    }
    lap = score->results_P1_Lap;
    lapTimeShown = 0;
    blinkLapCounter = 0;
    if (0 < lap) {
        lastLapTime = (&score->results_P1_Lap1)[lap - 1];
        // the popup fades out over the first 4 seconds of the new lap
        fade = 1.0f - (&score->results_P1_Lap1)[lap] * 0.25f;
        if (fade <= 0.0f || 1.0f <= fade) {
            // popup window over: release the fanfare guard once the sfx cooldown lapses
            if (swrSound_TestSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE) != 0 && swrSound_IsSfxOnCooldown(6, 0) == 0)
                swrSound_ClearSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE);
        } else {
            flicker = 223.25f;
            if (pauseState == 0)
                flicker = (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f;
            colR = (int)flicker;
            colG = (int)((float)colR * 0.5f);
            alpha = (int)(fade * 255.0f) * 8;
            if (255 < alpha)
                alpha = 255;
            text = swrText_Translate("~f3~c~s");
            swrText_CreateTimeEntry((int)x, (int)y, lastLapTime, colR, colG, 0x40, alpha, text);
            text = swrText_Translate("/SCREENTEXT_420/~c~sLAP TIME");
            swrText_CreateTextEntry1((int)x, (int)y + 17, colR, colG, 0x40, alpha, text);
            if (lastLapTime <= jdge->best_lap_time_ms && ((int)(fade * 16.0f) & 1) != 0) {
                // this lap tied/beat the session best: blinking "New Record" + one fanfare
                text = swrText_Translate("/SCREENTEXT_538/~s~cNew Record");
                swrText_CreateTextEntry1((int)x, (int)y + 25, -0x38, -1, 0, alpha, text);
                if (swrSound_TestSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE) == 0) {
                    swrSound_PlaySfxThrottled(6, 0, 0x27, NULL);
                    swrSound_SetSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE);
                }
            }
            lapTimeShown = 1;
            if (lap + 1 == jdge->num_laps) {
                if (numLocalPlayers < 2) {
                    // FINAL LAP banner, fading in over the second half of the popup window
                    fade = (fade - 0.5f) * 2.0f;
                    if (0.0f < fade) {
                        alpha = (int)(fade * 255.0f) * 4;
                        if (255 < alpha)
                            alpha = 255;
                        colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        text = swrText_Translate("/SCREENTEXT_526/~f6~s~cFINAL LAP");
                        swrText_CreateTextEntry1(0xa0, 0x46, colR, colG, colB, alpha, text);
                    }
                } else {
                    // splitscreen has no room for the banner: blink the LAP counter instead
                    blinkLapCounter = ((int)(fade * 36.0f) & 1) != 0;
                }
            }
        }
    }
    if (lapTimeShown == 0 && numLocal < 2) {
        // no lap popup: show the running total race time
        swrRace_hudTimeLabelShown = 0;
        text = swrText_Translate("~f3~c~s");
        swrText_CreateTimeEntry((int)x, (int)y, score->results_P1_total_time, -1, -1, -1, -0x42, text);
        text = swrText_Translate("/SCREENTEXT_422/~c~sTIME");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, -1, -1, -0x42, text);
    }
    if (jdge->hud_mode == swrObjJdge_HUDMODE_SPLIT_OFF || jdge->hud_mode == swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME)
        swrText_CreateTimeEntry(0x121, (int)y, score->results_P1_total_time, -1, -1, -1, -0x42, "~f3~r~s");

    // LAP x/y counter
    x = 62.0f;
    if (jdge->hud_mode != swrObjJdge_HUDMODE_PROGRESS_RING)
        x = 42.0f;
    lapShown = lap + 1;
    if (jdge->num_laps < lapShown)
        lapShown = jdge->num_laps;
    text = swrText_Translate("~f3~c~s%d/%d");
    sprintf(buffer, text, lapShown, jdge->num_laps);
    if (numLocalPlayers < 2 || blinkLapCounter == 0) {
        swrText_CreateTextEntry1((int)x, (int)y, -1, -1, -1, -0x42, buffer);
        text = swrText_Translate("/SCREENTEXT_424/~c~sLAP");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, -1, -1, -0x42, text);
    } else {
        swrText_CreateTextEntry1((int)x, (int)y, -1, 0x3f, 0x3f, -1, buffer);
        text = swrText_Translate("/SCREENTEXT_424/~c~sLAP");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, 0x3f, 0x3f, -1, text);
    }

    // POS x/y counter (hidden in hud modes 1/6/7)
    if (jdge->hud_mode != swrObjJdge_HUDMODE_PROGRESS_RING && jdge->hud_mode != swrObjJdge_HUDMODE_SPLIT_OFF && jdge->hud_mode != swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME) {
        if (0 < (short)score->results_P1_Position) {
            text = swrText_Translate("~f3~c~s%d/%d");
            sprintf(buffer, text, (int)(short)score->results_P1_Position, jdge->num_players);
            swrText_CreateTextEntry1(0x116, (int)y, -1, -1, -1, -0x42, buffer);
        }
        text = swrText_Translate("/SCREENTEXT_426/~c~sPOS");
        swrText_CreateTextEntry1(0x116, (int)y + 17, -1, -1, -1, -0x42, text);
    }

    if (1 < numLocalPlayers && isPlayer2 == 0)
        dialY = 0x36;
    swrObjJdge_DrawBoostDialHud(jdge, pod, 0xe1, (short)dialY, isPlayer2);
    if (swrRace_DebugLevel != 0 && assetBufferOverflow != 0)
        swrText_CreateTextEntry1(0xa0, 0x14, -1, 0, 0, -1, "~c~oZOT");
}

// 0x004611f0
void swrRace_InRaceEngineUI(swrScore* score, int slot)
{
    swrRace* pod = score->obj_test_ptr;
    int leftDamaged = 0;
    int rightDamaged = 0;
    int anySmoking = 0;
    int anyMaxDamage = 0;
    int anyFire = 0;
    float heatSfxVolume = 0.25f;
    float heatSfxPitch = 0.0f;
    float baseY = slot == 0 ? 175.0f : 65.0f;
    int spriteOffset = slot != 0 ? SWR_HUD_ENGINE_SPRITE_P2_OFFSET : 0;
    int partR[6], partG[6], partB[6], partA[6];
    int leftR, leftG, leftB, leftA;
    int rightR, rightG, rightB, rightA;
    unsigned int status;
    int show;
    int i;

    if (pod->flags0 & swrObjTest_FLAG0_RESPAWN) {
        swrRace_engineUiFade[slot] = 1.0f;
        swrRace_engineUiFadeRate[slot] = 0.0f;
    } else if (pod->flags0 & swrObjTest_FLAG0_DEAD) {
        swrRace_engineUiFadeRate[slot] = -1.0f;
    } else {
        show = 0;
        if (pod->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC)
            show = 1;
        if (pod->flags1 & swrObjTest_FLAG1_EXPLODING)
            show = 1;
        if (pod->vibrationMagnitude > 0.0f)
            show = 1;
        if (pod->engineTemp < 50.0f)
            show = 1;
        for (i = 0; i < 6; i++) {
            if (pod->engineHealth[i] > 0.6)
                show = 1;
            if (pod->engineStatus[i] & 0x1c)
                show = 1;
        }
        if (pod->flags0 & swrObjTest_FLAG0_REPAIRING)
            show = 1;
        if (show) {
            swrRace_engineUiFadeRate[slot] = 4.0f;
            swrRace_engineUiHoldTimer[slot] = 5.0f;
        }
    }

    if (!swrRace_GetPauseState()) {
        double pulse = swrRace_engineUiPulse[slot] - swrRace_deltaTimeSecs * 1.5;
        swrRace_engineUiPulse[slot] = pulse;
        if (pulse <= 0.0)
            swrRace_engineUiPulse[slot] = pulse + 1.0;

        double vibration = pod->vibrationMagnitude - swrRace_deltaTimeSecs;
        pod->vibrationMagnitude = vibration;
        if (vibration < 0.0)
            pod->vibrationMagnitude = 0.0f;

        double fade = swrRace_engineUiFadeRate[slot] * swrRace_deltaTimeSecs + swrRace_engineUiFade[slot];
        swrRace_engineUiFade[slot] = fade;
        if (fade > 1.0) {
            swrRace_engineUiFade[slot] = 1.0f;
            swrRace_engineUiFadeRate[slot] = 0.0f;
        }
        if (swrRace_engineUiFade[slot] > 0.0f) {
            double hold = swrRace_engineUiHoldTimer[slot] - swrRace_deltaTimeSecs;
            swrRace_engineUiHoldTimer[slot] = hold;
            if (hold <= 0.0)
                swrRace_engineUiFadeRate[slot] = -4.0f;
        }
    }

    if (swrRace_engineUiFade[slot] <= 0.0f) {
        swrRace_engineUiFade[slot] = 0.0f;
        swrRace_engineUiFadeRate[slot] = 0.0f;
        for (i = 0; i < 6; i++)
            swrSprite_SetVisible(SWR_HUD_ENGINE_SPRITE_FIRST + spriteOffset + i, 0);
        swrSprite_SetVisible(SWR_HUD_ENGINE_BRACKET_LEFT + spriteOffset, 0);
        swrSprite_SetVisible(SWR_HUD_ENGINE_BRACKET_RIGHT + spriteOffset, 0);
        return;
    }

    if (!swrRace_GetPauseState()) {
        for (i = 0; i < 6; i++)
            pod->engineStatus[i] ^= swrRace_ENGINESTATUS_BLINK;
    }

    leftR = 0;
    leftG = 255;
    leftB = 255;
    leftA = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 64.0f + 64.0f : 112.0f);
    rightR = 0;
    rightG = 255;
    rightB = 255;
    rightA = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 64.0f + 64.0f : 112.0f);

    if (pod->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) {
        for (i = 0; i < 6; i++) {
            if (pod->engineStatus[i] & swrRace_ENGINESTATUS_BLINK) {
                partR[i] = 100;
                partG[i] = 100;
                if (pauseState == 0)
                    partB[i] = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f);
                else
                    partB[i] = (int)223.25f;
            } else {
                partR[i] = 200;
                partG[i] = 200;
                partB[i] = 200;
            }
            partA[i] = 255;
        }
    } else if ((pod->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) || (pod->flags1 & swrObjTest_FLAG1_EXPLODING)) {
        for (i = 0; i < 6; i++)
            partA[i] = 255;
        for (i = 0; i < 6; i++)
            partR[i] = 255;
        for (i = 0; i < 6; i++) {
            partG[i] = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 200.0f : 150.0f);
            partB[i] = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 128.0f : 96.0f);
            if (partB[i] > partG[i])
                partB[i] = partG[i];
        }
    } else {
        float textY;
        float lowerTextY;
        float noticeAlpha;
        int alpha;

        for (i = 0; i < 6; i++) {
            status = pod->engineStatus[i];
            if (status & 4) {
                if (i < 3)
                    leftDamaged = 1;
                else
                    rightDamaged = 1;
            }
            if (status & 0x10)
                anySmoking = 1;
            if (pod->engineHealth[i] >= 1.0f)
                anyMaxDamage = 1;
            if (status & swrRace_ENGINESTATUS_ON_FIRE)
                anyFire = 1;
        }
        if (leftDamaged) {
            leftR = 255;
            leftG = 255;
            leftB = 0;
            leftA = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        }
        if (rightDamaged) {
            rightR = 255;
            rightG = 255;
            rightB = 0;
            rightA = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        }

        for (i = 0; i < 6; i++) {
            float damage = pod->engineHealth[i];
            int r, g, b, a;

            a = 100;
            if (damage < 0.0f)
                damage = 0.0f;
            if (damage > 1.0f)
                damage = 1.0f;
            r = (int)(damage * 510.0f);
            g = (int)(((1.0 - damage) + (1.0 - damage)) * 255.0);
            b = 0;
            // rand() is drawn even while paused (faithful)
            if (damage > 0.8 && (float)swrUtils_Rand() * (1.0f / 2147483648.0f) > 0.5f) {
                r = 0x80;
                g = 0;
                b = 0;
            }
            if (damage >= 1.0f) {
                float pulse = swrRace_engineUiPulse[slot] * 127.0f;
                r = (int)(pulse + 128.0f);
                g = (int)pulse;
                b = g;
                a = r;
            }

            status = pod->engineStatus[i];
            if (!(status & swrRace_ENGINESTATUS_ON_FIRE)) {
                if (pod->vibrationMagnitude > 0.0f && (status & swrRace_ENGINESTATUS_HIT)) {
                    if (status & swrRace_ENGINESTATUS_BLINK) {
                        r = 255;
                        g = 255;
                        b = 150;
                        a = 255;
                    }
                } else {
                    pod->engineStatus[i] = status & ~swrRace_ENGINESTATUS_HIT;
                }
            }
            status = pod->engineStatus[i];
            if ((status & 4) && (status & swrRace_ENGINESTATUS_BLINK)) {
                r = 0x80;
                g = 0x80;
                b = 255;
                a = 200;
            }
            if (status & swrRace_ENGINESTATUS_ON_FIRE) {
                if ((leftDamaged || rightDamaged) && (status & swrRace_ENGINESTATUS_BLINK)) {
                    r = 0x80;
                    g = 0x80;
                    b = 255;
                    a = 200;
                } else {
                    r = (int)((float)(255 - r) * swrRace_engineUiPulse[slot] + r);
                    g = (int)((float)(0x80 - g) * swrRace_engineUiPulse[slot] + g);
                    b = (int)((float)(-b) * swrRace_engineUiPulse[slot] + b);
                    a = (int)((float)(200 - a) * swrRace_engineUiPulse[slot] + a);
                }
            }
            if (r < 0)
                r = 0;
            if (r > 255)
                r = 255;
            if (g < 0)
                g = 0;
            if (g > 255)
                g = 255;
            if (b < 0)
                b = 0;
            if (b > 255)
                b = 255;
            if (a < 0)
                a = 0;
            if (a > 255)
                a = 255;
            partR[i] = r;
            partG[i] = g;
            partB[i] = b;
            partA[i] = a;
        }

        textY = baseY - 45.0f;
        lowerTextY = textY + 15.0f;
        if (anyFire) {
            alpha = (int)(swrRace_engineUiPulse[slot] * 255.0f);
            swrText_CreateTextEntry1(0x36, (int)(lowerTextY + 48.0f), -1, -0x80, 0, alpha, swrText_Translate("/SCREENTEXT_433/~c~sENGINE~n~cFIRE"));
        }
        if (pod->engineTemp < 20.0f) {
            alpha = (int)(swrRace_engineUiPulse[slot] * 255.0f);
            if (!anyFire && (pod->flags0 & swrObjTest_FLAG0_BOOSTING))
                swrText_CreateTextEntry1(0x36, (int)(lowerTextY + 48.0f), -1, -0x80, 0, alpha, swrText_Translate("/SCREENTEXT_434/~c~sOVERHEAT"));
            leftR = 255;
            rightR = 255;
            leftG = 0x80;
            leftB = 0;
            leftA = alpha;
            rightG = 0x80;
            rightB = 0;
            rightA = alpha;
            if (pod->flags0 & swrObjTest_FLAG0_BOOSTING) {
                heatSfxVolume = 0.3f;
                heatSfxPitch = 0.75f;
            }
        } else if (pod->engineTemp < 50.0f) {
            float heat = (pod->engineTemp - 50.0f) * -0.033333335f;
            int r, g, b, a;

            if (heat < 0.0f)
                heat = 0.0f;
            if (heat > 1.0f)
                heat = 1.0f;
            r = (int)(heat * 255.0f);
            g = (int)((1.0 - heat) * 127.0 + 128.0);
            b = (int)((1.0 - heat) * 255.0);
            alpha = (int)(swrRace_engineUiPulse[slot] * 255.0f);
            if (pod->flags0 & swrObjTest_FLAG0_BOOSTING)
                swrText_CreateTextEntry1(0x36, (int)(lowerTextY + 48.0f), r, g, b, alpha, swrText_Translate("/SCREENTEXT_435/~c~sTEMP~n~cWARNING"));
            a = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
            leftA = a;
            rightA = a;
            leftR = r;
            leftG = g;
            leftB = b;
            rightR = r;
            rightG = g;
            rightB = b;
            if (pod->flags0 & swrObjTest_FLAG0_BOOSTING) {
                heatSfxVolume = 0.2f;
                heatSfxPitch = 0.5f;
            }
        }
        if (anyMaxDamage) {
            float pulse = swrRace_engineUiPulse[slot] * 127.0f;
            int bright = (int)(pulse + 128.0f);
            int dim = (int)pulse;
            swrText_CreateTextEntry1(0x36, (int)(textY + 48.0f), bright, dim, dim, bright, swrText_Translate("/SCREENTEXT_432/~c~sWarning"));
            textY -= 12.0f;
        }

        if (pod->flags0 & swrObjTest_FLAG0_REPAIRING) {
            if (!leftDamaged && !rightDamaged && !anySmoking) {
                if (swrRace_engineUiRepairTime[slot] <= 0.0f)
                    swrSound_Play2D(0x46, 7, 0.25f, 1.0f, 0);
                double repairTime = swrRace_engineUiRepairTime[slot] + swrRace_deltaTimeSecs;
                swrRace_engineUiRepairTime[slot] = repairTime;
                if (repairTime < 0.8f) {
                    noticeAlpha = pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f;
                    swrText_CreateTextEntry1(0x36, (int)(textY + 48.0f), 0x40, -0x80, 0x40, (int)noticeAlpha, swrText_Translate("/SCREENTEXT_437/~c~sRepair"));
                }
            } else {
                swrRace_engineUiRepairTime[slot] = 0.0f;
                noticeAlpha = pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f;
                swrText_CreateTextEntry1(0x36, (int)(textY + 48.0f), -0x80, -0x80, -1, (int)noticeAlpha, swrText_Translate("/SCREENTEXT_436/~c~sRepair"));
            }
        } else {
            swrRace_engineUiRepairTime[slot] = 0.0f;
        }

        if (!swrRace_GetPauseState()) {
            // one-shot when a fire starts (none for 2 s), then a loop after 1.8 s
            if (anyFire) {
                if (swrRace_engineFireSfxLastTime < timetotal - 2.0) {
                    swrRace_engineFireSfxStartTime = timetotal;
                    swrSound_Play2D(0x87, 7, 0.25f, 1.0f, 0);
                }
                if (swrRace_engineFireSfxStartTime < timetotal - (double)1.8f)
                    swrSound_Play2D(0x86, 6, 0.25f, 1.0f, 1);
                swrRace_engineFireSfxLastTime = timetotal;
            }
            if (heatSfxPitch > 0.0f)
                swrSound_Play2D(0x83, 7, heatSfxVolume, heatSfxPitch, 1);
            if ((pod->flags0 & swrObjTest_FLAG0_REPAIRING) && (leftDamaged || rightDamaged || anySmoking)) {
                if (swrRace_engineRepairSfxLastTime < timetotal - 2.0) {
                    swrRace_engineRepairSfxStartTime = timetotal;
                    swrSound_Play2D(0x85, 7, 0.25f, 1.0f, 0);
                }
                if (swrRace_engineRepairSfxStartTime < timetotal - (double)1.8f)
                    swrSound_Play2D(0x75, 6, 0.25f, 1.0f, 1);
                swrRace_engineRepairSfxLastTime = timetotal;
            }
        }
    }

    for (int row = 0; row < 2; row++) {
        float rowX = (float)(row * 24) + 30.0f + 4.0f;
        for (int col = 0; col < 3; col++) {
            int part = row * 3 + col;
            short id = SWR_HUD_ENGINE_SPRITE_FIRST + spriteOffset + part;
            float spread = (1.0f - swrRace_engineUiFade[slot]) * 15.0f;
            float y = (float)(col * 14) + baseY + 2.0f;
            float offset = spread;
            float x;

            if (col == 1)
                offset *= 1.5f;
            if (row == 0)
                x = rowX - offset;
            else
                x = offset + rowX;
            if (col == 0)
                y -= spread;
            else if (col == 2)
                y = spread + y;
            swrSprite_SetVisible(id, 1);
            if (GameSettingFlags & GAME_SETTING_MIRROR)
                x = 92.0f - x;
            swrSprite_SetPos(id, (short)(int)x, (short)(int)y);
            swrSprite_SetDim(id, 0.75f, 0.75f);
            swrSprite_SetColor(id, partR[part], partG[part], partB[part], (int)((float)partA[part] * swrRace_engineUiFade[slot]));
        }
    }

    {
        float bracketX = (GameSettingFlags & GAME_SETTING_MIRROR) ? 12.0f : -12.0f;
        short bracketY = (short)(int)baseY;
        short id = SWR_HUD_ENGINE_BRACKET_LEFT + spriteOffset;

        swrSprite_SetVisible(id, 1);
        swrSprite_SetPos(id, (short)(int)(bracketX + 30.0f + 12.0f), bracketY);
        swrSprite_SetDim(id, 0.75f, 0.75f);
        swrSprite_SetColor(id, leftR, leftG, leftB, (int)((float)leftA * swrRace_engineUiFade[slot] * swrRace_engineUiFade[slot]));
        id = SWR_HUD_ENGINE_BRACKET_RIGHT + spriteOffset;
        swrSprite_SetVisible(id, 1);
        swrSprite_SetPos(id, (short)(int)(42.0f - bracketX), bracketY);
        swrSprite_SetDim(id, 0.75f, 0.75f);
        swrSprite_SetColor(id, rightR, rightG, rightB, (int)((float)rightA * swrRace_engineUiFade[slot] * swrRace_engineUiFade[slot]));
    }
}

// Post-race statistics panel: per-lap rows, the Total row, and the place text with the medal
// sprite sliding in against jdge->raceTimer_ms. The ONLY writer of jdge->recordLap3_ms -- the
// session-best race total is latched here, in the draw pass.
// 0x00462320
void swrRace_InRaceEndStatistics(swrObjJdge* jdge, swrScore* score)
{
    char* text;
    float total;
    float lapTime;
    int numLocal;
    int x;
    int rowY;
    int placeY;
    int textY;
    int colR;
    int colG;
    int colB;
    int i;
    short pos;
    short spriteX;
    char buf[32];

    numLocal = swrObjJdge_NumLocalPlayers();
    if (numLocal == 2) {
        if (score == firstLocalPlayer) {
            rowY = 0x69;
            placeY = 0x1e;
            for (i = 0xf; i < 0x13; i++)
                swrSprite_SetVisible((short)i, 0);
        } else {
            rowY = 0xd7;
            placeY = 0x8c;
            for (i = 0x13; i < 0x17; i++)
                swrSprite_SetVisible((short)i, 0);
        }
    } else {
        for (i = 0; i < 0x13; i++)
            swrSprite_SetVisible((short)i, 0);
        rowY = 0xd7;
        placeY = 0x37;
    }
    rowY -= jdge->num_laps * 0xe;

    // time-column x scales with the total's digit count
    total = score->results_P1_total_time;
    if (total < 60.0f)
        x = 0x5b;
    else if (total < 600.0f)
        x = 0x69;
    else if (total < 6000.0f)
        x = 0x73;
    else if (total < 60000.0f)
        x = 0x7d;
    else
        x = 0x87;

    for (i = 0; i < jdge->num_laps; i++) {
        lapTime = (&score->results_P1_Lap1)[i];
        text = swrText_Translate("/SCREENTEXT_211/~sLap");
        sprintf(buf, "~f4%s", text);
        swrText_CreateTextEntry1(0x19, rowY + 1, -1, -1, 0, -1, buf);
        sprintf(buf, "~s%d", i + 1);
        swrText_CreateTextEntry1(0x2d, rowY, -1, -1, 0, -1, buf);
        if (jdge->best_lap_time_ms < lapTime) {
            colR = 0xff;
            colG = 0x80;
        } else {
            // this row is the session-best lap: flicker it
            if (pauseState == 0)
                colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f);
            else
                colR = (int)223.25f;
            colG = colR - 0x14;
        }
        swrText_CreateTimeEntry(x, rowY - 3, lapTime, colR, colG, 0, -1, "~f1~r~s");
        rowY += 0xe;
    }

    if (jdge->recordLap3_ms < total) {
        colR = 0x32;
        colG = 0xff;
        colB = 5;
    } else {
        // new session-best race total: latch it and flicker the row
        jdge->recordLap3_ms = total;
        if (pauseState == 0)
            colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 26.0f + 24.0f);
        else
            colR = (int)43.5f;
        if (pauseState == 0)
            colG = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f);
        else
            colG = (int)223.25f;
        colB = 0;
    }
    text = swrText_Translate("/SCREENTEXT_534/~sTotal: ");
    sprintf(buf, "~f4%s", text);
    swrText_CreateTextEntry1(0x19, rowY + 1, -0x10, -1, 0, -1, buf);
    swrText_CreateTimeEntry(x, rowY - 3, total, colR, colG, colB, -1, "~f1~r~s");

    if (numLocalPlayers < 2) {
        if (jdge->num_players < 2)
            return;
        if (8.0f < jdge->raceTimer_ms) {
            swrSprite_SetVisible(0xa4, 0);
            swrSprite_SetVisible(0xa5, 0);
            swrSprite_SetVisible(0xa6, 0);
            return;
        }
        // finishing-place banner slides in over the first half second and back out after 7.5s
        x = 0xa0;
        if (jdge->raceTimer_ms < 0.5f)
            x = (int)(160.0f - (0.5f - jdge->raceTimer_ms) * 380.0f);
        if (7.5f < jdge->raceTimer_ms)
            x = (int)((float)x + (jdge->raceTimer_ms - 7.5f) * 380.0f);
        textY = placeY;
        pos = (short)score->results_P1_Position;
        if (pos < 4) {
            x -= 0x14;
            textY = placeY + 0x14;
            swrSprite_AddDirtyRect(-x + 0x12f, placeY - 0xd, -x + 0x151, placeY + 0x35);
            spriteX = (short)(0x140 - x);
            if (pos == 1) {
                swrSprite_SetVisible(0xa4, 1);
                swrSprite_SetPos(0xa4, spriteX, (short)placeY);
            }
            if (pos == 2) {
                swrSprite_SetVisible(0xa5, 1);
                swrSprite_SetPos(0xa5, spriteX, (short)placeY);
            }
            if (pos == 3) {
                swrSprite_SetVisible(0xa6, 1);
                swrSprite_SetPos(0xa6, spriteX, (short)placeY);
            }
        }
        if (pos == 1)
            text = "/SCREENTEXT_427/~sst";
        else if (pos == 2)
            text = "/SCREENTEXT_428/~snd";
        else if (pos == 3)
            text = "/SCREENTEXT_429/~srd";
        else
            text = "/SCREENTEXT_430/~sth";
        text = swrText_Translate(text);
        colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        sprintf(buf, "~f2~r~s%d", (int)pos);
        swrText_CreateTextEntry1(x, textY, colR, colG, colB, -2, buf);
        swrText_CreateTextEntry1(x + 1, textY, colR, colG, colB, -2, text);
        return;
    }

    // splitscreen: fixed-position place text, no medal sprite
    pos = (short)score->results_P1_Position;
    if (pos == 1)
        text = "/SCREENTEXT_427/~sst";
    else if (pos == 2)
        text = "/SCREENTEXT_428/~snd";
    else if (pos == 3)
        text = "/SCREENTEXT_429/~srd";
    else
        text = "/SCREENTEXT_430/~sth";
    text = swrText_Translate(text);
    colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    sprintf(buf, "~f2~r~s%d", (int)pos);
    swrText_CreateTextEntry1(0xa0, placeY, colR, colG, colB, -2, buf);
    swrText_CreateTextEntry1(0xa1, placeY, colR, colG, colB, -2, text);
}

// Bitmask of which engine sides are under repair: 0x1 = a left engine (parts 0..2),
// 0x2 = a right engine (parts 3..5).
// 0x0046a9c0
unsigned int swrRace_GetDamagedEngineSides(swrRace* player)
{
    unsigned int sides = 0;
    for (int i = 0; i < 6; i++) {
        if ((player->engineStatus[i] & (swrRace_ENGINESTATUS_REPAIRING | swrRace_ENGINESTATUS_EXTINGUISHING)) != 0) {
            sides |= (i < 3) ? 1 : 2;
        }
    }
    return sides;
}

// Handling bias from asymmetric engine damage: each badly damaged engine (health > 0.8)
// shifts the result by -0.33 (left, parts 0..2) or +0.33 (right, parts 3..5), so a
// lopsidedly damaged pod pulls to one side.
// 0x0046a9f0
RETAIL_FP long double swrRace_GetEngineDamagePenalty(swrRace* player)
{
    // The health threshold is the double 0.8, so an engine at exactly 0.8f (just above it) counts.
    long double penalty = 0.0f;
    for (int i = 0; i < 6; i++) {
        if ((double)0.8 < player->engineHealth[i]) {
            if (i < 3) {
                penalty -= (float)0.33f;
            } else {
                penalty += (float)0.33f;
            }
        }
    }
    return penalty;
}

// Per-tick engine repair and the destroyed-engine explosion countdown. While repairTimer is
// positive one engine is repaired toward half its peak damage; any burning engine may go out.
// An engine at full damage starts a 6-10s countdown that ends in swrRace_Explode.
// 0x0046ab10
RETAIL_FP void swrRace_Repair(swrRace* player)
{
    const unsigned int repairBits = swrRace_ENGINESTATUS_REPAIRING | swrRace_ENGINESTATUS_EXTINGUISHING;
    bool repairing = false;
    bool leftDestroyed = false;
    bool rightDestroyed = false;
    char explodeSide = 0;
    int target = -1;

    player->repairTimer = player->repairTimer - swrRace_deltaTimeSecs;
    if (player->flags0 & swrObjTest_FLAG0_REPAIRING) {
        player->repairTimer = (float)SWR_REPAIR_HELD_TIMER;
    }

    for (int i = 0; i < 6; i++) {
        if (player->engineStatus[i] & swrRace_ENGINESTATUS_REPAIRING) {
            target = i;
        }
        player->engineStatus[i] &= ~repairBits;
    }

    if (player->repairTimer > 0.0f) {
        if (target < 0) {
            float worst = 0.0f;
            for (int i = 0; i < 6; i++) {
                if (worst < player->engineHealth[i] && player->engineHealth[i] > SWR_CTL_HALF) {
                    worst = player->engineHealth[i];
                    target = i;
                }
            }
        }
        if (target >= 0 && player->engineHealthMin[target] * (double)SWR_CTL_HALF_HOLD < player->engineHealth[target]) {
            player->engineStatus[target] |= swrRace_ENGINESTATUS_REPAIRING;
        }
        if ((player->flags1 & swrObjTest_FLAG1_ON_LAVA) == 0) {
            for (int i = 0; i < 6; i++) {
                if (player->engineStatus[i] & swrRace_ENGINESTATUS_ON_FIRE) {
                    player->engineStatus[i] |= swrRace_ENGINESTATUS_EXTINGUISHING;
                }
            }
        }
    }

    for (int i = 0; i < 6; i++) {
        if (player->engineStatus[i] & swrRace_ENGINESTATUS_REPAIRING) {
            repairing = true;
            // Retail spills the heal rate to a float before scaling it by the frame time.
            float healRate = (player->engineHealthMin[i] * SWR_CTL_HALF - player->engineHealthMin[i]) * player->podStats.repairRate * SWR_CTL_HALF;
            player->engineHealth[i] = swrRace_deltaTimeSecs * healRate + player->engineHealth[i];
        }
        if ((player->engineStatus[i] & swrRace_ENGINESTATUS_EXTINGUISHING) &&
            (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM < (double)SWR_REPAIR_EXTINGUISH_CHANCE) {
            player->engineStatus[i] &= ~swrRace_ENGINESTATUS_ON_FIRE;
        }
    }

    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        if (repairing) {
            swrControl_PlayForceEffect(swrForceEffect_REPAIR, -1, -1, -1);
        } else {
            swrControl_StopForceEffect(swrForceEffect_REPAIR);
        }
        if (repairing) {
            if ((long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM < (float)SWR_REPAIR_VOICE_CHANCE &&
                swrSound_TestSfxFlag((char)player->score_ptr->sfxChannel, swrSound_SFXFLAG_REPAIRING) == 0) {
                swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 10, 10, 10, 10, 10, (rdVector3*)&player->transform.vD);
                swrSound_SetSfxFlag((char)player->score_ptr->sfxChannel, swrSound_SFXFLAG_REPAIRING);
            }
        } else if (swrSound_TestSfxFlag((char)player->score_ptr->sfxChannel, swrSound_SFXFLAG_REPAIRING) != 0) {
            swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 11, 11, 11, 11, 11, (rdVector3*)&player->transform.vD);
            swrSound_ClearSfxFlag((char)player->score_ptr->sfxChannel, swrSound_SFXFLAG_REPAIRING);
        }
    }

    for (int i = 0; i < 6; i++) {
        if (player->engineHealth[i] >= (double)SWR_ENGINE_DESTROYED) {
            if (i < 3) {
                leftDestroyed = true;
            } else {
                rightDestroyed = true;
            }
        }
    }

    if (!leftDestroyed && !rightDestroyed) {
        player->damageWarningTimer = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * SWR_DAMAGE_WARNING_SECS_RANGE + SWR_DAMAGE_WARNING_SECS_MIN;
    } else {
        player->damageWarningTimer = player->damageWarningTimer - swrRace_deltaTimeSecs;
        if (player->flags0 & swrObjTest_FLAG0_WAS_BOOSTING) {
            player->damageWarningTimer = 0.0f;
        }
    }
    if (player->damageWarningTimer > 0.0f) {
        return;
    }

    if (leftDestroyed && rightDestroyed) {
        explodeSide = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM < SWR_CTL_HALF ? swrRace_EXPLODE_SIDE_LEFT : swrRace_EXPLODE_SIDE_RIGHT;
    } else if (leftDestroyed) {
        explodeSide = swrRace_EXPLODE_SIDE_LEFT;
    } else if (rightDestroyed) {
        explodeSide = swrRace_EXPLODE_SIDE_RIGHT;
    }
    swrRace_Explode(player, explodeSide);
}

// AI glide-dive pitch. When the pod has dropped below its spline path, pitch hard nose-down
// (-1.0) to dive back onto the line; swrRace_UpdateSpeed grants the AI a 1.3x speed bonus in
// that state. Near/full-sim pods (useGroundClearance) only dive when actually launched high
// (ground clearance > 400) unless the AIRBORNE flag is set; far simplified pods dive whenever
// they are below the line. lookaheadPos is passed by the caller but unused.
// 0x0046aec0
void swrRace_UpdateAIGlidePitch(swrRace* player, rdVector3* lookaheadPos, rdVector3* splinePos, int useGroundClearance)
{
    float height = 0.0f;
    if (player->transform.vD.z <= splinePos->z) {
        height = 500.0f;
        if ((player->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0 && useGroundClearance != 0) {
            height = player->groundToPodMeasure;
        }
    }
    player->pitch = (height <= 400.0f) ? 0.0f : -1.0f;
}

// AI steering autopilot for one racing pod. Sets the throttle (0.98 under power, 0.48
// coasting), re-rolls the spline fork branch choice (coin flip each frame, overridden on
// the six ai_track_script tracks inside fixed lap-fraction windows = the scripted shortcut
// take/avoid forks), updates the glide-dive pitch, adapts the spline look-ahead parameter
// so the look-ahead segment's world length tracks aiLookAheadDistSq (~90 units), then
// steers at the look-ahead point with a proportional heading controller: deadzone +/-0.02,
// gain -10/7, and a throttle lift ((1 - |err|) * 0.5) when the error exceeds +/-0.3.
// The final turn rate scales with paceMultiplier, so a rubberbanding AI also turns harder.
// 0x0046af20
RETAIL_FP void swrRace_AutopilotSteer(swrRace* player)
{
    if ((player->flags0 & swrObjTest_FLAG0_THROTTLE_SETTLED) == 0) {
        player->throttle = (float)0.48f;
    } else {
        player->throttle = (float)0.98f;
    }

    if (player->aiLookAhead < (float)0.01f) {
        player->aiLookAhead = (float)0.01f;
    }
    if (2.0f < player->aiLookAhead) {
        player->aiLookAhead = 2.0f;
    }

    // Coin-flip the spline fork branch selector for this frame. The selector lives in the
    // spline cursor's scale.y slot but is an INT (the original stores the __ftol result and
    // the literals 0/1 directly). swrUtils_Rand is non-negative, so the negative-sample
    // branch below is defensively dead: pick is uniform over {0, 1}.
    long double sample = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * 2.0f;
    long double pick;
    if (sample < 0.0f) {
        pick = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * 2.0f - (float)0.99999899f;
    } else {
        pick = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * 2.0f;
    }
    player->splineCursor.branchSelector = (int)pick;

    // Scripted fork choices: signature tracks force the branch inside lap-fraction windows
    // (scripts 1-4 force the main line = 0, scripts 5-6 force the alternate = 1).
    if (0 < ai_track_script) {
        if (ai_track_script == 1) {
            if (player->lapCompMax < (float)0.01f) {
                player->splineCursor.branchSelector = 0;
            } else if ((float)0.07f < player->lapComp && player->lapComp < (float)0.14f) {
                player->splineCursor.branchSelector = 0;
            }
        } else if (ai_track_script == 2) {
            if (((float)0.53f < player->lapComp && player->lapComp < (float)0.54f) || ((float)0.55f < player->lapComp && player->lapComp < (float)0.57f)) {
                player->splineCursor.branchSelector = 0;
            }
        } else if (ai_track_script == 3) {
            if ((float)0.27f < player->lapComp && player->lapComp < (float)0.29f) {
                player->splineCursor.branchSelector = 0;
            }
        } else if (ai_track_script == 4) {
            if ((float)0.72f < player->lapComp && player->lapComp < (float)0.73f) {
                player->splineCursor.branchSelector = 0;
            }
        } else if (ai_track_script == 5) {
            if ((float)0.063f < player->lapComp && player->lapComp < (float)0.072f) {
                player->splineCursor.branchSelector = 1;
            }
        } else if (ai_track_script == 6) {
            if ((float)0.093f < player->lapComp && player->lapComp < (float)0.108f) {
                player->splineCursor.branchSelector = 1;
            }
        }
    }

    rdMatrix44 splineMat;
    swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0f);
    rdVector3 cursorPos;
    cursorPos.x = splineMat.vD.x;
    cursorPos.y = splineMat.vD.y;
    cursorPos.z = splineMat.vD.z;
    swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, player->aiLookAhead);

    // Full-sim pods: lodDistance under 1000 ((d - 400) / 600 < 1), a local human, or force-grounded.
    int useGroundClearance = ((float)player->lodDistance - 400.0f) * (float)0.0016666667f < 1.0 || (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0 || (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0;
    swrRace_UpdateAIGlidePitch(player, (rdVector3*)&splineMat.vD, &cursorPos, useGroundClearance);

    // Ease the look-ahead parameter so the segment's world length tracks aiLookAheadDistSq.
    long double dx = cursorPos.x - splineMat.vD.x;
    long double dy = cursorPos.y - splineMat.vD.y;
    long double dz = cursorPos.z - splineMat.vD.z;
    float dxSpill = dx; // retail multiplies the register copy by an FST spill
    float dzSpill = dz;
    long double segLenSq = dx * dxSpill + dy * dy + dz * dzSpill;
    if (segLenSq < player->aiLookAheadDistSq) {
        player->aiLookAhead += (float)0.01f;
    } else if (player->aiLookAheadDistSq < segLenSq) {
        player->aiLookAhead -= (float)0.01f;
    }

    // Aim point = the look-ahead spline point, lifted to the pod's height along gravity.
    rdVector3 target;
    target.x = splineMat.vD.x;
    target.y = splineMat.vD.y;
    target.z = splineMat.vD.z;
    float heightAlongGravity = (player->transform.vD.x - target.x) * player->world_gravity.x + (player->transform.vD.z - target.z) * player->world_gravity.z + (player->transform.vD.y - target.y) * player->world_gravity.y;
    rdVector3 aimPoint;
    rdVector_Scale3Add3(&aimPoint, &target, heightAlongGravity, &player->world_gravity);

    rdVector3 dir;
    dir.x = aimPoint.x - player->transform.vD.x;
    dir.y = aimPoint.y - player->transform.vD.y;
    dir.z = aimPoint.z - player->transform.vD.z;
    float len = rdVector_Len3(&dir);
    if (len <= (float)0.01f) {
        return; // on top of the aim point: keep the caller's zeroed turn rate
    }
    long double invLen = 1.0f / len; // stays in ST0 in retail
    dir.x *= invLen;
    dir.y *= invLen;
    dir.z *= invLen;

    // Signed heading error: cross(forward, dir) projected on the gravity axis.
    rdVector3 cross;
    rdVector_Cross3(&cross, (rdVector3*)&player->transform.vB, &dir);
    long double err = cross.z * player->world_gravity.z + cross.x * player->world_gravity.x + cross.y * player->world_gravity.y;
    float errSpill = err; // only the deadzone test reads the raw value

    long double steer;
    if (err <= (float)0.02f) {
        steer = 0.0f;
        if (errSpill < (float)-0.02f) {
            steer = errSpill * (float)-1.42857146f; // -10/7
            if (errSpill < (float)-0.3f) {
                player->throttle = (errSpill - -1.0f) * 0.5f * player->throttle;
            }
        }
    } else {
        steer = errSpill * (float)-1.42857146f;
        if ((float)0.3f < errSpill) {
            player->throttle = (1.0f - errSpill) * 0.5f * player->throttle;
        }
    }
    player->turnRateTarget = player->paceMultiplier * player->podStats.maxTurnRate * steer;
}

// Pod-vs-pod steering interaction for a racing AI pod (called from swrRace_CalcTargetTurnRate).
// Finds the nearest other pod within 50 units and adds a turn-rate nudge steering away from
// its side, ramping quadratically as they close: ((50 - d) * 0.2)^2 * 0.8, up to 80 at contact.
// Special case: when the single nearby pod is a local human closing from behind, the sign
// flips and the AI steers INTO the player's line instead -- the "blocking" wiggle. AI never
// block each other, and blocking disengages as soon as a second pod is within range.
// 0x0046b430
RETAIL_FP void swrRace_ApplyPodProximityForce(swrRace* player)
{
    float distsSq[4];
    void* objs[4];
    rdVector3 deltas[4];

    float sign = 1.0f;
    player->speedLoss = 0.0f;
    int count = swrEvent_FindNearestObjects(0x54657374, (rdVector3*)&player->transform.vD, 2500.0f, player, 4, distsSq, deltas, objs);
    if (count < 1) {
        return;
    }

    rdVector3 cross;
    rdVector_Cross3(&cross, (rdVector3*)&player->transform.vB, deltas);
    float dist = stdMath_Sqrt(distsSq[0]);
    // retail squares the raw closeness against its spilled float copy
    long double closeness = (50.0f - dist) * 0.2f;
    float closenessSpill = (float)closeness;
    long double force = closeness * closenessSpill * 0.1f * 8.0f;
    // Which side the nearest pod is on: cross(forward, delta) projected on the gravity axis.
    float side = (player->world_gravity.x * cross.x + player->world_gravity.z * cross.z) + player->world_gravity.y * cross.y;

    // Block instead of avoid: exactly one pod nearby, it is a local human, and it is behind us.
    if (count == 1 && (((swrRace*)objs[0])->flags0 & swrObjTest_FLAG0_LOCAL) != 0 && (deltas[0].x * player->transform.vB.x + player->transform.vB.y * deltas[0].y) + player->transform.vB.z * deltas[0].z < 0.0f) {
        sign = -1.0f;
    }
    if (0.0f < side) {
        player->turnRateTarget = sign * force + player->turnRateTarget;
    } else if (side < 0.0f) {
        player->turnRateTarget = player->turnRateTarget - sign * force;
    }
}

// 0x0046b5a0
void swrRace_Tilt(swrRace* player, float b)
{
    // Below 200 speed the pod cannot bank; force the tilt target to neutral.
    if (player->speedValue < 200.0f)
        b = 0.0f;

    // Ease tiltManualMult toward the target at 3.2/sec, snapping on overshoot.
    if (b <= player->tiltManualMult)
    {
        if (b < player->tiltManualMult)
        {
            player->tiltManualMult -= swrRace_deltaTimeSecs * 3.2f;
            if (player->tiltManualMult < b)
                player->tiltManualMult = b;
        }
    }
    else
    {
        player->tiltManualMult += swrRace_deltaTimeSecs * 3.2f;
        if (b < player->tiltManualMult)
            player->tiltManualMult = b;
    }

    // Near neutral, damp the residual so the pod settles level.
    if (b == 0.0f)
    {
        float mag = (player->tiltManualMult < 0.0f) ? -player->tiltManualMult : player->tiltManualMult;
        if (mag < 0.1)
            player->tiltManualMult *= 0.5;
    }
}

// Per-frame pacing "brain" for one AI racer. It never touches the flight model directly;
// it only computes a per-racer speed multiplier (aiSpeedTarget, smoothed into
// paceMultiplier) and a station-keeping offset target (aiPaceOffsetTarget, laps behind the
// pace-setter). The smoothed multiplier is copied into speedMultiplier by swrRace_UpdateCatchup
// and scales the pod in swrRace_UpdateSpeed. The two tuning inputs are the globals swrRace_AILevel
// (track base level * AI Speed setting) and ai_spread, both set in swrObjJdge_InitAISettingsForTrack.
// The rubberband is player-relative on three paths: the AI_SIMPLE pace-setter chases local
// player 1 directly, tethered pods (AI_TETHER_LOCAL*) pace on their raw gap to that player,
// and everyone else station-keeps behind the pace-setter.
// 0x0046b670
RETAIL_FP void swrRace_AI(int player)
{
    swrRace* p = (swrRace*) player;

    // Start from the track/difficulty-wide base level.
    p->aiSpeedTarget = swrRace_AILevel;

    if ((p->flags1 & swrObjTest_FLAG1_FINISHED) != 0) {
        // Finished / parked: coast at a fixed 0.65x and wind the AI look-ahead down to 75^2.
        p->aiSpeedTarget = (float)0.65f;
        p->podStats.turnResponse = 1500.0f;
        p->podStats.maxTurnRate = 400.0f;
        if (p->aiLookAheadDistSq <= 5625.0f) {
            p->aiLookAheadDistSq = 5625.0f;
        } else {
            p->aiLookAheadDistSq = p->aiLookAheadDistSq - swrRace_deltaTimeSecs * 100.0;
        }
    } else {
        // Normalize the tuning by track length so the feel is consistent across courses.
        float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
        long double spreadScaledRaw = ai_spread * (float)0.0001f;
        float spreadScaled = spreadScaledRaw;
        float spreadBand = spreadScaledRaw * invTrackLen; // raw register value, not the spill

        if ((p->flags0 & swrObjTest_FLAG0_AI_SIMPLE) != 0) {
            // Pace-setter (the track-favorite pod): coarse player-relative pacing.
            // 1.06x while leading, 1.4x when local player 1 is far ahead (catch back
            // up to the player), 1.1x otherwise (pull ahead of the player).
            p->aiPaceOffsetTarget = 0.0f;
            if ((short) p->score_ptr->results_P1_Position == 1) {
                p->aiSpeedTarget *= (float)1.06f;
            } else if (spreadBand * 3.0f < p->gapToLocalPlayer1) {
                p->aiSpeedTarget *= (float)1.4f;
            } else {
                p->aiSpeedTarget *= (float)1.1f;
            }
        } else if ((short) p->score_ptr->results_P1_Position == 1) {
            // Leading the race: cruise at the base level.
            p->aiPaceOffsetTarget = 0.0f;
        } else {
            // Tick the decision timer; on expiry reroll the interval and nudge the
            // target finishing position by +/-1, kept within +/-2 of the baseline.
            long double timer = p->aiDecisionTimer - swrRace_deltaTimeSecs;
            p->aiDecisionTimer = timer;
            if (timer < 0.0f) {
                // rand() * 2^-31 gives [0,1); next reroll in ~8..18 seconds.
                p->aiDecisionTimer = (long double) swrUtils_Rand() * (float) SWR_CTL_RAND_NORM * 10.0f + 8.0f;

                long double r = (long double) swrUtils_Rand() * (float) SWR_CTL_RAND_NORM;
                if (r < (float)0.15f) {
                    int newRank = p->aiRankTarget - 1; // try to move up a place
                    p->aiRankTarget = newRank;
                    if (newRank < 2 || newRank - p->aiRankBaseline > 2 || p->aiRankBaseline - newRank > 2) {
                        p->aiRankTarget = newRank + 1; // out of band: revert
                    }
                } else if ((float)0.85f < r) {
                    int newRank = p->aiRankTarget + 1; // try to drop back a place
                    p->aiRankTarget = newRank;
                    if (newRank - p->aiRankBaseline > 2 || p->aiRankBaseline - newRank > 2) {
                        p->aiRankTarget = newRank - 1; // out of band: revert
                    }
                }
            }

            if (0.0f < ai_rank_speed_factor) {
                // Simplified rank-only pacing. Disabled in the shipped game:
                // ai_rank_speed_factor has no writer and stays 0.
                long double base = p->aiSpeedTarget * (float)1.06f;
                p->aiSpeedTarget =
                    (1.0f - ((float) p->aiRankTarget - 1.0f) * ai_rank_speed_factor) * base;
            } else {
                // Full model: hold a rank-derived station behind the pace-setter, unless
                // this pod is tethered to a local player, in which case pace directly on
                // the raw gap to that player (10.3 catching up vs 10.02 easing off).
                long double paceOffset = (((float)p->aiRankTarget - 1.0f) * spreadScaled - (float)0.0008f) * invTrackLen;
                p->aiPaceOffsetTarget = paceOffset;

                long double v;
                if (spreadBand * 0.25f < p->gapToPacer && (p->flags0 & (swrObjTest_FLAG0_AI_TETHER_LOCAL1 | swrObjTest_FLAG0_AI_TETHER_LOCAL2)) != 0) {
                    float gap = (p->flags0 & swrObjTest_FLAG0_AI_TETHER_LOCAL1) != 0 ? p->gapToLocalPlayer1 : p->gapToLocalPlayer2;
                    v = (0.0f < gap) ? gap * (float)10.3f : gap * (float)10.02f;
                } else {
                    v = (p->gapToPacer - paceOffset) * 10.0f;
                }

                long double target = (v * 40.0f) / invTrackLen + (float)1.045f;
                if ((float)1.6f < target) {
                    target = (float)1.6f;
                }
                if (target < 0.5f) {
                    target = 0.5f;
                }
                p->aiSpeedTarget = target;
            }
        }
    }

    // Slew the applied multiplier toward the target at 0.2/sec, never overshooting.
    if (p->paceMultiplier < p->aiSpeedTarget) {
        long double pace = p->paceMultiplier + swrRace_deltaTimeSecs * (float)0.2f;
        p->paceMultiplier = pace;
        if (p->aiSpeedTarget < pace) {
            p->paceMultiplier = p->aiSpeedTarget;
        }
    } else if (p->aiSpeedTarget < p->paceMultiplier) {
        long double pace = p->paceMultiplier - swrRace_deltaTimeSecs * (float)0.2f;
        p->paceMultiplier = pace;
        if (p->aiSpeedTarget > pace) {
            p->paceMultiplier = p->aiSpeedTarget;
        }
    }
}

// Per-frame control entry for an AI pod (dispatched by swrRace_CalcTargetTurnRate). In credits
// mode it fires a 'Snap' sub-event each frame; with the AI debug flag set (0x100 + debug
// level), keyboard inputs fire manual 'Snap's. While racing it runs the steering autopilot,
// cuts the throttle when dead, and tilts into Side-tagged surfaces.
// 0x0046bb70
void swrRace_UpdateAutopilotControl(swrRace* player)
{
    if (swrRace_creditsMode != 0) {
        int subEvents[2];
        subEvents[0] = 0x536e6170; // 'Snap'
        subEvents[1] = 2;
        swrEvent_DispatchSubEvents(player, subEvents);
    }
    if ((swrRace_DebugFlag & 0x100) != 0 && swrRace_DebugLevel != 0) {
        swrRace_CheckResetInput(player, 1);
        if ((inRaceLocalPlayerInputBitset3[0] & 0x800) != 0 || (inRaceLocalPlayerInputBitset3[0] & 0x400) != 0) {
            int subEvents[2];
            subEvents[0] = 0x536e6170; // 'Snap'
            subEvents[1] = (inRaceLocalPlayerInputBitset3[0] & 0x800) != 0 ? -1 : 1;
            swrEvent_DispatchSubEvents(player, subEvents);
        }
    }
    if (((uint8_t)player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) {
        swrRace_AutopilotSteer(player);
        if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0) {
            player->throttle = 0.0f;
            return;
        }
        if ((player->flags1 & swrObjTest_FLAG1_ON_SIDE) != 0) {
            swrRace_Tilt(player, 1.0f);
            return;
        }
        swrRace_Tilt(player, 0.0f);
    }
}

// 0x0046bc50
void swrRace_GetBoostBarColor(swrRace* pod, uint8_t* outRgb, uint8_t* outRgba, float* outFill)
{
    outRgb[0] = 0;
    outRgb[1] = 0xff;
    outRgb[2] = 0;
    outRgba[0] = 0xff;
    outRgba[1] = 0xff;
    outRgba[2] = 0xff;
    outRgba[3] = 100;
    *outFill = 0.0f;
    switch (pod->boostIndicatorStatus) {
    case 0:
        outRgb[0] = 0;
        outRgb[1] = 0xff;
        outRgb[2] = 0;
        outRgba[0] = 0xff;
        outRgba[1] = 0xff;
        outRgba[2] = 0xff;
        outRgba[3] = 100;
        *outFill = pod->speedValue / (pod->podStats.maxSpeed * 0.75);
        if (*outFill > 1.0f)
            *outFill = 1.0f;
        break;
    case 1:
        outRgb[0] = 0;
        outRgb[1] = 0xff;
        outRgb[2] = 0;
        outRgba[0] = 0xff;
        outRgba[1] = 0x80;
        outRgba[2] = 0;
        outRgba[3] = 200;
        *outFill = pod->boostChargeTimer;
        break;
    case 2:
        outRgb[0] = 0xff;
        outRgb[1] = 0xff;
        outRgb[2] = 0;
        outRgba[0] = 0xff;
        outRgba[1] = 0x80;
        outRgba[2] = 0;
        outRgba[3] = 200;
        *outFill = 1.0f;
        break;
    }
}

// Picks the speed multiplier source for one racer and commits it to speedMultiplier.
// AI racers (flags0 0x80) defer to swrRace_AI. 'Locl' splitscreen humans (flags0 0x20)
// with an active catchup field get a distance-based boost (capped at 1.25x); everyone
// else holds a neutral 1.0x.
// 0x0046ce30
void swrRace_UpdateCatchup(swrRace* player)
{
    swrScore* score = player->score_ptr;

    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 || score->localPlayerProfile == NULL) {
        if ((player->flags0 & swrObjTest_FLAG0_AI) != 0) {
            swrRace_AI((int) player);
        } else {
            player->paceMultiplier = 1.0f;
        }
    } else {
        player->paceMultiplier = 1.0f;
        if (1 < swrObjJdge_NumLocalPlayers() && 0.0f < player->gapToLocalPlayer1) {
            float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
            float boost = (player->gapToLocalPlayer1 * 100.0f) / invTrackLen + 1.0f;
            player->paceMultiplier = boost;
            if (1.25f < boost) {
                player->paceMultiplier = 1.25f;
            }
        }
    }
    player->speedMultiplier = player->paceMultiplier;
}

// 0x0046a990
void swrRace_CheckResetInput(swrRace* player, int playerIndex)
{
    if ((inRaceLocalPlayerInputBitset3[playerIndex] & swrRace_INRACE_INPUT_RESPAWN) != 0 &&
        (player->flags0 & swrObjTest_FLAG0_RESPAWN) == 0) {
        player->flags0 |= swrObjTest_FLAG0_RESPAWN;
    }
}

// 0x0046aa30
void swrRace_ApplyEngineDamage(swrRace* player)
{
    int lastBurning = -1;
    int i;

    for (i = 0; i < 6; i++) {
        if ((player->engineStatus[i] & 8) != 0) {
            swrRace_TakeDamage((int)player, i, (float)(((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.1f + 0.1f) * swrRace_deltaTimeSecs));
            lastBurning = i;
        }
    }
    if (lastBurning < 0) {
        swrSound_ClearSfxFlag(0, swrSound_SFXFLAG_ENGINE_FIRE);
        return;
    }
    if (swrSound_TestSfxFlag(0, swrSound_SFXFLAG_ENGINE_FIRE) != 0)
        return;
    swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 0xc, 0xc, 0xc, 0xc, 0xc, (rdVector3*)&player->transform.vD);
    swrSound_SetSfxFlag(0, swrSound_SFXFLAG_ENGINE_FIRE);
    // EXE tests the loop counter (always 6 here), so the direction is always 90
    swrControl_PlayForceEffect(0x15, -1, (i >= 3 && i <= 5) * 180 + 90, -1);
}

// 0x0046ba30
void swrRace_SpawnFlameAttack(swrRace* player)
{
    rdVector3* pos;
    rdVector3 smokPos;

    if ((player->flags0 & (swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 || player->flameSmokeHandle != NULL)
        return;

    pos = (rdVector3*)&player->transform.vD;
    swrSound_PlaySpatialRange(0x87, 6, (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.04 - (-0.23), 1.0f, pos, 0, 1, 50.0f, 500.0f);
    swrSound_PlaySpatialRange(0x88, 7, (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.04 - (-0.23), 1.0f, pos, 0, 1, 50.0f, 500.0f);
    player->unk12_2 = 15.0f;
    rdVector_Copy3(&smokPos, pos);
    player->flameSmokeHandle = swrObjSmok_Spawn(swrObjSmok_TYPE_FLAME_ATTACK, 0, 8.0f, &smokPos, 2.0f);
    swrObjSmok_SetOwnerHandle(player->flameSmokeHandle, &player->flameSmokeHandle);
}

// 0x0046bb50
void swrRace_SpawnFlameAttackByIndex(int racerIndex)
{
    swrRace_SpawnFlameAttack(swrScores[racerIndex].obj_test_ptr);
}

// 0x0046bb30
void swrRace_SendFlameAttackEvent(int player, double param_2, void* param_3, void* param_4, int param_5)
{
    swrMultiplayer_SendEvent(SITH_MESSAGE_TO_ALL, 0, 'flam', player);
}

// The per-frame human-input -> pod-intent routine for a 'Locl' racer. Reads the processed input
// (swrControl button-state @0x00ec8840[] / hold-time @0x00ec88a0[] arrays + analog axes), dispatches
// on the profile control-type byte (profile+0x23) to gather steer/pitch/throttle/brake/bank/boost/
// repair/taunt, applies the engine-damage steering pull + force feedback, boost-start detection and
// flame-attack, then commits turnRateTarget / throttle / tilt / flags0 / flags1. Reverse-hooked
// (dormant). Preserves an original bug: the analog pitch LOW clamp also writes +0.8 (see below).
// 0x0046bec0
void swrRace_UpdatePlayerControl(swrRace* player)
{
    float steerInput = 0.0f;
    float pitchForward = 0.0f;
    float throttleRaw = 0.0f;
    int thrustDigital = 0;
    int brakeDigital = 0;
    int bankLeft = 0;
    int bankRight = 0;
    int viewButtonInput = 0;
    int lookBackInput = 0;
    int flameTaunt = 0;
    int slideInput = 0;
    bool repairHold = false;

    player->throttle = 0.0f;
    player->turnRateTarget = 0.0f;

    swrScore* score = player->score_ptr;
    int playerIndex = *(int8_t*) &score->sfxChannel; // score+0x10 low byte = local-player slot
    int controlType = *((int8_t*) score->localPlayerProfile + 0x23);
    score->flag &= ~0x4;
    player->score_ptr->flag &= ~0x8;

    uint32_t canChargeBoost = player->flags0 & swrObjTest_FLAG0_CAN_CHARGE_BOOST;
    int bitset3 = inRaceLocalPlayerInputBitset3[playerIndex];
    int mirror = GameSettingFlags & 0x4000; // invert-steering option

    // ---- input-gather dispatch on the profile control-type byte ----
    // controlType 0/9 -> analog axes; 1..7 -> per-player bitset; 8/>9 -> no input (all stay zero).
    if (controlType == 0 || controlType == 9) {
        if (mirror) {
            steerInput = -swrRace_SteeringInput;
            bankRight = (int) swrControl_rollLeftButton;
            bankLeft = (int) swrControl_rollRightButton;
        } else {
            steerInput = swrRace_SteeringInput;
            bankLeft = (int) swrControl_rollLeftButton;
            bankRight = (int) swrControl_rollRightButton;
        }
        thrustDigital = (int) swrRace_ThrustInput;
        brakeDigital = (int) swrControl_brakeButton;
        viewButtonInput = (int) swrControl_viewButton;
        lookBackInput = (int) swrControl_inputStateButton;
        flameTaunt = (int) swrControl_tauntButton;
        repairHold = swrControl_repairButton != 0.0f && swrControl_repairHoldTime > (float) SWR_CTL_HALF_HOLD;
        slideInput = (int)swrControl_slideButton;
        throttleRaw = swrRace_ThrottleInput;

        if ((swrControl_brakeIsAnalog == 0 && brakeDigital != 0) || thrustDigital != 0) {
            score->flag &= ~0x8;
        } else if (swrRace_ThrottleInput != 0.0f) {
            score->flag |= 0x8;
        }
        if (thrustDigital != 0 && swrControl_brakeIsAnalog != 0 && brakeDigital != 0) {
            brakeDigital = 0;
        }

        pitchForward = swrRace_PitchInput * SWR_CTL_STEER_SCALE;
        if (SWR_CTL_STEER_SCALE < swrRace_PitchInput * SWR_CTL_STEER_SCALE) {
            pitchForward = SWR_CTL_STEER_SCALE;
        }
        // BUG (preserved from retail): the low clamp writes +0.8, not -0.8.
        if (pitchForward < -SWR_CTL_STEER_SCALE) {
            pitchForward = SWR_CTL_STEER_SCALE;
        }
    } else if (controlType >= 1 && controlType <= 7) {
        steerInput = swrControl_aPlayerAxisX[playerIndex];
        if (mirror) {
            steerInput = -steerInput;
            bankRight = bitset3 & 0x10;
            bankLeft = bitset3 & 0x20;
        } else {
            bankLeft = bitset3 & 0x10;
            bankRight = bitset3 & 0x20;
        }
        pitchForward = swrControl_aPlayerAxisY[playerIndex];
        thrustDigital = (int) swrRace_ThrustInput;
        brakeDigital = bitset3 & 0x2;
        lookBackInput = bitset3 & 0x8;
        viewButtonInput = inRaceLocalPlayerInputBitset1[playerIndex] & 0x4;
        if ((inRaceLocalPlayerInputBitset1[playerIndex] & 0x80) != 0) {
            if ((float) timetotal - player->tauntTapTime > (float) SWR_CTL_BOOST_TAP_TIMEOUT) {
                *((char*) &player->tauntTapState + 1) = 0;
            }
            char taps = *((char*) &player->tauntTapState + 1) + 1;
            player->tauntTapTime = (float) timetotal;
            *((char*) &player->tauntTapState + 1) = taps;
            if (taps > 1) {
                flameTaunt = 1;
            }
        }
        if ((*(char*) &inRaceLocalPlayerInputBitset2[playerIndex] & 0x80) != 0) {
            player->tauntTapTime = (float) timetotal;
        }
        if ((bitset3 & 0x80) != 0 && (float) timetotal - player->tauntTapTime > (float) SWR_CTL_HALF_HOLD) {
            repairHold = true;
        }
        slideInput = (bitset3 & 0x100) != 0;
        if (controlType == 1) {
            slideInput = thrustDigital == 0;
        }
    }

    int boostCharge = swrRace_BoostCharge((int) player);

    // ---- dual-control mode (N64 leftover): one pod driven by two controllers, one stick per engine.
    // Throttle = either stick forward, steer = difference between the sticks, brake = both back. ----
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_DUAL_CONTROL) != 0) {
        int dualIndex = (char) player->score_ptr->sfxChannel != '\0';
        float steerA = swrControl_aPlayerAxisX[dualIndex];
        float pitchA = swrControl_aPlayerAxisY[dualIndex];
        float steerB = swrControl_aPlayerAxisX[2 + dualIndex];
        float pitchB = swrControl_aPlayerAxisY[2 + dualIndex];
        thrustDigital = pitchA > SWR_CTL_THROTTLE_SETTLE_MIN || pitchB > SWR_CTL_THROTTLE_SETTLE_MIN;
        if (mirror == 0) {
            steerInput = (pitchA - pitchB) * SWR_CTL_HALF;
            bankLeft = steerA < SWR_CTL_NEG_HALF && steerB < SWR_CTL_NEG_HALF;
            bankRight = steerA > SWR_CTL_HALF && steerB > SWR_CTL_HALF;
        } else {
            steerInput = (pitchA - pitchB) * SWR_CTL_NEG_HALF;
            bankRight = steerA < SWR_CTL_NEG_HALF && steerB < SWR_CTL_NEG_HALF;
            bankLeft = steerA > SWR_CTL_HALF && steerB > SWR_CTL_HALF;
        }
        pitchForward = (pitchB + pitchA) * SWR_CTL_HALF;
        brakeDigital = pitchA < SWR_CTL_DMG_STEER_PULL && pitchB < SWR_CTL_DMG_STEER_PULL;
        viewButtonInput = inRaceLocalPlayerInputBitset1[dualIndex] & 0x4;
        lookBackInput = inRaceLocalPlayerInputBitset3[dualIndex] & 0x8;
        if ((inRaceLocalPlayerInputBitset1[dualIndex] & 0x80) != 0) {
            if ((float) timetotal - player->tauntTapTime > (float) SWR_CTL_BOOST_TAP_TIMEOUT) {
                *((char*) &player->tauntTapState + 1) = 0;
            }
            char taps = *((char*) &player->tauntTapState + 1) + 1;
            player->tauntTapTime = (float) timetotal;
            *((char*) &player->tauntTapState + 1) = taps;
            if (taps > 1) {
                flameTaunt = 1;
            }
        }
        if ((*(char*) &inRaceLocalPlayerInputBitset2[dualIndex] & 0x80) != 0) {
            player->tauntTapTime = (float) timetotal;
        }
        if ((*(char*) &inRaceLocalPlayerInputBitset3[dualIndex] & 0x80) != 0 &&
            (float) timetotal - player->tauntTapTime > (float) SWR_CTL_HALF_HOLD) {
            repairHold = true;
        }
        slideInput = steerA > SWR_CTL_HALF && steerB < SWR_CTL_NEG_HALF;
        playerIndex = dualIndex;
    }

    // ---- scripted spline-fork override: force branch 1 during the script 5/6 lap windows ----
    // (retail clears the slot with a float 0.0 store and sets it with an int 1; both are the same
    // dword on this int field, so the plain integer assignments below are bit-identical.)
    player->splineCursor.branchSelector = 0;
    if (ai_track_script > 0) {
        if (ai_track_script == 5 && SWR_CTL_SCRIPT5_LAP_MIN < player->lapComp && player->lapComp < SWR_CTL_SCRIPT5_LAP_MAX) {
            player->splineCursor.branchSelector = 1;
        }
        if (ai_track_script == 6 && SWR_CTL_SCRIPT6_LAP_MIN < player->lapComp && player->lapComp < SWR_CTL_SCRIPT6_LAP_MAX) {
            player->splineCursor.branchSelector = 1;
        }
    }

    int damagedSides = swrRace_GetDamagedEngineSides(player);
    if (damagedSides != 0) {
        damagedSides = 1;
        bankLeft = 0;
        bankRight = 0;
        boostCharge = 0;
        player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;
    }

    // ---- engine-damage steering pull + force feedback ----
    if ((player->flags0 & swrObjTest_FLAG0_THROTTLE_SETTLED) != 0 &&
        (player->flags0 & swrObjTest_FLAG0_BRAKING) == 0 &&
        (player->flags1 & swrObjTest_FLAG1_FINISHED) == 0) {
        float penalty = swrRace_GetEngineDamagePenalty(player);
        if ((damagedSides & 1) != 0) {
            penalty -= SWR_CTL_DMG_PEN_LEFT;
        } else if ((damagedSides & 2) != 0) {
            penalty -= SWR_CTL_DMG_PEN_RIGHT;
        }
        penalty *= SWR_CTL_DMG_PEN_GAIN;
        if (penalty == 0.0f) {
            swrControl_StopForceEffect(1);
        } else {
            int direction = penalty >= 0.0f ? 0x5a + 0xb4 : 0x5a;
            int magnitude = (int) (SWR_CTL_FF_MAG_BASE - penalty * SWR_CTL_FF_MAG_SLOPE);
            swrControl_PlayForceEffect(1, magnitude, direction, -1);
            swrControl_damageForceEffectPreempted = 1;
        }
        steerInput -= penalty * SWR_CTL_DMG_STEER_PULL;
        swrRace_engineDamageSteeringPenalty = penalty;
    }

    // ---- debug event dispatch ('Snap' teleport + reset-input) ----
    if ((swrRace_DebugFlag & 0x100) != 0 && swrRace_DebugLevel != 0) {
        if ((bitset3 & 0x800) != 0 || (bitset3 & 0x400) != 0) {
            int snap[2];
            snap[0] = 0x536e6170; // 'Snap'
            snap[1] = (bitset3 & 0x800) != 0 ? 1 : 2;
            swrEvent_DispatchSubEvents(player, snap);
        }
        if ((swrRace_DebugFlag & 0x100) != 0 && swrRace_DebugLevel != 0) {
            swrRace_CheckResetInput(player, playerIndex);
        }
    }

    // ---- flame attack / taunt ----
    if (flameTaunt != 0 || swrRace_debugTauntRequest != 0) {
        swrRace_debugTauntRequest = 0;
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING &&
            (player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_POD_HIDDEN)) == 0 &&
            (player->flags1 & swrObjTest_FLAG1_EXPLODING) == 0) {
            int soundSource = *score->pilotId;
            if (soundSource == 2) {
                swrRace_SpawnFlameAttack(player);
                // retail passes only the timestamp; the reconstructed 5-arg prototype's extra params are fillers.
                swrRace_SendFlameAttackEvent((int) score->time_unk, 0.0, NULL, NULL, 0);
            }
            int rng = swrUtils_Rand();
            int sfxRet;
            int to;
            if ((float) SWR_CTL_HALF_HOLD <= (float) rng * SWR_CTL_RAND_NORM) {
                sfxRet = swrSound_PlayRandomSfx(1, soundSource, 0x15, 0x16, 0x17, 0x18, 0x19,
                                                (rdVector3*) &player->transform.vD);
                to = -1;
            } else if (soundSource == 0xe) {
                sfxRet = swrSound_PlayRandomSfx(1, 0xe, 3, 0x12, 0x12, 0x13, 0x14,
                                                (rdVector3*) &player->transform.vD);
                to = -1;
            } else {
                sfxRet = swrSound_PlayRandomSfx(1, soundSource, 3, 0x11, 0x12, 0x13, 0x14,
                                                (rdVector3*) &player->transform.vD);
                to = 1;
            }
            swrMultiplayer_SendEvent(to, 0, 'taun', 1, soundSource, sfxRet);
        }
    }

    // ---- flags0 write-back: INPUT_STATE (0x100000), REPAIRING (0x400), clear high bit ----
    player->flags0 = lookBackInput != 0 ? (player->flags0 | swrObjTest_FLAG0_LOOK_BACK)
                                        : (player->flags0 & ~swrObjTest_FLAG0_LOOK_BACK);
    player->flags0 = repairHold ? (player->flags0 | swrObjTest_FLAG0_REPAIRING)
                                : (player->flags0 & ~swrObjTest_FLAG0_REPAIRING);
    player->flags0 &= 0x7fffffff;

    // ---- camera ('cMan') event: view button held -> 'CBut', else a pending debug camera event ----
    if (((uint8_t) player->flags0 & 0xf) != 0 && (player->flags0 & swrObjTest_FLAG0_DEAD) == 0) {
        if (viewButtonInput == 0) {
            if (swrRace_pendingCameraEvent != 0) {
                int event[2];
                event[0] = swrRace_pendingCameraEvent;
                event[1] = (int) player;
                swrEvent_CallF4(0x634d616e, event); // 'cMan'
                swrRace_pendingCameraEvent = 0;
            }
        } else {
            int event[2];
            event[0] = 0x43427574; // 'CBut'
            event[1] = (int) player;
            swrEvent_CallF4(0x634d616e, event); // 'cMan'
        }
    }

    swrRace_ApplyEngineDamage(player);
    swrRace_Repair(player);

    // ---- zero-g (ZON): the pitch stick becomes a pitch-RATE demand ----
    if ((player->flags0 & swrObjTest_FLAG0_ZON) != 0) {
        if (pitchForward >= SWR_CTL_STEER_DEADZONE || -pitchForward >= SWR_CTL_STEER_DEADZONE) {
            float squared = pitchForward * SWR_CTL_STEER_SQUARE_GAIN * (pitchForward * SWR_CTL_STEER_SQUARE_GAIN);
            if (pitchForward < 0.0f) {
                squared = -squared;
            }
            player->zeroGPitchRateTarget = -(player->podStats.maxTurnRate * squared * SWR_CTL_STEER_SCALE) * SWR_CTL_HALF;
        } else {
            player->zeroGPitchRateTarget = 0.0f;
        }
        pitchForward = 0.0f;
    }

    // ---- boost-start window (flags1 0x800 -> 0x1000 -> 0x2000) ----
    if ((swrRace_ThrustInput != 0.0f && swrControl_thrustHoldTime < (float) SWR_CTL_BOOST_WINDOW &&
         (float) SWR_CTL_BOOST_WINDOW_LO < swrControl_thrustHoldTime) ||
        (swrRace_ThrottleInput > (float) SWR_CTL_BOOST_THROTTLE && swrRace_BoostInput != 0.0f &&
         swrControl_boostHoldTime < (float) SWR_CTL_BOOST_WINDOW &&
         (float) SWR_CTL_BOOST_WINDOW_LO < swrControl_boostHoldTime)) {
        if ((player->flags1 & swrObjTest_FLAG1_BOOST_START_CANCEL) == 0) {
            player->flags1 |= swrObjTest_FLAG1_BOOST_START_CANCEL;
            if ((player->flags1 & swrObjTest_FLAG1_BOOST_START_WINDOW) != 0) {
                player->flags1 |= swrObjTest_FLAG1_BOOST_START;
            }
        }
    }
    if ((player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) {
        if (swrSound_TestSfxFlag(0, 0x80000) == 0) {
            swrSound_PlayRandomSfx(1, *score->pilotId, 2, 2, 2, 2, 2, (rdVector3*) &player->transform.vD);
            swrSound_SetSfxFlag(0, 0x80000);
        }
        if ((swrRace_ThrustInput == 0.0f && swrRace_ThrottleInput <= (float) SWR_CTL_BOOST_THROTTLE) ||
            player->speedValue > SWR_CTL_BOOST_CANCEL_SPEED) {
            player->flags1 &= ~swrObjTest_FLAG1_BOOST_START;
        }
    }

    if (((uint8_t) player->flags0 & 0xf) != swrObjTest_FLAG0_RACING) {
        return;
    }
    if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0) {
        return;
    }

    // ---- BRAKING ----
    if (brakeDigital == 0) {
        player->flags0 &= ~swrObjTest_FLAG0_BRAKING;
    } else {
        player->flags0 |= swrObjTest_FLAG0_BRAKING;
        if (player->speedValue < (float) SWR_CTL_BRAKE_SETTLE_SPEED) {
            player->flags0 = (player->flags0 & ~swrObjTest_FLAG0_THROTTLE_SETTLED) | swrObjTest_FLAG0_BRAKING;
        }
    }

    // ---- throttle ----
    if ((score->flag & 0x8) != 0) {
        float mapped = (throttleRaw - SWR_CTL_NEG_ONE) * SWR_CTL_HALF * SWR_CTL_ANALOG_THROTTLE_GAIN;
        player->throttle = mapped;
        if (mapped > SWR_CTL_ONE) {
            player->throttle = 1.0f;
        }
        if (player->throttle < SWR_CTL_NEG_ONE) {
            player->throttle = -1.0f;
        }
    } else if (thrustDigital == 0) {
        if (pitchForward >= SWR_CTL_NEG_HALF || player->speedValue >= (float) SWR_CTL_IDLE_SPEED) {
            player->throttle = 0.1f;
        } else {
            player->throttle = pitchForward * SWR_CTL_PITCH_TRIM;
        }
    } else {
        player->throttle = 1.0f;
        if (damagedSides != 0) {
            player->throttle = 0.5f;
        }
    }

    if (player->wallHitCooldown <= 0.0f && player->throttle > SWR_CTL_THROTTLE_SETTLE_MIN) {
        player->flags0 |= swrObjTest_FLAG0_THROTTLE_SETTLED;
    }

    // ---- SLIDING (airborne forces it) ----
    uint32_t sliding = (player->flags1 & swrObjTest_FLAG1_AIRBORNE) != 0 ? 1u : (uint32_t) slideInput;
    player->flags1 = sliding != 0 ? (player->flags1 | swrObjTest_FLAG1_SLIDING)
                                  : (player->flags1 & ~swrObjTest_FLAG1_SLIDING);

    // ---- NOT_ACCEL ----
    player->flags1 = (thrustDigital != 0 || throttleRaw > SWR_CTL_HALF)
                         ? (player->flags1 & ~swrObjTest_FLAG1_NOT_ACCEL)
                         : (player->flags1 | swrObjTest_FLAG1_NOT_ACCEL);

    // ---- slide2 easing ----
    if (sliding == 0 || player->speedValue <= SWR_CTL_SLIDE_SPEED) {
        player->slide -= (float) (swrRace_deltaTimeSecs * SWR_CTL_HALF_HOLD);
        if (player->slide < 0.0f) {
            player->slide = 0.0f;
        }
    } else {
        player->slide -= (float) (swrRace_deltaTimeSecs * SWR_CTL_NEG_HALF);
        if (player->slide > SWR_CTL_ONE) {
            player->slide = 1.0f;
        }
    }

    // ---- boost latch ----
    if (boostCharge != 0 && canChargeBoost != 0) {
        swrUtils_Rand();
        player->flags0 |= swrObjTest_FLAG0_BOOSTING;
    }
    if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0 && thrustDigital == 0 && throttleRaw <= SWR_CTL_HALF) {
        player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;
    }

    player->unk1f14 -= (float) swrRace_deltaTimeSecs;

    // ---- tilt / bank ----
    if ((bankLeft != 0 || bankRight != 0) && (player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) {
        swrSound_Play2D(0x4b, 7, 0.5f, 1.0f, 1);
    }
    float tilt = (bankLeft != 0 && bankRight == 0) ? -1.0f : (bankLeft == 0 && bankRight != 0) ? 1.0f : 0.0f;
    swrRace_Tilt(player, tilt);

    // ---- turnRateTarget from steer (squared) ----
    if (steerInput >= SWR_CTL_STEER_DEADZONE || -steerInput >= SWR_CTL_STEER_DEADZONE) {
        float squared = steerInput * SWR_CTL_STEER_SQUARE_GAIN * (steerInput * SWR_CTL_STEER_SQUARE_GAIN);
        if (steerInput < 0.0f) {
            squared = -squared;
        }
        player->turnRateTarget = -(player->podStats.maxTurnRate * squared * SWR_CTL_STEER_SCALE);
    } else {
        player->turnRateTarget = 0.0f;
    }

    // ---- pitch trims turn rate + throttle ----
    player->pitch = pitchForward;
    if (pitchForward > SWR_CTL_PITCH_HI) {
        player->turnRateTarget *= (SWR_CTL_ONE - pitchForward * SWR_CTL_PITCH_TRIM);
        if (player->throttle > SWR_CTL_HALF) {
            player->throttle -= pitchForward * SWR_CTL_PITCH_THROTTLE_TRIM;
        }
    }
    if (pitchForward < SWR_CTL_PITCH_LO) {
        player->turnRateTarget *= (SWR_CTL_ONE - pitchForward * SWR_CTL_PITCH_TRIM);
        if ((player->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0 && player->throttle > SWR_CTL_HALF) {
            player->throttle -= pitchForward * SWR_CTL_PITCH_THROTTLE_TRIM;
        }
    }
    if ((player->flags0 & swrObjTest_FLAG0_BOOST_OVERDRIVE) != 0 && player->throttle < SWR_CTL_FLAT_THROTTLE_FLOOR) {
        player->throttle = 1.2f;
    }

    player->paceMultiplier = 1.0f;
}

// Computes this racer's per-frame target turn rate and throttle, dispatched by control ownership:
// a 'Locl' human with a bound profile -> swrRace_UpdatePlayerControl; a racing remote pod replays
// its stored turn target; AI -> autopilot (with a FORCE_GROUND repair kick). Then applies catchup,
// folds speedMultiplier into throttle for AI, zeroes throttle during the post-wall-impact
// window (wallHitCooldown > 0), and clamps turnRateTarget to +/- podStats.maxTurnRate (both
// scaled by paceMultiplier).
// 0x0046cf00
void swrRace_CalcTargetTurnRate(swrRace* player)
{
    uint32_t flags0 = player->flags0;
    player->throttle = 0.0f;
    player->turnRateTarget = 0.0f;

    if ((flags0 & swrObjTest_FLAG0_LOCAL) != 0 && player->score_ptr->localPlayerProfile != NULL) {
        swrRace_UpdatePlayerControl(player);
    } else if ((flags0 & swrObjTest_FLAG0_REMOTE) != 0) {
        if (((uint8_t) flags0 & 0xf) != swrObjTest_FLAG0_RACING) {
            return;
        }
        player->turnRateTarget = player->remoteSteerTarget;
    } else if ((flags0 & swrObjTest_FLAG0_AI) != 0) {
        swrRace_UpdateAutopilotControl(player);
        if ((player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0) {
            player->flags0 |= swrObjTest_FLAG0_REPAIRING;
            swrRace_Repair(player);
        }
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) {
            swrRace_ApplyPodProximityForce(player);
        }
    }

    if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) {
        swrRace_UpdateCatchup(player);
    }
    if ((player->flags0 & swrObjTest_FLAG0_AI) != 0) {
        player->throttle *= player->speedMultiplier;
    }
    if (0.0f < player->wallHitCooldown) {
        player->throttle = 0.0f;
    }

    float target = player->turnRateTarget * player->paceMultiplier;
    float cap = player->podStats.maxTurnRate * player->paceMultiplier;
    player->turnRateTarget = target;
    if (cap < target) {
        player->turnRateTarget = cap;
    }
    if (player->turnRateTarget < -cap) {
        player->turnRateTarget = -cap;
    }
}

// Accumulate collision/scrape damage into engine part `engineIndex`. The hit magnitude
// is scaled by podStats.damageImmunity (really a damage *multiplier*: higher = more
// fragile), capped at 1.0 (fully destroyed), recorded as that part's worst damage, and
// added to totalDamage. No-op while invincible, spun out (flags0 0x6000), or finished
// (flags1 0x2000000).
// 0x00474cd0
void swrRace_TakeDamage(int player, int engineIndex, float amount)
{
    swrRace* p = (swrRace*) player;

    if (swrRace_IsInvincible != 0) {
        return;
    }
    if ((p->flags0 & (swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 || (p->flags1 & swrObjTest_FLAG1_FINISHED) != 0) {
        return;
    }

    p->flags0 &= ~swrObjTest_FLAG0_BOOSTING; // taking damage cancels an active boost
    float health = p->podStats.damageImmunity * amount + p->engineHealth[engineIndex];
    p->engineHealth[engineIndex] = health;
    if (1.0f < health) {
        p->engineHealth[engineIndex] = 1.0f;
    }
    p->engineStatus[engineIndex] |= 1;
    if (p->engineHealthMin[engineIndex] < p->engineHealth[engineIndex]) {
        p->engineHealthMin[engineIndex] = p->engineHealth[engineIndex];
    }
    p->totalDamage += amount;
}

// 0x00475ad0
void swrRace_Init(swrRace* player, swrSpline* spline, swrModel_Node** partNodes, swrModel_Node* collisionModel, int lightIndex, float* spawnTransform, int gridPos, int racerCount, int localPlayerCount, int duplicatePods)
{
    float ray[7];
    rdVector3 hitPoint;
    rdVector3 hitNormal;
    float aabb[6];
    int subEvents[2];
    float hitDist;
    unsigned int flags;
    int i;

    player->splineCursor.spline = spline;
    player->splineCursor.velocity = 0.0f;
    player->splineCursor.segmentT = 0.0f;
    player->splineCursor.tangentLength = 0.0f;
    player->splineCursor.endFlag = 0;
    player->splineCursor.startFlag = 0;
    player->splineCursor.branchSelector = 0;
    player->splineCursor.branchFlags = 0;
    if (spline != NULL)
        swrSpline_CursorSeek(&player->splineCursor, 0);
    player->splineCursor.segmentT = 0.01f;

    player->flags0 = 0;
    player->flags1 = 0;
    flags = player->flags0 & ~swrObjTest_FLAG0_STATE_MASK;
    player->flags0 = flags;
    if (player->score_ptr->identifier == 'Locl') {
        player->flags0 = flags | swrObjTest_FLAG0_LOCAL;
    } else if (player->score_ptr->identifier == 'REMO') {
        player->flags0 = flags | swrObjTest_FLAG0_REMOTE;
        player->remoteId = -1;
    } else if (player->score_ptr->identifier == 'AAII') {
        player->flags0 = flags | swrObjTest_FLAG0_AI;
    }
    if ((player->score_ptr->flag & 0x20) != 0)
        player->flags0 |= swrObjTest_FLAG0_AI_SIMPLE;
    else
        player->flags0 &= ~swrObjTest_FLAG0_AI_SIMPLE;

    player->podStats = player->score_ptr->podStats;
    player->podStats.intersectRadius = 2.0f;
    player->collisionWidth = player->score_ptr->podStats.intersectRadius;
    memcpy(&player->transform, spawnTransform, sizeof(rdMatrix44));

    // drop onto the track: cast 40 units straight down and settle at the hover height
    ray[0] = player->transform.vD.x;
    ray[1] = player->transform.vD.y;
    ray[2] = player->transform.vD.z;
    ray[3] = 0.0f;
    ray[4] = 0.0f;
    ray[5] = -1.0f;
    ray[6] = 40.0f;
    hitDist = swrRace_RaycastModel(collisionModel, ray, &hitPoint, &hitNormal);
    player->transform.vD.z = player->transform.vD.z - (hitDist - player->podStats.hoverHeight);
    rdMatrix_ExtractTransform(&player->transform, &player->spawn_pos_rot);

    player->repairTimer = 0.0f;
    player->splineSampleSpacing = 0.0f;
    player->lapComp = 0.9f;
    player->lapCompPrev = 0.9f;
    player->lapCompMax = 0.0f;
    player->splineTrackMesh = NULL;
    player->splineProjResult1 = 0;
    player->splineProjResult2 = 0;
    player->splineTrackMeshPrev = NULL;
    player->trackOffset.w = 1.0f;
    player->trackOffset.x = 0.0f;
    player->trackOffset.y = 0.0f;
    player->trackOffset.z = 1.0f;
    player->gapToLeader = 0.0f;
    player->gapToLocalPlayer1 = 0.0f;
    player->gapToLocalPlayer2 = 0.0f;
    player->aiPaceOffsetTarget = 0.0f;
    player->gapToPacer = 0.0f;
    player->aiLookAhead = 0.2f;
    player->aiLookAheadDistSq = 8100.0f;
    player->checkpointCount = 0;
    player->splineRebindResult = 0;
    player->idleTick = 0.0f;
    player->moveTick = 0;
    player->deathExplodeTimer = 0.0f;
    player->spinoutEngineAngle = 0.0f;
    player->spinoutCockpitAngle = 0.0f;
    player->spinoutSpinRamp = 0.0f;
    player->engineDamageSmoke[0] = NULL;
    player->engineDamageSmoke[1] = NULL;
    player->flameSmokeHandle = NULL;
    player->unk320 = 0;
    player->unk328 = 0;
    player->unk32c = 0;
    player->fireballEngineSlot = -1;
    player->throttle = 0.0f;
    player->gravityScale = 32.0f;
    rdVector_Set3(&player->world_gravity, 0.0f, 0.0f, -1.0f);
    player->speedValue = 0.0f;
    player->fallStep = 0.0f;
    player->fallVelocity = 0.0f;
    player->accelThrust = 0.0f;
    player->boostValue = 0.0f;
    rdVector_Set3(&player->velocityDir, 0.0f, 0.0f, 0.0f);
    player->unk1efc = 0.25f;
    player->turnRate = 0.0f;
    player->turnRateTarget = 0.0f;
    player->unk10_3 = 0;
    player->zeroGPitchRate = 0.0f;
    player->zeroGPitchRateTarget = 0.0f;
    player->turnModifier = 0.0f;
    player->autoTilt = 0.0f;
    player->contactSteerKick = 0.0f;
    player->tiltAngleTarget = 0.0f;
    player->tiltAngle = 0.0f;
    rdVector_Set3(&player->velocitySlope, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&player->velocityCollision, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&player->velocityCollisionOpponent, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&player->bumpDirection, 0.0f, 0.0f, 1.0f);
    rdVector_Set3(&player->wallPushback, 0.0f, 0.0f, 0.0f);
    rdVector_Copy3(&player->positionPrev, (rdVector3*)&player->transform.vD);
    rdVector_Copy3(&player->positionDeath, (rdVector3*)&player->transform.vD);
    rdVector_Set3(&player->up, 0.0f, 0.0f, 1.0f);
    player->speedLoss = 0.0f;
    player->unk1f18 = 0;
    player->unk11_1 = 0.0f;
    player->engineTemp = 100.0f;
    player->unk1f00 = 80.0f;
    player->unk1f04 = 0;
    *(int*)player->unk1f08 = 0;
    player->unk2f0 = 0;
    player->tauntTapTime = 0.0f;
    player->tauntTapState = 0;
    player->pitch = 0.0f;
    player->engineTiltSmoothed = 0.0f;
    player->unk1f14 = 0.0f;
    player->tiltManualMult = 0.0f;
    player->unk9 = 0;
    player->orthoRenormCounter = 0;
    player->groundToPodMeasure = 0.0f;
    player->groundZ = 0.0f;
    player->speedMultiplier = 1.0f;
    player->surfaceSpeedFactor = 1.0f;
    player->surfaceSpeedBonus = 0.0f;
    player->surfaceGripFactor = 1.0f;
    player->exhaustSizeLeft = 0.0f;
    player->exhaustSizeRight = 0.0f;
    player->slide2 = 1.0f;
    player->slide = 0.0f;
    player->paceMultiplier = 1.0f;
    player->aiSpeedTarget = 1.0f;
    player->aiDecisionTimer = 10.0f;

    // grid slot -> AI finishing-rank baseline: slots 0/1 stay, 2+ shift up one, capped at 5
    player->aiRankBaseline = gridPos;
    if (gridPos < 0) {
        player->aiRankBaseline = 0;
    } else {
        player->aiRankBaseline = gridPos + 1;
        if (player->aiRankBaseline > 2)
            player->aiRankBaseline--;
        if (player->aiRankBaseline > 5)
            player->aiRankBaseline--;
    }
    player->wallHitCooldown = 0.0f;
    player->aiRankTarget = player->aiRankBaseline;
    player->unk12_2 = 60.0f;
    player->lodDistance = 0;
    player->collisionToggles = 0xffffff00;
    player->terrainModel = NULL;
    player->unk1f24 = 0;
    player->unk1f1c = 0;
    player->unk1f20 = 0;
    player->gravityTubeAngle = 0.0f;
    for (i = 0; i < 6; i++) {
        player->engineHealthMin[i] = 0.0f;
        player->engineHealth[i] = 0.0f;
        player->engineStatus[i] = 0.0f;
    }
    player->vibrationMagnitude = 0.0f;
    player->repairTimer = 0.0f;
    player->damageWarningTimer = 0.0f;
    player->totalDamage = 0.0f;
    player->fallTimer = 0.0f;
    player->respawnInvincibilityTimer = 0.0f;
    player->vehicleBumpTimer = 0.0f;
    player->historyWriteIdx = 0;
    for (i = 0; i < 18; i++)
        rdMatrix_Copy44(&player->transformHistory[i], &player->transform);
    player->historyLagEngines = 9;
    player->historyLagCockpit = 6;
    rdVector_Set3(&player->cockpitSpringPos, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&player->cockpitSpringVel, 0.0f, 0.0f, 0.0f);
    player->collisionModel = collisionModel;
    player->cockpitPitchPrev = 0.0f;
    player->partNodes = partNodes;
    player->current_light_index = lightIndex;
    player->lightColorMode = 0;
    if (duplicatePods != 0 && (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0 && (char)player->score_ptr->sfxChannel != 0)
        player->lightColorMode = 2;

    // 75 consecutive part transforms start at unk350_mat (later ones carry their own field names)
    for (i = 0; i < 75; i++) {
        rdMatrix_SetIdentity44(&(&player->unk350_mat)[i]);
        rdVector_Set3(&player->partOffset[i], 0.0f, 0.0f, 0.0f);
    }
    player->scrapeSparkXf.vD.z = -2000.0f;
    player->scrapeSparkXf2.vD.z = -2000.0f;
    for (i = 0; i < 4; i++)
        player->wobblePhase[i] = (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 60.0f;
    player->unk19b0 = 0.0f;
    player->wobbleAmplitude = 1.0f;
    player->unk19b4 = 1.0f;

    subEvents[0] = 'sLOD';
    subEvents[1] = swrConfig_VIDEO_MODEL_DETAIL == 1 ? 2 : 0;
    swrEvent_DispatchSubEvents(player, subEvents);
    swrRace_ResetModelNodeFlags(player);
    if (player->partNodes != NULL) {
        if (player->partNodes[0x3e] != NULL)
            player->partNodes[0x3e]->flags_5 |= 1;
        if (player->partNodes[2] != NULL)
            player->partNodes[2]->flags_5 |= 1;
        if (player->partNodes[4] != NULL)
            player->partNodes[4]->flags_5 |= 1;
        if (player->partNodes[0xe] != NULL)
            player->partNodes[0xe]->flags_5 |= 1;
    }

    player->footprintX = 2.0f;
    player->footprintY = 2.0f;
    if (player->partNodes != NULL && player->partNodes[0x3e] != NULL && swrModel_NodeComputeFirstMeshAABB(player->partNodes[0x3e], aabb, 0) != 0) {
        player->footprintY = (aabb[4] - aabb[1]) * 0.004f;
        player->footprintX = (aabb[3] - aabb[0]) * 0.0036000002f;
    }
    if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE) {
        player->footprintX = 3.0f;
        player->footprintY = 5.0f;
    }

    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) {
        swrControl_StopAllForceEffects(0);
        swrControl_SetForceFeedbackPlayer(player);
    }
    if ((player->flags0 & (swrObjTest_FLAG0_LOCAL | swrObjTest_FLAG0_AI_SIMPLE)) != 0)
        swr_noop2();
    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0)
        swrModel_FxAnimGetState_Maybe();
}

// 0x00476AC0
void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2)
{
    for (swrModel_TriggerDescription* trigger = a2; trigger != NULL; trigger = trigger->next) {
        unsigned short flags = trigger->flags;
        int skip = 0;
        if (flags != 0) {
            int lap;
            if (flags & swrModel_TRIGGERFLAG_DISABLED)
                skip = 1;
            if ((flags & swrModel_TRIGGERFLAG_MIN_SPEED) && a->speedValue < 150.0f)
                skip = 1;
            if (!(a->flags0 & swrObjTest_FLAG0_LOCAL) && (flags & swrModel_TRIGGERFLAG_LOCAL_ONLY))
                skip = 1;
            lap = a->score_ptr->results_P1_Lap;
            if (lap == 0 && (flags & swrModel_TRIGGERFLAG_SKIP_LAP1))
                skip = 1;
            if (lap == 1 && (flags & swrModel_TRIGGERFLAG_SKIP_LAP2))
                skip = 1;
            if (lap == 2 && (flags & swrModel_TRIGGERFLAG_SKIP_LAP3))
                skip = 1;
        }
        if (skip)
            continue;

        swrObjTrig* trig = swrObjTrig_FindOrCreate(trigger);
        if (trig == NULL)
            continue;

        // The volume is a vertical box: a horizontal segment A-B of length size_xy across the
        // trigger's facing (direction rotated 90 deg), extruded +-size_z/2 around center.z.
        float halfWidth = trigger->size_xy * 0.5f;
        float halfHeight = trigger->size_z * 0.5f;
        float cx = trigger->center.x;
        float cy = trigger->center.y;
        float cz = trigger->center.z;
        float px = a->transform.vD.x;
        float py = a->transform.vD.y;
        float pz = a->transform.vD.z;
        float ax = cx - halfWidth * trigger->direction.y;
        float ay = cy + halfWidth * trigger->direction.x;
        float bx = cx + halfWidth * trigger->direction.y;
        float by = cy - halfWidth * trigger->direction.x;
        float dx = ax - bx;
        float dy = ay - by;
        float dz = 0.0f;
        float lenSq = dx * dx + dy * dy + dz * dz;
        float dotPos = dx * px + dy * py + dz * pz;
        // faithful: the segment's z term reuses the racer's z
        float dotB = dx * bx + dy * by + dz * pz;
        float t;
        float closestX = bx;
        float closestY = by;
        if (lenSq > 0.001) {
            // compared unrounded on the x87 stack, then reloaded from its float slot
            double tExact = (dotPos - dotB) / lenSq;
            t = (float)tExact;
            if (tExact > 0.0f) {
                if (t < 1.0f) {
                    closestX = dx * t + bx;
                    closestY = dy * t + by;
                } else {
                    closestX = ax;
                    closestY = ay;
                }
            }
        } else {
            t = 0.0f;
        }

        int hit = 0;
        if (trigger->type == swrModel_TriggerType_BreakDestructable_102 || trigger->type == swrModel_TriggerType_KillPlayer) {
            // plane crossing between last and current position, within the segment's span
            if (t > 0.0f && t < 1.0f && pz < cz + halfHeight && cz - halfHeight < pz) {
                float plane = cz * trigger->direction.z + cy * trigger->direction.y + cx * trigger->direction.x;
                float prev = a->positionPrev.z * trigger->direction.z + a->positionPrev.y * trigger->direction.y + a->positionPrev.x * trigger->direction.x;
                float cur = pz * trigger->direction.z + px * trigger->direction.x + py * trigger->direction.y;
                // faithful: also fires when both samples sit on/behind the plane
                hit = (prev > plane) == (cur < plane);
            }
        } else {
            float ex = closestX - px;
            float ey = closestY - py;
            hit = ex * ex + ey * ey < halfWidth * halfWidth && pz < cz + halfHeight && cz - halfHeight < pz;
        }
        if (hit)
            swrRace_TriggerHandler(trig, a, 0);
    }
}

// Eases *value toward target at `rate` units/sec (used for the traction/skid multipliers below).
static void swrRace_easeTraction(float* value, float target, double rate)
{
    if (target <= *value) {
        if (target < *value) {
            *value = *value - swrRace_deltaTimeSecs * rate;
            if (*value < target)
                *value = target;
        }
    } else {
        *value = *value + swrRace_deltaTimeSecs * rate;
        if (target < *value)
            *value = target;
    }
}

// Reads the terrain mesh's swrModel_Behavior tag and translates its bitfields into pod flags +
// traction targets each frame. behavior.unk1 & 0x20 sets flags1 0x400 (the surface-relative "magnet"
// gravity); vehicle_reaction bits drive zero-g/orbit (1/2), surface friction (4/8/0x10/0x20), wall
// reactions, reflections, triggers, etc. The clear mask 0xff63fb1e drops the per-frame tag bits up
// front so they re-latch only while the pod is over a tagged surface.
// 0x00476ea0
void swrRace_UpdateSurfaceTag(swrRace* test)
{
    float iceTarget = 0.0;
    float terrainTractionTarget = 1.0;
    float terrainSkidTarget = 1.0;

    if (((test->flags0 & swrObjTest_FLAG0_ZON) != 0) && (test->speedValue < 75.0f))
        iceTarget = 75.0f - test->speedValue;

    test->flags1 = test->flags1 & ~(swrObjTest_FLAG1_ON_SWAMP | swrObjTest_FLAG1_ON_SIDE | swrObjTest_FLAG1_ON_MIRR | swrObjTest_FLAG1_FULL_RAYCAST | swrObjTest_FLAG1_MAGNET | swrObjTest_FLAG1_ON_LAVA | swrObjTest_FLAG1_ON_FALL | swrObjTest_FLAG1_ON_SOFT | swrObjTest_FLAG1_ON_FLAT);

    swrModel_Behavior* behavior = NULL;
    if (test->terrainModel != NULL)
        behavior = swrModel_MeshGetBehavior((swrModel_Mesh*) test->terrainModel);

    if (behavior != NULL) {
        uint32_t toggles = test->collisionToggles & ~behavior->unk20;
        test->collisionToggles = (((behavior->unk21 >> 8) | (toggles >> 8)) & 0xFFFFFF) << 8;

        if ((behavior->unk1 & 0x10) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_FULL_RAYCAST;
        if ((behavior->unk1 & 0x20) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_MAGNET;// surface-relative "magnet" gravity
        if ((behavior->vehicle_reaction & swrVehicleReaction_Lava) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_LAVA;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Fall) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_FALL;
        if (((behavior->vehicle_reaction & swrVehicleReaction_Flat) != 0) && ((test->flags0 & swrObjTest_FLAG0_AI) != 0) &&
            ((test->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0))
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_FLAT;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Soft) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SOFT;

        // debug hotkey: toggle the zero-g flag while held
        if (((swrRace_DebugFlag & 0x2000) != 0) && ((inRaceLocalPlayerInputBitset1[0] & 0x100) != 0) &&
            (((uint8_t) inRaceLocalPlayerInputBitset3[0] & 0x80) != 0))
            test->flags0 = test->flags0 ^ swrObjTest_FLAG0_ZON;

        if ((behavior->vehicle_reaction & swrVehicleReaction_ZOn) != 0)
            test->flags0 = test->flags0 | swrObjTest_FLAG0_ZON;
        if (((behavior->vehicle_reaction & swrVehicleReaction_ZOff) != 0) && ((test->flags0 & swrObjTest_FLAG0_ZON) != 0)) {
            // entering zero-g/orbit: seed velocityDir from the last move, clear the slide
            test->velocityDir.x = test->transform.vD.x - test->positionPrev.x;
            test->velocityDir.y = test->transform.vD.y - test->positionPrev.y;
            test->velocityDir.z = test->transform.vD.z - test->positionPrev.z;
            test->unk10_3 = 0x40400000;// 3.0f
            test->velocitySlope.x = 0.0;
            test->velocitySlope.y = 0.0;
            test->velocitySlope.z = 0.0;
            test->flags0 = (test->flags0 & ~swrObjTest_FLAG0_ZON) | swrObjTest_FLAG0_ZOFF;
        }

        if ((behavior->vehicle_reaction & swrVehicleReaction_Fast) != 0)
            iceTarget = 200.0f;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Slow) != 0) {
            terrainTractionTarget = 0.75f;
            if ((test->flags0 & swrObjTest_FLAG0_ZON) != 0)
                test->flags0 = test->flags0 & ~swrObjTest_FLAG0_BOOSTING;
        }
        if ((behavior->vehicle_reaction & swrVehicleReaction_Swst) != 0) {
            terrainTractionTarget = 0.1f;
            test->flags0 = test->flags0 & ~swrObjTest_FLAG0_BOOSTING;
        }
        if ((behavior->vehicle_reaction & swrVehicleReaction_Slip) != 0)
            terrainSkidTarget = 0.2f;
        if ((test->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
            terrainSkidTarget = 1.0f;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Swmp) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SWAMP;
        if (behavior->triggers != NULL)
            swrRace_ActivateTriggersInRange(test, behavior->triggers);
        if (((behavior->vehicle_reaction & swrVehicleReaction_Mirr) != 0) && (swrConfig_VIDEO_REFLECTIONS == 1))
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_MIRR;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Side) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SIDE;
    }

    if (specialActiveTrigger != NULL)
        swrRace_ActivateTriggersInRange(test, specialActiveTrigger);

    swrRace_easeTraction(&test->surfaceSpeedBonus, iceTarget, 25.0);
    swrRace_easeTraction(&test->surfaceSpeedFactor, terrainTractionTarget, 0.5);
    swrRace_easeTraction(&test->surfaceGripFactor, terrainSkidTarget, 0.5);

    test->unk11_1 = 0;
    if (((((float) test->lodDistance - 400.0f) * 0.0016666667f < 1.0f) || ((test->flags0 & swrObjTest_FLAG0_LOCAL) != 0) ||
         ((test->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) &&
        (((test->flags1 & swrObjTest_FLAG1_ON_FALL) != 0) && ((test->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0)))
        test->flags0 = test->flags0 | swrObjTest_FLAG0_RESPAWN;
}

// 0x004774f0
RETAIL_FP void swrRace_ApplyGravity(swrRace* player, float* a, float b)
{
    // Down direction: surface-relative on walls/tubes (flags1 0x400), else the world vector.
    float gx, gy, gz;
    uint32_t flags1 = player->flags1;
    if ((flags1 & swrObjTest_FLAG1_MAGNET) == 0)
    {
        gx = player->world_gravity.x;
        gy = player->world_gravity.y;
        gz = player->world_gravity.z;
    }
    else
    {
        gx = -player->up.x;
        gy = -player->up.y;
        gz = -player->up.z;
    }

    // Distance to the hover plane, corrected for the pod's roll.
    float groundDist = b - player->podStats.intersectRadius;
    float hoverDelta = player->podStats.hoverHeight - player->podStats.intersectRadius;
    float vAz = player->transform.vA.z;
    if (vAz < 0.0f)
        vAz = -vAz;
    long double rollTerm = player->collisionWidth * vAz;
    if (3.0f < rollTerm)
        groundDist = groundDist - (rollTerm - 3.0f);

    // Too-high-for-too-long watchdog forces a respawn.
    if (b <= 99999.0f)
    {
        player->fallTimer = 0.0f;
    }
    else
    {
        // Retail compares the sum before rounding it into fallTimer.
        long double fallTimer = swrRace_deltaTimeSecs + player->fallTimer;
        player->fallTimer = fallTimer;
        if (3.0f < fallTimer)
            player->flags0 |= swrObjTest_FLAG0_RESPAWN;
    }

    // Airborne flag once high enough off the ground.
    if (b <= 30.0f)
        flags1 &= ~swrObjTest_FLAG1_AIRBORNE;
    else
        flags1 |= swrObjTest_FLAG1_AIRBORNE;
    player->flags1 = flags1;

    // Integrate the vertical-velocity accumulator (fallVelocity).
    if (groundDist <= 12.0f)
    {
        // The sign test uses the sum before it is rounded into fallVelocity.
        long double fallVelocity = (1.0f - (12.0f - groundDist) / (12.0f - hoverDelta)) * swrRace_deltaTimeSecs + player->fallVelocity;
        player->fallVelocity = fallVelocity;
        if (hoverDelta < groundDist && fallVelocity < 0.0f)
            player->fallVelocity = stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs) * player->fallVelocity;
    }
    else if (player->speedValue < 0.0f)
    {
        player->fallVelocity = player->fallVelocity - swrRace_deltaTimeSecs * -2.0;
    }
    else
    {
        player->fallVelocity = swrRace_deltaTimeSecs + player->fallVelocity;
    }

    // fallStep = dt * gravityScale * fallVelocity * 30. Negative pitch scales the fall step DOWN by
    // (1 + 0.9*pitch), i.e. reduces the descent (glide) -- this is a reduction, not a boost.
    float fallStep = swrRace_deltaTimeSecs * player->gravityScale * player->fallVelocity * 30.0f;
    player->fallStep = fallStep;
    if (player->pitch < 0.0f && 0.0f <= player->speedValue && 0.0f < fallStep)
        player->fallStep = (player->pitch * (float)0.9f + 1.0f) * fallStep;

    // Clamp the fall to the ground; on a hard landing dispatch the "HitBotm" event.
    if (player->fallStep <= groundDist)
    {
        player->flags0 &= ~swrObjTest_FLAG0_HIT_BOTTOM;
    }
    else
    {
        // Retail spills the impact rate but keeps bounceMag on the FPU stack.
        float impactRate = player->fallStep / swrRace_deltaTimeSecs;
        long double bounceMag = player->fallVelocity * 8.0f;
        player->fallStep = groundDist;
        if (0.0f < player->fallVelocity)
            player->fallVelocity = -(player->fallVelocity * (float)0.2f);
        if (4.0f < bounceMag && (player->flags0 & swrObjTest_FLAG0_HIT_BOTTOM) == 0)
        {
            int subEvents[3];
            subEvents[0] = 0x48697474; // 'Hitt'
            subEvents[1] = 0x426f746d; // 'Botm'
            *(float*)&subEvents[2] = impactRate * 0.5f;
            swrEvent_DispatchSubEvents(player, subEvents);
        }
        player->flags0 |= swrObjTest_FLAG0_HIT_BOTTOM;
    }

    // Apply the fall along the down direction.
    a[0] += player->fallStep * gx;
    a[1] += player->fallStep * gy;
    a[2] += player->fallStep * gz;
}

// Normal-mode slope steering (no magnet). Projects world gravity (world_gravity) onto the surface plane
// to accumulate the downhill slide into velocitySlope (force quadratic in the steer term), and drives
// autoTilt (auto-tilt) from the downhill/facing alignment. Also publishes the slope angle to
// swrRace_slopeAngle. Bails near-flat / near-inverted surfaces (dot(normal, worldDown) outside
// [-0.995, 0.995]); out1 is scratch for the gradient, out2 the integrated slide.
// 0x004791d0
RETAIL_FP void swrRace_ApplySlopeSteering(swrRace* player, int velocity, int scrapeData, float groundDist,
                                          rdVector3* normal, rdVector3* out1, rdVector3* out2)
{
    rdVector3 downhillAxis;
    rdVector3 slopeForce;
    rdVector3 surfDir;
    rdVector3 vbFlat;

    // stays in ST0 in retail, compared against double constants
    long double dotND = (normal->x * player->world_gravity.x + normal->y * player->world_gravity.y) +
                        normal->z * player->world_gravity.z;
    if (!(dotND >= (double)-0.995) || ((double)0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, (float)0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->autoTilt = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->world_gravity);
    rdVector_Cross3(out1, normal, &downhillAxis);
    rdVector_Normalize3Acc(out1);// out1 = normalized downhill gradient on the surface
    float slopeSin = (out1->x * player->world_gravity.x + out1->y * player->world_gravity.y) +
                     out1->z * player->world_gravity.z;
    swrRace_slopeAngle = stdMath_ArcSin(slopeSin);

    float steerMag;
    if (!(groundDist > 50.0f))
        steerMag = (1.0f - groundDist * 0.02f) * slopeSin;
    else
        steerMag = 0.0;

    float force = steerMag * steerMag * 400.0f;
    rdVector_Scale3(&slopeForce, -force, out1);
    rdVector_Scale3Add3(out2, &player->velocitySlope, swrRace_deltaTimeSecs + swrRace_deltaTimeSecs,
                        &slopeForce);
    float outLen = rdVector_Len3(out2);
    float absLen = (outLen < 0.0) ? -outLen : outLen;
    float absForce = (force < 0.0) ? -force : force;
    if (absForce < absLen) {
        float scale = force / outLen;
        if (scale < 0.0)
            scale = -scale;
        rdVector_Scale3(out2, scale, out2);
    }
    rdVector_Copy3(&player->velocitySlope, out2);

    surfDir.x = out1->x;
    surfDir.y = out1->y;
    surfDir.z = 0.0;
    vbFlat.x = player->transform.vB.x;
    vbFlat.y = player->transform.vB.y;
    vbFlat.z = 0.0;
    float surfLen = rdVector_Normalize3Acc(&surfDir);
    if (surfLen < (float)0.01f) {
        surfDir.x = -normal->x;
        surfDir.y = -normal->y;
        surfDir.z = -normal->z;
    }
    rdVector_Normalize3Acc(&vbFlat);
    // align / tiltScale / t stay in registers in retail
    long double align = (surfDir.x * vbFlat.x + surfDir.y * vbFlat.y) + surfDir.z * vbFlat.z;
    long double tiltScale = 0.0;
    if (0.0 <= align) {
        if (0.70700002f < align)
            align = (1.0f - align) * 2.5445292f * 0.70700002f;
        tiltScale = ((surfDir.z * out1->z + surfDir.y * out1->y) + surfDir.x * out1->x) * align;
        if (0.0 <= surfDir.y * vbFlat.x - surfDir.x * vbFlat.y)
            tiltScale = tiltScale * -2.0f;
        else
            tiltScale = tiltScale + tiltScale;
    }

    long double t = steerMag + 0.15f;
    if (!(t >= 0.0)) {
        t = t * 1.1764705f;
        player->autoTilt = t * t * tiltScale * 600.0f;
        return;
    }
    player->autoTilt = 0.0;
}

// Magnet-mode slope steering (flags1 0x400): keeps the pod glued to a tagged surface. Same gravity-on-
// surface velocitySlope build as the normal version but with a much stronger, speed-tiered steer term,
// and the auto-tilt (autoTilt) aligns the pod's facing to the downhill direction. Same near-flat /
// near-inverted bail. NOTE: the [-0.995, 0.995] gate + the speed tiers are the limits a "banking magnet"
// corkscrew mode would relax. velocity/scrapeData/groundDist are unused here (kept for signature parity).
// 0x00479550
RETAIL_FP void swrRace_ApplySlopeSteeringMagnet(swrRace* player, int velocity, int scrapeData, float groundDist,
                                      rdVector3* normal, rdVector3* out1, rdVector3* out2)
{
    rdVector3 downhillAxis;
    rdVector3 slopeForce;
    rdVector3 surfDir;
    rdVector3 vbFlat;

    float dotND = normal->x * player->world_gravity.x + normal->y * player->world_gravity.y +
                  normal->z * player->world_gravity.z;
    if ((dotND < -0.995) || (0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, 0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->autoTilt = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->world_gravity);
    rdVector_Normalize3Acc(&downhillAxis);
    rdVector_Cross3(out1, normal, &downhillAxis);// out1 = downhill gradient on the surface
    float slopeSin = out1->x * player->world_gravity.x + out1->y * player->world_gravity.y +
                     out1->z * player->world_gravity.z;
    long double slopeAngle = stdMath_ArcSin(slopeSin);
    float steerMag = slopeAngle * (float)-1.1111112f;

    if (200.0f <= player->speedValue) {
        if (250.0f <= player->speedValue) {
            if (300.0f <= player->speedValue) {
                if (350.0f <= player->speedValue)
                    steerMag = (steerMag - 80.0f) * 5.0f;
                else
                    steerMag = (steerMag - 60.0f) * 2.5f;
            } else {
                steerMag = (steerMag - 40.0f) * (float)1.6666666f;
            }
        } else {
            steerMag = (steerMag - 25.0f) * (float)1.3333334f;
        }
    }
    if (steerMag < 0.0)
        steerMag = 0.0;
    if (87.0f < slopeAngle)
        steerMag = steerMag + steerMag;

    rdVector_Scale3(&slopeForce, -steerMag, out1);
    rdVector_Scale3Add3(out2, &player->velocitySlope, swrRace_deltaTimeSecs + swrRace_deltaTimeSecs,
                        &slopeForce);
    float outLen = rdVector_Len3(out2);
    float absLen = (outLen < 0.0) ? -outLen : outLen;
    float absSteer = (steerMag < 0.0) ? -steerMag : steerMag;
    if (absSteer < absLen) {
        float scale = steerMag / outLen;
        if (scale < 0.0)
            scale = -scale;
        rdVector_Scale3(out2, scale, out2);
    }
    rdVector_Copy3(&player->velocitySlope, out2);

    surfDir.x = out1->x;
    surfDir.y = out1->y;
    surfDir.z = 0.0;
    vbFlat.x = player->transform.vB.x;
    vbFlat.y = player->transform.vB.y;
    vbFlat.z = 0.0;
    float surfLen = rdVector_Normalize3Acc(&surfDir);
    if (surfLen < 0.01f) {
        surfDir.x = -normal->x;
        surfDir.y = -normal->y;
        surfDir.z = -normal->z;
    }
    rdVector_Normalize3Acc(&vbFlat);
    float align = surfDir.x * vbFlat.x + surfDir.y * vbFlat.y + surfDir.z * vbFlat.z;
    if (0.0 <= align) {
        long double a = stdMath_ArcSin(align);
        float side = vbFlat.x * downhillAxis.x + vbFlat.y * downhillAxis.y + vbFlat.z * downhillAxis.z;
        if (side <= 0.0)
            player->autoTilt = -(a * slopeSin);
        else
            player->autoTilt = -(-a * slopeSin);
    } else {
        player->autoTilt = 0.0;
    }
}

// Casts a ray "down" (world world_gravity, or -up in magnet mode, started 2 units up) to find the
// ground. Tries the fast mesh ray (CollideRayWithMesh) then the full query (InitUnk); in magnet mode,
// retries once straight down (world gravity) if the surface-relative cast missed. Writes the surface
// normal to outSurfaceNormal (world-up on a miss) and the hit node to player->terrainModel. Returns the ground
// distance minus a 2-unit skin, or a large value (100000) when nothing was hit.
// 0x004772f0
float swrRace_RaycastGround(swrRace* player, rdVector3* pos, int* outSurfaceNormal)
{
    rdVector3 down;
    rdVector3 origin;
    rdVector3 outPoint;
    rdVector3 outNormal;
    float ray[7];
    float hitDist;

    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0) {
        down = player->world_gravity;
    } else {
        down.x = -player->up.x;
        down.y = -player->up.y;
        down.z = -player->up.z;
    }
    rdVector_Scale3Add3(&origin, pos, -2.0f, &down);
    ray[0] = origin.x;
    ray[1] = origin.y;
    ray[2] = origin.z;
    ray[3] = down.x;
    ray[4] = down.y;
    ray[5] = down.z;
    ray[6] = 10000.0f;

    swrRace_ResetCollisionHit();
    if ((player->flags1 & swrObjTest_FLAG1_FULL_RAYCAST) == 0)
        hitDist = swrModel_CollideRayWithMesh(player->splineTrackMesh, ray,
                                              (float*) &outPoint, (float*) &outNormal);
    else
        hitDist = -1.0f;

    if (hitDist < 0.0)
        hitDist = swrRace_RaycastModel(player->collisionModel, ray, &outPoint, &outNormal);

    if (((player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) && (hitDist < 0.0)) {
        // surface-relative cast missed: retry straight down (world gravity)
        ray[3] = player->world_gravity.x;
        ray[4] = player->world_gravity.y;
        ray[5] = player->world_gravity.z;
        hitDist = swrRace_RaycastModel(player->collisionModel, ray, &outPoint, &outNormal);
    }

    player->terrainModel = swrRace_GetCollisionHit();

    if (hitDist < 0.0) {
        ((float*) outSurfaceNormal)[0] = 0.0;
        ((float*) outSurfaceNormal)[1] = 0.0;
        ((float*) outSurfaceNormal)[2] = 1.0;
        player->groundZ = -10000.0f;
        return 100000.0f;
    }

    ((float*) outSurfaceNormal)[0] = outNormal.x;
    ((float*) outSurfaceNormal)[1] = outNormal.y;
    ((float*) outSurfaceNormal)[2] = outNormal.z;
    player->groundZ = outPoint.z;
    return hitDist - 2.0f;
}

// Per-frame ground-contact orchestrator. Raycasts the ground (RaycastGround) to get the surface
// normal, stores it as the pod's "up" in up, runs slope steering (magnet variant when flags1
// 0x400 is set), applies gravity, then resolves track/wall collision and hover pads. Returns the
// ground distance (also cached in groundToPodMeasure). The `up.z < 0.05` floor below is THE limit a
// vertical/inverted "magnet" corkscrew would have to lift -- it stops the surface normal from ever
// pointing sideways-past-vertical or downward.
// 0x00479e10
float swrRace_UpdateGroundContact(swrRace* player, float* velocity, int scrapeData, rdVector3* up, int hoverPadState)
{
    rdVector3 prevPos;
    rdVector3 slopeOut1;
    rdVector3 slopeOut2;
    rdVector3 wallDelta;
    rdVector3 collideNormal;
    rdMatrix44 splineMat;
    float groundDist;

    prevPos.x = velocity[0];
    prevPos.y = velocity[1];
    prevPos.z = velocity[2];

    const float progress = ((float) player->lodDistance - 400.0f) * 0.0016666667f;
    if ((progress < 1.0f) || ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) || ((player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) {
        uint32_t flags1;
        if (((player->flags1 & swrObjTest_FLAG1_FLAT_CACHE) == 0) || ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) == 0)) {
            groundDist = swrRace_RaycastGround(player, (rdVector3*) velocity, (int*) up);
            flags1 = player->flags1;
            if ((flags1 & swrObjTest_FLAG1_ON_FLAT) == 0)
                flags1 = flags1 & ~swrObjTest_FLAG1_FLAT_CACHE;
            else
                flags1 = flags1 | swrObjTest_FLAG1_FLAT_CACHE;
        } else {
            groundDist = velocity[2] - player->groundZ;
            up->x = player->up.x;
            up->y = player->up.y;
            up->z = player->up.z;
            player->terrainModel = (swrModel_Node*)player->splineTrackMesh;
            flags1 = player->flags1 | swrObjTest_FLAG1_GROUND_CACHED;
        }
        player->flags1 = flags1;

        // surface-relative magnet mode: keep the "up" normal from tipping past ~horizontal/inverted
        if (((flags1 & swrObjTest_FLAG1_MAGNET) != 0) && (up->z < 0.05f)) {
            up->z = 0.05f;
            rdVector_Normalize3Acc(up);
        }
        player->up.x = up->x;
        player->up.y = up->y;
        player->up.z = up->z;

        if (((player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0) &&
            ((0.1f < player->throttle) || (0.1f < -player->throttle) ||
             ((player->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) == 0))) {
            if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0)
                swrRace_ApplySlopeSteering(player, (int) velocity, scrapeData, groundDist, up, &slopeOut1,
                                           &slopeOut2);
            else
                swrRace_ApplySlopeSteeringMagnet(player, (int) velocity, scrapeData, groundDist, up,
                                                 &slopeOut1, &slopeOut2);
        }

        if ((player->flags0 & swrObjTest_FLAG0_ZOFF) == 0)
            swrRace_ApplyGravity(player, velocity, groundDist);

        if (groundDist < 0.0)
            groundDist = 2.0f;

        if ((((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) && ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0) &&
            (0.0f <= progress && progress <= 1.0f)) {
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
            velocity[2] = progress * (splineMat.vD.z - velocity[2]) + velocity[2];
        }

        if ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) == 0) {
            if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0) {
                swrRace_CollideBlockMove((rdVector3*) velocity, &prevPos, player->collisionModel, &collideNormal);
            } else {
                rdVector3 before;
                before.x = velocity[0];
                before.y = velocity[1];
                before.z = velocity[2];
                swrRace_DetectWallScrape(player, velocity, (float*) scrapeData);
                wallDelta.x = player->wallPushback.x + (velocity[0] - before.x);
                wallDelta.y = player->wallPushback.y + (velocity[1] - before.y);
                wallDelta.z = player->wallPushback.z + (velocity[2] - before.z);
                swrRace_ApplyWallCollision(player, &wallDelta, up);
            }
        }

        if (1.0f <= ((float) player->lodDistance - 40.0f) * 0.016666668f) {
            // no fresh hover-pad data: mark all four pads "no ground"
            rdMatrix44* pad = &player->shadowXf0;
            for (int i = 0; i < 4; i++)
                pad[i].vD.z = -100000.0f;
        } else {
            groundDist = swrRace_UpdateHoverPads(player, (rdVector3*) velocity, *(int*) (hoverPadState + 8),
                                                 groundDist, &up->x);
        }
    } else {
        player->terrainModel = (swrModel_Node*)player->splineTrackMesh;
        player->flags1 = player->flags1 | swrObjTest_FLAG1_GROUND_CACHED;
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) {
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
            velocity[2] = splineMat.vD.z;
        }
        groundDist = 2.0f;
        up->x = 0.0;
        up->y = 0.0;
        up->z = 1.0;
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING)
            player->flags1 = player->flags1 | swrObjTest_FLAG1_SPLINE_SNAP;
    }

    player->groundToPodMeasure = groundDist;
    return groundDist;
}

// Boost charge state machine on boostIndicatorStatus: 0 idle, 1 charging, 2 ready. Throttle
// plus stick forward arms and charges it; holding that for a second makes it ready, and the
// boost input then fires it. Returns 1 on the tick the boost fires.
// 0x0046bd20
RETAIL_FP int swrRace_BoostCharge(int player)
{
    swrRace* p = (swrRace*)player;
    int boostPressed = (int)swrRace_BoostInput;

    if ((p->flags0 & swrObjTest_FLAG0_CAN_CHARGE_BOOST) == 0 || (p->flags0 & swrObjTest_FLAG0_BOOSTING) != 0) {
        p->flags0 &= ~swrObjTest_FLAG0_BOOST_OVERDRIVE;
        p->boostIndicatorStatus = 0;
        return 0;
    }

    bool throttleHeld = swrRace_ThrustInput != 0.0f || swrRace_ThrottleInput > (double)SWR_CTL_BOOST_THROTTLE;
    bool stickForward = swrRace_PitchInput > (float)SWR_CTL_BOOST_PITCH;

    switch (p->boostIndicatorStatus) {
    case 0:
        if (throttleHeld && stickForward) {
            p->boostIndicatorStatus = 1;
            p->boostChargeTimer = 0.0f;
        }
        return 0;
    case 1:
        if (throttleHeld && stickForward) {
            // Retail compares the sum before rounding it into boostChargeTimer.
            long double charge = p->boostChargeTimer + swrRace_deltaTimeSecs;
            p->boostChargeTimer = charge;
            if (charge > SWR_CTL_ONE) {
                p->boostIndicatorStatus = 2;
            }
            return 0;
        }
        break;
    case 2:
        if (swrRace_PitchInput >= (float)SWR_CTL_BOOST_PITCH) {
            if (boostPressed == 0) {
                return 0;
            }
            p->boostIndicatorStatus = 0;
            float pitch = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * (double)SWR_BOOST_SFX_PITCH_RANGE + (double)SWR_BOOST_SFX_PITCH_MIN;
            swrSound_PlaySpatialRange(0x72, 7, pitch, 1.0f, (rdVector3*)&p->transform.vD, 0, 1, 10.0f, 500.0f);
            return 1;
        }
        break;
    }
    p->boostIndicatorStatus = 0;
    return 0;
}

// Extracts the pitch (out->y, measured from horizontal) and signed roll/bank (out->z) of a
// forward/right basis relative to a reference (down) vector. Angles are in degrees
// (stdMath_ArcCos). out->x is unused (0). Leaf used by swrRace_AlignToSurface.
// 0x00476390
RETAIL_FP void swrRace_ComputeTiltAngles(rdVector3* fwd, rdVector3* right, rdVector3* ref, rdVector3* out)
{
    rdVector3 refCrossFwd;
    rdVector3 rightCross;
    float len;
    float roll;

    // Dot products sum as (y + z) + x, and ArcCos is used unrounded.
    out->x = 0.0f;
    out->z = 0.0f;
    out->y = stdMath_ArcCosUnrounded((ref->y * fwd->y + ref->z * fwd->z) + fwd->x * ref->x) - 90.0f;

    rdVector_Cross3(&refCrossFwd, ref, fwd);
    rdVector_Cross3(&rightCross, right, &refCrossFwd);
    len = rdVector_Len3(&refCrossFwd);
    if (len <= (float)0.01f)
        return;

    roll = stdMath_ArcCosUnrounded(((refCrossFwd.x * right->x + right->y * refCrossFwd.y) + right->z * refCrossFwd.z) / len);
    if (0.0f < (rightCross.y * fwd->y + rightCross.z * fwd->z) + rightCross.x * fwd->x)
        out->z = -roll;
    else
        out->z = roll;
}

// Builds a surface-aligned basis (right = vB x up, fwd = up x right), measures the pod's
// heading/tilt error against it via swrRace_ComputeTiltAngles, and accumulates a correction into
// the turn input pRDot (->y heading, ->z tilt). In magnet mode (flags1 0x400) the surface-tilt
// alignment (out->z / bank) is clamped to +-85 deg. groundDist/hoverHi/hoverLo gate how strongly
// the correction applies as the pod nears the ground.
// 0x004764e0
RETAIL_FP void swrRace_AlignToSurface(swrRace* player, rdVector3* up, rdVector3* fwd_vB, rdVector3* vA_fallback,
                                      rdVector3* down_ref, float groundDist, float hoverHi, float hoverLo,
                                      rdVector3* pRDot)
{
    rdVector3 surfRight;
    rdVector3 surfFwd;
    rdVector3 angles;
    float len;

    rdVector_Cross3(&surfRight, fwd_vB, up);
    len = rdVector_Len3(&surfRight);
    if (0.01f < len)
        rdVector_Scale3(&surfRight, 1.0f / len, &surfRight);
    else
        surfRight = *vA_fallback;

    rdVector_Cross3(&surfFwd, up, &surfRight);
    len = rdVector_Len3(&surfFwd);
    if (0.01f < len)
        rdVector_Scale3(&surfFwd, 1.0f / len, &surfFwd);
    else
        surfFwd = *fwd_vB;

    swrRace_ComputeTiltAngles(&surfFwd, &surfRight, down_ref, &angles);

    // magnet mode: clamp the surface-tilt (bank) alignment to +-85 deg
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) {
        if (85.0f < angles.z)
            angles.z = 85.0f;
        if (angles.z < -85.0f)
            angles.z = -85.0f;
    }

    // both deltas stay in ST0/ST1 in retail until the final FSTPs
    long double headingDelta = angles.y - pRDot->y;
    long double tiltDelta = angles.z - pRDot->z;
    if (angles.y < pRDot->y)
        headingDelta = headingDelta * 0.33333334f;
    else if (pRDot->y < angles.y)
        headingDelta = headingDelta * 0.5f;
    tiltDelta = tiltDelta * 0.125f;

    if ((player->flags0 & swrObjTest_FLAG0_ZOFF) == 0) {
        // the <= 0 test reads the raw quotient, the rest reads its float copy
        long double blendRaw = (hoverHi - groundDist) / (hoverHi - hoverLo);
        float blend = blendRaw;
        if (blendRaw <= 0.0) {
            tiltDelta = pRDot->z * -0.125f;
            headingDelta = 0.0;
            if (-37.0f < pRDot->y)
                headingDelta = swrRace_deltaTimeSecs * -22.0f;
            if ((player->pitch < 0.0) && (pRDot->y < -10.0f))
                headingDelta = headingDelta - swrRace_deltaTimeSecs * player->pitch * 20.0f;
        } else if (blend < 1.0f) {
            headingDelta = headingDelta * blend;
            tiltDelta = tiltDelta * blend;
        }
    }

    pRDot->y = headingDelta + pRDot->y;
    pRDot->z = tiltDelta + pRDot->z;
}

// Walk a model-node tree gathering up to 10 distinct mesh-group entries (deduped by
// their data pointer) into the swrRace_meshNodeCollection scratch list.
// 0x0046d4c0
void swrRace_ResetModelNodeFlags(swrRace* player)
{
    if (player->partNodes == NULL)
        return;
    swrRace_nodeFlagsResetLatch = 0;
    for (int i = 0; i < SWR_POD_PART_NODE_COUNT; i++) {
        if (player->partNodes[i] != NULL)
            swrModel_NodeModifyFlags(player->partNodes[i], 2, 3, 0x10, 2);
    }
    if (player->partNodes[SWR_POD_PART_SHADOW_FIRST] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[SWR_POD_PART_SHADOW_FIRST], 2, -4, 0x10, 3);
    for (int i = SWR_POD_PART_SHADOW_FIRST + 1; i <= SWR_POD_PART_SHADOW_LAST; i++) {
        if (player->partNodes[i] != NULL)
            swrModel_NodeModifyFlags(player->partNodes[i], 2, 3, 0x10, 2);
    }
    // parts 0x10, 0xe, 0xf (in this order) are hidden; their roles are unidentified
    if (player->partNodes[0x10] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[0x10], 2, -4, 0x10, 3);
    if (player->partNodes[0xe] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[0xe], 2, -4, 0x10, 3);
    if (player->partNodes[0xf] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[0xf], 2, -4, 0x10, 3);
}

// 0x0046e750
void swrRace_CollectMeshNodes(swrModel_Node* node)
{
    if (swrRace_meshNodeCount >= 10 || node == NULL) {
        return;
    }
    if (swrModel_NodeGetFlags(node) == NODE_MESH_GROUP) {
        for (int i = 0; i < (int) node->num_children && swrRace_meshNodeCount < 10; i++) {
            swrModel_NodeType mesh = node->children.nodes[i]->type;
            if (mesh != 0 && *(int*) ((char*) mesh + 8) != 0) {
                bool dup = false;
                for (int j = 0; j < swrRace_meshNodeCount && !dup; j++) {
                    if (*(int*) ((char*) swrRace_meshNodeCollection[j] + 8) == *(int*) ((char*) mesh + 8)) {
                        dup = true;
                    }
                }
                if (!dup) {
                    swrRace_meshNodeCollection[swrRace_meshNodeCount] = mesh;
                    swrRace_meshNodeCount++;
                }
            }
        }
    } else if ((swrModel_NodeGetFlags(node) & NODE_HAS_CHILDREN) != 0) {
        for (int i = 0; i < (int) swrModel_NodeGetNumChildren(node); i++) {
            swrRace_CollectMeshNodes(node->children.nodes[i]);
        }
    }
}

// Recursively re-skin a node tree's mesh-group children by round-robining through the
// collected mesh list (up to 5 assignments).
// 0x0046e850
void swrRace_AssignRandomMeshNodes(swrModel_Node* node)
{
    if (swrRace_meshNodeAssignCount >= 5 || node == NULL) {
        return;
    }
    if (swrModel_NodeGetFlags(node) == NODE_MESH_GROUP) {
        for (int i = 0; i < (int) node->num_children; i++) {
            if (node->children.nodes[i]->type != 0) {
                swrRace_meshNodeRoundRobin = (swrRace_meshNodeRoundRobin + 1) % swrRace_meshNodeCount;
                node->children.nodes[i]->type = swrRace_meshNodeCollection[swrRace_meshNodeRoundRobin];
                swrRace_meshNodeAssignCount++;
            }
        }
    } else if ((swrModel_NodeGetFlags(node) & NODE_HAS_CHILDREN) != 0) {
        for (int i = 0; i < (int) swrModel_NodeGetNumChildren(node); i++) {
            swrRace_AssignRandomMeshNodes(node->children.nodes[i]);
        }
    }
}

// Collect the source pod's mesh-group nodes, then randomly reassign the destination
// (fireball) node's meshes from that pool, giving each engine-blowout a varied look.
// 0x0046e910
void swrRace_RandomizeMeshNodes(swrModel_Node* dst, swrModel_Node* src)
{
    swrRace_meshNodeCount = 0;
    swrRace_meshNodeAssignCount = 0;
    swrRace_CollectMeshNodes(src);
    if (0 < swrRace_meshNodeCount) {
        swrRace_AssignRandomMeshNodes(dst);
    }
}

// Spawn the engine-blowout fireball: re-skin the shared fireball node from the pod's
// meshes and place it at the given engine with a random orientation and scale. Gated on
// a free fx-animation slot (swrModel_AnyFxAnimDone).
// 0x0046ebf0
void swrRace_UpdateEngineFireballNode(int player)
{
    swrRace* racer = (swrRace*)player;
    rdMatrix44 m;

    if (fireballNodePtr == NULL || fx_podasx_anim == NULL)
        return;
    if (swrModel_AnyFxAnimDone(fx_podasx_anim) != 0) {
        // burnt out: hide the fireball and park it far below the track
        if (fireballNodePtr != NULL)
            swrModel_NodeModifyFlags(fireballNodePtr, 2, -4, 0x10, 3);
        racer->fireballEngineSlot = -1;
        swrRace_fireballTransform.vD.z = -50000.0f;
        return;
    }
    rdMatrix_Copy44(&m, &swrRace_fireballTransform);
    if (racer->fireballEngineSlot >= 0)
        rdVector_Copy3((rdVector3*)&m.vD, (rdVector3*)&(&racer->unk350_mat)[racer->fireballEngineSlot].vD);
    rdMatrix_Copy44(&swrRace_fireballTransform, &m);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)fireballNodePtr, &m);
    if (fireballNodePtr != NULL)
        swrModel_NodeModifyFlags(fireballNodePtr, 2, 3, 0x10, 2);
}

// 0x0046e950
void swrRace_SpawnEngineFireball(swrRace* player, int engineSlot, rdVector3* pos, float scale)
{
    if (fireballNodePtr == NULL || fx_podasx_anim == NULL || swrModel_AnyFxAnimDone(fx_podasx_anim) == 0) {
        return;
    }

    int subEvent[4];
    subEvent[0] = 0x42697473; // 'Bits'
    swrEvent_CallF4(0x54657374, subEvent); // 'Test'
    player->fireballEngineSlot = engineSlot;

    // Build a random orientation+scale basis for the fireball node.
    rdMatrix44 m;
    rdMatrix_SetIdentity44(&m);
    for (int k = 0; k < 3; k++) {
        float a = (float) swrUtils_Rand() * 4.6566129e-10f * 0.99f + 0.01f;
        if ((swrUtils_Rand() & 1) != 0) {
            a = -a;
        }
        (&m.vA.x)[k] = a;
        float b = (float) swrUtils_Rand() * 4.6566129e-10f * 0.99f + 0.01f;
        if ((swrUtils_Rand() & 1) != 0) {
            b = -b;
        }
        (&m.vB.x)[k] = b;
    }
    rdVector_Cross3((rdVector3*) &m.vC, (rdVector3*) &m.vA, (rdVector3*) &m.vB);
    rdVector_Cross3((rdVector3*) &m.vB, (rdVector3*) &m.vC, (rdVector3*) &m.vA);
    rdVector_Normalize3Acc((rdVector3*) &m.vA);
    rdVector_Normalize3Acc((rdVector3*) &m.vB);
    rdVector_Normalize3Acc((rdVector3*) &m.vC);
    float spread = scale * 1.5f - scale;
    rdVector_Scale3((rdVector3*) &m.vA, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vA);
    rdVector_Scale3((rdVector3*) &m.vB, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vB);
    rdVector_Scale3((rdVector3*) &m.vC, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vC);

    swrModel_AnimationsResetToZero(fx_podasx_anim);
    swrModel_AnimationsResetToZero2(fx_podasx_anim, 3.0f);

    // When a valid engine slot is set, position the fireball at that engine's matrix;
    // otherwise use the caller-supplied point.
    if (player->fireballEngineSlot >= 0) {
        pos = (rdVector3*) ((char*) player + (player->fireballEngineSlot + 0xe) * 0x40);
    }
    rdVector_Copy3((rdVector3*) &m.vD, pos);

    swrModel_Node* src =
        (player->partNodes == NULL) ? player->lodBodyNode : player->partNodes[1];
    swrRace_RandomizeMeshNodes(fireballNodePtr, src);
    rdMatrix_Copy44(&swrRace_fireballTransform, &m);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*) fireballNodePtr, &m);
    swrModel_NodeModifyFlags(fireballNodePtr, 2, 3, 0x10, 2);
}

// One exhaust plume: flicker scale, spin with race time, fade out when small. Pilots 4, 6 and 16
// get a fixed-size plume with random alpha; 8 and 10 don't spin.
static void updateExhaustPlume(swrRace* player, swrModel_NodeTransformed* node, int saveSlot, int pilot, float size)
{
    rdMatrix44 m;
    float scale;
    float angle;
    float alphaScale;

    scale = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.20000005f - -1.0f;
    swrUtils_Rand();
    alphaScale = 1.0f;
    angle = (float)(timetotal * 30.0f);
    if (size < 0.25f) {
        scale = size * scale;
        if (player == NULL) {
            alphaScale = size;
        }
    }
    switch (pilot) {
    case 4:
    case 6:
    case 0x10:
        scale = 1.0f;
        angle = 0.0f;
        alphaScale = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.100000024f - -0.9f;
        break;
    case 8:
    case 10:
        angle = 0.0f;
        break;
    }
    rdMatrix_SetRotation44(&m, 0.0f, 0.0f, angle);
    rdVector_Scale3((rdVector3*)&m.vA, scale, (rdVector3*)&m.vA);
    rdVector_Scale3((rdVector3*)&m.vC, scale, (rdVector3*)&m.vC);
    if (player != NULL) {
        rdMatrix_Copy44(&(&player->unk350_mat)[saveSlot], &m);
    }
    swrModel_NodeSetTransform(node, &m);
    swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    swrModel_NodeSetColorsOnAllMaterials(&node->node, 0, 0, 0xff, 0xff, 0xff, (int)(alphaScale * 255.0f));
}

// One exhaust glow: stretched along the pod's forward axis by size, or a random burst while boosting.
static void updateExhaustGlow(swrRace* player, swrModel_NodeTransformed* node, int saveSlot, int boosting, float size)
{
    rdMatrix44 m;
    swrModel_MeshMaterial* material;
    float flicker;
    float scale;

    material = swrModel_NodeFindFirstMeshMaterial(&node->node);
    swrUtils_Rand();
    flicker = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.25f - -1.0f;
    swrUtils_Rand();
    scale = size * flicker;
    if (boosting) {
        scale = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.6999998f - -3.5f;
    }
    swrUtils_Rand();
    rdMatrix_SetRotation44(&m, 0.0f, 0.0f, 0.0f);
    rdVector_Scale3((rdVector3*)&m.vB, scale, (rdVector3*)&m.vB);
    if (player != NULL) {
        rdMatrix_Copy44(&(&player->unk350_mat)[saveSlot], &m);
    }
    swrModel_NodeSetTransform(node, &m);
    swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    if (material != NULL) {
        swrModel_MeshMaterialSetColors(material, 0, 0, 0xff, 0xff, 0xff, 0xff);
        swrModel_MeshMaterialSetTextureUVOffset(material, 0.11f, 0.0f);
    }
}

// player == NULL drives a display pod (hangar/shop) from partNodes, whose slot 0x3c holds the pilot id.
// 0x0046f2c0
void swrRace_UpdateEngineExhaust(swrRace* player, swrModel_Node** partNodes, float sizeLeft, float sizeRight)
{
    int pilot;
    int boosting;
    int damagedLeft;
    int damagedRight;
    float throttleLeft;
    float throttleRight;
    float left;
    float right;
    int i;

    damagedLeft = 0;
    damagedRight = 0;
    boosting = 0;
    if (player == NULL) {
        pilot = *(int*)&partNodes[0x3c];
    } else {
        partNodes = player->partNodes;
        if (partNodes == NULL) {
            return;
        }
        pilot = *player->score_ptr->pilotId;
        if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0 || (player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) {
            boosting = 1;
        }
        for (i = 0; i < 6; i++) {
            if ((player->engineStatus[i] & 4) != 0) {
                if (i < 3) {
                    damagedLeft = 1;
                } else {
                    damagedRight = 1;
                }
            }
        }
    }

    left = 0.0f;
    right = 0.0f;
    if (sizeLeft >= 0.0f) {
        left = sizeLeft;
    }
    if (sizeRight >= 0.0f) {
        right = sizeRight;
    }
    if ((swrRace_DebugFlag & 0x100) != 0 && swrRace_DebugLevel != 0 && (inRaceLocalPlayerInputBitset3[1] & 0x1000) != 0) {
        left = 1.0f;
        right = 1.0f;
        boosting = 0;
    }

    if (player != NULL) {
        throttleLeft = player->throttle;
        throttleRight = player->throttle;
        if ((player->flags1 & swrObjTest_FLAG1_SLIDING) != 0) {
            throttleLeft = throttleLeft * 0.5f;
            throttleRight = throttleRight * 0.5f;
        }
        if (damagedLeft) {
            throttleLeft = throttleLeft * 0.2f;
        }
        if (damagedRight) {
            throttleRight = throttleRight * 0.2f;
        }
        left = (throttleLeft + player->exhaustSizeLeft) * 0.5f;
        right = (throttleRight + player->exhaustSizeRight) * 0.5f;
        player->exhaustSizeLeft = left;
        player->exhaustSizeRight = right;
    }

    // saveSlot indexes the per-part transforms at unk350_mat, aligned with partNodes
    if (partNodes[0x1c] != NULL) {
        updateExhaustPlume(player, (swrModel_NodeTransformed*)partNodes[0x1c], 0x1c, pilot, left);
    }
    // faithful: the right plume is saved into the left plume's slot (0x1c), not 0x2a
    if (partNodes[0x2a] != NULL) {
        updateExhaustPlume(player, (swrModel_NodeTransformed*)partNodes[0x2a], 0x1c, pilot, right);
    }
    if (partNodes[0x1d] != NULL) {
        updateExhaustGlow(player, (swrModel_NodeTransformed*)partNodes[0x1d], 0x1d, boosting, left);
    }
    if (partNodes[0x2b] != NULL) {
        updateExhaustGlow(player, (swrModel_NodeTransformed*)partNodes[0x2b], 0x2b, boosting, right);
    }
}

// 0x0046f9a0
void swrRace_UpdateEngineDamageFX(swrRace* player)
{
    int burning[2];
    int side;
    int i;
    int count;
    int engine;
    rdMatrix44* engineXf;
    rdMatrix44* src;
    float scale;
    rdVector3 pos;
    rdVector3 vel;
    rdVector3 probe;
    float nearDist[8];
    rdVector3 nearDelta[8];
    swrRace* nearPods[8];
    swrObjSmok* flame;
    swrRace* other;

    burning[0] = 0;
    burning[1] = 0;
    if (player->partNodes != NULL) {
        for (i = 0; i < 6; i++) {
            if (player->engineStatus[i] & swrRace_ENGINESTATUS_ON_FIRE)
                burning[i / 3] = 1;
        }
        for (side = 0; side < 2; side++) {
            if (!burning[side] && player->engineDamageSmoke[side] == NULL)
                continue;
            // side 0 -> engineXfL (partXf[2]), side 1 -> engineXfR (partXf[1])
            engineXf = &(&player->unk350_mat)[2 - side];
            pos.x = engineXf->vD.x;
            pos.y = engineXf->vD.y;
            pos.z = engineXf->vD.z;
            rdVector_Scale3Add3(&pos, &pos, -2.0f, (rdVector3*)&engineXf->vB);
            if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
                rdVector_Scale3Add3(&pos, &pos, side != 0 ? 2.0f : -2.0f, (rdVector3*)&engineXf->vA);
            rdVector_Scale3(&vel, -20.0f, (rdVector3*)&engineXf->vB);
            if (burning[side]) {
                if (player->engineDamageSmoke[side] == NULL) {
                    player->engineDamageSmoke[side] = swrObjSmok_Spawn(swrObjSmok_TYPE_ENGINE_SMOKE, 0, 1000.0f, &pos, 1.0f);
                    swrObjSmok_SetOwnerHandle(player->engineDamageSmoke[side], &player->engineDamageSmoke[side]);
                } else {
                    swrObjSmok_SetLifetime(player->engineDamageSmoke[side], 5.0f);
                }
            }
            if (player->engineDamageSmoke[side] != NULL) {
                swrObjSmok_SetPosition(player->engineDamageSmoke[side], &pos);
                swrObjSmok_SetVelocity(player->engineDamageSmoke[side], &vel);
            }
        }
        if ((player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_POD_HIDDEN)) || (player->flags1 & swrObjTest_FLAG1_EXPLODING)) {
            for (i = 0; i < 2; i++) {
                if (player->engineDamageSmoke[i] != NULL)
                    swrObjSmok_SetLifetime(player->engineDamageSmoke[i], 0.0f);
            }
        }
    }

    flame = player->flameSmokeHandle;
    if (flame == NULL || flame->type != swrObjSmok_TYPE_FLAME_ATTACK || !(flame->lifetime > 3.0f))
        return;

    if (player->partNodes != NULL) {
        src = &player->engineXfR;
        scale = 12.0f;
    } else {
        src = &player->transform;
        scale = 15.0f;
    }
    pos.x = src->vD.x;
    pos.y = src->vD.y;
    pos.z = src->vD.z;
    rdVector_Scale3Add3(&pos, &pos, 1.0f, (rdVector3*)&src->vB);
    rdVector_Scale3Add3(&pos, &pos, scale, (rdVector3*)&src->vA);
    rdVector_Scale3(&vel, 10.0f, (rdVector3*)&src->vA);
    swrObjSmok_SetPosition(flame, &pos);
    swrObjSmok_SetVelocity(flame, &vel);

    // sets a random engine on fire on each pod in the flame's path (rear bank when facing away)
    rdVector_Scale3Add3(&probe, &pos, 0.5f, &vel);
    count = swrEvent_FindNearestObjects('Test', &probe, 64.0f, NULL, 2, nearDist, nearDelta, (void**)nearPods);
    for (i = 0; i < count; i++) {
        other = nearPods[i];
        if (other == player)
            continue;
        if (other->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD))
            continue;
        if (other->flags1 & swrObjTest_FLAG1_FINISHED)
            continue;
        engine = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 3.0f);
        if (player->transform.vB.x * other->transform.vB.x + player->transform.vB.y * other->transform.vB.y + player->transform.vB.z * other->transform.vB.z < 0.0f)
            engine += 3;
        other->engineStatus[engine] |= swrRace_ENGINESTATUS_ON_FIRE;
    }

    if (((player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_POD_HIDDEN)) || (player->flags1 & swrObjTest_FLAG1_EXPLODING)) && player->flameSmokeHandle != NULL)
        swrObjSmok_SetLifetime(player->flameSmokeHandle, 0.0f);
}

// 0x0046fd60
void swrRace_SpawnGroundDustKick(swrRace* player, float* transform, float sx, float sy, float sz, float offset, int tossFlag)
{
    swrModel_Behavior* behavior;
    uint32_t reaction;
    int lava = 0;
    int soft = 0;
    int wet = 0;
    int ruff = 0;
    int swamp = 0;
    int mirr = 0;
    int snow = 0;
    int dust = 0;
    int playSplash = 0;
    int tossFlags = 0; // original leaves this uninitialized when tossFlag == 0
    rdMatrix44 m;
    float intensity;
    float r = 0.0f;
    float g = 0.0f;
    float b = 0.0f;
    float alphaBase = 0.0f;
    float alpha;
    int ri;
    int alphaI;
    int spawned;

    if (player == NULL)
        return;
    if (player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_ZON))
        return;
    if (player->slide > 0.5f)
        return;
    if (player->terrainModel != NULL) {
        behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)player->terrainModel);
        if (behavior != NULL) {
            if (behavior->unk1 & swrModel_BEHAVIOR_SURFACE_MAGNET)
                return;
            reaction = behavior->vehicle_reaction;
            lava = (reaction & swrVehicleReaction_Lava) != 0;
            if (reaction & swrVehicleReaction_Fall)
                return;
            soft = (reaction & swrVehicleReaction_Soft) != 0;
            wet = (reaction & swrVehicleReaction_Wet) != 0;
            ruff = (reaction & swrVehicleReaction_Ruff) != 0;
            swamp = (reaction & swrVehicleReaction_Swmp) != 0;
            mirr = (reaction & swrVehicleReaction_Mirr) != 0;
            snow = (reaction & swrVehicleReaction_Snow) != 0;
            dust = (reaction & swrVehicleReaction_Dust) != 0;
        }
    }
    if (tossFlag != 0)
        tossFlags |= 1;

    rdMatrix_SetIdentity44(&m);
    m.vD.x = transform[12];
    m.vD.y = transform[13];
    m.vD.z = transform[14];
    m.vB.x = transform[8];
    m.vB.y = transform[9];
    m.vB.z = transform[10];
    m.vA.x = transform[4];
    m.vA.y = transform[5];
    m.vA.z = transform[6];
    m.vC.x = transform[0];
    m.vC.y = transform[1];
    m.vC.z = transform[2];
    rdVector_Normalize3Acc((rdVector3*)&m.vA);
    rdVector_Normalize3Acc((rdVector3*)&m.vB);
    rdVector_Normalize3Acc((rdVector3*)&m.vC);

    intensity = (player->speedValue - 200.0f) * 0.005f;
    if (intensity <= 0.0f)
        return;
    if (intensity > 1.0f)
        intensity = 1.0f;

    switch (PlanetID) {
    case 0:
        if (dust || (!ruff && swamp)) {
            r = 200.0f;
            g = 170.0f;
            b = 120.0f;
            alphaBase = 255.0f;
        } else if (ruff) {
            r = 150.0f;
            g = 120.0f;
            b = 100.0f;
            alphaBase = 255.0f;
        } else {
            r = 182.0f;
            g = 164.0f;
            b = 136.0f;
            alphaBase = 200.0f;
        }
        break;
    case 1:
        r = 220.0f;
        g = 250.0f;
        b = 255.0f;
        if (snow)
            alphaBase = 255.0f;
        else if (dust)
            alphaBase = 150.0f;
        else if (mirr || soft)
            alphaBase = 0.0f;
        else
            alphaBase = 50.0f;
        break;
    case 2:
        if (wet) {
            r = 120.0f;
            g = 100.0f;
            b = 120.0f;
            alphaBase = 255.0f;
        } else if (dust) {
            r = 75.0f;
            g = 75.0f;
            b = 120.0f;
            alphaBase = 64.0f;
        } else {
            r = 120.0f;
            g = 100.0f;
            b = 120.0f;
            alphaBase = 16.0f;
        }
        break;
    case 4:
        if (dust) {
            r = 190.0f;
            g = 150.0f;
            b = 110.0f;
            alphaBase = 255.0f;
        } else if (ruff) {
            r = 175.0f;
            g = 135.0f;
            b = 85.0f;
            alphaBase = 255.0f;
        } else if (swamp) {
            r = 75.0f;
            g = 70.0f;
            b = 50.0f;
            alphaBase = 255.0f;
        } else if (wet) {
            r = 220.0f;
            g = 220.0f;
            b = 200.0f;
            alphaBase = 255.0f;
        } else if (lava) {
            r = 255.0f;
            g = 100.0f;
            b = 30.0f;
            alphaBase = 255.0f;
        } else {
            r = 110.0f;
            g = 90.0f;
            b = 80.0f;
            alphaBase = 50.0f;
        }
        break;
    case 5:
        r = 210.0f;
        g = 130.0f;
        b = 60.0f;
        if (dust)
            alphaBase = 200.0f;
        else
            alphaBase = ruff ? 255.0f : 16.0f;
        break;
    case 6:
        if (dust) {
            r = 186.0f;
            g = 179.0f;
            b = 170.0f;
            alphaBase = 150.0f;
        } else if (ruff) {
            r = 137.0f;
            g = 122.0f;
            b = 104.0f;
            alphaBase = 255.0f;
        } else {
            r = 203.0f;
            g = 203.0f;
            b = 204.0f;
            alphaBase = 75.0f;
        }
        break;
    case 7:
        if (wet) {
            r = 0.0f;
            g = 255.0f;
            b = 0.0f;
            alphaBase = 255.0f;
        } else {
            r = 150.0f;
            g = 150.0f;
            b = 230.0f;
            alphaBase = ruff ? 255.0f : 128.0f;
        }
        break;
    }

    if (!(m.vB.z > 0.8f))
        return;
    if (wet) {
        offset = 0.0f;
        playSplash = 1;
    }
    rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, -offset, (rdVector3*)&m.vA);
    alpha = alphaBase * intensity;
    m.vA.x *= sx;
    m.vA.y *= sx;
    m.vA.z *= sx;
    m.vB.x *= sy;
    m.vB.y *= sy;
    m.vB.z *= sy;
    m.vC.x *= sz;
    m.vC.y *= sz;
    m.vC.z *= sz;
    if (alpha < 1.0f)
        alpha = 1.0f;
    else if (alpha > 254.0f)
        alpha = 254.0f;
    if (swamp)
        playSplash = 1;
    if (!(alpha > 0.0f))
        return;

    alphaI = (int)alpha;
    ri = (int)r;
    spawned = swrRace_SpawnDustKickObject(&m, (uint8_t)ri, (uint8_t)(int)g, (uint8_t)(int)b, alphaI, 0.2f, tossFlags);
    // a faint puff returns without setting EAX, so the original sees the leftover red value
    if (alphaI <= 15)
        spawned = ri;
    if (spawned && playSplash)
        swrSound_Play2D(0x45, 7, intensity * 0.1f * 0.25f, 1.0f, 1);
}

// 0x00472750
RETAIL_FP void swrRace_UpdateEnergyBinder(swrRace* player, int side, rdVector3* pointA, rdVector3* pointB)
{
    int beam;
    int scale;
    long double t;
    float alpha;
    float width;
    float len;
    rdVector3 dir;
    rdVector3 perp;
    rdMatrix44 m;

    if (player->partNodes == NULL)
        return;
    if (side == 1) {
        scale = 7;
        beam = 6;
    } else {
        scale = 9;
        beam = 8;
    }
    if ((player->flags0 & swrObjTest_FLAG0_STATE_MASK) == swrObjTest_FLAG0_RACING)
        swrRace_energyBinderTime = 1000.0f;

    t = swrRace_energyBinderTime - (float)player->obj.id * 0.1f; // stays in ST0 in retail
    if (t > 0.0f)
        t = t * t;
    if (t < 0.01) {
        if (player->partNodes[beam] != NULL)
            swrModel_NodeModifyFlags(player->partNodes[beam], 2, -4, 0x10, 3);
        rdMatrix_SetTranslation44(&(&player->unk350_mat)[beam], 0.0f, 0.0f, -100000.0f);
        rdMatrix_SetIdentity44(&(&player->unk350_mat)[scale]);
        return;
    }
    alpha = t * 8.0f;
    if (alpha > 1.0f)
        alpha = 1.0f;
    width = t * 0.1f;
    if (width > 1.0f)
        width = 1.0f;

    dir.x = pointA->x - pointB->x;
    dir.y = pointA->y - pointB->y;
    dir.z = pointA->z - pointB->z;
    len = rdVector_Len3(&dir);
    rdVector_Scale3(&dir, 1.0f / len, &dir);
    perp.x = dir.y;
    perp.y = -dir.x;
    perp.z = 0.0f;
    rdVector_Normalize3Acc(&perp);
    rdVector_Cross3((rdVector3*)&m.vA, &dir, &perp);
    rdVector_Copy3((rdVector3*)&m.vC, &dir);
    rdVector_Copy3((rdVector3*)&m.vB, &perp);
    m.vA.w = 0.0f;
    m.vB.w = 0.0f;
    m.vC.w = 0.0f;
    m.vD.w = 1.0f;
    rdVector_Scale3((rdVector3*)&m.vD, 0.5f, pointA);
    rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, 0.5f, pointB);
    rdMatrix_Copy44(&(&player->unk350_mat)[beam], &m);
    rdMatrix_SetDiagonal44(&m, width * 0.2f, width, alpha * len * 0.05f);
    rdMatrix_Copy44(&(&player->unk350_mat)[scale], &m);

    if (player->partNodes[beam] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[beam], 2, 3, 0x10, 2);
    if (player->partNodes[scale] != NULL)
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[scale], &(&player->unk350_mat)[scale]);
    if (player->partNodes[beam] != NULL)
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[beam], &(&player->unk350_mat)[beam]);
}

// 0x00477ad0
void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot)
{
    swrRace* player = (swrRace*) pEngine;
    float hoverHi = player->podStats.hoverHeight * 1.5f;
    float hoverLo = (player->podStats.intersectRadius + player->podStats.intersectRadius +
                     player->podStats.hoverHeight) *
                    0.33333334f;

    // Outside magnet mode, lift the standing tilt target out of pRDot->z before re-aligning.
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0)
        pRDot->z = pRDot->z - player->tiltAngleTarget;

    swrRace_AlignToSurface(player, (rdVector3*) pXformZ, (rdVector3*) &player->transform.vB,
                           (rdVector3*) &player->transform.vA, &player->world_gravity, ZMotion, hoverHi,
                           hoverLo, pRDot);

    // Magnet mode (flags1 0x400) suppresses ALL of the player banking + manual tilt below; only the
    // surface alignment from swrRace_AlignToSurface reaches the tilt axis.
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0) {
        pRDot->z = player->tiltAngleTarget + pRDot->z;

        // Bank-into-turn: ease tiltAngleTarget toward the turn-rate-driven lean (capped at 300 deg
        // on the ground / 70 deg airborne), then blend the change into pRDot->z.
        float prevTilt = player->tiltAngleTarget;
        float maxAngle = ((player->flags0 & swrObjTest_FLAG0_AI) == 0) ? 70.0f : 300.0f;
        swrRace_SetAngleFromTurnRate(&player->tiltAngleTarget, player->turnRate,
                                     *(void**) &player->turnRateTarget, player->podStats.maxTurnRate,
                                     maxAngle);
        pRDot->z = pRDot->z - (player->tiltAngleTarget - prevTilt) * 0.2f;

        // Manual tilt (player holding a lean) pulls pRDot->z toward tiltManualMult * 80 deg.
        if (player->tiltManualMult != 0.0) {
            float mag = player->tiltManualMult;
            if (mag < 0.0)
                mag = -mag;
            pRDot->z = (player->tiltManualMult * 80.0f - pRDot->z) * mag + pRDot->z;
        }
    }

    player->tiltAngle = pRDot->z;
}

// Per-frame orientation update: rotates the pod's transform basis (vA/vB/vC) by the accumulated turn
// input (turnInput->z about vB via a vector-angle matrix, ->y pitch about the horizontal surface axis,
// ->x roll about Z), then stores the new position into vD. Above a progress threshold (and outside
// debug/zero-g) it takes a cheap yaw-only path. Re-normalizes the basis every 8 frames to fight drift.
// NOTE: address corrected 0x00477c27 -> 0x00477c30 (the former was a bogus {return;} with no xrefs).
// 0x00477c30
RETAIL_FP void swrRace_UpdateTurn2(swrRace* player, rdVector3* pos, rdVector3* turnInput)
{
    rdMatrix44 m;
    float vAx = player->transform.vA.x;
    float vAy = player->transform.vA.y;
    float vAz = player->transform.vA.z;
    float vBx = player->transform.vB.x;
    float vBy = player->transform.vB.y;
    float vBz = player->transform.vB.z;
    float vCx = player->transform.vC.x;
    float vCy = player->transform.vC.y;
    float vCz = player->transform.vC.z;

    if (((player->lodDistance - 400.0f) * (float)0.0016666667f < 1.0) || ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) ||
        ((player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) {
        // full 3-axis update: build a horizontal axis (hx, hy) from vB (fall back to vC near-vertical)
        float hx = -vBx;
        float hy = vBy;
        float h = stdMath_Sqrt(hx * hx + vBy * vBy);
        if (h < (float)0.1f) {
            hx = -vCx;
            hy = vCy;
            h = stdMath_Sqrt(hx * hx + vCy * vCy);
        }
        hy = hy / h;
        hx = hx / h;

        rdMatrix_BuildFromVectorAngle44(&m, turnInput->z, vBx, vBy, vBz);

        // pitch rotation about the (hx, hy, 0) axis. Every product row sums as (x + y) + z;
        // r00 and c1r stay at register width, the other coefficients are spilled to float.
        float ps, pc;
        stdMath_SinCos(turnInput->y, &ps, &pc);
        float hx2 = hx * hx;
        long double r00 = hy * hy + pc * hx2;
        float r11 = pc * (hy * hy) + hx2;
        float r01 = (hx * hy) * (1.0f - pc);
        float r02 = hy * ps;
        float r12 = -(hx * ps);
        float r20 = -r12;
        float r21 = -r02;

        float a0 = (m.vA.x * r00 + m.vA.y * r01) + m.vA.z * r20;
        float a1 = (m.vA.x * r01 + m.vA.y * r11) + m.vA.z * r21;
        float a2 = (m.vA.x * r12 + m.vA.y * r02) + pc * m.vA.z;
        float b0 = (m.vB.x * r00 + m.vB.y * r01) + m.vB.z * r20;
        float b1 = (m.vB.x * r01 + m.vB.y * r11) + m.vB.z * r21;
        float b2 = (m.vB.x * r12 + m.vB.y * r02) + pc * m.vB.z;
        float c0 = (m.vC.x * r00 + m.vC.y * r01) + m.vC.z * r20;
        float c1 = (m.vC.x * r01 + m.vC.y * r11) + m.vC.z * r21;
        float c2 = (m.vC.x * r12 + m.vC.y * r02) + pc * m.vC.z;

        // roll rotation about Z
        float rs, rc;
        stdMath_SinCos(turnInput->x, &rs, &rc);
        float a0r = rc * a0 - rs * a1;
        float a1r = rc * a1 + rs * a0;
        float b0r = rc * b0 - rs * b1;
        float b1r = rc * b1 + rs * b0;
        float c0r = rc * c0 - rs * c1;
        long double c1r = rc * c1 + rs * c0;

        player->transform.vA.x = (vAx * a0r + vAy * b0r) + vAz * c0r;
        player->transform.vA.y = (vAx * a1r + vAy * b1r) + vAz * c1r;
        player->transform.vA.z = (vAx * a2 + vAy * b2) + vAz * c2;
        player->transform.vB.x = (vBx * a0r + vBy * b0r) + vBz * c0r;
        player->transform.vB.y = (vBx * a1r + vBy * b1r) + vBz * c1r;
        player->transform.vB.z = (vBx * a2 + vBy * b2) + vBz * c2;
        player->transform.vC.x = (vCx * a0r + vCy * b0r) + vCz * c0r;
        player->transform.vC.y = (vCx * a1r + vCy * b1r) + vCz * c1r;
        player->transform.vC.z = (vCx * a2 + vCy * b2) + vCz * c2;
    } else {
        // cheap yaw-only update (roll about Z by turnInput->x)
        float rs, rc;
        stdMath_SinCos(turnInput->x, &rs, &rc);
        player->transform.vA.x = rc * vAx - rs * vAy;
        player->transform.vA.y = rc * vAy + rs * vAx;
        player->transform.vB.x = rc * vBx - rs * vBy;
        player->transform.vB.y = rc * vBy + rs * vBx;
        player->transform.vA.z = vAz;
        player->transform.vC.x = rc * vCx - rs * vCy;
        player->transform.vB.z = vBz;
        player->transform.vC.z = vCz;
        player->transform.vC.y = rc * vCy + rs * vCx;
    }

    player->orthoRenormCounter = player->orthoRenormCounter - 1;
    if (player->orthoRenormCounter < 0) {
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vA);
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vB);
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vC);
        player->orthoRenormCounter = 8;
    }
    player->transform.vD.x = pos->x;
    player->transform.vD.y = pos->y;
    player->transform.vD.z = pos->z;
}

// 0x004783e0
RETAIL_FP long double swrRace_UpdateSpeed(swrRace* player)
{
    // Acceleration scale: 4.0 while boosting or in the boost-start window, otherwise 1.5.
    float accel = ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0 || (player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) ? 4.0f : 1.5f;

    // swrScore.flag bit 3 (e.g. AI/replay) skips the fast idle-decay path below.
    bool scoreFlag = (player->score_ptr->flag & 8) != 0;
    long double v;
    long double ceiling;
    long double speed;

    if (player->throttle <= 0.1f) {
        if (-0.1f <= player->throttle) {
            // Near-zero throttle: coast accelThrust down.
            if (scoreFlag || 0.2f <= player->accelThrust)
                player->accelThrust *= stdMath_Decelerator(player->podStats.deceleration_interval, swrRace_deltaTimeSecs);
            else
                player->accelThrust *= stdMath_Decelerator(10.0f, swrRace_deltaTimeSecs);
        } else {
            // Reverse throttle below -0.1: integrate, then brake hard on overshoot.
            v = swrRace_deltaTimeSecs * accel * player->throttle + player->accelThrust; // stays in ST0 in retail
            player->accelThrust = v;
            if (-0.6f < player->throttle && v < player->throttle * 0.5f)
                player->accelThrust *= stdMath_Decelerator(20.0f, swrRace_deltaTimeSecs);
        }
    } else {
        // Forward throttle above 0.1: integrate, then clamp via a throttle-dependent ceiling.
        v = swrRace_deltaTimeSecs * accel * player->throttle + player->accelThrust; // stays in ST0 in retail
        player->accelThrust = v;
        if (player->throttle < 0.99f)
            ceiling = player->throttle / (1.0L - player->throttle);
        else
            ceiling = 10000.0f;
        if (ceiling < v)
            player->accelThrust *= stdMath_Decelerator(player->podStats.deceleration_interval, swrRace_deltaTimeSecs);
    }

    // Air brake.
    if ((player->flags0 & swrObjTest_FLAG0_BRAKING) != 0)
        player->accelThrust *= stdMath_Decelerator(player->podStats.airBrakeInv, swrRace_deltaTimeSecs);

    // Map the integrated throttle to a speed via the pod's accel/maxSpeed curve.
    if (player->accelThrust <= 0.0f)
        speed = -((-player->accelThrust * player->podStats.maxSpeed) / (player->podStats.acceleration - player->accelThrust));
    else
        speed = (player->accelThrust * player->podStats.maxSpeed) / (player->podStats.acceleration + player->accelThrust);
    speed *= player->speedMultiplier;

    // Terrain drag, applied once the pod is close to the ground.
    if (15.0f <= player->groundToPodMeasure) {
        player->flags1 &= ~swrObjTest_FLAG1_GROUNDED;
    } else {
        uint32_t f = player->flags1;
        if ((f & swrObjTest_FLAG1_GROUNDED) == 0) {
            bool slow = player->surfaceSpeedFactor < 1.0f;
            player->flags1 = f | swrObjTest_FLAG1_GROUNDED;
            if (slow)
                player->flags1 = f | (swrObjTest_FLAG1_GROUNDED | swrObjTest_FLAG1_IMMUNITY);
        }
        speed *= player->surfaceSpeedFactor;
    }
    speed += player->surfaceSpeedBonus;

    // Minimum-speed floor on certain surfaces.
    if ((player->flags0 & swrObjTest_FLAG0_ZOFF) != 0 && speed < 75.0f)
        speed = 75.0f;

    // AI glide-assist speed bonus. This is not a player nose-down input: for AI, `pitch` is
    // driven to -1.0 (else 0.0) by swrRace_UpdateAIGlidePitch when the pod has dropped below
    // its spline path (glide-dive back onto the line), so this branch only fires in that
    // dive state -- 1.3x (1.9x if finished).
    if ((player->flags0 & swrObjTest_FLAG0_AI) != 0 && player->pitch < -0.5f) {
        if ((player->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
            return speed * 1.9f;
        speed *= 1.3f;
    }
    return speed;
}

// Per-frame engine-temperature model. The gauge runs 0..100: boosting drains it at
// heatRate, idling recovers it at coolRate, and a spinout drains it fast (biasing which
// engine fails). When it bottoms out, a random engine part overheats and blows.
// 0x004788c0
RETAIL_FP void swrRace_UpdateHeat(swrRace* player)
{
    int spinDir = 0; // -1 / 0 / +1 spinout-tilt bias for which engine part fails

    if ((player->flags1 & swrObjTest_FLAG1_ON_LAVA) != 0) {
        // On lava terrain: drain fast regardless of throttle; tilt direction biases the failure.
        player->engineTemp = player->engineTemp - swrRace_deltaTimeSecs * 20.0f;
        if (player->tiltManualMult < -0.5f) {
            spinDir = -1;
        } else if (0.5f < player->tiltManualMult) {
            spinDir = 1;
        }
    } else if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0) {
        player->engineTemp = player->engineTemp - swrRace_deltaTimeSecs * player->podStats.heatRate;
    } else {
        player->engineTemp = swrRace_deltaTimeSecs * player->podStats.coolRate + player->engineTemp;
    }

    if (100.0f <= player->engineTemp) {
        player->engineTemp = 100.0f;
    }
    if (0.0f < player->engineTemp) {
        return;
    }

    // Overheated: pick an engine part (left/right half biased by spin direction) and blow it.
    player->engineTemp = 0.0f;
    int part;
    if (spinDir < 0) {
        part = (int) ((long double) swrUtils_Rand() * (float) SWR_CTL_RAND_NORM * 3.0f);
    } else if (spinDir > 0) {
        part = 3 - (int) ((long double) swrUtils_Rand() * (float) SWR_CTL_RAND_NORM * -3.0f);
    } else {
        part = (int) ((long double) swrUtils_Rand() * (float) SWR_CTL_RAND_NORM * 6.0f);
    }

    if ((player->engineStatus[part] & swrRace_ENGINESTATUS_ON_FIRE) == 0) {
        rdVector3 origin = {0.0f, 0.0f, 0.0f};
        swrRace_SpawnEngineFireball(player, 2 - part / 3, &origin, (float) 0.1f);
    }
    player->engineStatus[part] |= swrRace_ENGINESTATUS_ON_FIRE;
    player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;
}

// 0x00478a70
RETAIL_FP void swrRace_ApplyTraction(swrRace* player, float b, rdVector3* c, rdVector3* d)
{
    float dx, dy, dz;
    long double dot;
    long double grip;
    long double target;
    long double slide;
    float traction;
    float dtf;
    float keep;
    float sumY;
    float sumZ;

    // Remove any part of velocityDir that opposes the (sign-of-b) input direction c.
    if (b <= 0.0f) {
        dx = -c->x;
        dy = -c->y;
        dz = -c->z;
    } else {
        dx = c->x;
        dy = c->y;
        dz = c->z;
    }
    dot = dx * player->velocityDir.x + dy * player->velocityDir.y + dz * player->velocityDir.z;
    if (dot < 0.0f) {
        dot = -dot;
        player->velocityDir.x += dx * dot;
        player->velocityDir.y += dy * dot;
        player->velocityDir.z += dz * dot;
    }

    // Desired velocity this frame.
    rdVector_Scale3(d, b, c);

    // Traction factor from grip stats; a multiplayer handicap can reduce or zero it.
    grip = player->podStats.antiSkid * player->surfaceGripFactor * player->slide2;
    traction = (1.0f - grip * grip) * 0.99666601f;
    if (1.0f < player->paceMultiplier) {
        if (player->paceMultiplier <= 2.0f)
            traction = (2.0f - player->paceMultiplier) * traction;
        else
            traction = 0.0f;
    }

    // Blend velocityDir between the desired velocity and its current value by traction.
    // Retail divides X by the float dt but Y/Z by the double dt, with Y/Z sums rounded to float.
    dtf = swrRace_deltaTimeSecs;
    keep = 1.0f - traction;
    player->velocityDir.x = (1.0L / dtf) * (dtf * player->velocityDir.x * traction + d->x * dtf * keep);
    sumY = dtf * player->velocityDir.y * traction + dtf * d->y * keep;
    player->velocityDir.y = (1.0L / swrRace_deltaTimeSecs) * sumY;
    sumZ = dtf * player->velocityDir.z * traction + dtf * d->z * keep;
    player->velocityDir.z = (1.0L / swrRace_deltaTimeSecs) * sumZ;

    // Output the normalized velocity scaled by |b|.
    d->x = player->velocityDir.x;
    d->y = player->velocityDir.y;
    d->z = player->velocityDir.z;
    rdVector_Normalize3Acc(d);
    if (b < 0.0f)
        b = -b;
    rdVector_Scale3(d, b, d);

    // Ease slide2 toward its target (1.0, lowered to 0.8 / x0.45 on certain surfaces).
    if ((player->flags1 & swrObjTest_FLAG1_SLIDE_LOCK) == 0) {
        target = 1.0f;
        if ((player->flags1 & swrObjTest_FLAG1_NOT_ACCEL) != 0)
            target = 0.8f;
        if ((player->flags1 & swrObjTest_FLAG1_SLIDING) != 0)
            target *= 0.45f; // stays in ST0 in retail

        if (target < player->slide2) {
            slide = player->slide2 - (swrRace_deltaTimeSecs + swrRace_deltaTimeSecs);
            player->slide2 = slide;
            if (slide < target)
                player->slide2 = target;
        } else if (player->slide2 < target) {
            // Stored rate constant is -2.0, applied as slide2 - dt*(-2).
            slide = player->slide2 - swrRace_deltaTimeSecs * -2.0f;
            player->slide2 = slide;
            if (target < slide)
                player->slide2 = target;
        }
    }
}

// 0x0044acb0
int swrRace_CollideTrack(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal)
{
    rdVector3 seg;
    seg.x = curPos->x - prevPos->x;
    seg.y = curPos->y - prevPos->y;
    seg.z = curPos->z - prevPos->z;

    float len = rdVector_Len3(&seg);
    if (0.001f < len) {
        // Cast a ray from prevPos along the unit movement direction, over the segment length.
        float inv = 1.0f / len;
        float ray[7];
        ray[0] = prevPos->x;
        ray[1] = prevPos->y;
        ray[2] = prevPos->z;
        ray[3] = seg.x * inv;
        ray[4] = seg.y * inv;
        ray[5] = seg.z * inv;
        ray[6] = len;

        rdVector3 hitPoint, normal;
        float dist = swrRace_RaycastModel(model, ray, &hitPoint, &normal);
        if (0.0f <= dist) {
            // Push curPos back out past the contact plane along the normal (+2.0 of clearance,
            // i.e. the stored -2.0 skin subtracted).
            float push = (normal.x * hitPoint.x + normal.y * hitPoint.y + normal.z * hitPoint.z) -
                         (normal.x * curPos->x + normal.y * curPos->y + normal.z * curPos->z) + 2.0f;
            curPos->x += normal.x * push;
            curPos->y += normal.y * push;
            curPos->z += normal.z * push;
            *outNormal = normal;
            return 1;
        }
    }
    return 0;
}

// 0x00478d80
void swrRace_IntegrateMotion(swrRace* player, rdVector3* b, rdVector3* c, rdVector3* d)
{
    rdVector3 vel;

    // Longitudinal speed + boost, run through traction into the frame velocity.
    float speed = swrRace_UpdateSpeed(player);
    speed += swrRace_ApplyBoost(player);
    swrRace_ApplyTraction(player, speed, d, &vel);

    // Flatten a too-steep climb (unless on a wall/repulsor surface).
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0 && (player->flags0 & swrObjTest_FLAG0_ZON) == 0 && 0.0f < vel.z)
    {
        float horiz = vel.y * vel.y + vel.x * vel.x;
        if (horiz * 0.13690001f < vel.z * vel.z)
            vel.z = stdMath_Sqrt(horiz) * 0.2f;
    }

    // Fold in opponent-collision velocity, then bleed both collision velocities down.
    vel.x += player->velocityCollisionOpponent.x;
    vel.y += player->velocityCollisionOpponent.y;
    vel.z += player->velocityCollisionOpponent.z;
    player->velocityCollision.x *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollision.y *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollision.z *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.x *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.y *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.z *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);

    // Blend in the slope velocity (skipped while spun out / idle on the ground).
    if ((player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0 &&
        (0.1f < player->throttle || 0.1f < -player->throttle || (player->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) == 0))
    {
        float dot = vel.x * player->velocitySlope.x + vel.y * player->velocitySlope.y + vel.z * player->velocitySlope.z;
        float len;
        if (dot < 0.0f || (len = rdVector_Len3(&player->velocitySlope)) <= 1.0f)
        {
            vel.x += player->velocitySlope.x;
            vel.y += player->velocitySlope.y;
            vel.z += player->velocitySlope.z;
        }
        else
        {
            if (1.0f < speed)
            {
                float ratio = dot / (speed * 60.0f);
                if (0.0f < ratio)
                {
                    float dtr = swrRace_deltaTimeSecs * ratio;
                    player->accelThrust += dtr + dtr;
                }
            }
            float factor = (dot / len) * 0.01f;
            if (factor < 1.0f)
                factor = 1.0f;
            rdVector_Scale3Add3(&vel, &vel, factor, &player->velocitySlope);
        }
    }

    // Advance the position: c = b + dt * vel.
    rdVector_Scale3Add3(c, b, swrRace_deltaTimeSecs, &vel);

    // Once the pod is beyond the LOD distance, freeze the move delta and bail. lodDistance is the
    // distance to the nearest active viewport camera (set in swrObjTest_F0); (lodDistance - 400)/600 >= 1
    // means >= ~1000 units away. Skipped for local players and FORCE_GROUND pods.
    if (1.0 <= ((float)player->lodDistance - 400.0f) * 0.0016666667f &&
        (player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 && (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0)
    {
        player->wallPushback.x = 0.0f;
        player->wallPushback.y = 0.0f;
        player->wallPushback.z = 0.0f;
        return;
    }
    if ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) != 0)
    {
        player->wallPushback.x = 0.0f;
        player->wallPushback.y = 0.0f;
        player->wallPushback.z = 0.0f;
        return;
    }

    // Resolve track collisions (up to 6 passes), then record the resulting move delta.
    rdVector3 outNormal;
    float savedX = c->x, savedY = c->y, savedZ = c->z;
    int iter;
    int hit = swrRace_CollideTrack(c, b, player->collisionModel, &outNormal);
    for (iter = 0; hit != 0 && iter < 6; iter++)
        hit = swrRace_CollideTrack(c, b, player->collisionModel, &outNormal);
    if (0 < iter && (player->flags0 & swrObjTest_FLAG0_AI) != 0)
        player->accelThrust *= stdMath_Decelerator(5.0f, swrRace_deltaTimeSecs);
    player->wallPushback.x = c->x - savedX;
    player->wallPushback.y = c->y - savedY;
    player->wallPushback.z = c->z - savedZ;
}

// Returns the unrounded ST0 result: swrRace_IntegrateMotion adds it to the speed before storing.
// 0x004787f0
long double swrRace_ApplyBoost(swrRace* player)
{
    if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) == 0)
    {
        // Not boosting: bleed boostValue down, then snap tiny values to zero.
        if (0.0f < player->boostValue)
            player->boostValue *= stdMath_Decelerator(5.0f, swrRace_deltaTimeSecs);
        if (player->boostValue < 0.001f)
            player->boostValue = 0.0f;
    }
    else
    {
        // Boosting: charge boostValue at 1.5/sec.
        player->boostValue += swrRace_deltaTimeSecs * 1.5f;
    }

    // Air-brake cancels an active boost.
    if ((player->flags0 & swrObjTest_FLAG0_BRAKING) != 0)
        player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;

    // The stored divisor constant is -0.33, so the denominator is boostValue + 0.33.
    if (0.0f < player->boostValue)
        return (player->boostValue * player->podStats.boost_thrust) / (player->boostValue + 0.33f);
    return 0.0f;
}

// 0x0047b000
void swrRace_DeathSpeed(swrRace* player, float a, float b)
{
    uint32_t flags0 = player->flags0;
    // Ignore while already exploding/dying/respawning, or collision-disabled.
    if ((flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 || (player->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
        return;
    if ((player->flags1 & swrObjTest_FLAG1_IMMUNITY) != 0)
    {
        player->flags1 &= ~swrObjTest_FLAG1_IMMUNITY;
        return;
    }

    // Both impact components must clear their thresholds, and the pod must not be invincible.
    if (swrRace_DeathSpeedDrop < b && swrRace_DeathSpeedMin < a && swrRace_IsInvincible == 0)
    {
        if (200.0f <= player->speedValue && (flags0 & swrObjTest_FLAG0_AI) == 0)
        {
            // Fast enough and not on a no-death surface: explode, spinning toward the turn direction.
            swrRace_Explode(player, (0.0f <= player->turnModifier) ? 2 : 1);
            player->throttle = 5.0f;
            player->flags0 |= swrObjTest_FLAG0_BOOSTING;
        }
        else
        {
            // Otherwise just flag for a respawn instead of exploding.
            player->flags0 |= swrObjTest_FLAG0_RESPAWN;
        }
    }
}

// 0x0047ce60
void swrRace_TriggerHandler(swrObjTrig* trig, swrRace* player, char fromNetwork)
{
    swrModel_TriggerDescription* desc;
    swrModel_Animation* anim;
    int shake[3];
    char message[256];

    if ((fromNetwork & 1) == 0)
        swrObjTrig_SendMultiplayerTriggerEvent(trig->trigger_description, player);

    desc = trig->trigger_description;
    trig->unk14_ms = 0.0f;

    switch (desc->type) {
    case swrModel_TriggerType_BreakDestructable_100:
    case swrModel_TriggerType_BreakDestructable_102:
    case swrModel_TriggerType_BreakDestructable_201:
    case swrModel_TriggerType_BreakDestructable_202:
    case swrModel_TriggerType_BreakDestructable_212:
        swrObjTrig_HandleCrashHitTrigger(trig, player);
        return;

    case swrModel_TriggerType_StartAnimDoor:
        trig->flag |= swrObjTrig_FLAG_ACTIVE;
        anim = trig->unk40_animation;
        if (anim == NULL)
            return;
        anim->flags &= ~ANIMATION_LOOP;
        if (trig->unk10_ms <= SWR_TRIG_REARM_SECS)
            return;
        trig->unk10_ms = 0.0f;
        if (0.125 < anim->animation_speed)
            swrModel_AnimationSetSpeed(anim, -SWR_TRIG_DOOR_ANIM_SPEED);
        else
            swrModel_AnimationSetSpeed(anim, SWR_TRIG_DOOR_ANIM_SPEED);
        return;

    case swrModel_TriggerType_RemoveTargetTent:
        if (desc == NULL)
            return;
        if (desc->affected_node != NULL)
            swrModel_NodeModifyFlags(desc->affected_node, 2, -4, 0x10, 3);
        swrModel_NodeModifyFlags(trig->trigger_description->affected_node, 0, -3, 0x10, 3);
        break;

    case swrModel_TriggerType_KillPlayer:
        if (0.5 <= (float)swrUtils_Rand() * SWR_CTL_RAND_NORM)
            swrRace_Explode(player, 2);
        else
            swrRace_Explode(player, 1);
        return;

    case swrModel_TriggerType_CollapsingGlacier:
    case swrModel_TriggerType_FallingPillar:
        trig->flag |= swrObjTrig_FLAG_ACTIVE;
        desc->flags |= swrModel_TRIGGERFLAG_DISABLED;
        swrModel_NodeSetAnimationFlagsAndSpeed(trig->trigger_description->affected_node, 0, ANIMATION_ENABLED, 0.6f);
        shake[0] = 'Shak';
        ((float*)shake)[1] = 0.05f;
        ((float*)shake)[2] = 4.0f;
        swrEvent_CallF4('cMan', shake);
        trig->unk10_ms = 0.0f;
        return;

    case swrModel_TriggerType_FallingAsteroids:
        swrRace_UpdateFireEffects(player);
        return;

    case swrModel_TriggerType_SpawnFlag:
        swrObjTrig_HandleTrigger108(trig, player);
        return;

    case swrModel_TriggerType_TuskenRaiders:
        if ((trig->flag & swrObjTrig_FLAG_ACTIVE) == 0)
            trig->unk10_ms = 100.0f;
        trig->flag |= swrObjTrig_FLAG_ACTIVE;
        if (trig->unk10_ms <= SWR_TRIG_REARM_SECS)
            return;
        trig->unk10_ms = 0.0f;
        swrSound_Play2D(0x30, 7, 0.25f, 1.0f, 0);
        swrRace_UpdateFireEffects(player);
        return;

    case swrModel_TriggerType_EarthquakeShortcut:
    case swrModel_TriggerType_Earthquake:
        if (desc == NULL)
            return;
        desc->flags |= swrModel_TRIGGERFLAG_DISABLED;
        shake[0] = 'Shak';
        ((float*)shake)[1] = 0.25f;
        ((float*)shake)[2] = 8.0f;
        swrEvent_CallF4('cMan', shake);
        trig->model_material = NULL;
        trig->test_obj_transform_ptr = NULL;
        trig->flag = (trig->flag & ~swrObjTrig_FLAG_FX_SPAWNED) | swrObjTrig_FLAG_ACTIVE;
        trig->unk10_ms = 0.0f;
        return;

    case swrModel_TriggerType_StartTram:
        if (trig->unk44_animation != NULL)
            swrModel_AnimationSetSpeed(trig->unk44_animation, 1.0f);
        if (trig->unk40_animation != NULL)
            swrModel_AnimationSetSpeed(trig->unk40_animation, 1.0f);
        break;

    case swrModel_TriggerType_StartAnimDoor2:
        trig->flag |= swrObjTrig_FLAG_ACTIVE;
        if (desc->affected_node == NULL)
            return;
        if (trig->unk10_ms <= SWR_TRIG_REARM_SECS)
            return;
        trig->unk10_ms = 0.0f;
        swrModel_NodeSetAnimationFlagsAndSpeed(desc->affected_node, ANIMATION_LOOP, 0, 1.0f);
        return;

    case swrModel_TriggerType_MethaneVapor:
        swrObjTrig_Handle314Or501Trigger(trig, 0);
        return;

    case swrModel_TriggerType_LavaSplash:
        swrObjTrig_Handle314Or501Trigger(trig, 5);
        return;

    case swrModel_TriggerType_TeleportToSpline:
        // retail shows an uninitialized stack buffer here
        message[0] = '\0';
        swrText_ShowTimedMessage(message, 3.0f);
        swrRace_ResetToSpline(player, 0.0f);
        return;

    default:
        return;
    }

    // one-shot: disable the trigger and release its object
    trig->trigger_description->flags |= swrModel_TRIGGERFLAG_DISABLED;
    trig->flag &= ~swrObjTrig_FLAG_ACTIVE;
    swrObj_Free(&trig->obj);
}

// 0x0047e450
void swrRace_UpdateFireEffects(swrRace* player)
{
    rdMatrix44 splineFrame;
    rdMatrix44 podTransform;

    swrUtils_Rand();
    swrUtils_Rand();
    for (int i = 0; i < SWR_FIRE_EFFECT_COUNT; i++) {
        if (swrRace_FireTimer[i] <= 0.0f) {
            swrRace_FireTimer[i] = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 6.0f - 2.0f;
            rdMatrix_Copy44(&podTransform, &player->transform);
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineFrame, player->speedValue * 0.0033333334f * (swrRace_FireTimer[i] * 0.2857143f) * 1.2f);
            swrRace_FireLocation[i].x = splineFrame.vD.x;
            swrRace_FireLocation[i].y = splineFrame.vD.y;
            swrRace_FireLocation[i].z = splineFrame.vD.z - 8.0f;
            swrRace_FireLocation[i].x = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 200.0f - 100.0f) + swrRace_FireLocation[i].x;
            swrRace_FireLocation[i].y = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 200.0f - 100.0f) + swrRace_FireLocation[i].y;
        }
    }
}

// Ticks the 8 flame timers: a crackle sfx as each passes 0.8s, then a positional burst + smoke at 0.
// 0x0047e580
void swrRace_InitFireEffects(int racer, float reset)
{
    float volume;
    float pitch;
    int sfx;
    int i;
    rdVector3 pos;

    if (reset != 0.0f) {
        for (i = 0; i < 8; i++)
            swrRace_FireTimer[i] = -1.0f;
        return;
    }
    for (i = 0; i < 8; i++) {
        float prev = swrRace_FireTimer[i];
        if (prev <= 0.0f)
            continue;
        swrRace_FireTimer[i] = (float)(prev - swrRace_deltaTimeSecs);
        if (prev > 0.8f && swrRace_FireTimer[i] <= 0.8f) {
            sfx = 0x43;
            volume = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.100000009f + 0.2f;
            pitch = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.199999988f + 0.5f;
            if (racer == 6) {
                sfx = 0x6e;
                pitch = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.199999988f + 0.8f;
            }
            swrSound_Play2D(sfx, 7, volume, pitch, 0);
        }
        if (swrRace_FireTimer[i] <= 0.0f) {
            volume = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.0800000057f + 0.1f;
            pitch = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.199999988f + 0.8f;
            swrSound_PlaySpatialRange(0x43, 6, volume, pitch, &swrRace_FireLocation[i], 0, 0, 1000.0f, 2000.0f);
            pos = swrRace_FireLocation[i];
            swrObjSmok_Spawn(2, 0, 5.0f, &pos, 5.0f);
        }
    }
}

// Lap progress in [0..1): the control point's baked progress base plus segmentT scaled by the
// segment's span (swrSpline_progressTable). Closed tracks clamp just under 1.0 (the wrap is what
// swrRace_LapCompletion detects); open tracks (swrSpline_finishNodeIdx >= 0) clamp to 1.0.
// 0x0047f810
RETAIL_FP float swrRace_LapProgress(swrSplineCursor* cursor)
{
    int cp;
    float progress;

    cp = swrSpline_getControlPoint(cursor, 0);
    progress = cursor->segmentT * swrSpline_progressTable[cp].y + swrSpline_progressTable[cp].x;
    if (swrSpline_finishNodeIdx < 0) {
        if (1.0f <= progress)
            progress = 0.9999f;
    } else if (1.0f < progress) {
        progress = 1.0f;
    }
    return progress;
}

// True when the pod crossed the start/finish line this frame. lapCompMax is the furthest progress
// reached, unwrapped by -1.0 near the line (lapComp < 0.1) so a crossing reads as progress
// overtaking a NEGATIVE lapCompMax. Remote ('REMO') pods read the swrMultiplayer_aRemote* arrays
// instead of the local spline cursor.
// 0x0047fdd0
RETAIL_FP int swrRace_LapCompletion(swrRace* player, int checkCrossing)
{
    swrScore* score;
    int netSlot;
    float maxComp;
    int crossed; // retail returns the full EAX; its caller tests all 32 bits

    if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        checkCrossing = 1;
    player->lapCompPrev = player->lapComp;
    if (swrMultiplayer_enabled != 0 && (player->flags0 & swrObjTest_FLAG0_REMOTE) != 0) {
        score = player->score_ptr;
        netSlot = *(int*)&score->time_unk;
        player->lapCompMax = swrMultiplayer_aRemoteLapCompMax[netSlot];
        score->results_P1_Lap = swrMultiplayer_aRemoteLap[netSlot];
    }
    if (swrMultiplayer_enabled == 0 || (player->flags0 & swrObjTest_FLAG0_REMOTE) == 0)
        player->lapComp = swrRace_LapProgress(&player->splineCursor);
    else
        player->lapComp = swrMultiplayer_aRemoteLapComp[*(int*)&player->score_ptr->time_unk];

    if (player->moveTick < 9)
        player->idleTick = (float)(swrRace_deltaTimeSecs + player->idleTick); // double dt, one rounding
    else
        player->idleTick = 0.0f;

    // skip the crossing test when the pod just jumped backward over the line
    // (progress snapped high while the previous frame was just past it)
    if (checkCrossing != 0 && (player->lapComp <= 0.8f || 0.1f <= player->lapCompPrev)) {
        maxComp = player->lapCompMax;
        if (player->lapComp < 0.1f) {
            if (0.8f < maxComp)
                maxComp -= 1.0f;
            if (0.8f < player->lapCompPrev)
                player->lapCompPrev -= 1.0f;
        }
        if (swrSpline_finishNodeIdx >= 0) {
            // open (point-to-point) track: done once progress reaches 1.0
            crossed = 1.0f <= player->lapComp;
            player->idleTick = 0.0f;
            player->lapCompMax = player->lapComp;
            return crossed;
        }
        if (maxComp < player->lapComp && player->lapCompPrev - 0.01f <= maxComp) {
            // a negative (unwrapped) high-water mark being overtaken == line crossed
            crossed = maxComp < 0.0f;
            player->idleTick = 0.0f;
            player->lapCompMax = player->lapComp;
            return crossed;
        }
    }
    return 0;
}

// 0x0047f890
swrModel_Mesh* swrRace_GetTrackMeshAtCursor(swrSplineCursor* cursor)
{
    long double sample = (long double)cursor->segmentT * (float)SWR_SPLINE_SAMPLES_PER_NODE; // unrounded into __ftol, as retail
    if (sample < 0.0f)
        sample -= 0.999999f;
    int sampleIndex = (int)sample;
    int node = swrSpline_getControlPoint(cursor, 0);
    return swrSpline_sampleMeshes[node * SWR_SPLINE_SAMPLES_PER_NODE + sampleIndex];
}

// Steps the cursor over each node plane the pod passed (segmentT += 0.01 per step). Entering node 0
// sets *outCrossTime by line-plane interpolation of positionPrev -> position, times the raw delta.
// 0x0047f8e0
void swrRace_AdvanceSplineCursor(swrRace* player, float* outCrossTime, int* outForward, int* outBackward)
{
    swrSplineCursor* cursor = &player->splineCursor;
    rdMatrix44 m;
    rdVector3 moved;
    bool done;

    *outForward = 0;
    *outBackward = 0;
    int node = cursor->nodeLookahead[0];
    swrSpline_EvaluateToMatrix(cursor, &m);
    moved.x = player->transform.vD.x - player->positionPrev.x;
    moved.y = player->transform.vD.y - player->positionPrev.y;
    moved.z = player->transform.vD.z - player->positionPrev.z;
    rdVector_Len3(&moved);
    *outCrossTime = 0.0f;

    // forward: step past every node plane the pod is beyond
    do {
        done = true;
        float posDist = m.vB.x * player->transform.vD.x + m.vB.y * player->transform.vD.y + m.vB.z * player->transform.vD.z;
        float planeDist = m.vD.z * m.vB.z + m.vD.y * m.vB.y + m.vD.x * m.vB.x;
        float prevDist = m.vB.x * player->positionPrev.x + m.vB.y * player->positionPrev.y + m.vB.z * player->positionPrev.z;
        if (planeDist < posDist) {
            if (cursor->endFlag == 0) {
                cursor->segmentT -= -0.01f;
                swrSpline_EvaluateToMatrix(cursor, &m);
                done = false;
                if (cursor->nodeLookahead[0] != node) {
                    if (cursor->nodeLookahead[0] == 0) {
                        if (0.01f <= posDist - prevDist)
                            *outCrossTime = ((planeDist - prevDist) * (float)swrRace_dt_raw_d) / (posDist - prevDist);
                        else
                            *outCrossTime = 0.0f;
                    }
                    node = cursor->nodeLookahead[0];
                }
            } else if (0.01f <= posDist - prevDist) {
                *outCrossTime = ((planeDist - prevDist) * (float)swrRace_dt_raw_d) / (posDist - prevDist);
            } else {
                *outCrossTime = 0.0f;
            }
            *outForward = 1;
        }
    } while (!done);

    // backward: no forward progress, so step back while the pod is behind the plane
    if (*outForward == 0 && cursor->startFlag == 0) {
        cursor->segmentT -= 0.01f;
        swrSpline_EvaluateToMatrix(cursor, &m);
        do {
            done = true;
            float posDist = m.vB.x * player->transform.vD.x + m.vB.y * player->transform.vD.y + m.vB.z * player->transform.vD.z;
            float planeDist = m.vD.z * m.vB.z + m.vD.y * m.vB.y + m.vD.x * m.vB.x;
            if (posDist < planeDist) {
                done = cursor->startFlag != 0;
                if (!done) {
                    cursor->segmentT -= 0.01f;
                    swrSpline_EvaluateToMatrix(cursor, &m);
                }
                *outBackward = 1;
            }
        } while (!done);
        if (cursor->startFlag == 0) {
            cursor->segmentT -= -0.01f;
            swrSpline_EvaluateToMatrix(cursor, &m);
        }
    }
}

// 0x0047fbb0
int swrRace_UpdateSplineBinding(swrRace* player)
{
    swrModel_Mesh* stoodOn = (swrModel_Mesh*)player->terrainModel;
    swrModel_Behavior* behavior;
    float crossTime;
    int crossed;

    if (player->splineTrackMesh == stoodOn || player->splineTrackMesh == NULL || stoodOn == NULL || (player->flags1 & swrObjTest_FLAG1_GROUND_CACHED) != 0)
        return 0;

    behavior = swrModel_MeshGetBehavior(stoodOn);
    if (behavior != NULL && (behavior->unk1 & swrModel_BEHAVIOR_SPLINE_AMBIGUOUS) != 0)
        return -1;

    stoodOn = (swrModel_Mesh*)player->terrainModel;
    if (stoodOn->splineSampleIndex != 0) {
        swrSpline_CursorSeekToProgress(&player->splineCursor, (short)stoodOn->splineSampleIndex);
        swrRace_AdvanceSplineCursor(player, &crossTime, &crossed, &crossed);
    }
    player->splineTrackMesh = swrRace_GetTrackMeshAtCursor(&player->splineCursor);
    player->splineSampleSpacing = swrSpline_GetSampleSpacing();
    player->splineProjResult1 = swrSpline_ProjectPointStub(&player->splineCursor, &player->splineProjOut1);
    player->splineProjResult2 = swrSpline_ProjectPointStub(&player->splineCursor, &player->splineProjOut2);
    return 1;
}

// 0x0047fca0
RETAIL_FP void swrRace_ComputeTrackOffset(swrRace* player)
{
    rdMatrix44 frame;
    rdVector3 closest;
    rdVector3 delta;
    float dist;
    long double invDist;
    float along;

    swrSpline_EvaluateToMatrix(&player->splineCursor, &frame);
    // project the pod onto the spline frame's forward axis (vB) through its origin (vD)
    along = (frame.vB.z * player->transform.vD.z + frame.vB.y * player->transform.vD.y + frame.vB.x * player->transform.vD.x) - (frame.vD.x * frame.vB.x + frame.vD.y * frame.vB.y + frame.vD.z * frame.vB.z);
    rdVector_Scale3Add3(&closest, (rdVector3*)&frame.vD, along, (rdVector3*)&frame.vB);
    delta.x = player->transform.vD.x - closest.x;
    delta.y = player->transform.vD.y - closest.y;
    delta.z = player->transform.vD.z - closest.z;
    dist = rdVector_Len3(&delta);
    player->trackOffset.w = dist;
    if (0.1f < dist) {
        invDist = 1.0f / (long double)dist; // stays in ST0 in retail
        player->trackOffset.x = delta.x * invDist;
        player->trackOffset.y = delta.y * invDist;
        player->trackOffset.z = delta.z * invDist;
        return;
    }
    player->trackOffset.z = 1.0f;
    player->trackOffset.x = 0.0f;
    player->trackOffset.y = 0.0f;
}

// Per-racer progress update, called from swrObjJdge_F2. Nonzero when the pod completed a lap this
// frame; *outCrossTime then holds the portion of the frame delta spent before the crossing.
// 0x0047ffb0
int swrRace_UpdateRaceProgress(swrRace* player, float* outCrossTime)
{
    int movedForward;
    int wentBackward;
    int binding;
    int completedLap;

    swrRace_AdvanceSplineCursor(player, outCrossTime, &movedForward, &wentBackward);
    player->splineTrackMeshPrev = player->splineTrackMesh;
    player->splineTrackMesh = swrRace_GetTrackMeshAtCursor(&player->splineCursor);
    // the original passes the cursor, but the retail GetSampleSpacing stub ignores it
    player->splineSampleSpacing = swrSpline_GetSampleSpacing();
    player->splineProjResult1 = swrSpline_ProjectPointStub(&player->splineCursor, &player->splineProjOut1);
    player->splineProjResult2 = swrSpline_ProjectPointStub(&player->splineCursor, &player->splineProjOut2);
    if (player->splineTrackMeshPrev != player->splineTrackMesh)
        player->unk1f24 = 0;
    binding = swrRace_UpdateSplineBinding(player);
    swrRace_ComputeTrackOffset(player);
    completedLap = swrRace_LapCompletion(player, (movedForward != 0 || binding == 1) ? 1 : 0);
    if (wentBackward != 0) {
        player->checkpointCount++;
        player->moveTick = 0;
    }
    if (movedForward != 0) {
        player->checkpointCount = 0;
        if (wentBackward == 0 && player->moveTick < 200)
            player->moveTick++;
    }
    player->splineRebindResult = (short)binding;
    return completedLap;
}

// 0x004804c0
void swrRace_InitFrameTimer(void)
{
    if (swr_fixedDeltaTimeSecs <= swrRace_minDeltaTimeSecs)
        swr_fixedDeltaTimeSecs = (double)(1.0f / 15.0f);
    swrRace_deltaTimeSecs = swr_fixedDeltaTimeSecs;
    swrRace_fdeltaTimeSecs = (float)swr_fixedDeltaTimeSecs;
    timetotal = 0.0;
    frametotal = 0;
    swrGui_Stopped = 0;
    if (swr_FastMode == 0)
        swr_systemTimeMs = timeGetTime();
}

// 0x00480540
void swrRace_IncrementFrameTimer(void)
{
    // Per-frame timestep update. The original calls stdlib_timeGetTime (0x0048c490),
    // a thin wrapper around the winmm timeGetTime import; src/ reimpls call timeGetTime
    // directly (see stdControl.c). swr_FastMode swaps the measured delta for a fixed one.
    if (swr_FastMode == 0)
    {
        DWORD now = timeGetTime();
        swrRace_deltaTimeSecs = (double)(now - swr_systemTimeMs) * swrRace_msToSecondsScale;
        // dt_raw_d keeps the un-clamped delta (this copy precedes the max clamp below).
        swrRace_dt_raw_d = swrRace_deltaTimeSecs;
        if (swrRace_maxDeltaTimeSecs < swrRace_deltaTimeSecs)
        {
            swrRace_deltaTimeSecs = 0.1f;
        }
        swr_systemTimeMs = now;
    }
    else
    {
        swrRace_deltaTimeSecs = swr_fixedDeltaTimeSecs;
    }
    if (swrGui_Stopped != 0)
    {
        swrRace_deltaTimeSecs = 0.0;
    }
    if (swrRace_deltaTimeSecs <= swrRace_minDeltaTimeSecs)
    {
        swrRace_deltaTimeSecs = 0.002f;
    }
    swrRace_fdeltaTimeSecs = (float)swrRace_deltaTimeSecs;
    timetotal = timetotal + swrRace_deltaTimeSecs;
    frametotal = frametotal + 1;
}

// 0x0044abc0
int swrRace_CollideBlockMove(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal)
{
    rdVector3 hit;
    float ray[7]; // origin xyz, unit direction xyz, max distance
    rdVector3 delta;
    int blocked = 0;

    delta.x = curPos->x - prevPos->x;
    delta.y = curPos->y - prevPos->y;
    delta.z = curPos->z - prevPos->z;
    ray[6] = rdVector_Len3(&delta);
    if (0.001f < ray[6]) {
        float invLen = 1.0f / ray[6];
        ray[0] = prevPos->x;
        ray[1] = prevPos->y;
        ray[2] = prevPos->z;
        ray[3] = delta.x * invLen;
        ray[4] = delta.y * invLen;
        ray[5] = delta.z * invLen;
        if (0.0f <= swrRace_RaycastModel(model, ray, &hit, outNormal)) {
            blocked = 1;
            *curPos = *prevPos;
        }
    }
    return blocked;
}

// Aims a scrape-spark emitter (side 1 = right, else left) at the wall contact and scales it;
// half the time the spray size is jittered to 0.25..0.75.
// 0x00477850
RETAIL_FP void swrRace_SetupScrapeSpray(swrRace* player, float scale, float offset, rdVector3* pos, rdVector3* normal, int side)
{
    rdMatrix44* emitter;
    swrObjTest_FLAG0 flag;

    if (side == 1) {
        emitter = &player->scrapeSparkXf;
        flag = swrObjTest_FLAG0_SCRAPE_SPARK_R;
    } else {
        emitter = &player->scrapeSparkXf2;
        flag = swrObjTest_FLAG0_SCRAPE_SPARK_L;
    }
    float length = scale;
    float width = scale;
    if (0.2 < scale)
        width = 0.2f;
    if ((long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM < 0.5) {
        long double jitter = (long double)swrUtils_Rand() * (float)SWR_CTL_RAND_NORM * 0.5f - -0.25f; // FILD + ST0, as retail
        width = jitter * width;
        length = jitter * scale;
    }
    rdMatrix_BuildBasisFromDirection(emitter, pos, normal, (rdVector3*)&player->transform.vB, offset);
    rdMatrix_ScaleBasis44(emitter, length, width, width, emitter);
    player->flags0 |= flag;
}

// Pushes the pod out of track walls with a swept sphere (radius shrinks with manual tilt, min 1.5,
// slab +-1 along the pod's up axis), sprays scrape sparks on a side-on contact above speed 50,
// then blocks the move outright if the segment prevPos -> pos still crosses geometry.
// 0x00477940
void swrRace_DetectWallScrape(swrRace* player, float* pos, float* prevPos)
{
    rdVector3 normal;
    rdVector3 normal2;
    rdVector3 slide;
    float contact[3];
    float contact2[3];
    rdVector3 blockNormal;
    int hits = 0;

    float tilt = player->tiltManualMult;
    if (tilt < 0.0f)
        tilt = -tilt;
    float radius = player->collisionWidth - player->collisionWidth * 0.75f * tilt;
    if (radius < 1.5f)
        radius = 1.5f;

    rdVector3* up = (rdVector3*)&player->transform.vC;
    if (swrModel_CollideSphereWithModel((swrModel_NodeTransformed*)player->collisionModel, (rdVector3*)pos, radius, up, 1.0f, -1.0f, &normal, &slide, contact) != 0) {
        hits = 1;
        swrRace_GetCollisionHit();
        if (swrModel_CollideSphereWithModel((swrModel_NodeTransformed*)player->collisionModel, (rdVector3*)pos, radius, up, 1.0f, -1.0f, &normal2, &slide, contact2) != 0) {
            hits = 2;
            swrRace_GetCollisionHit();
        }
    }
    if (hits > 0 && 50.0f < player->speedValue) {
        float facing = player->transform.vC.y * normal.y + normal.x * up->x + player->transform.vC.z * normal.z;
        if (facing < 0.5f && -facing < 0.5f)
            swrRace_SetupScrapeSpray(player, player->speedValue * 0.002f, 0.3f, (rdVector3*)contact, &normal, 1);
    }
    swrRace_CollideBlockMove((rdVector3*)pos, (rdVector3*)prevPos, player->collisionModel, &blockNormal);
}

// 0x00479920
RETAIL_FP void swrRace_ApplyWallCollision(swrRace* player, rdVector3* normal, rdVector3* dir)
{
    rdVector3 push;
    rdVector3 side;
    int subEvents[3];
    bool hardHit = false;

    float dx = dir->x;
    float dy = dir->y;
    float dz = dir->z;
    float along = dy * normal->y + dz * normal->z + dx * normal->x;
    float len = rdVector_Len3(normal);
    long double approach = 0.0f;
    if (!(len < (float)0.1f))
        approach = (float)0.7f - along / len;
    float impact = 0.0f;
    if (!(approach < 0.0f))
        impact = approach * (float)1.4285715f;

    // strip the component along dir, leaving the wall push
    push.x = dx * -along + normal->x;
    push.y = dy * -along + normal->y;
    push.z = dz * -along + normal->z;
    *normal = push;
    float pushLen = rdVector_Len3(&push);
    if (pushLen < (float)0.01f)
        return;
    long double inv = 1.0f / pushLen;
    long double pushX = push.x * inv;
    push.x = pushX;
    push.y = push.y * inv;
    push.z = push.z * inv;

    // Retail dots the unrounded x term with the y and z it has already stored.
    float headOn = player->transform.vB.x * pushX + player->transform.vB.y * push.y + player->transform.vB.z * push.z;
    rdVector_Cross3(&side, &player->world_gravity, (rdVector3*)&player->transform.vB);
    rdVector_Normalize3Acc(&side);
    // The hard-hit test uses the unrounded product; everything after reads the spilled copy.
    long double strengthRaw = impact * headOn * headOn;
    float strength = strengthRaw;
    float sideways = side.x * push.x + side.y * push.y + side.z * push.z;
    if ((float)0.7f < strengthRaw) {
        unsigned int flags = player->flags0;
        hardHit = true;
        player->flags0 = flags & ~swrObjTest_FLAG0_THROTTLE_SETTLED;
        if ((flags & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) == 0)
            player->wallHitCooldown = (float)0.1f;
    }
    long double kick = strength * player->speedValue * 1.5f;
    player->velocityCollision.x = push.x * kick + player->velocityCollision.x;
    player->velocityCollision.y = push.y * kick + player->velocityCollision.y;
    player->velocityCollision.z = push.z * kick + player->velocityCollision.z;

    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) {
        player->turnModifier = 0.0f;
    } else {
        if (0.0f <= headOn) {
            player->turnModifier = 0.0f;
        } else if (0.0f <= sideways) {
            long double turn = ((sideways - headOn) - 1.0f) * 2.5f;
            player->turnModifier = turn;
            if (turn < 0.0f)
                player->turnModifier = 0.0f;
        } else {
            long double turn = ((sideways + headOn) - -1.0f) * 2.5f;
            player->turnModifier = turn;
            if (0.0f < turn)
                player->turnModifier = 0.0f;
        }
        player->turnModifier = impact * -150.0f * player->turnModifier;
    }

    if (0.0 < strength && 100.0 < player->speedValue) {
        player->accelThrust = stdMath_Decelerator(50.0f, (float)swrRace_deltaTimeSecs) * player->accelThrust;
        if ((float)0.05f < strength)
            player->flags0 |= swrObjTest_FLAG0_WALL_IMPACT_CLAMP;
        subEvents[0] = 'Hitt';
        if (hardHit) {
            subEvents[1] = 'KPow';
        } else {
            float absHeadOn = headOn < 0.0f ? -headOn : headOn;
            float absSideways = sideways < 0.0f ? -sideways : sideways;
            if (absHeadOn <= absSideways)
                subEvents[1] = 0.0 <= sideways ? 'LtSd' : 'RtSd';
            else
                subEvents[1] = 0.0 <= sideways ? 'LtFt' : 'RtFt';
        }
        // Divides by the double frame time, not a float copy of it.
        *(float*)&subEvents[2] = pushLen / swrRace_deltaTimeSecs;
        swrEvent_DispatchSubEvents(player, subEvents);
    }
}

// 0x00476740
RETAIL_FP float swrRace_UpdateHoverPads(swrRace* player, rdVector3* pos, int padFlags, float groundDist, float* up)
{
    rdVector3 offsets[4];
    rdVector3 padPos[4];
    rdVector3 padNormal[4];
    float padHeight[4];
    rdVector3 rotated;
    rdMatrix44 mat;
    const swrRacerVisualData* visual = &swrRacer_PodVisualData[*player->score_ptr->pilotId];

    rdVector_Set3(&offsets[0], 0.0f, 0.0f, 0.0f);
    rdVector_Copy3(&offsets[1], &visual->hoverPadOffsetB);
    rdVector_Copy3(&offsets[2], &visual->hoverPadOffsetB);
    offsets[2].x = -offsets[2].x;
    rdVector_Copy3(&offsets[3], &visual->hoverPadOffsetA);

    for (int i = 0; i < 4; i++) {
        rdVector_Scale3(&rotated, offsets[i].x, (rdVector3*)&player->transform.vA);
        rdVector_Scale3Add3(&rotated, &rotated, offsets[i].y, (rdVector3*)&player->transform.vB);
        rdVector_Scale3Add3(&rotated, &rotated, offsets[i].z, (rdVector3*)&player->transform.vC);
        rdVector_Add3(&padPos[i], pos, &rotated);
        padNormal[i].x = up[0];
        padNormal[i].y = up[1];
        padNormal[i].z = up[2];
        if (up[2] < 0.05f && up[2] > -0.05f) {
            padPos[i].z = padPos[i].z - groundDist;
            padHeight[i] = groundDist;
        } else {
            // project the pad offset onto the ground plane through pos; stays in ST0 in retail
            long double planeZ = (-(rotated.x * up[0]) - rotated.y * up[1]) / up[2] - rotated.z;
            padHeight[i] = groundDist - planeZ;
            padPos[i].z = (planeZ + padPos[i].z) - groundDist;
        }
    }

    rdMatrix44* shadow = &player->shadowXf0;
    if (1.0 <= ((long double)player->lodDistance - 40.0f) * 0.016666668f) {
        for (int i = 0; i < 4; i++)
            shadow[i].vD.z = -100000.0f;
    } else {
        for (int i = 0; i < 4; i++) {
            if (padHeight[i] <= 0.0f) {
                shadow[i].vD.z = -100000.0f;
                continue;
            }
            rdMatrix_SetIdentity44(&mat);
            mat.vC.x = padNormal[i].x;
            mat.vC.y = padNormal[i].y;
            mat.vC.z = padNormal[i].z;
            mat.vB.x = player->transform.vB.x;
            mat.vB.y = player->transform.vB.y;
            mat.vB.z = player->transform.vB.z;
            rdVector_Cross3((rdVector3*)&mat.vA, (rdVector3*)&mat.vB, (rdVector3*)&mat.vC);
            rdVector_Cross3((rdVector3*)&mat.vB, (rdVector3*)&mat.vC, (rdVector3*)&mat.vA);
            mat.vD.x = padPos[i].x;
            mat.vD.y = padPos[i].y;
            mat.vD.z = padPos[i].z;
            rdMatrix_Copy44(&shadow[i], &mat);
            rdMatrix_ScaleBasis44(&shadow[i], 0.004f, 0.004f, 0.004f, &shadow[i]);
        }
    }

    float height = padHeight[1];
    if (padHeight[2] > 0.0f && padHeight[2] < padHeight[1])
        height = padHeight[2];
    if (height >= 0.0f)
        return height - 2.0f;
    if (groundDist < 0.0f)
        return 100000.0f;
    return groundDist;
}

// 0x004764a0
void swrRace_ResetGravityDown(swrRace* player)
{
    player->gravityScale = swrRace_defaultGravityScale * 0.25f;
    player->world_gravity.x = rdVector_negZ.x;
    player->world_gravity.y = rdVector_negZ.y;
    player->world_gravity.z = rdVector_negZ.z;
}

// 0x0047a930
void swrRace_UpdateCollisionToggles(swrRace* player)
{
    const float y = player->transform.vD.y;
    const float x = player->transform.vD.x;
    const float marginY = swrObjTrig_regionMarginY;
    const float marginX = swrObjTrig_regionMarginX;

    // one bit per region row the pod overlaps (rows 0..7 = bits 16..23), widened by the margin
    int rows = 0;
    if (y > swrObjTrig_regionBoundsY[7] - marginY)
        rows = 0x800000;
    for (int row = 6; row >= 1; row--) {
        if (y < marginY + swrObjTrig_regionBoundsY[row + 1] && y > swrObjTrig_regionBoundsY[row] - marginY)
            rows |= 0x10000 << row;
    }
    if (y < marginY + swrObjTrig_regionBoundsY[1])
        rows |= 0x10000;

    // same row bits per column: column 0 in bits 24..31, column 1 in 16..23, column 2 in 8..15
    int toggles = 0;
    if (x > swrObjTrig_regionBoundsX[2] - marginX)
        toggles = rows >> 8;
    if (x < marginX + swrObjTrig_regionBoundsX[2] && x > swrObjTrig_regionBoundsX[1] - marginX)
        toggles |= rows;
    if (x < marginX + swrObjTrig_regionBoundsX[1])
        toggles |= rows << 8;
    player->collisionToggles = toggles;
}

// 0x0047a200
float swrRace_UpdateWallContact(swrRace* player, float* pos, float* prevPos, rdVector3* up)
{
    rdVector3 startPos;
    rdVector3 collideNormal;
    rdMatrix44 splineMat;
    startPos.x = pos[0];
    startPos.y = pos[1];
    startPos.z = pos[2];
    int lodFar = ((float)player->lodDistance - 400.0f) * 0.0016666667f >= 1.0;
    unsigned int flags1 = player->flags1 & ~swrObjTest_FLAG1_AIRBORNE;
    player->flags1 = flags1;

    if (lodFar && !(player->flags0 & swrObjTest_FLAG0_LOCAL) && !(flags1 & swrObjTest_FLAG1_FORCE_GROUND)) {
        // far, non-local pod: ride the spline instead of colliding
        if (((uint8_t)player->flags0 & swrObjTest_FLAG0_STATE_MASK) == swrObjTest_FLAG0_RACING) {
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
            pos[2] = splineMat.vD.z;
        } else {
            pos[2] = 0.0f;
        }
        up->x = 0.0f;
        up->y = 0.0f;
        up->z = 1.0f;
        if (((uint8_t)player->flags0 & swrObjTest_FLAG0_STATE_MASK) == swrObjTest_FLAG0_RACING)
            player->flags1 = player->flags1 | swrObjTest_FLAG1_SPLINE_SNAP;
        return 2.0f;
    }

    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        rdVector3 before;
        rdVector3 wallDelta;
        before.x = pos[0];
        before.y = pos[1];
        before.z = pos[2];
        swrRace_DetectWallScrape(player, pos, prevPos);
        wallDelta.x = player->wallPushback.x + (pos[0] - before.x);
        wallDelta.y = player->wallPushback.y + (pos[1] - before.y);
        wallDelta.z = player->wallPushback.z + (pos[2] - before.z);
        swrRace_ApplyWallCollision(player, &wallDelta, up);
    } else {
        swrRace_CollideBlockMove((rdVector3*)pos, &startPos, player->collisionModel, &collideNormal);
    }
    return 0.0f;
}

// 0x0047a3a0
void swrRace_ApplySmokProximityPush(swrRace* player, rdVector3* pos)
{
    float sign = 1.0f;
    float distSq;
    rdVector3 delta;
    swrObjSmok* smok;
    rdVector3 side;

    if (player->flags1 & swrObjTest_FLAG1_SLIDE_LOCK) {
        double dt = swrRace_deltaTimeSecs;
        player->slide2 = 0.25f;
        // decay the kick toward zero at 100/s, then release the lock
        if (player->contactSteerKick > 0.0f) {
            player->contactSteerKick = player->contactSteerKick - dt * 100.0f;
            if (player->contactSteerKick < 0.0f) {
                player->contactSteerKick = 0.0f;
                player->flags1 = player->flags1 & ~swrObjTest_FLAG1_SLIDE_LOCK;
            }
        } else {
            player->contactSteerKick = player->contactSteerKick - dt * -100.0f;
            if (player->contactSteerKick > 0.0f) {
                player->contactSteerKick = 0.0f;
                player->flags1 = player->flags1 & ~swrObjTest_FLAG1_SLIDE_LOCK;
            }
        }
    }

    if (swrEvent_FindNearestObjects('Smok', pos, 5625.0f, NULL, 1, &distSq, &delta, (void**)&smok) <= 0)
        return;
    float dist = stdMath_Sqrt(distSq);
    if (smok->type != 1) {
        if (smok->type != swrObjSmok_TYPE_FIRE)
            return;
        if (smok->lifetime < 2.0f)
            return;
        sign = -1.0f;
        if (dist < 30.0f && (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25) {
            int engine = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 7.0f + 0.5f);
            if (engine > 5)
                engine = 0;
            player->engineStatus[engine] |= 8;
        }
    }

    float strength = (75.0f - dist) * 0.014285714f * player->podStats.maxTurnRate;
    side.x = delta.y;
    side.y = -delta.x;
    side.z = 0.0f;
    float push;
    if (rdVector_Normalize3Acc(&side) < 0.1f)
        push = 1.0f;
    else
        push = -(player->transform.vA.z * side.z + player->transform.vA.y * side.y + player->transform.vA.x * side.x) * strength;

    if (!(player->flags1 & swrObjTest_FLAG1_SLIDE_LOCK)) {
        player->flags1 = player->flags1 | swrObjTest_FLAG1_SLIDE_LOCK;
        player->contactSteerKick = sign * push;
        return;
    }
    float absPush = push < 0.0f ? -push : push;
    float absKick = player->contactSteerKick < 0.0f ? -player->contactSteerKick : player->contactSteerKick;
    if (absPush > absKick)
        player->contactSteerKick = sign * push;
}

// 0x0047a610
void swrRace_UpdateSplineOrientation(swrRace* player, rdVector3* pos)
{
    rdMatrix44 splineMat;
    rdVector3 target;
    rdVector3 dir;
    rdVector3 toDir;
    rdVector3 forward;
    rdVector3 savedPos;
    rdVector3* vA = (rdVector3*)&player->transform.vA;
    rdVector3* vB = (rdVector3*)&player->transform.vB;
    rdVector3* vC = (rdVector3*)&player->transform.vC;

    if (player->aiLookAhead < 0.01f)
        player->aiLookAhead = 0.01f;
    if (player->aiLookAhead > 2.0f)
        player->aiLookAhead = 2.0f;

    // ease the look-ahead so the cursor-to-target span stays within [18000, 90000] (squared)
    swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
    target.x = splineMat.vD.x;
    target.y = splineMat.vD.y;
    target.z = splineMat.vD.z;
    swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, player->aiLookAhead);
    float dx = target.x - splineMat.vD.x;
    float dy = target.y - splineMat.vD.y;
    float dz = target.z - splineMat.vD.z;
    float spanSq = dz * dz + dy * dy + dx * dx;
    if (spanSq < 18000.0f)
        player->aiLookAhead = player->aiLookAhead + 0.01f;
    else if (spanSq > 90000.0f)
        player->aiLookAhead = player->aiLookAhead - 0.01f;

    target.x = splineMat.vD.x;
    target.y = splineMat.vD.y;
    target.z = splineMat.vD.z;
    rdVector_Sub3(&dir, &target, (rdVector3*)&player->transform.vD);
    rdVector_Normalize3Acc(&dir);
    rdVector_Sub3(&toDir, &dir, vB);
    rdVector_Scale3Add3(&forward, vB, 0.2f, &toDir);

    if (player->flags0 & swrObjTest_FLAG0_ZOFF) {
        player->gravityTubeAngle = player->turnInput.z * 10.0f;
    } else {
        player->gravityTubeAngle = player->gravityTubeAngle - (swrRace_deltaTimeSecs * player->turnRateTarget) * 2;
        player->gravityTubeAngle = player->gravityTubeAngle - swrRace_deltaTimeSecs * player->tiltManualMult * -1000.0f;
        if (player->gravityTubeAngle > 180.0)
            player->gravityTubeAngle = 180.0f;
        if (player->gravityTubeAngle < -180.0)
            player->gravityTubeAngle = -180.0f;
        player->gravityTubeAngle = player->gravityTubeAngle * 0.98f;
    }

    rdVector_Copy3(&savedPos, pos);
    rdVector_Copy3(vB, &forward);
    rdVector_Cross3(vA, vB, vC);
    rdVector_Cross3(vC, vA, vB);
    rdVector_Normalize3Acc(vA);
    rdVector_Normalize3Acc(vB);
    rdVector_Normalize3Acc(vC);
    rdMatrix_AddRotationFromVectorAngle44Before(&player->transform, swrRace_deltaTimeSecs * player->turnRate * 1.5f, 0.0f, 0.0f, 1.0f, &player->transform);
    rdMatrix_AddRotationFromVectorAngle44Before(&player->transform, swrRace_deltaTimeSecs * player->zeroGPitchRate * 1.5f, 1.0f, 0.0f, 0.0f, &player->transform);
    rdMatrix_AddRotationFromVectorAngle44Before(&player->transform, swrRace_deltaTimeSecs * player->gravityTubeAngle, 0.0f, 1.0f, 0.0f, &player->transform);
    rdVector_Copy3((rdVector3*)&player->transform.vD, &savedPos);
    player->tiltAngle = 0.0f;
}

// 0x00479d40
void swrRace_HandleWallScrapeHit(swrRace* player)
{
    rdVector3 sparkPos;
    rdVector3 sparkDir;
    int subEvents[3];

    rdVector_Scale3Add3(&sparkPos, (rdVector3*)&player->transform.vD, 6.0f, &player->bumpDirection);
    sparkDir.x = -player->bumpDirection.x;
    sparkDir.y = -player->bumpDirection.y;
    sparkDir.z = -player->bumpDirection.z;
    swrRace_SetupScrapeSpray(player, 0.2f, 0.0f, &sparkPos, &sparkDir, 2);
    swrMultiplayer_SendEvent(SITH_MESSAGE_TO_ALL, 0, 'Sprk', *(int*)&player->score_ptr->time_unk, (double)0.2f, 0.0, &sparkPos, &sparkDir, 2);
    subEvents[0] = 'Hitt';
    subEvents[1] = 'VhLt';
    *(float*)&subEvents[2] = player->speedLoss;
    swrEvent_DispatchSubEvents(player, subEvents);
}

// 0x0047b0c0
void swrRace_ResolvePodCollision(swrRace* player)
{
    float distances[4];
    rdVector3 deltas[4];
    swrRace* others[4];
    rdVector2 closestA;
    rdVector2 closestB;
    rdVector2 dirA;
    rdVector2 dirB;
    rdVector2 mid;
    rdVector2 momentum;
    rdVector2 contact;
    rdVector2 backA;
    rdVector2 backB;
    rdVector2 normal;
    rdVector2 pushA;
    rdVector2 pushB;
    rdVector2 movedSelf;
    rdVector2 movedOther;

    if (player->flags0 & (swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_RESPAWN_INVINC))
        return;
    if (player->flags1 & swrObjTest_FLAG1_FINISHED)
        return;
    int found = swrEvent_FindNearestObjects('Test', (rdVector3*)&player->transform.vD, 2500.0f, player, 4, distances, deltas, (void**)others);
    player->speedLoss = 0.0f;
    if (found <= 0)
        return;
    swrRace* other = others[0];
    if (other->flags0 & (swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_RESPAWN_INVINC))
        return;
    if (other->flags1 & swrObjTest_FLAG1_FINISHED)
        return;

    float t = swrRace_ClosestApproach2D((rdVector2*)&player->positionPrev, &player->position.x, (rdVector2*)&other->positionPrev, &other->position.x, &closestA, &closestB, &dirA, &dirB);
    if (t < 0.0f)
        return;
    float gapX = closestA.x - closestB.x;
    float gapY = closestA.y - closestB.y;
    if (!(gapY * gapY + gapX * gapX < 100.0f))
        return;
    if (t < 0.01f)
        return;

    // momentum-weighted contact point at the time of closest approach
    rdVector_Scale2(&mid, 0.5f, &closestA);
    rdVector_Scale2Add2(&mid, &mid, 0.5f, &closestB);
    rdVector_Scale2(&momentum, player->podStats.bumpMass, &dirA);
    rdVector_Scale2Add2(&momentum, &momentum, other->podStats.bumpMass, &dirB);
    rdVector_Scale2(&momentum, (1.0f - t) / (other->podStats.bumpMass + player->podStats.bumpMass), &momentum);
    contact.x = momentum.x + mid.x;
    contact.y = momentum.y + mid.y;

    // separate the pods 5 units each along the line between them just before contact
    t = t - 0.05f;
    rdVector_Scale2Add2(&backA, (rdVector2*)&player->positionPrev, t, &dirA);
    rdVector_Scale2Add2(&backB, (rdVector2*)&other->positionPrev, t, &dirB);
    normal.x = backA.x - backB.x;
    normal.y = backA.y - backB.y;
    rdVector_Normalize2Acc(&normal);
    rdVector_Scale2(&pushA, 5.0f, &normal);
    rdVector_Scale2(&pushB, -5.0f, &normal);
    rdVector_Add2((rdVector2*)&player->position, &contact, &pushA);
    rdVector_Add2((rdVector2*)&other->position, &contact, &pushB);

    movedOther.x = other->position.x - other->transform.vD.x;
    movedOther.y = other->position.y - other->transform.vD.y;
    movedSelf.x = player->position.x - player->transform.vD.x;
    player->transform.vD.x = player->position.x;
    movedSelf.y = player->position.y - player->transform.vD.y;
    player->transform.vD.y = player->position.y;
    other->transform.vD.x = other->position.x;
    other->transform.vD.y = other->position.y;

    float impactSpeed = other->speedValue < player->speedValue ? player->speedValue : other->speedValue;

    player->speedLoss = rdVector_Len2(&movedSelf) / swrRace_deltaTimeSecs;
    player->bumpDirection.z = 0.0f;
    player->bumpDirection.x = -normal.x;
    player->bumpDirection.y = -normal.y;
    swrRace_HandleWallScrapeHit(player);
    swrRace_DeathSpeed(player, impactSpeed, player->speedLoss);

    other->speedLoss = rdVector_Len2(&movedOther) / swrRace_deltaTimeSecs;
    other->bumpDirection.x = normal.x;
    other->bumpDirection.z = 0.0f;
    other->bumpDirection.y = normal.y;
    swrRace_HandleWallScrapeHit(other);
    swrRace_DeathSpeed(other, impactSpeed, other->speedLoss);

    player->velocityCollisionOpponent.x = player->velocityCollisionOpponent.x - movedSelf.x * -0.5f;
    player->velocityCollisionOpponent.y = player->velocityCollisionOpponent.y - movedSelf.y * -0.5f;
    other->velocityCollisionOpponent.x = other->velocityCollisionOpponent.x - movedOther.x * -0.5f;
    other->velocityCollisionOpponent.y = other->velocityCollisionOpponent.y - movedOther.y * -0.5f;
}

// 0x0046d6a0
void swrRace_ApplyPartSinkOffset(swrRace* player)
{
    float sink = player->unk11_1;
    swrModel_Node** nodes = player->partNodes;
    if (nodes == NULL)
        return;
    if (nodes[1] != NULL)
        player->engineXfR.vD.z = sink + player->engineXfR.vD.z;
    if (nodes[2] != NULL)
        player->engineXfL.vD.z = sink + player->engineXfL.vD.z;
    if (nodes[3] != NULL)
        player->engineXfR2.vD.z = sink + player->engineXfR2.vD.z;
    if (nodes[4] != NULL)
        player->engineXfL2.vD.z = sink + player->engineXfL2.vD.z;
    if (nodes[5] != NULL)
        player->cockpitXf.vD.z = sink + player->cockpitXf.vD.z;
}

// 0x0046d7a0
void swrRace_PlayEngineSounds(swrRace* player, float gain)
{
    swrScore* score;
    float pitchScale;
    float speedRatio;
    float downThreshold;
    float upThreshold;
    float pitch;
    float volume;
    int muted;
    int numLocal;
    int local;
    int gear;
    short oldGear;
    short newGear;
    int sfx;

    muted = 0;
    // heavier pods get a lower engine pitch
    pitchScale = (1.0f - (swrRacer_PodHandlingData[*player->score_ptr->pilotId].bumpMass - 50.0f) * 0.04347826f) * 0.5f - -0.75f;
    swrSound_UpdateEngineAudio(PlanetID, PlanetTrackNumber, swrRace_LapProgress(&player->splineCursor), player->speedValue);
    if (player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD))
        muted = 1;
    score = player->score_ptr;
    numLocal = swrObjJdge_NumLocalPlayers();
    if (numLocal == 0) {
        local = 0;
    } else {
        local = swrRace_GetLocalPlayerNumberFromScore(score);
        if (local < 0)
            return;
    }
    speedRatio = player->speedValue / score->podStats.maxSpeed;
    if ((player->flags0 & swrObjTest_FLAG0_STATE_MASK) != swrObjTest_FLAG0_RACING) {
        swrRace_engineGear[local] = 0;
        swrRace_brakeSfxTimer[local] = 1.0f;
        swrRace_boostStartSfxPlayed = 0;
    }

    // engine "gear" 0..3 follows speed / max speed with a 0.1 hysteresis
    gear = swrRace_engineGear[local];
    downThreshold = swrRace_engineGearThresholds[gear] - 0.1f;
    if (downThreshold < 0.0f)
        downThreshold = 0.0f;
    oldGear = (short)swrRace_engineGear[local];
    upThreshold = swrRace_engineGearThresholds[gear + 1] - -0.1f;
    if (speedRatio < downThreshold)
        swrRace_engineGear[local] = gear - 1;
    if (speedRatio > upThreshold)
        swrRace_engineGear[local]++;
    if (swrRace_engineGear[local] < 0)
        swrRace_engineGear[local] = 0;
    if (swrRace_engineGear[local] > SWR_ENGINE_SFX_MAX_GEAR)
        swrRace_engineGear[local] = SWR_ENGINE_SFX_MAX_GEAR;
    newGear = (short)swrRace_engineGear[local];
    sfx = (short)(swrRace_engineGear[local] + (local == 0 ? 0xaa : 0xb0));

    if (sfx >= 0) {
        pitch = (swrRace_engineGearPitch[newGear][0] + swrRace_engineGearPitch[newGear][1]) * 0.5f;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.05f)
            swrUtils_Rand(); // result unused
        pitch = pitchScale * pitch;
        if (player->flags1 & swrObjTest_FLAG1_EXPLODING) {
            pitch = pitch * 1.5f;
        } else if (player->flags1 & swrObjTest_FLAG1_AIRBORNE) {
            pitch = 0.25f;
            sfx = local != 0 ? 0xb5 : 0xaf;
        }
        if (!muted)
            swrSound_PlaySpatialRange(sfx, 6, pitch, gain, (rdVector3*)&player->transform.vD, 1, 0, 20.0f, 500.0f);
    }

    if ((player->flags1 & swrObjTest_FLAG1_BOOST_START) && swrRace_boostStartSfxPlayed == 0) {
        swrRace_boostStartSfxPlayed = 1;
        swrUtils_Rand(); // result unused
        if (!muted)
            swrSound_PlaySpatialRange(0x72, 7, 0.25f, gain, (rdVector3*)&player->transform.vD, 0, 1, 10.0f, 500.0f);
    }

    // throttle above half: extra engine layer, single local player only
    if (player->throttle > 0.5f && numLocal == 1) {
        pitch = pitchScale * 0.2f;
        sfx = local != 0 ? 0xb4 : 0xae;
        volume = gain * 1.3f;
        if (volume > 1.0f)
            volume = 1.0f;
        if (player->flags1 & swrObjTest_FLAG1_AIRBORNE)
            volume = volume * 0.3f;
        if (!muted)
            swrSound_PlaySpatialRange(sfx, 6, pitch, volume, (rdVector3*)&player->transform.vD, 1, 0, 10.0f, 500.0f);
    }

    // brake on/off one-shots, rate-limited by a 1 s ramp
    if (player->flags0 & swrObjTest_FLAG0_BRAKING) {
        if (swrRace_brakeSfxTimer[local] == 1.0f && !muted)
            swrSound_PlaySpatialRange(0x80, 6, pitchScale * 0.25f, gain, (rdVector3*)&player->transform.vD, 0, 1, 10.0f, 500.0f);
        swrRace_brakeSfxTimer[local] = swrRace_brakeSfxTimer[local] - swrRace_deltaTimeSecs;
        if (swrRace_brakeSfxTimer[local] < 0.0f)
            swrRace_brakeSfxTimer[local] = 0.0f;
    } else {
        if (swrRace_brakeSfxTimer[local] == 0.0f && !muted)
            swrSound_PlaySpatialRange(0x7f, 6, pitchScale * 0.25f, gain, (rdVector3*)&player->transform.vD, 0, 1, 10.0f, 500.0f);
        swrRace_brakeSfxTimer[local] = swrRace_brakeSfxTimer[local] + swrRace_deltaTimeSecs;
        if (swrRace_brakeSfxTimer[local] > 1.0f)
            swrRace_brakeSfxTimer[local] = 1.0f;
    }

    if (oldGear > newGear) {
        swrUtils_Rand(); // results unused
        swrUtils_Rand();
        return;
    }
    if (oldGear < newGear) {
        // gear-up whoosh with a random pitch (0.1..0.25) and gain (0.3..0.6)
        pitch = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.1 - -0.15) * pitchScale;
        volume = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.30000000000000004 - -0.5) * gain;
        if (!muted)
            swrSound_PlaySpatialRange(0x7a, 6, pitch, volume, (rdVector3*)&player->transform.vD, 0, 1, 10.0f, 500.0f);
    }
}

// Engine-side tilt envelope: 0 outside [0, 2], ramps up to 1 and back down.
static float engineTiltEnvelope(float tilt)
{
    if (tilt < 0.0f || tilt > 2.0f)
        return 0.0f;
    if (tilt > 1.0f)
        return 2.0f - tilt;
    return tilt;
}

// 0x0046dcd0
RETAIL_FP void swrRace_TiltEngines(swrRace* player)
{
    // target and smoothed stay in ST0 in retail; only the stored engineTiltSmoothed rounds
    long double target = 0.0f;
    if (player->pitch < 0.0f)
        target = player->pitch * -15.0f;
    if (player->speedValue < 100.0f)
        target = 0.0f;
    float tilt = player->tiltAngle * 0.022222223f;
    long double smoothed = (target - player->engineTiltSmoothed) * 0.1f + player->engineTiltSmoothed;
    player->engineTiltSmoothed = (float)smoothed;
    float right = engineTiltEnvelope(tilt);
    float left = engineTiltEnvelope(-tilt);
    float angleRight = (right * 0.5f + 1.0f) * smoothed;
    float angleLeft = (left * 0.5f + 1.0f) * smoothed;
    float lift = smoothed * 0.01f;
    if (player->partNodes[1] != NULL) {
        rdMatrix_AddRotationFromVectorAngle44Before(&player->engineXfR, angleRight, 1.0f, 0.0f, 0.0f, &player->engineXfR);
        player->engineXfR.vD.z = lift + player->engineXfR.vD.z;
    }
    if (player->partNodes[2] != NULL) {
        rdMatrix_AddRotationFromVectorAngle44Before(&player->engineXfL, angleLeft, 1.0f, 0.0f, 0.0f, &player->engineXfL);
        player->engineXfL.vD.z = lift + player->engineXfL.vD.z;
    }
}

// 0x0046e2c0
void swrRace_AnimateEngineWobble(swrRace* player)
{
    rdVector3 push;
    rdVector3 toPod;
    float sinPhase;
    float cosPhase;
    // retail reads these uninitialized when the matching main engine node is missing
    float bobRight = 0.0f;
    float bobLeft;

    if (player->partNodes == NULL)
        return;
    int pilot = *player->score_ptr->pilotId;
    for (int i = 0; i < 4; i++)
        player->wobblePhase[i] = (float)(swrRace_deltaTimeSecs + player->wobblePhase[i]);
    if ((player->flags0 & swrObjTest_FLAG0_HIT_BOTTOM) != 0)
        player->wobbleAmplitude = 1.0f;
    // grows below 200 speed, decays above it
    if (player->speedValue > 200.0f)
        player->wobbleAmplitude = (float)(player->wobbleAmplitude - swrRace_deltaTimeSecs * 0.5f);
    else
        player->wobbleAmplitude = (float)(player->wobbleAmplitude - swrRace_deltaTimeSecs * -0.5f);
    if (player->wobbleAmplitude < 0.4f)
        player->wobbleAmplitude = 0.4f;
    else if (player->wobbleAmplitude > 1.0f)
        player->wobbleAmplitude = 1.0f;

    // collision push direction; engines on the struck side are shoved along it
    push.x = player->velocityCollision.x + player->velocityCollisionOpponent.x;
    push.y = player->velocityCollision.y + player->velocityCollisionOpponent.y;
    push.z = player->velocityCollision.z + player->velocityCollisionOpponent.z;
    float pushSq = push.x * push.x + push.y * push.y + push.z * push.z;
    // pushSq doubles as the left bob when there is no left engine
    bobLeft = pushSq;
    if (pushSq > 0.5f) {
        rdVector_Normalize3Acc(&push);
    } else {
        push.x = 0.0f;
        push.y = 0.0f;
        push.z = 0.0f;
    }

    float amplitude = player->wobbleAmplitude * 0.4f;
    if (player->partNodes[1] != NULL) {
        stdMath_SinCos(player->wobblePhase[0] * 72.0f, &sinPhase, &cosPhase);
        rdVector_Scale3Add3((rdVector3*)&player->engineXfR.vD, (rdVector3*)&player->engineXfR.vD, sinPhase * amplitude, (rdVector3*)&player->engineXfR.vC);
        if (player->engineXfR.vA.y * push.y + player->engineXfR.vA.x * push.x + player->engineXfR.vA.z * push.z < 0.0f)
            rdVector_Scale3Add3((rdVector3*)&player->engineXfR.vD, (rdVector3*)&player->engineXfR.vD, pushSq / (pushSq + 30.0f), &push);
        bobRight = sinPhase * amplitude;
    }
    amplitude = player->wobbleAmplitude * 0.4f;
    if (player->partNodes[2] != NULL) {
        stdMath_SinCos(player->wobblePhase[1] * 79.200005f, &sinPhase, &cosPhase);
        rdVector_Scale3Add3((rdVector3*)&player->engineXfL.vD, (rdVector3*)&player->engineXfL.vD, sinPhase * amplitude, (rdVector3*)&player->engineXfL.vC);
        if (player->engineXfL.vA.x * push.x + player->engineXfL.vA.y * push.y + player->engineXfL.vA.z * push.z > 0.0f)
            rdVector_Scale3Add3((rdVector3*)&player->engineXfL.vD, (rdVector3*)&player->engineXfL.vD, pushSq / (pushSq + 30.0f), &push);
        bobLeft = sinPhase * amplitude;
    }
    amplitude = player->wobbleAmplitude * 0.2f;
    if (player->partNodes[5] != NULL) {
        stdMath_SinCos(player->wobblePhase[2] * 86.4f, &sinPhase, &cosPhase);
        rdVector_Scale3Add3((rdVector3*)&player->cockpitXf.vD, (rdVector3*)&player->cockpitXf.vD, sinPhase * amplitude, (rdVector3*)&player->cockpitXf.vC);
    }
    if (player->partNodes[3] != NULL)
        rdVector_Scale3Add3((rdVector3*)&player->engineXfR2.vD, (rdVector3*)&player->engineXfR2.vD, (bobRight + bobRight + bobLeft) * 0.5f, (rdVector3*)&player->engineXfR2.vC);
    if (player->partNodes[4] != NULL)
        rdVector_Scale3Add3((rdVector3*)&player->engineXfL2.vD, (rdVector3*)&player->engineXfL2.vD, (bobLeft + bobLeft + bobRight) * 0.5f, (rdVector3*)&player->engineXfL2.vC);
    swrRace_TiltEngines(player);
    swrRace_AnimateSpinoutEngines(player);
    if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
        return;

    // keep the cockpit within its tether length of the pod origin
    float tether = swrRacer_PodVisualData[pilot].hoverPadOffsetA.y * 1.5f;
    if (tether < 0.0f)
        tether = -tether;
    if (player->partNodes[5] == NULL)
        return;
    toPod.x = player->transform.vD.x - player->cockpitXf.vD.x;
    toPod.y = player->transform.vD.y - player->cockpitXf.vD.y;
    toPod.z = player->transform.vD.z - player->cockpitXf.vD.z;
    if (tether * tether < toPod.x * toPod.x + toPod.y * toPod.y + toPod.z * toPod.z) {
        float dist = rdVector_Normalize3Acc(&toPod);
        rdVector_Scale3Add3((rdVector3*)&player->cockpitXf.vD, (rdVector3*)&player->cockpitXf.vD, dist - tether, &toPod);
    }
}

// 0x0046dea0
void swrRace_AnimateSpinoutEngines(swrRace* player)
{
    float dir;
    int engine;
    rdMatrix44* engineXf;
    rdMatrix44 tmp;
    rdVector3 axis;
    rdVector3 cockpitAxis;
    rdVector3 savedPos;

    if (!(player->flags0 & swrObjTest_FLAG0_LOCAL) && !(player->flags1 & swrObjTest_FLAG1_FORCE_GROUND))
        return;
    if (player->flags1 & swrObjTest_FLAG1_EXPLODING_LEFT) {
        dir = -1.0f;
    } else if (player->flags1 & swrObjTest_FLAG1_EXPLODING_RIGHT) {
        dir = 1.0f;
    } else {
        dir = 0.0f;
        player->spinoutSpinRamp = 0.0f;
        player->spinoutCockpitAngle = 0.0f;
        player->spinoutEngineAngle = 0.0f;
    }
    if (dir == 0.0f)
        return;

    player->spinoutSpinRamp = player->spinoutSpinRamp - swrRace_deltaTimeSecs * -0.5;
    if (player->spinoutSpinRamp > 1.0f)
        player->spinoutSpinRamp = 1.0f;

    engine = dir > 0.0f ? 1 : 2;
    engineXf = &(&player->unk350_mat)[engine];
    player->spinoutEngineAngle = player->spinoutEngineAngle - dir * swrRace_deltaTimeSecs * player->spinoutSpinRamp * -360.0;
    rdMatrix_Copy44(&tmp, engineXf);
    // the first two axis writes are dead: the spin axis is always overwritten below
    rdVector_Scale3Add3(&axis, (rdVector3*)&tmp.vB, 0.0f, (rdVector3*)&tmp.vA);
    rdVector_Copy3(&axis, (rdVector3*)&tmp.vB);
    rdVector_Set3(&axis, 0.0f, 1.0f, 0.0f);
    rdVector_Normalize3Acc(&axis);
    rdVector_Copy3(&savedPos, (rdVector3*)&engineXf->vD);
    rdMatrix_AddRotationFromVectorAngle44Before(engineXf, player->spinoutEngineAngle, axis.x, axis.y, axis.z, engineXf);
    rdVector_Copy3((rdVector3*)&engineXf->vD, &savedPos);
    if (player->partNodes[engine] != NULL)
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[engine], engineXf);

    player->spinoutCockpitAngle = player->spinoutCockpitAngle - dir * swrRace_deltaTimeSecs * player->spinoutSpinRamp * -600.0;
    rdMatrix_Copy44(&tmp, &player->cockpitXf);
    rdVector_Scale3Add3(&cockpitAxis, (rdVector3*)&tmp.vB, 0.0f, (rdVector3*)&tmp.vA);
    rdVector_Copy3(&cockpitAxis, (rdVector3*)&tmp.vB);
    rdVector_Set3(&cockpitAxis, dir * 0.5f, 1.0f, 0.0f);
    rdVector_Normalize3Acc(&cockpitAxis);
    rdVector_Copy3(&savedPos, (rdVector3*)&player->cockpitXf.vD);
    rdMatrix_AddRotationFromVectorAngle44Before(&player->cockpitXf, player->spinoutCockpitAngle, cockpitAxis.x, cockpitAxis.y, cockpitAxis.z, &player->cockpitXf);
    rdVector_Copy3((rdVector3*)&player->cockpitXf.vD, &savedPos);
    if (player->partNodes[5] != NULL)
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[5], &player->cockpitXf);
}

// 0x0046e150
void swrRace_UpdateSpinoutNodes(swrRace* player)
{
    if (!(player->flags0 & swrObjTest_FLAG0_LOCAL) && !(player->flags1 & swrObjTest_FLAG1_FORCE_GROUND))
        return;
    swrModel_Node** nodes = player->partNodes;
    // hide the parts left behind by a one-sided spinout
    if (player->flags1 & swrObjTest_FLAG1_EXPLODING_LEFT) {
        if (nodes[1] != NULL)
            swrModel_NodeModifyFlags(nodes[1], 2, -4, 0x10, 3);
        if (nodes[6] != NULL)
            swrModel_NodeModifyFlags(nodes[6], 2, -4, 0x10, 3);
        if (nodes[10] != NULL)
            swrModel_NodeModifyFlags(nodes[10], 2, -4, 0x10, 3);
        if (nodes[0x3e] != NULL)
            swrModel_NodeModifyFlags(nodes[0x3e], 2, -4, 0x10, 3);
        if (nodes[0x43] != NULL)
            swrModel_NodeModifyFlags(nodes[0x43], 2, -4, 0x10, 3);
    } else if (player->flags1 & swrObjTest_FLAG1_EXPLODING_RIGHT) {
        if (nodes[2] != NULL)
            swrModel_NodeModifyFlags(nodes[2], 2, -4, 0x10, 3);
        if (nodes[6] != NULL)
            swrModel_NodeModifyFlags(nodes[6], 2, -4, 0x10, 3);
        if (nodes[11] != NULL)
            swrModel_NodeModifyFlags(nodes[11], 2, -4, 0x10, 3);
        if (nodes[0x3f] != NULL)
            swrModel_NodeModifyFlags(nodes[0x3f], 2, -4, 0x10, 3);
        if (nodes[0x44] != NULL)
            swrModel_NodeModifyFlags(nodes[0x44], 2, -4, 0x10, 3);
    }
}

// 0x0046f0e0
void swrRace_BuildStretchedQuad(rdMatrix44* a, rdMatrix44* b, float mirrorX, float mirrorZ, int pilot, rdMatrix44* out)
{
    const swrRacerVisualData* visual = &swrRacer_PodVisualData[pilot];
    rdVector3 start;
    rdVector3 end;
    rdVector3 startOffset;
    rdVector3 endOffset;
    rdVector3 dir;
    rdMatrix44 m;
    float length;

    rdVector_Copy3(&start, (rdVector3*)&a->vD);
    rdVector_Copy3(&end, (rdVector3*)&b->vD);
    startOffset.x = visual->cableCockpitAnchor.x * mirrorX;
    startOffset.y = visual->cableCockpitAnchor.y;
    startOffset.z = visual->cableCockpitAnchor.z;
    endOffset.y = visual->cableEngineAnchor.y;
    endOffset.x = visual->cableEngineAnchor.x * mirrorX;
    endOffset.z = visual->cableEngineAnchor.z * mirrorZ;
    rdMatrix_Multiply3(&startOffset, &startOffset, a);
    rdVector_Add3(&start, &startOffset, &start);
    rdMatrix_Multiply3(&endOffset, &endOffset, b);
    rdVector_Add3(&end, &endOffset, &end);

    // unit quad along +Y from start to end, scaled to the cable length
    rdVector_Sub3(&dir, &start, &end);
    length = rdVector_Len3(&dir);
    rdVector_Normalize3Acc(&dir);
    rdMatrix_SetTranslation44(&m, start.x, start.y, start.z);
    rdVector_Copy3((rdVector3*)&m.vB, &dir);
    rdVector_Set3((rdVector3*)&m.vC, 0.0f, 0.0f, 1.0f);
    rdVector_Cross3((rdVector3*)&m.vA, (rdVector3*)&m.vB, (rdVector3*)&m.vC);
    rdVector_Cross3((rdVector3*)&m.vC, (rdVector3*)&m.vA, (rdVector3*)&m.vB);
    rdMatrix_ScaleBasis44(&m, 0.004f, length * 0.01f, 0.004f, &m);
    rdMatrix_Copy44(out, &m);
}

// 0x00470510
RETAIL_FP long double swrRace_SmoothEngineExhaustSize(swrRace* player, int part, float target, float brakeTarget, float lowerRate, float upperRate, float min, float max)
{
    float* value = &player->partOffset[part].y;
    float current = *value;
    long double result; // retail returns the finished-pod average unrounded (FST, not FSTP)

    lowerRate *= swrRace_deltaTimeSecs;
    upperRate *= swrRace_deltaTimeSecs;
    if (player->flags0 & swrObjTest_FLAG0_BOOSTING)
        target *= 0.5f;
    if (player->flags0 & swrObjTest_FLAG0_BRAKING) {
        upperRate += upperRate;
        target = brakeTarget;
    }
    result = swrMath_StepTowardClamped(target, current, min, max, upperRate, lowerRate);
    if (player->flags1 & swrObjTest_FLAG1_FINISHED)
        result = (result + current) * 0.5f;
    *value = result;
    return result;
}

// 0x004705d0
void swrRace_ExtrapolateTransform(swrRace* player, rdMatrix44* out, rdMatrix44* in, float dt)
{
    rdMatrix_Copy44(out, in);
    rdVector_Scale3Add3((rdVector3*)&out->vD, (rdVector3*)&out->vD, player->speedValue * dt, (rdVector3*)&out->vB);
}

// 0x004709a0
void swrRace_UpdateReflectionNode(swrRace* player)
{
    swrModel_Node* node = player->reflectionNode;
    if (node == NULL)
        return;
    int hide = !(player->flags1 & swrObjTest_FLAG1_ON_MIRR) || (player->flags0 & (swrObjTest_FLAG0_DEAD | swrObjTest_FLAG0_POD_HIDDEN));
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_DEBUG_KEYS) && swrRace_DebugLevel != 0 && (inRaceLocalPlayerInputBitset3[0] & 0x1000))
        hide = 1;
    if (hide) {
        swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
        return;
    }
    swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
    swrModel_NodeSetTranslation((swrModel_NodeTransformed*)player->reflectionNode, 0.0f, 0.0f, (player->groundZ + player->groundZ) - 3.0f);
}

// 0x00470a40
void swrRace_UpdateEngineSound(swrRace* player)
{
    if (!(player->flags0 & swrObjTest_FLAG0_LOCAL) && !(player->flags1 & swrObjTest_FLAG1_FORCE_GROUND)) {
        if (!(player->flags0 & swrObjTest_FLAG0_AI_SIMPLE) || swrObjJdge_NumLocalPlayers() != 0) {
            if ((double)player->lodDistance < 500.0) {
                swrRace_aiEngineLoopPlayed = 0;
                swrSound_PlaySpatialRange((short)((*(uint8_t*)player->score_ptr->pilotId & 1) + 0xa6 + swrRace_aiEngineLoopSoundBase), 4, 0.25f, 1.0f, (rdVector3*)&player->transform.vD, 1, 0, 10.0f, 5000.0f);
            }
            return;
        }
    }
    swrRace_PlayEngineSounds(player, 0.7f);
}

// 0x0046ecd0
RETAIL_FP void swrRace_ApplyEngineProximityPush(swrRace* player, float* otherPos, rdVector3* out)
{
    rdVector3 pos;
    rdVector3 fromRight;
    rdVector3 fromLeft;
    float halfWidth;
    long double distRight;
    long double distLeft;
    float distLeftSpill;
    float push;

    if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
        return;

    pos.x = otherPos[0];
    pos.y = otherPos[1];
    pos.z = otherPos[2];
    rdVector_Sub3(&fromRight, &pos, (rdVector3*)&player->engineXfR.vD);
    rdVector_Sub3(&fromLeft, &pos, (rdVector3*)&player->engineXfL.vD);
    // both dots stay in ST0; the left one is also spilled and the spill reused
    distRight = (fromRight.x * player->engineXfR.vA.x + player->engineXfR.vA.y * fromRight.y) + player->engineXfR.vA.z * fromRight.z;
    distLeft = (fromLeft.x * player->engineXfL.vA.x + player->engineXfL.vA.y * fromLeft.y) + player->engineXfL.vA.z * fromLeft.z;
    distLeftSpill = (float)distLeft;
    halfWidth = player->footprintX * 0.5f;

    if (distLeft * distLeftSpill <= distRight * distRight) {
        push = -(halfWidth + distLeftSpill);
        if (push <= 0.0f)
            return;
        rdVector_Scale3Add3(out, &pos, push, (rdVector3*)&player->engineXfL.vA);
    } else {
        push = -(distRight - halfWidth);
        if (push >= 0.0f)
            return;
        rdVector_Scale3Add3(out, &pos, push, (rdVector3*)&player->engineXfR.vA);
    }
}

// 0x0046ee20
void swrRace_UpdateScrapeSparks(swrRace* player)
{
    swrModel_Node** nodes = player->partNodes;

    if (nodes == NULL)
        return;

    if (player->flags0 & swrObjTest_FLAG0_SCRAPE_SPARK_R) {
        if (nodes[1] != NULL) {
            swrRace_ApplyEngineProximityPush(player, (float*)&player->scrapeSparkXf.vD, (rdVector3*)&player->scrapeSparkXf.vD);
            rdMatrix_ScaleBasis44(&player->scrapeSparkXf, 3.0f, 3.0f, 3.0f, &player->scrapeSparkXf);
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[0x41], &player->scrapeSparkXf);
        }
        player->flags0 &= ~swrObjTest_FLAG0_SCRAPE_SPARK_R;
        if (player->partNodes[0x41] != NULL)
            swrModel_NodeModifyFlags(player->partNodes[0x41], 2, 3, 0x10, 2);
        // -0.75 is the double at 0x004ada08: re-arm a timer that sits too far ahead
        if (timetotal - -0.75 < swrRace_scrapeSparkSoundTime)
            swrRace_scrapeSparkSoundTime = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.25f - -0.5f + timetotal;
        if (swrRace_scrapeSparkSoundTime < timetotal) {
            swrSound_PlaySpatialRange(0x3c, 5, (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.19999999f - -0.3f, 0.6f, (rdVector3*)&player->transform.vD, 0, 0, 10.0f, 500.0f);
            swrRace_scrapeSparkSoundTime = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.25f - -0.5f + timetotal;
        }
    } else if (nodes[0x41] != NULL) {
        swrModel_NodeModifyFlags(nodes[0x41], 2, -4, 0x10, 3);
    }

    if (player->flags0 & swrObjTest_FLAG0_SCRAPE_SPARK_L) {
        if (player->partNodes[1] != NULL) {
            swrRace_ApplyEngineProximityPush(player, (float*)&player->scrapeSparkXf2.vD, (rdVector3*)&player->scrapeSparkXf2.vD);
            rdMatrix_ScaleBasis44(&player->scrapeSparkXf2, 2.0f, 2.0f, 2.0f, &player->scrapeSparkXf2);
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[0x42], &player->scrapeSparkXf2);
        }
        if (player->partNodes[0x42] != NULL)
            swrModel_NodeModifyFlags(player->partNodes[0x42], 2, 3, 0x10, 2);
        player->flags0 &= ~swrObjTest_FLAG0_SCRAPE_SPARK_L;
        if (swrRace_scrapeSparkSoundTime < timetotal) {
            swrSound_PlaySpatialRange(0x3c, 5, (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.19999999f - -0.3f, 0.6f, (rdVector3*)&player->transform.vD, 0, 0, 10.0f, 500.0f);
            swrRace_scrapeSparkSoundTime = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.25f - -0.5f + timetotal;
        }
    } else if (player->partNodes[0x42] != NULL) {
        swrModel_NodeModifyFlags(player->partNodes[0x42], 2, -4, 0x10, 3);
    }
}

// Index of the transform recorded `lag` frames before the newest one.
static int podHistoryIndex(int writeIdx, int lag)
{
    int index = writeIdx - lag;
    if (index < 0)
        index += ((unsigned int)(SWR_POD_TRANSFORM_HISTORY - 1 - index) / SWR_POD_TRANSFORM_HISTORY) * SWR_POD_TRANSFORM_HISTORY;
    return index;
}

// Blend a lagged pod frame toward the current one and re-orthonormalize it.
static void podBlendHistoryFrame(rdMatrix44* lagged, const rdMatrix44* current, float weight)
{
    rdVector_Scale3Add3((rdVector3*)&lagged->vA, (rdVector3*)&lagged->vA, weight, (rdVector3*)&current->vA);
    rdVector_Scale3Add3((rdVector3*)&lagged->vB, (rdVector3*)&lagged->vB, weight, (rdVector3*)&current->vB);
    rdVector_Scale3Add3((rdVector3*)&lagged->vC, (rdVector3*)&lagged->vC, weight, (rdVector3*)&current->vC);
    rdVector_Cross3((rdVector3*)&lagged->vA, (rdVector3*)&lagged->vB, (rdVector3*)&lagged->vC);
    rdVector_Cross3((rdVector3*)&lagged->vC, (rdVector3*)&lagged->vA, (rdVector3*)&lagged->vB);
    rdVector_Normalize3Acc((rdVector3*)&lagged->vA);
    rdVector_Normalize3Acc((rdVector3*)&lagged->vB);
    rdVector_Normalize3Acc((rdVector3*)&lagged->vC);
}

// Move a pod-local offset into the frame of `pod` and add it to m's translation.
static void podAddLocalOffset(rdMatrix44* m, const rdMatrix44* pod, float x, float y, float z)
{
    rdVector_Scale3Add3((rdVector3*)&m->vD, (rdVector3*)&m->vD, x, (rdVector3*)&pod->vA);
    rdVector_Scale3Add3((rdVector3*)&m->vD, (rdVector3*)&m->vD, y, (rdVector3*)&pod->vB);
    rdVector_Scale3Add3((rdVector3*)&m->vD, (rdVector3*)&m->vD, z, (rdVector3*)&pod->vC);
}

// 0x00470ae0
RETAIL_FP void swrRace_PoddAnimateEngines(swrRace* player)
{
    rdMatrix44 podXf;
    rdMatrix44 lagEngines;
    rdMatrix44 lagCockpit;
    rdMatrix44 m;
    rdVector3 offset;
    rdVector3 lagDelta;
    rdVector3 springTarget;
    rdVector3 springPos;
    int hasSecondEngines = 0;
    int isFused = 0;
    // only read while swrObjJdge_splitscreenActive is set
    int localPlayer = -1;
    swrModel_Node* node;

    rdMatrix_Copy44(&podXf, &player->transform);
    if (swrRace_creditsMode != 0)
        player->flags0 |= swrObjTest_FLAG0_POD_HIDDEN;
    int hidden = player->flags0 & (swrObjTest_FLAG0_POD_HIDDEN | swrObjTest_FLAG0_DEAD);
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_DEBUG_KEYS) != 0 && swrRace_DebugLevel != 0 && (inRaceLocalPlayerInputBitset3[0] & 0x1000) != 0)
        hidden = 1;
    if (swrObjJdge_splitscreenActive != 0) {
        if (swrObjJdge_NumLocalPlayers() == 0)
            localPlayer = -1;
        else
            localPlayer = swrRace_GetLocalPlayerNumberFromScore(player->score_ptr);
    }

    if (player->partNodes == NULL) {
        rdMatrix_ScaleBasis44(&player->farLodPodXf, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, &podXf);
        if (hidden != 0 && (player->flags0 & (swrObjTest_FLAG0_RESET | swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) != 0) {
            if (player->lodBodyNode != NULL)
                swrModel_NodeModifyFlags(player->lodBodyNode, 2, -4, 0x10, 3);
            if (player->lodSelectorNode != NULL)
                swrModel_NodeModifyFlags(player->lodSelectorNode, 2, -4, 0x10, 3);
        } else {
            if (player->lodBodyNode != NULL)
                swrModel_NodeModifyFlags(player->lodBodyNode, 2, 3, 0x10, 2);
            if (player->lodSelectorNode != NULL)
                swrModel_NodeModifyFlags(player->lodSelectorNode, 2, 3, 0x10, 2);
        }
        if (swrObjJdge_splitscreenActive != 0 && localPlayer >= 0) {
            if ((player->flags0 & (swrObjTest_FLAG0_POD_HIDDEN | swrObjTest_FLAG0_DEAD)) == swrObjTest_FLAG0_POD_HIDDEN) {
                (&swrModel_Node1)[localPlayer] = player->lodBodyNode;
                (&swrModel_Node3)[localPlayer] = player->lodSelectorNode;
            } else {
                (&swrModel_Node1)[localPlayer] = NULL;
                (&swrModel_Node3)[localPlayer] = NULL;
            }
        }
        if (swrMultiplayer_IsMultiplayerEnabled() == 0)
            return;
        if (player->lodBodyNode != NULL)
            swrModel_NodeModifyFlags(player->lodBodyNode, 2, 3, 0x10, 2);
        if (player->lodSelectorNode != NULL)
            swrModel_NodeModifyFlags(player->lodSelectorNode, 2, 3, 0x10, 2);
        return;
    }

    node = player->partNodes[0];
    if (hidden != 0) {
        if (node != NULL)
            swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
    } else if (node != NULL) {
        swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
    }
    if (swrObjJdge_splitscreenActive != 0) {
        // unlike the far-LOD path, localPlayer is not range-checked here
        if ((player->flags0 & (swrObjTest_FLAG0_POD_HIDDEN | swrObjTest_FLAG0_DEAD)) == swrObjTest_FLAG0_POD_HIDDEN)
            (&swrModel_Node1)[localPlayer] = player->partNodes[0];
        else
            (&swrModel_Node1)[localPlayer] = NULL;
    }

    // cockpit follow strength: 1 at rest, 0 at 200+ speed or in zero-g
    // stays in ST0 in retail until squared
    long double followRaw = 1.0f - player->speedValue * 0.005f;
    if ((player->flags0 & (swrObjTest_FLAG0_ZON | swrObjTest_FLAG0_ZOFF)) != 0)
        followRaw = 0.0f;
    if (!(followRaw >= 0.0f))
        followRaw = 0.0f;
    if (followRaw > 1.0f)
        followRaw = 1.0f;
    float follow = followRaw * followRaw;

    if (player->partNodes[0x3b] != NULL)
        swrModel_NodeModifyFlags(player->partNodes[0x3b], 2, 3, 0x10, 2);
    if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
        isFused = 1;
    if (player->partNodes[3] != NULL && player->partNodes[4] != NULL)
        hasSecondEngines = 1;
    if (player->partNodes[0] != NULL)
        swrModel_NodeSetSelectedChildNode((swrModel_NodeSelector*)player->partNodes[0], 0);

    player->historyWriteIdx = (unsigned int)(player->historyWriteIdx + 1) % SWR_POD_TRANSFORM_HISTORY;
    player->historyLagEngines = 16;
    player->historyLagCockpit = 10;
    rdMatrix_Copy44(&player->transformHistory[player->historyWriteIdx], &podXf);
    if (player->lodDistance > 75 || player->partNodes == NULL || isFused) {
        rdMatrix_Copy44(&lagEngines, &podXf);
        rdMatrix_Copy44(&lagCockpit, &podXf);
    } else {
        rdMatrix_Copy44(&lagEngines, &player->transformHistory[podHistoryIndex(player->historyWriteIdx, player->historyLagEngines)]);
        rdMatrix_Copy44(&lagCockpit, &player->transformHistory[podHistoryIndex(player->historyWriteIdx, player->historyLagCockpit)]);
        // the history advances a second time this frame
        player->historyWriteIdx = (unsigned int)(player->historyWriteIdx + 1) % SWR_POD_TRANSFORM_HISTORY;
        rdMatrix_Copy44(&player->transformHistory[player->historyWriteIdx], &podXf);
        rdMatrix_Copy44(&lagEngines, &player->transformHistory[podHistoryIndex(player->historyWriteIdx, player->historyLagEngines)]);
        rdMatrix_Copy44(&lagCockpit, &player->transformHistory[podHistoryIndex(player->historyWriteIdx, player->historyLagCockpit)]);
        podBlendHistoryFrame(&lagEngines, &podXf, 0.1f);
        podBlendHistoryFrame(&lagCockpit, &podXf, 0.2f);
    }

    if (isFused) {
        rdMatrix_Copy44(&player->cockpitXf, &podXf);
        swrRace_AnimateEngineWobble(player);
        return;
    }

    // cockpit: lagged frame at the cockpit offset, then a lag spring on its position
    const swrRacerVisualData* visual = &swrRacer_PodVisualData[*player->score_ptr->pilotId];
    rdVector_Copy3(&offset, &visual->hoverPadOffsetA);
    rdVector_Add3(&offset, &offset, &player->partOffset[5]);
    rdMatrix_Copy44(&m, &lagCockpit);
    rdVector_Copy3((rdVector3*)&m.vD, (rdVector3*)&podXf.vD);
    podAddLocalOffset(&m, &podXf, offset.x, offset.y, offset.z);
    float pitch = podXf.vB.x * player->world_gravity.x + podXf.vB.z * player->world_gravity.z + podXf.vB.y * player->world_gravity.y;
    rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, (pitch - player->cockpitPitchPrev) * 50.0f, (rdVector3*)&podXf.vC);
    player->cockpitPitchPrev = pitch;
    rdVector_Sub3(&lagDelta, (rdVector3*)&m.vD, (rdVector3*)&podXf.vD);
    rdVector_Sub3(&springTarget, &lagDelta, &player->cockpitSpringPos);
    float stretch = rdVector_Len3(&springTarget);
    rdVector_Normalize3Acc(&springTarget);
    rdVector_Scale3Add3(&player->cockpitSpringVel, &player->cockpitSpringVel, (float)(swrRace_deltaTimeSecs * stretch * 20.0f), &springTarget);
    rdVector_Scale3(&player->cockpitSpringVel, stdMath_Decelerator(10.0f, (float)swrRace_deltaTimeSecs), &player->cockpitSpringVel);
    rdVector_Scale3Add3(&springPos, &player->cockpitSpringPos, (float)swrRace_deltaTimeSecs, &player->cockpitSpringVel);
    if ((player->flags0 & swrObjTest_FLAG0_RACING) == 0) {
        rdVector_Copy3(&springPos, &lagDelta);
        rdVector_Set3(&player->cockpitSpringVel, 0.0f, 0.0f, 0.0f);
    }
    rdVector_Sub3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &lagDelta);
    rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &springPos);
    rdVector_Copy3(&player->cockpitSpringPos, &springPos);
    // FST: the upper clamp tests the unrounded ST0, the lower one the stored float
    long double rollRaw = (player->cockpitSpringVel.y * player->world_gravity.y + player->cockpitSpringVel.z * player->world_gravity.z + player->cockpitSpringVel.x * player->world_gravity.x) * -2.0f;
    float roll = rollRaw;
    if (rollRaw > 50.0)
        roll = 50.0f;
    if (!(roll >= -50.0))
        roll = -50.0f;
    rdMatrix_AddRotationFromVectorAngle44Before(&m, roll, 1.0f, 0.0f, 0.0f, &m);
    // bob toward the ground under the pod, eased by the follow strength
    // stays in ST0 in retail; only the two stores round
    long double bob = (player->shadowXf0.vD.z - m.vD.z) * follow;
    if (bob > 12.0f)
        bob = 12.0f;
    if (!(bob >= -12.0f))
        bob = -12.0f;
    bob = bob * 0.5;
    m.vD.z = bob + m.vD.z;
    player->unk19b4 = bob;
    rdMatrix_Copy44(&player->cockpitXf, &m);

    rdVector_Copy3(&offset, &visual->hoverPadOffsetB);
    rdVector_Add3(&offset, &offset, &player->partOffset[1]);
    float yaw = player->tiltAngle * -0.5f;
    rdMatrix_Copy44(&m, &podXf);
    rdMatrix_AddRotationFromVectorAngle44Before(&m, yaw, 0.0f, 1.0f, 0.0f, &m);
    podAddLocalOffset(&m, &podXf, offset.x, offset.y, offset.z);
    rdMatrix_Copy44(&player->engineXfR, &m);
    if (hasSecondEngines) {
        podAddLocalOffset(&m, &podXf, swrRace_secondEngineOffset.x, swrRace_secondEngineOffset.y, swrRace_secondEngineOffset.z);
        rdMatrix_Copy44(&player->engineXfR2, &m);
    }

    rdVector_Copy3(&offset, &visual->hoverPadOffsetB);
    offset.x = -offset.x;
    rdVector_Add3(&offset, &offset, &player->partOffset[2]);
    yaw = player->tiltAngle * -0.5f;
    rdMatrix_Copy44(&m, &podXf);
    rdMatrix_AddRotationFromVectorAngle44Before(&m, yaw, 0.0f, 1.0f, 0.0f, &m);
    podAddLocalOffset(&m, &podXf, offset.x, offset.y, offset.z);
    rdMatrix_Copy44(&player->engineXfL, &m);
    if (hasSecondEngines) {
        podAddLocalOffset(&m, &podXf, -swrRace_secondEngineOffset.x, swrRace_secondEngineOffset.y, swrRace_secondEngineOffset.z);
        rdMatrix_Copy44(&player->engineXfL2, &m);
    }
    swrRace_AnimateEngineWobble(player);
}

// 0x00410430
void swrRace_PollScreenshotKey(void)
{
    if (stdControl_ReadKey(DIK_F12, NULL) != 0 && swrRace_screenshotKeyHeld == 0) {
        swrSound_PlayUISound(0x46);
        sithRender_MakeScreenShot("snap_");
        swrRace_screenshotKeyHeld = 1;
        return;
    }
    swrRace_screenshotKeyHeld = 0;
}

// 0x004556c0
void swrRace_UpdatePartNodeSelection(void)
{
    swrModel_Node* node;
    int i;

    for (i = 0; i < swrRace_MenuMaxSelection; i++) {
        node = swr_sceneModels[SWR_SCENE_SLOT_INSTALLED_PARTS + i]->entries[0].node;
        if (node == NULL)
            continue;
        if (i == swrObjHang_hangarUpgradeType)
            node->light_index = 0;
        else
            node->light_index = 1;
        node->flags_5 |= swrModel_NODEFLAGS5_LIGHT_INDEX;
    }
}

// 0x00455720
void swrRace_SetupStatsMenuLighting(void)
{
    rdVector3 ambient;
    rdVector3 color;
    rdVector3 direction;

    rdVector_Set3(&ambient, 255.0f, 255.0f, 255.0f);
    rdVector_Set3(&color, 255.0f, 255.0f, 255.0f);
    rdVector_Set3(&direction, 0.0f, 120.0f, 0.0f);
    swrRender_SetLight1FromFloats(0, &ambient, &color, &direction);
    rdVector_Set3(&ambient, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&color, 128.0f, 128.0f, 128.0f);
    swrRender_SetLight1FromFloats(1, &ambient, &color, &direction);
}
