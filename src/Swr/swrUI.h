#ifndef SWRUI_H
#define SWRUI_H

#include "types.h"

// typedef swrUI_unk* (*swrUI_unk_F1)(swrUI_unk* self, int param_2, void* param_3, int param_4);
// typedef swrUI_unk* (*swrUI_unk_F2)(swrUI_unk* self, unsigned int param_2, void* param_3, int param_4);

// F1 callback
/*

FUN_00415850
FUN_00415b80
FUN_00415ca0
FUN_00415ed0
FUN_00416130
FUN_00416370
FUN_00416690
FUN_00416820
FUN_00417940
FUN_00417be0
FUN_0041ac00

*/

// F2 callback
/*

FUN_00401000
swrRace_SelectProfileMenu
FUN_00401960
FUN_00401af0
swrControl_MappingsMenu
FUN_004030f0
FUN_00403430
FUN_004039a0
FUN_00403d70
FUN_004191f0
FUN_00419390
FUN_004194c0
FUN_00419570
FUN_00419700
FUN_00419770
FUN_00419620
FUN_004196b0
FUN_0041ead0
FUN_0041ede0
FUN_0041f330
FUN_0041fc70
FUN_004206b0

*/

#define swrUI_UpdateProgressBar_ADDR (0x00408640)

#define swrUI_ResetProgressBar_ADDR (0x00408800)

#define swrUI_GetUI1_ADDR (0x00411480)

#define swrUI_GetValue_ADDR (0x00413fa0)

#define swrUI_RunCallbacksScreenText_ADDR (0x00414b80)
#define swrUI_GetAllocatedString_ADDR (0x00414ba0)
#define swrUI_SetColorUnk_ADDR (0x00414be0)
#define swrUI_SetColorUnk4_ADDR (0x00414c10)
#define swrUI_SetColorUnk3_ADDR (0x00414c40)
#define swrUI_SetColorUnk5_ADDR (0x00414c70)
#define swrUI_SetColorUnk2_ADDR (0x00414ca0)

#define swrUI_GetById_ADDR (0x00414d90)

#define swrUI_SetSelected_ADDR (0x00414e30)

#define swrUI_RunCallbacks2_ADDR (0x00414e60)

#define swrUI_SetUI5_ADDR (0x00414f00)

#define swrUI_GetUI4_ADDR (0x00414fe0)

#define swrUI_GetUI5_ADDR (0x00414ff0)

#define swrUI_GetUI6_ADDR (0x00415000)

#define swrUI_ClearUI5_ADDR (0x00415010)

#define swrUI_RunCallbacks_ADDR (0x004151a0)

#define swrUI_HandleKeyEvent_ADDR (0x00415640)

#define swrUI_ReplaceIndex_ADDR (0x004157d0)

#define swrUI_SetBBox_ADDR (0x00415810)

#define swrUI_Enqueue_ADDR (0x00416840)

#define swrUI_HandleKeyEvent2_ADDR (0x00416D70)
#define swrUI_New_ADDR (0x00416d90)

#define swrUI_ClearAllSprites_ADDR (0x00417060)

#define swrUI_replaceAllocatedStr_ADDR (0x004174e0)

#define swrUI_GetByValue_ADDR (0x0041b5e0)

#define swrUI_LoadTrackFromId_ADDR (0x00420930)

#define HandleCircuits_ADDR (0x0043b0b0)

#define swrUI_TextMenu_ADDR (0x0043fce0)

#define MenuAxisHorizontal_ADDR (0x00440150)

#define swrUI_DrawRecord_ADDR (0x004403e0)

#define swrUI_GetTrackNameFromId_ADDR (0x00440620)

#define BeatEverything1stPlace_ADDR (0x00440bc0)

#define swrUI_LoadPlanetModels_ADDR (0x00457C20)
#define swrUI_LoadMapPartModels_ADDR (0x00457CF0)
#define swrUI_LoadUIElements_ADDR (0x00457ed0)
#define swrUI_LoadWindowUIElements_ADDR (0x00457fd0)
#define swrUI_LoadPartsUIElements_ADDR (0x004580e0)
#define swrUI_LoadSelectionsUIElements_ADDR (0x00458250)

// 0041ac00 swrUI_fun_unk(swrUI_unk* ui_unk, int p2, int p3, int p4)

// 0x004206b0 swrUI_fun_unk2(int p1, int p2, int p3, int p4)

// 0x00416d90

// 0x0043b880 Planet before race screen

// 0x0043ec10 Strong SHOP Candidate

void swrUI_UpdateProgressBar(int progressPercent);

void swrUI_ResetProgressBar(void);

swrUI_unk* swrUI_GetUI1(void);

int swrUI_GetValue(swrUI_unk* ui);

int swrUI_RunCallbacksScreenText(swrUI_unk* ui, char* screenText, int bool_unk);
char* swrUI_GetAllocatedString(swrUI_unk* ui, char* str_out, int len);
void swrUI_SetColorUnk(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk4(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk3(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk5(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);
void swrUI_SetColorUnk2(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id);

void swrUI_SetSelected(swrUI_unk* ui, int bSelected);

int swrUI_RunCallbacks2(swrUI_unk* ui, int bool_unk);

void swrUI_SetUI5(swrUI_unk* ui);

swrUI_unk* swrUI_GetUI4(void);

swrUI_unk* swrUI_GetUI5(void);

swrUI_unk* swrUI_GetUI6(void);

void swrUI_ClearUI5(void);

int swrUI_HandleKeyEvent(int virtual_key_code, int pressed);

int swrUI_RunCallbacks(swrUI_unk* ui, int forward1, int forward2, int forward3);

int swrUI_ReplaceIndex(swrUI_unk* ui, int new_index);

void swrUI_SetBBox(swrUI_unk* ui, int x, int y, int x2, int y2);

void swrUI_Enqueue(swrUI_unk* ui1, swrUI_unk* toEnqueue);

int  swrUI_HandleKeyEvent2(void *forward2, int);
swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1* f1, swrUI_unk_F2* f2);

void swrUI_ClearAllSprites(swrUI_unk* ui);

char* swrUI_replaceAllocatedStr(char* str, char* mondo_text);

swrUI_unk* swrUI_GetByValue(swrUI_unk* ui, int value);

void swrUI_LoadTrackFromId(swrRace_TRACK trackId, char* buffer, size_t len);

void HandleCircuits(swrObjHang* hang);

void swrUI_TextMenu(int posX, int posY, int R, int G, int B, int A, char* screenText);

void MenuAxisHorizontal(void* pUnused, short posY);

void swrUI_DrawRecord(swrObjHang* hang, int param_2, int param_3, float param_4, char param_5);

char* swrUI_GetTrackNameFromId(int trackId);

bool BeatEverything1stPlace(swrObjHang* hang);

void swrUI_LoadPlanetModels();
void swrUI_LoadMapPartModels();
void swrUI_LoadUIElements(void);
void swrUI_LoadWindowUIElements(void);
void swrUI_LoadPartsUIElements(void);
void swrUI_LoadSelectionsUIElements(void);

#endif // SWRUI_H
