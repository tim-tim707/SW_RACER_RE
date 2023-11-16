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

#define swrUI_GetUI1_ADDR (0x00411480)

#define swrUI_GetValue_ADDR (0x00413fa0)

#define swrUI_RunCallbacksScreenText_ADDR (0x00414b80)

#define swrUI_SetColorUnk_ADDR (0x00414be0)

#define swrUI_SetColorUnk3_ADDR (0x00414c10)

#define swrUI_SetColorUnk4_ADDR (0x00414c40)

#define swrUI_SetColorUnk5_ADDR (0x00414c70)

#define swrUI_SetColorUnk2_ADDR (0x00414ca0)

#define swrUI_GetById_ADDR (0x00414d90)

#define swrUI_RunCallbacks2_ADDR (0x00414e60)

#define swrUI_SetUI5_ADDR (0x00414f00)

#define swrUI_GetUI4_ADDR (0x00414fe0)

#define swrUI_GetUI5_ADDR (0x00414ff0)

#define swrUI_GetUI6_ADDR (0x00415000)

#define swrUI_ClearUI5_ADDR (0x00415010)

#define swrUI_RunCallbacks_ADDR (0x004151a0)

#define swrUI_ReplaceIndex_ADDR (0x004157d0)

#define swrUI_SetUnk_ADDR (0x00415810)

#define swrUI_Enqueue_ADDR (0x00416840)

#define swrUI_New_ADDR (0x00416d90)

#define swrUI_replaceAllocatedStr_ADDR (0x004174e0)

#define swrUI_GetByValue_ADDR (0x0041b5e0)

// 0041ac00 swrUI_fun_unk(swrUI_unk* ui_unk, int p2, int p3, int p4)

// 0x004206b0 swrUI_fun_unk2(int p1, int p2, int p3, int p4)

// 0x00416d90

// 0x0043b880 Planet before race screen

// 0x0043ec10 Strong SHOP Candidate

swrUI_unk* swrUI_GetUI1(void);

int swrUI_GetValue(swrUI_unk* ui);

int swrUI_RunCallbacksScreenText(swrUI_unk* ui, char* screenText, int bool_unk);

void swrUI_SetColorUnk(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrUI_SetColorUnk3(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrUI_SetColorUnk4(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrUI_SetColorUnk5(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

void swrUI_SetColorUnk2(swrUI_unk* ui, uint8_t r, uint8_t g, uint8_t b, uint8_t a);

swrUI_unk* swrUI_GetById(swrUI_unk* ui, int id);

int swrUI_RunCallbacks2(swrUI_unk* ui, int bool_unk);

void swrUI_SetUI5(swrUI_unk* ui);

swrUI_unk* swrUI_GetUI4(void);

swrUI_unk* swrUI_GetUI5(void);

swrUI_unk* swrUI_GetUI6(void);

void swrUI_ClearUI5(void);

int swrUI_RunCallbacks(swrUI_unk* ui, int forward1, int forward2, int forward3);

int swrUI_ReplaceIndex(swrUI_unk* ui, int new_index);

void swrUI_SetUnk(swrUI_unk* ui, int a, int b, int c, int d);

void swrUI_Enqueue(swrUI_unk* ui1, swrUI_unk* toEnqueue);

swrUI_unk* swrUI_New(swrUI_unk* ui, int id, int new_index, char* mondo_text, int flag, int size_unk2, int size_unk1, swrUI_unk_F1* f1, swrUI_unk_F2* f2);

char* swrUI_replaceAllocatedStr(char* str, char* mondo_text);

// 0x0041b5e0
swrUI_unk* swrUI_GetByValue(swrUI_unk* ui, int value);

#endif // SWRUI_H
