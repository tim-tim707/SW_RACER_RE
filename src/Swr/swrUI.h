#ifndef SWRUI_H
#define SWRUI_H

#include "types.h"

// 0041ac00 swrUI_fun_unk(swrUI_unk* ui_unk, int p2, int p3, int p4)

// 0x004206b0 swrUI_fun_unk2(int p1, int p2, int p3, int p4)

// 0x004151a0

// 0x00416d90

// 0x0043b880 Planet before race screen

// 0x0043ec10 Strong SHOP Candidate

#define swrUI_replaceAllocatedStr_ADDR (0x004174e0)

char* swrUI_replaceAllocatedStr(char* str, char* mondo_text);

#endif // SWRUI_H
