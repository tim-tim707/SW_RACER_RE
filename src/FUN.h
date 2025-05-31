#ifndef FUN_H
#define FUN_H

#include <stdint.h>

#include "types.h"

// Functions used by decompiled functions but not yet analyzed

int FUN_00409d70(unsigned int param_1);

void FUN_0040a120(int param_1);

void FUN_004118b0(void);

void FUN_0041e5a0(void);

void FUN_0041e660(void);

void FUN_00427d90(int planetId, int planetTrackNumber);

void FUN_0042de10(char* str, int index);

void FUN_0043b1d0(swrObjHang* hang);

void FUN_0043fe90(short x, short y, int scale);

void FUN_00440550(int soundId);

int FUN_004409d0(char* param_1, char* param_2);

void FUN_00440c10(swrObjHang* hang);

void FUN_0045a3e0(void);

void FUN_0045b290(swrObjHang* hang, int* param_2, int param_3);

void FUN_0045bee0(swrObjHang* hang, int index, swrObjHang_STATE param_3, int param_4);

float FUN_00469b90(float f);

void FUN_00469c30(int index, float param_2, int param_3);

#endif // FUN_H
