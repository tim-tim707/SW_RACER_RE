#ifndef FUN_H
#define FUN_H

#include <stdint.h>

#include "types.h"

// Functions used by decompiled functions but not yet analyzed

// Macros from Ben1138
#define DEF_TYPE(Addr, RetType, ...) typedef RetType(FUN_##Addr##_t)(__VA_ARGS__);

#define DEF_FUN(Addr, RetType, ...)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                \
    DEF_TYPE(Addr, RetType, __VA_ARGS__);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
    FUN_##Addr##_t* FUN_##Addr = (FUN_##Addr##_t*)0x##Addr

#define DEF_FUN_DECL(Addr, RetType, ...)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           \
    DEF_TYPE(Addr, RetType, __VA_ARGS__);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          \
    extern FUN_##Addr##_t* FUN_##Addr;

DEF_FUN_DECL(00409d70, int, unsigned int param_1);

DEF_FUN_DECL(0040a120, void, int param_1);

DEF_FUN_DECL(004118b0, void, void);

DEF_FUN_DECL(0041e5a0, void, void);

DEF_FUN_DECL(0041e660, void, void);

DEF_FUN_DECL(00427d90, void, int planetId, int planetTrackNumber);

DEF_FUN_DECL(0042de10, void, char* str, int index);

DEF_FUN_DECL(0043b1d0, void, swrObjHang* hang);

DEF_FUN_DECL(0043fe90, void, short x, short y, int scale);

DEF_FUN_DECL(00440550, void, int soundId);

DEF_FUN_DECL(004409d0, int, char* param_1, char* param_2);

DEF_FUN_DECL(00440c10, void, swrObjHang* hang);

DEF_FUN_DECL(0045a3e0, void, void);

DEF_FUN_DECL(0045b290, void, swrObjHang* hang, int* param_2, int param_3);

DEF_FUN_DECL(0045bee0, void, swrObjHang* hang, int index, swrObjHang_STATE param_3, int param_4);

DEF_FUN_DECL(00469b90, float, float f);

DEF_FUN_DECL(00469c30, void, int index, float param_2, int param_3);

#endif // FUN_H
