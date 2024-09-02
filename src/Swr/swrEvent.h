#ifndef SWREVENT_H
#define SWREVENT_H

#include "types.h"
#include "macros.h"

#include "swr.h"
#include "swrObj.h"

#if 0
// 0x004bfec0
swrEventManager eventManagerMain[][9] = {
    {
        {
            .event = EVENT("Test"),
            .flags = 0x31,
            .count = 0,
            .size = 0x1f28,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjTest_F0,
            .f1 = (void (*)(swrObj*))swrObjTest_TurnResponse,
            .f2 = (void (*)(swrObj*))swrObjTest_SuperUnk,
            .f3 = (void (*)(swrObj*))swrObjTest_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjTest_F4,
        },
        {
            .event = EVENT("Toss"),
            .flags = 1,
            .count = 0,
            .size = 0x7c,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swr_noop1,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swrObjToss_F2,
            .f3 = (void (*)(swrObj*))swrObjToss_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjToss_F4,
        },
        {
            .event = EVENT("Trig"),
            .flags = 0,
            .count = 0,
            .size = 0x58,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjTrig_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swrObjTrig_F2,
            .f3 = (void (*)(swrObj*))swr_noop1,
            .f4 = (void (*)(swrObj*, int*))swrObjTrig_F4,
        },
        {
            .event = EVENT("Hang"),
            .flags = 0,
            .count = 0,
            .size = 0xd0,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjHang_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swrObjHang_F2,
            .f3 = (void (*)(swrObj*))swrObjHang_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjHang_F4,
        },
        {
            .event = EVENT("Jdge"),
            .flags = 0x31,
            .count = 0,
            .size = 0x1e8,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjJdge_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swrObjJdge_F2,
            .f3 = (void (*)(swrObj*))swrObjJdge_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjJdge_F4,
        },
        {
            .event = EVENT("Scen"),
            .flags = 0,
            .count = 0,
            .size = 0x1b4c,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjScene_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swr_noop1,
            .f3 = (void (*)(swrObj*))swr_noop1,
            .f4 = (void (*)(swrObj*, int*))swrObjScene_F4,
        },
        {
            .event = EVENT("Elmo"),
            .flags = 0x31,
            .count = 0,
            .size = 0xc0,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjElmo_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swr_noop1,
            .f3 = (void (*)(swrObj*))swrObjElmo_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjElmo_F4,
        },
        {
            .event = EVENT("Smok"),
            .flags = 0x31,
            .count = 0,
            .size = 0x108,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjSmok_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swr_noop1,
            .f3 = (void (*)(swrObj*))swrObjSmok_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjSmok_F4,
        },
        {
            .event = EVENT("cMan"),
            .flags = 0x31,
            .count = 0,
            .size = 0x3a8,
            .head = NULL,
            .f0 = (void (*)(swrObj*))swrObjcMan_F0,
            .f1 = NULL,
            .f2 = (void (*)(swrObj*))swrObjcMan_F2,
            .f3 = (void (*)(swrObj*))swrObjcMan_F3,
            .f4 = (void (*)(swrObj*, int*))swrObjcMan_F4,
        },
    },
    NULL,
};
#endif

#define swrEvent_AllocateAndLoadObjs_ADDR (0x00447300)
#define swrEvent_ClearObjs_ADDR (0x00447350)

#define swrEvent_Initialize_ADDR (0x00450850)

#define swrEvent_CallAllF0_ADDR (0x004508b0)

#define swrEvent_CallAllF1_ADDR (0x00450930)

#define swrEvent_CallAllF2_ADDR (0x004509b0)

#define swrEvent_CallAllF3_ADDR (0x00450a30)

#define swrEvent_FindObjectById_ADDR (0x00450aa0)

#define swrEvent_GetEventCount_ADDR (0x00450b00)

#define swrEvent_GetItem_ADDR (0x00450b30)

#define swrEvent_DispatchSubEvents_ADDR (0x00450c00)

#define swrEvent_CallF4_ADDR (0x00450c50)

#define swrEvent_SetObjs_ADDR (0x00450ce0)

#define swrEvent_AllocObj_ADDR (0x00450d20)

#define swrEvent_FreeObjs_ADDR (0x00450db0)

void  swrEvent_AllocateAndLoadObjs(int event, int count);
void swrEvent_ClearObjs(int event);

void swrEvent_Initialize(int event);

void swrEvent_CallAllF0(void);

void swrEvent_CallAllF1(void);

void swrEvent_CallAllF2(void);

void swrEvent_CallAllF3(void);

void* swrEvent_FindObjectById(int event, int id);

int swrEvent_GetEventCount(int event);

void* swrEvent_GetItem(int event, int index);

void swrEvent_DispatchSubEvents(void* obj, int* subEvents); // int[2]

void swrEvent_CallF4(int event, void* forward_param);

void* swrEvent_SetObjs(int event, int count, void* obj);

void* swrEvent_AllocObj(int event);

void swrEvent_FreeObjs(int event);

#endif // SWREVENT_H
