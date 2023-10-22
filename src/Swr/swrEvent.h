#ifndef SWREVENT_H
#define SWREVENT_H

#include "types.h"
#include "macros.h"

// 0x004bfec0
swrEventManager unk[][9] = {
    {
        {
            .event = EVENT("Test"),
            .unk1 = 0x31,
            .count = 0,
            .size = 0x1f28,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL, // TODO
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Toss"),
            .unk1 = 1,
            .count = 0,
            .size = 0x7c,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Trig"),
            .unk1 = 0,
            .count = 0,
            .size = 0x58,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Hang"),
            .unk1 = 0,
            .count = 0,
            .size = 0xd0,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Jdge"),
            .unk1 = 0x31,
            .count = 0,
            .size = 0x1e8,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Scen"),
            .unk1 = 0,
            .count = 0,
            .size = 0x1b4c,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Elmo"),
            .unk1 = 0x31,
            .count = 0,
            .size = 0xc0,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("Smok"),
            .unk1 = 0x31,
            .count = 0,
            .size = 0x108,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
        {
            .event = EVENT("cMan"),
            .unk1 = 0x31,
            .count = 0,
            .size = 0x3a8,
            .head = NULL,
            .f0 = NULL, // TODO
            .f1 = NULL,
            .f2 = NULL, // TODO
            .f3 = NULL, // TODO
            .f4 = NULL, // TODO
        },
    },
    NULL,
};

#define swrEvent_CallAllF0_ADDR (0x004508b0)

#define swrEvent_CallAllF1_ADDR (0x00450930)

#define swrEvent_CallAllF2_ADDR (0x004509b0)

#define swrEvent_CallAllF3_ADDR (0x00450a30)

#define swrEvent_GetEventCount_ADDR (0x00450b00)

#define swrEvent_GetItem_ADDR (0x00450b30)

#define swrEvent_CallF4_ADDR (0x00450c50)

#define swrEvent_ChangeItemList_ADDR (0x00450ce0)

void swrEvent_CallAllF0(void);

void swrEvent_CallAllF1(void);

void swrEvent_CallAllF2(void);

void swrEvent_CallAllF3(void);

int swrEvent_GetEventCount(int event);

void* swrEvent_GetItem(int event, int index);

void swrEvent_CallF4(int event, void* forward_param);

void* swrEvent_ChangeItemList(int event, int index, void* list);

#endif // SWREVENT_H
