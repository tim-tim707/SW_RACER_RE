#ifndef SWROBJ_H
#define SWROBJ_H

#include "types.h"

#define swrObjHang_F0_ADDR (0x00457620)

#define swrObjHang_F2_ADDR (0x00457b00)

#define swrObjHang_F3_ADDR (0x00457b90)

#define swrObjHang_F4_ADDR (0x0045a040)

#define swrObjTest_F0_ADDR (0x0046d170)

#define swrObjTest_F3_ADDR (0x00470610)

#define swrObjTest_F4_ADDR (0x00474d80)

#define swrObjTest_TurnResponse_ADDR (0x0047ab40)

#define swrObjTest_SuperUnk_ADDR (0x0047b520)

#define swrObjToss_F2_ADDR (0x0047b9e0)

#define swrObjToss_F3_ADDR (0x0047ba30)

#define swrObjToss_F4_ADDR (0x0047bba0)

#define swrObjTrig_F0_ADDR (0x0047c390)

#define swrObjTrig_F2_ADDR (0x0047c500)

#define swrObjTrig_F4_ADDR (0x0047c710)

void swrObjHang_F0(swrObjHang* hang);

void swrObjHang_F2(swrObjHang* hang);

void swrObjHang_F3(swrObjHang* hang);

int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5);

void swrObjTest_F0(swrRace* player);

void swrObjTest_F3(swrRace* player);

int swrObjTest_F4(swrRace* player, int* subEvent, int ghost);

void swrObjTest_TurnResponse(swrRace* player);

void swrObjTest_SuperUnk(int player);

void swrObjToss_F2(swrObjToss* toss);

void swrObjToss_F3(swrObjToss* toss);

int swrObjToss_F4(swrObjToss* toss);

void swrObjTrig_F0(swrObjTrig* trig);

void swrObjTrig_F2(swrObjTrig* trig);

int swrObjTrig_F4(swrObjTrig* trig, int* subEvents);

#endif // SWROBJ_H
