#ifndef SWROBJ_H
#define SWROBJ_H

#include "types.h"

#define swrObjcMan_F0_ADDR (0x00451cd0)

#define swrObjcMan_F2_ADDR (0x00451d40)

#define swrObjcMan_F3_ADDR (0x004542e0)

#define swrObjcMan_F4_ADDR (0x004543f0)

#define swrObjScene_F0_ADDR (0x00454a10)
#define swrObjScene_F4_ADDR (0x00454a30)

#define swrObjHang_F0_ADDR (0x00457620)

#define swrObjHang_F2_ADDR (0x00457b00)

#define swrObjHang_F3_ADDR (0x00457b90)

#define swrObjHang_F4_ADDR (0x0045a040)

#define swrObjJdge_F0_ADDR (0x0045e200)

#define swrObjJdge_F2_ADDR (0x0045ea30)

#define swrObjJdge_F3_ADDR (0x00463580)

#define swrObjJdge_F4_ADDR (0x00463a50)

#define swrObjElmo_F0_ADDR (0x00467cd0)

#define swrObjElmo_F3_ADDR (0x00468570)

#define swrObjElmo_F4_ADDR (0x00468660)

#define swrObjSmok_F0_ADDR (0x00469ed0)

#define swrObjSmok_F3_ADDR (0x00469fb0)

#define swrObjSmok_F4_ADDR (0x0046a500)

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

void swrObjcMan_F0(swrObjcMan* cman);

void swrObjcMan_F2(swrObjcMan* cman);

void swrObjcMan_F3(swrObjcMan* cman);

int swrObjcMan_F4(swrObjcMan* cman, int* subEvents, int p3);

void swrObjScene_F0(swrObjScen* scene);
int swrObjScene_F4(swrObjScen* scene, int* subEvents);

void swrObjHang_F0(swrObjHang* hang);

void swrObjHang_F2(swrObjHang* hang);

void swrObjHang_F3(swrObjHang* hang);

int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5);

void swrObjJdge_F0(swrObjJdge* jdge);

void swrObjJdge_F2(swrObjJdge* jdge);

void swrObjJdge_F3(swrObjJdge* jdge);

int swrObjJdge_F4(swrObjJdge* jdge, int* subEvents, int p3);

void swrObjElmo_F0(swrObjElmo* elmo);

void swrObjElmo_F3(swrObjElmo* elmo);

int swrObjElmo_F4(swrObjElmo* elmo, int* subEvents);

void swrObjSmok_F0(swrObjSmok* smok);

void swrObjSmok_F3(swrObjSmok* smok);

int swrObjSmok_F4(swrObjSmok* smok, int* subEvents);

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
