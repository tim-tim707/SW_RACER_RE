#ifndef SWRRACE_H
#define SWRRACE_H

#include "types.h"

#define swrRace_VehiclePlanetSelectScreen_ADDR (0x00435700)

#define swrRace_UpdatePartsHealth_ADDR (0x0043d720)

#define swrRace_InitUnk_ADDR (0x00444d10)

#define swrRace_UpdateUnk_ADDR (0x00445150)

#define swrRace_UpdateTurn_ADDR (0x0044ae40)

#define swrRace_ReplaceMarsGuoWithJinnReeso_ADDR (0x0044B530)
#define swrRace_ReplaceBullseyeWithCyYunga_ADDR (0x0044B5E0)

#define swrRace_Repair_ADDR (0x0046ab10)

#define swrRace_Tilt_ADDR (0x0046b5a0)

#define swrRace_AI_ADDR (0x0046b670)

#define swrRace_BoostCharge_ADDR (0x0046bd20)

#define swrRace_DeathSpeed_ADDR (0x0047b000)

#define swrRace_TakeDamage_ADDR (0x00474cd0)

#define swrRace_UpdateSurfaceTag_ADDR (0x00476ea0)

#define swrRace_ApplyGravity_ADDR (0x004774f0)

#define swrRace_UpdateTurn2_ADDR (0x00477c27)

#define swrRace_UpdateSpeed_ADDR (0x004783e0)
#define swrRace_ApplyBoost_ADDR (0x004787f0)
#define swrRace_UpdateHeat_ADDR (0x004788c0)
#define swrRace_ApplyTraction_ADDR (0x00478a70)
#define swrRace_MainSpeed_ADDR (0x00478d80)

#define swrRace_TurnResponse_ADDR (0x0047ab40)

#define swrRace_UpdateSpeedOnDeath_ADDR (0x0047b00)

#define swrRace_SuperUnk_ADDR (0x0047b520)

#define swrRace_TriggerHandler_ADDR (0x0047ce60)

#define swrRace_LapProgress_ADDR (0x0047f810)

void swrRace_VehiclePlanetSelectScreen(int player);

void swrRace_UpdatePartsHealth(void);

float swrRace_InitUnk(int a, float b, float c, int* d);

void swrRace_UpdateUnk(void);

void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6);

void swrRace_ReplaceMarsGuoWithJinnReeso(void);
void swrRace_ReplaceBullseyeWithCyYunga(void);

void swrRace_Repair(int player);

void swrRace_Tilt(int player, float b);

void swrRace_AI(int player);

void swrRace_TakeDamage(int player, int a, float b);

void swrRace_UpdateSurfaceTag(int player);

void swrRace_ApplyGravity(int player, float* a, float b);

int swrRace_BoostCharge(int player);

void swrRace_DeathSpeed(swrRace* player, float a, float b);

void swrRace_UpdateTurn2(int player, int a, int b, int c);

float swrRace_UpdateSpeed(int player);
float swrRace_ApplyBoost(int player);
void swrRace_UpdateHeat(int player);
void swrRace_ApplyTraction(float a, float b, rdVector3* c, rdVector3* d);
void swrRace_MainSpeed(float a, rdVector3* b, rdVector3* c, int d);

void swrRace_TurnResponse(int player);

void swrRace_UpdateSpeedOnDeath(int player, float a, float b);

void swrRace_SuperUnk(int player);

void swrRace_TriggerHandler(int player, int a, char b);

float swrRace_LapProgress(int a);

#endif // SWRRACE_H
