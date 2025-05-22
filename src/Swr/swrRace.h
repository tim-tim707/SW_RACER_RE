#ifndef SWRRACE_H
#define SWRRACE_H

#include "types.h"

#define swrRace_SelectProfileMenu_ADDR (0x00401340)

#define swrRace_ReservedSettingsMenu_ADDR (0x0040fb50)

#define swrRace_LoadSaveConfigMenu_ADDR (0x0040ffe0)

#define swrRace_SettingsMenu_ADDR (0x00411950)

#define swrRace_GetSelectedTrack_ADDR (0x0041c4e0)

#define swrRace_DebugSetVehicleStat_ADDR (0x0042a110)

#define swrRace_InRace_EscMenu_ADDR (0x0042a840)

#define swrRace_DebugSetGameValue_ADDR (0x0042a9f0)

#define swrRace_SelectVehicle_ADDR (0x00435700)

#define swrRace_MainMenu_ADDR (0x004368a0)

#define swrRace_AudioVideoSettings_ADDR (0x00436fa0)

#define swrRace_HangarMenu_ADDR (0x004396d0)

#define swrRace_ResultsMenu_ADDR (0x00439ce0)

#define swrRace_CourseSelectionMenu_ADDR (0x0043b240)

#define swrRace_CourseInfoMenu_ADDR (0x0043b880)

#define swrRace_UpdatePartsHealth_ADDR (0x0043d720)

#define swrRace_GenerateDefaultDataSAV_ADDR (0x0043ea00)

#define swrRace_BuyPitdroidsMenu_ADDR (0x0043f380)

#define swrRace_InitUnk_ADDR (0x00444d10)

#define swrRace_ApplyStatsMultipliers_ADDR (0x00449330)

#define swrRace_ApplyUpgradesToStats_ADDR (0x00449d00)

#define swrRace_CalculateUpgradedStat_ADDR (0x004493f0)

#define swrRace_UpdateTurn_ADDR (0x0044ae40)

#define swrRace_SetAngleFromTurnRate_ADDR (0x0044af50)

#define swrRace_ReplaceMarsGuoWithJinnReeso_ADDR (0x0044B530)
#define swrRace_ReplaceBullseyeWithCyYunga_ADDR (0x0044B5E0)

#define swrRace_VehicleStatisticsSubMenu_ADDR (0x004550d0)

#define swrRace_InRaceTimer_ADDR (0x00460950)

#define swrRace_InRaceEngineUI_ADDR (0x004611f0)

#define swrRace_InRaceEndStatistics_ADDR (0x00462320)

#define swrRace_Repair_ADDR (0x0046ab10)

#define swrRace_Tilt_ADDR (0x0046b5a0)

#define swrRace_AI_ADDR (0x0046b670)

#define swrRace_BoostCharge_ADDR (0x0046bd20)

#define swrRace_CalculateTiltFromTurn_ADDR (0x00477ad0)

#define swrRace_TakeDamage_ADDR (0x00474cd0)

#define swrRace_ActivateTriggersInRange_ADDR (0x00476AC0)
#define swrRace_UpdateSurfaceTag_ADDR (0x00476ea0)

#define swrRace_ApplyGravity_ADDR (0x004774f0)

#define swrRace_UpdateTurn2_ADDR (0x00477c27)

#define swrRace_UpdateSpeed_ADDR (0x004783e0)
#define swrRace_ApplyBoost_ADDR (0x004787f0)
#define swrRace_UpdateHeat_ADDR (0x004788c0)
#define swrRace_ApplyTraction_ADDR (0x00478a70)
#define swrRace_MainSpeed_ADDR (0x00478d80)

#define swrRace_DeathSpeed_ADDR (0x0047b000)

#define swrRace_TriggerHandler_ADDR (0x0047ce60)

#define swrRace_LapProgress_ADDR (0x0047f810)

#define swrRace_LapCompletion_ADDR (0x0047fdd0)

#define swrRace_IncrementFrameTimer_ADDR (0x00480540)

int swrRace_SelectProfileMenu(void* param_1, unsigned int param_2, unsigned int param_3, int param_4);

void swrRace_ReservedSettingsMenu(swrUI_unk* param_1);

void swrRace_LoadSaveConfigMenu(swrUI_unk* param_1);

int swrRace_SettingsMenu(void);

swrRace_TRACK swrRace_GetSelectedTrack(void);

void swrRace_DebugSetVehicleStat(unsigned int id, float value);

int swrRace_InRace_EscMenu(int textIndex, char* textBuffer, char* unk, int* c, float* d);

void swrRace_DebugSetGameValue(int id, float value);

void swrRace_SelectVehicle(swrObjHang* hang);

void swrRace_MainMenu(swrObjHang* hang);

void swrRace_AudioVideoSettings(swrObjHang* hang);

void swrRace_HangarMenu(swrObjHang* hang);

void swrRace_ResultsMenu(swrObjHang* hang);

void swrRace_CourseSelectionMenu(void);

void swrRace_CourseInfoMenu(swrObjHang* hang);

void swrRace_UpdatePartsHealth(void);

void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot);

void swrRace_BuyPitdroidsMenu(swrObjHang* hang);

float swrRace_InitUnk(int a, float b, float c, int* d);

void swrRace_ApplyStatsMultipliers(PodHandlingData* out_stats, PodHandlingData* stats);

void swrRace_ApplyUpgradesToStats(PodHandlingData* pActiveStats, PodHandlingData* pBaseStats, char* pUpgradeLevels, char* pUpgradeHealths);

void swrRace_CalculateUpgradedStat(PodHandlingData* podHandlingData, int upgradeCategory, int upgradeLevel, float upgradeHealth);

void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6);

void swrRace_SetAngleFromTurnRate(float* out_tilt, float cur_turnrate, void* unused, float max_turnrate, float max_angle);

void swrRace_ReplaceMarsGuoWithJinnReeso(void);
void swrRace_ReplaceBullseyeWithCyYunga(void);

void swrRace_VehicleStatisticsSubMenu(void* param_1, float param_2, float param_3);

void swrRace_InRaceTimer(void* param_1, void* param_2);

void swrRace_InRaceEngineUI(void* param_1, int param_2);

void swrRace_InRaceEndStatistics(void* param_1, void* param_2);

void swrRace_Repair(swrRace* player);

void swrRace_Tilt(swrRace* player, float b);

void swrRace_AI(int player);

void swrRace_TakeDamage(int player, int a, float b);

void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2);
void swrRace_UpdateSurfaceTag(swrRace* test);

void swrRace_ApplyGravity(swrRace* player, float* a, float b);

int swrRace_BoostCharge(int player);

void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot);

void swrRace_UpdateTurn2(int player, int a, int b, int c);

float swrRace_UpdateSpeed(swrRace* player);
float swrRace_ApplyBoost(swrRace* player);
void swrRace_UpdateHeat(swrRace* player);
void swrRace_ApplyTraction(swrRace* player, float b, rdVector3* c, rdVector3* d);
void swrRace_MainSpeed(swrRace* player, rdVector3* b, rdVector3* c, int d);

void swrRace_DeathSpeed(swrRace* player, float a, float b);

void swrRace_TriggerHandler(int player, int a, char b);

float swrRace_LapProgress(int a);

bool swrRace_LapCompletion(void* engineData, int param_2);

void swrRace_IncrementFrameTimer(void);

#endif // SWRRACE_H
