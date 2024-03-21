#include "swrRace.h"

#include "macros.h"
#include "globals.h"

#include <General/stdMath.h>

// 0x00401340
int swrRace_SelectProfileMenu(void* param_1, unsigned int param_2, unsigned int param_3, int param_4)
{
    HANG("TODO");
}

// 0x0040fb50
void swrRace_ReservedSettingsMenu(swrUI_unk* param_1)
{
    HANG("TODO");
}

// 0x0040ffe0
void swrRace_LoadSaveConfigMenu(swrUI_unk* param_1)
{
    HANG("TODO");
}

// 0x00411950
int swrRace_SettingsMenu(void)
{
    HANG("TODO");
}

// 0x0041c4e0
swrRace_TRACK swrRace_GetSelectedTrack(void)
{
    return multiplayer_track_select;
}

// 0x0042a110
void swrRace_DebugSetVehicleStat(unsigned int id, float value)
{
    HANG("TODO");
}

// 0x0042a840
int swrRace_InRace_EscMenu(int textIndex, char* textBuffer, char* unk, int* c, float* d)
{
    HANG("TODO");
    return 0;
}

// 0x0042a9f0
void swrRace_DebugSetGameValue(int id, float value)
{
    switch (id)
    {
    case 0:
        stdMath_AddScaledValueAndClamp_i32(&swrRace_DebugLevel, value, 1.0, 0, 6);
        return;
    case 1:
        if ((swrRace_DebugFlag & 4U) != 0)
        {
            swrRace_IsInvincible = (unsigned int)(swrRace_IsInvincible == 0);
            return;
        }
        break;
    case 2:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped((float*)&swrRace_AILevel, value, 0.001, 0.2, 2.0);
            return;
        }
        break;
    case 3:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&ai_spread, value, 0.5, 2.0, 200.0);
            return;
        }
        break;
    case 4:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&swrRace_DeathSpeedMin, value, 1.0, 20.0, 1000.0);
            return;
        }
        break;
    case 5:
        if ((swrRace_DebugFlag & 8U) != 0)
        {
            stdMath_MultiplyAddClamped(&swrRace_DeathSpeedDrop, value, 1.0, 20.0, 500.0);
            return;
        }
        break;
    case 6:
        if ((swrRace_DebugFlag & 0x10U) != 0)
        {
            debug_showSplineMarkers = (unsigned int)(debug_showSplineMarkers == 0);
            return;
        }
        break;
    case 7:
        if ((swrRace_DebugFlag & 0x20U) != 0)
        {
            if ((GameSettingFlags & 0x4000) != 0)
            {
                GameSettingFlags = GameSettingFlags & 0xffffbfff;
                return;
            }
            GameSettingFlags = GameSettingFlags | 0x4000;
        }
    }
}

// 0x00435700
void swrRace_SelectVehicle(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x004368a0
void swrRace_MainMenu(swrObjHang* hang)
{
    // start race, inspect vehicle, buy parts, junkyard
    HANG("TODO");
}

// 0x00436fa0
void swrRace_AudioVideoSettings(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x004396d0
void swrRace_HangarMenu(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00439ce0
void swrRace_ResultsMenu(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0043b240
void swrRace_CourseSelectionMenu(void)
{
    HANG("TODO");
}

// 0x0043b880
void swrRace_CourseInfoMenu(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0043d720
void swrRace_UpdatePartsHealth(void)
{
    HANG("TODO");
}

// 0x0043ea00
void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot)
{
    HANG("TODO");
}

// 0x0043f380
void swrRace_BuyPitdroidsMenu(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00444d10
float swrRace_InitUnk(int a, float b, float c, int* d)
{
    HANG("TODO");
    return 0.0;
}

// 0x00445150
void swrRace_UpdateUnk(void)
{
    // TODO easy
}

// TODO: look at 0x0045cf60

// 0x00449330
void swrRace_ApplyStatsMultipliers(PodHandlingData* out_stats, PodHandlingData* stats)
{
    int i;
    float tmp;

    out_stats->antiSkid = stats->antiSkid;
    out_stats->turnResponse = stats->turnResponse * 0.001;
    tmp = stdMath_Sqrt(stats->acceleration);
    out_stats->maxTurnRate = 1.0 - tmp * 0.4761905;
    out_stats->acceleration = (stats->maxSpeed - 450.0) * 0.005;
    tmp = stdMath_Sqrt(stats->airBrakeInv * 0.5);
    i = 7;
    out_stats->maxSpeed = 8.0 / tmp - 1.68;
    out_stats->airBrakeInv = stats->coolRate * 0.05;
    out_stats->deceleration_interval = stats->repairRate;
    do
    {
        if (out_stats->antiSkid < 0.05)
        {
            out_stats->antiSkid = 0.05;
        }
        if (1.0 < out_stats->antiSkid)
        {
            out_stats->antiSkid = 1.0;
        }
        out_stats = (PodHandlingData*)&out_stats->turnResponse;
        i = i + -1;
    } while (i != 0);
}

// 0x00449d00
void swrRace_ApplyUpgradesToStats(PodHandlingData* pActiveStats, PodHandlingData* pBaseStats, char* pUpgradeLevels, char* pUpgradeHealths)
{
    int i;
    memcpy(pActiveStats, pBaseStats, 0x3Cu);

    i = 0;
    do
    {
        swrRace_CalculateUpgradedStat(pActiveStats, i, (int)pUpgradeLevels[i], (float)(unsigned int)(uint8_t)(pUpgradeLevels + i)[(int)pUpgradeHealths - (int)pUpgradeLevels] * 0.003921569);
        i = i + 1;
    } while (i < 7);
}

// 0x004493f0
void swrRace_CalculateUpgradedStat(PodHandlingData* podHandlingData, int upgradeCategory, int upgradeLevel, float upgradeHealth)
{
    float tmp;

    switch (upgradeCategory)
    {
    case 0:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 0.05 + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->antiSkid = 1.0;
            }
            if (podHandlingData->antiSkid < 0.01)
            {
                podHandlingData->antiSkid = 0.01;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 0.1 + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->antiSkid = 1.0;
            }
            if (podHandlingData->antiSkid < 0.01)
            {
                podHandlingData->antiSkid = 0.01;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 0.15 + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->antiSkid = 1.0;
            }
            if (podHandlingData->antiSkid < 0.01)
            {
                podHandlingData->antiSkid = 0.01;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 0.2 + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->antiSkid = 1.0;
            }
            if (podHandlingData->antiSkid < 0.01)
            {
                podHandlingData->antiSkid = 0.01;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 0.25 + podHandlingData->antiSkid;
            podHandlingData->antiSkid = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->antiSkid = 1.0;
            }
            if (podHandlingData->antiSkid < 0.01)
            {
                podHandlingData->antiSkid = 0.01;
                return;
            }
        }
        break;
    case 1:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 116.0 + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->turnResponse = 1000.0;
            }
            if (podHandlingData->turnResponse < 50.0)
            {
                podHandlingData->turnResponse = 50.0;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 232.0 + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->turnResponse = 1000.0;
            }
            if (podHandlingData->turnResponse < 50.0)
            {
                podHandlingData->turnResponse = 50.0;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 348.0 + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->turnResponse = 1000.0;
            }
            if (podHandlingData->turnResponse < 50.0)
            {
                podHandlingData->turnResponse = 50.0;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 464.0 + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->turnResponse = 1000.0;
            }
            if (podHandlingData->turnResponse < 50.0)
            {
                podHandlingData->turnResponse = 50.0;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 578.0 + podHandlingData->turnResponse;
            podHandlingData->turnResponse = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->turnResponse = 1000.0;
            }
            if (podHandlingData->turnResponse < 50.0)
            {
                podHandlingData->turnResponse = 50.0;
                return;
            }
        }
        break;
    case 2:
        if (upgradeLevel == 1)
        {
            tmp = ((1.0 - upgradeHealth) * 0.14 - -0.86) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0 < tmp)
            {
                podHandlingData->acceleration = 5.0;
            }
            if (podHandlingData->acceleration < 0.1)
            {
                podHandlingData->acceleration = 0.1;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = ((1.0 - upgradeHealth) * 0.28 - -0.72) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0 < tmp)
            {
                podHandlingData->acceleration = 5.0;
            }
            if (podHandlingData->acceleration < 0.1)
            {
                podHandlingData->acceleration = 0.1;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = ((1.0 - upgradeHealth) * 0.42 - -0.58) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0 < tmp)
            {
                podHandlingData->acceleration = 5.0;
            }
            if (podHandlingData->acceleration < 0.1)
            {
                podHandlingData->acceleration = 0.1;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = ((1.0 - upgradeHealth) * 0.56 - -0.44) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0 < tmp)
            {
                podHandlingData->acceleration = 5.0;
            }
            if (podHandlingData->acceleration < 0.1)
            {
                podHandlingData->acceleration = 0.1;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = ((1.0 - upgradeHealth) * 0.7 - -0.3) * podHandlingData->acceleration;
            podHandlingData->acceleration = tmp;
            if (5.0 < tmp)
            {
                podHandlingData->acceleration = 5.0;
            }
            if (podHandlingData->acceleration < 0.1)
            {
                podHandlingData->acceleration = 0.1;
                return;
            }
        }
        break;
    case 3:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 40.0 + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0 < tmp)
            {
                podHandlingData->maxSpeed = 650.0;
            }
            if (podHandlingData->maxSpeed < 450.0)
            {
                podHandlingData->maxSpeed = 450.0;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 80.0 + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0 < tmp)
            {
                podHandlingData->maxSpeed = 650.0;
            }
            if (podHandlingData->maxSpeed < 450.0)
            {
                podHandlingData->maxSpeed = 450.0;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 120.0 + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0 < tmp)
            {
                podHandlingData->maxSpeed = 650.0;
            }
            if (podHandlingData->maxSpeed < 450.0)
            {
                podHandlingData->maxSpeed = 450.0;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 160.0 + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0 < tmp)
            {
                podHandlingData->maxSpeed = 650.0;
            }
            if (podHandlingData->maxSpeed < 450.0)
            {
                podHandlingData->maxSpeed = 450.0;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 200.0 + podHandlingData->maxSpeed;
            podHandlingData->maxSpeed = tmp;
            if (650.0 < tmp)
            {
                podHandlingData->maxSpeed = 650.0;
            }
            if (podHandlingData->maxSpeed < 450.0)
            {
                podHandlingData->maxSpeed = 450.0;
                return;
            }
        }
        break;
    case 4:
        if (upgradeLevel == 1)
        {
            tmp = ((1.0 - upgradeHealth) * 0.07999998 - -0.92) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0;
            }
            if (podHandlingData->airBrakeInv < 1.0)
            {
                podHandlingData->airBrakeInv = 1.0;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = ((1.0 - upgradeHealth) * 0.17 - -0.83) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0;
            }
            if (podHandlingData->airBrakeInv < 1.0)
            {
                podHandlingData->airBrakeInv = 1.0;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = ((1.0 - upgradeHealth) * 0.26 - -0.74) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0;
            }
            if (podHandlingData->airBrakeInv < 1.0)
            {
                podHandlingData->airBrakeInv = 1.0;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = ((1.0 - upgradeHealth) * 0.35 - -0.65) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0;
            }
            if (podHandlingData->airBrakeInv < 1.0)
            {
                podHandlingData->airBrakeInv = 1.0;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = ((1.0 - upgradeHealth) * 0.44 - -0.56) * podHandlingData->airBrakeInv;
            podHandlingData->airBrakeInv = tmp;
            if (1000.0 < tmp)
            {
                podHandlingData->airBrakeInv = 1000.0;
            }
            if (podHandlingData->airBrakeInv < 1.0)
            {
                podHandlingData->airBrakeInv = 1.0;
                return;
            }
        }
        break;
    case 5:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 1.6 + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0 < tmp)
            {
                podHandlingData->coolRate = 20.0;
            }
            if (podHandlingData->coolRate < 1.0)
            {
                podHandlingData->coolRate = 1.0;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 3.2 + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0 < tmp)
            {
                podHandlingData->coolRate = 20.0;
            }
            if (podHandlingData->coolRate < 1.0)
            {
                podHandlingData->coolRate = 1.0;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 4.8 + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0 < tmp)
            {
                podHandlingData->coolRate = 20.0;
            }
            if (podHandlingData->coolRate < 1.0)
            {
                podHandlingData->coolRate = 1.0;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 6.4 + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0 < tmp)
            {
                podHandlingData->coolRate = 20.0;
            }
            if (podHandlingData->coolRate < 1.0)
            {
                podHandlingData->coolRate = 1.0;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 8.0 + podHandlingData->coolRate;
            podHandlingData->coolRate = tmp;
            if (20.0 < tmp)
            {
                podHandlingData->coolRate = 20.0;
            }
            if (podHandlingData->coolRate < 1.0)
            {
                podHandlingData->coolRate = 1.0;
                return;
            }
        }
        break;
    case 6:
        if (upgradeLevel == 1)
        {
            tmp = upgradeHealth * 0.1 + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->repairRate = 1.0;
            }
            if (podHandlingData->repairRate < 0.0)
            {
                podHandlingData->repairRate = 0.0;
            }
        }
        if (upgradeLevel == 2)
        {
            tmp = upgradeHealth * 0.2 + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->repairRate = 1.0;
            }
            if (podHandlingData->repairRate < 0.0)
            {
                podHandlingData->repairRate = 0.0;
            }
        }
        if (upgradeLevel == 3)
        {
            tmp = upgradeHealth * 0.3 + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->repairRate = 1.0;
            }
            if (podHandlingData->repairRate < 0.0)
            {
                podHandlingData->repairRate = 0.0;
            }
        }
        if (upgradeLevel == 4)
        {
            tmp = upgradeHealth * 0.4 + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->repairRate = 1.0;
            }
            if (podHandlingData->repairRate < 0.0)
            {
                podHandlingData->repairRate = 0.0;
            }
        }
        if (upgradeLevel == 5)
        {
            tmp = upgradeHealth * 0.45 + podHandlingData->repairRate;
            podHandlingData->repairRate = tmp;
            if (1.0 < tmp)
            {
                podHandlingData->repairRate = 1.0;
            }
            if (podHandlingData->repairRate < 0.0)
            {
                podHandlingData->repairRate = 0.0;
            }
        }
    }
}

// 0x0044ae40
void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6)
{
    // TODO
}

// 0x0044af50
void swrRace_SetAngleFromTurnRate(float* out_tilt, float cur_turnrate, void* unused, float max_turnrate, float max_angle)
{
    float tilt;

    tilt = -(cur_turnrate / max_turnrate) * max_angle;
    if (80.0 < tilt)
    {
        tilt = 80.0;
    }
    if (tilt < -80.0)
    {
        tilt = -80.0;
    }
    *out_tilt = *out_tilt - (tilt - *out_tilt) * swrRace_deltaTimeSecs * -5.0;
}

// 0x0044B530
void swrRace_ReplaceMarsGuoWithJinnReeso(void)
{
    // TODO easy
}

// 0x0044B5E0
void swrRace_ReplaceBullseyeWithCyYunga(void)
{
    // TODO easy
}

// 0x004550d0
void swrRace_VehicleStatisticsSubMenu(void* param_1, float param_2, float param_3)
{
    HANG("TODO");
}

// 0x00460950
void swrRace_InRaceTimer(void* param_1, void* param_2)
{
    HANG("TODO");
}

// 0x004611f0
void swrRace_InRaceEngineUI(void* param_1, int param_2)
{
    HANG("TODO");
}

// 0x00462320
void swrRace_InRaceEndStatistics(void* param_1, void* param_2)
{
    HANG("TODO");
}

// 0x0046ab10
void swrRace_Repair(swrRace* player)
{
    // TODO
}

// 0x0046b5a0
void swrRace_Tilt(swrRace* player, float b)
{
    // TODO
}

// 0x0046b670
void swrRace_AI(int player)
{
    // TODO
}

// 0x00474cd0
void swrRace_TakeDamage(int player, int a, float b)
{
    // TODO
}

// 0x00476ea0
void swrRace_UpdateSurfaceTag(swrRace* test)
{
    // TODO
}

// 0x004774f0
void swrRace_ApplyGravity(swrRace* player, float* a, float b)
{
    // TODO
}

// 0x0046bd20
int swrRace_BoostCharge(int player)
{
    // TODO
    return 0;
}

// 0x00477ad0
void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot)
{
    // See swe1r-decomp
    HANG("TODO");
}

// 0x00477c27
void swrRace_UpdateTurn2(int player, int a, int b, int c)
{
    // TODO
}

// 0x004783e0
float swrRace_UpdateSpeed(swrRace* player)
{
    // TODO
    return 0.0;
}

// 0x004788c0
void swrRace_UpdateHeat(swrRace* player)
{
    // TODO
}

// 0x00478a70
void swrRace_ApplyTraction(swrRace* a, float b, rdVector3* c, rdVector3* d)
{
    // TODO
}

// 0x00478d80
void swrRace_MainSpeed(swrRace* a, rdVector3* b, rdVector3* c, int d)
{
    // TODO
}

// 0x004787f0
float swrRace_ApplyBoost(swrRace* player)
{
    // TODO
    return 0.0;
}

// 0x0047b000
void swrRace_DeathSpeed(swrRace* player, float a, float b)
{
    HANG("TODO");
}

// 0x0047ce60
void swrRace_TriggerHandler(int player, int a, char b)
{
    // TODO
}

// 0x0047f810
float swrRace_LapProgress(int a)
{
    // TODO
    return 0.0;
}

// 0x0047fdd0
bool swrRace_LapCompletion(void* engineData, int param_2)
{
    // See swe1r-decomp
    HANG("TODO");
}

// 0x00480540
void swrRace_IncrementFrameTimer(void)
{
    // See swe1r-decomp
    HANG("TODO");
}
