#include "swrRace.h"

#include "swrObj.h"
#include "swrEvent.h"
#include "swrSpline.h"
#include "macros.h"
#include "globals.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <Primitives/rdVector.h>

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

// Eases a turn rate (*param_1) toward target param_3 at param_4/sec, then integrates it
// (plus param_5/param_6) into a heading angle (*param_2) wrapped to [-180, 180] degrees.
// 0x0044ae40
void swrRace_UpdateTurn(float* param_1, float* param_2, float param_3, float param_4, float param_5, float param_6)
{
    if (*param_1 <= param_3)
    {
        // Accelerate the rate; 5x faster while still on the wrong side of zero.
        if (*param_1 < 0.0f)
            param_4 *= 5.0f;
        *param_1 += param_4 * swrRace_deltaTimeSecs;
        if (param_3 < *param_1)
            *param_1 = param_3;
    }
    else
    {
        if (0.0f < *param_1)
            param_4 *= 5.0f;
        *param_1 -= param_4 * swrRace_deltaTimeSecs;
        if (*param_1 < param_3)
            *param_1 = param_3;
    }

    // Snap to zero when the steering input (param_5) opposes the current rate's sign.
    if (0.0f < param_5 && *param_1 < 0.0f)
        *param_1 = 0.0f;
    if (param_5 < 0.0f && 0.0f < *param_1)
        *param_1 = 0.0f;

    // Integrate into the heading angle and wrap to [-180, 180].
    *param_2 += (*param_1 + param_6 + param_5) * swrRace_deltaTimeSecs;
    if (180.0f < *param_2)
        *param_2 -= 360.0f;
    if (*param_2 < -180.0f)
        *param_2 += 360.0f;
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
    // Below 200 speed the pod cannot bank; force the tilt target to neutral.
    if (player->speedValue < 200.0f)
        b = 0.0f;

    // Ease tiltManualMult toward the target at 3.2/sec, snapping on overshoot.
    if (b <= player->tiltManualMult)
    {
        if (b < player->tiltManualMult)
        {
            player->tiltManualMult -= swrRace_deltaTimeSecs * 3.2f;
            if (player->tiltManualMult < b)
                player->tiltManualMult = b;
        }
    }
    else
    {
        player->tiltManualMult += swrRace_deltaTimeSecs * 3.2f;
        if (b < player->tiltManualMult)
            player->tiltManualMult = b;
    }

    // Near neutral, damp the residual so the pod settles level.
    if (b == 0.0f)
    {
        float mag = (player->tiltManualMult < 0.0f) ? -player->tiltManualMult : player->tiltManualMult;
        if (mag < 0.1)
            player->tiltManualMult *= 0.5;
    }
}

// Per-frame "brain" for one AI racer. It never touches the flight model directly;
// it only computes a per-racer speed multiplier (aiSpeedTarget, smoothed into
// multiplayerStats) and a cross-track steer target (aiSteerTarget). The smoothed
// multiplier is copied into speedMultiplier by swrRace_UpdateCatchup and scales the
// pod in swrRace_UpdateSpeed. The two tuning inputs are the globals swrRace_AILevel
// (track base level * AI Speed setting) and ai_spread, both set in InitAISettingsForTrack.
// 0x0046b670
void swrRace_AI(int player)
{
    swrRace* p = (swrRace*) player;

    // Start from the track/difficulty-wide base level.
    p->aiSpeedTarget = swrRace_AILevel;

    if ((p->flags1 & 0x2000000) != 0) {
        // Finished / parked: coast at a fixed 0.65x and bleed off the parking timer.
        p->aiSpeedTarget = 0.65f;
        p->podStats.turnResponse = 1500.0f;
        p->podStats.maxTurnRate = 400.0f;
        if (p->unk108 <= 5625.0f) {
            p->unk108 = 5625.0f;
        } else {
            p->unk108 -= (float) (swrRace_deltaTimeSecs * 100.0);
        }
    } else {
        // Normalize the tuning by track length so the feel is consistent across courses.
        float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
        float spreadScaled = ai_spread * 0.0001f;
        float spreadBand = spreadScaled * invTrackLen;

        if ((p->flags0 & 0x100) != 0) {
            // Locked control (e.g. pre-start): no steering, pick a coarse pace.
            p->aiSteerTarget = 0.0f;
            if ((short) p->score_ptr->results_P1_Position == 1) {
                p->aiSpeedTarget *= 1.06f;
            } else if (spreadBand * 3.0f < p->rivalGapAhead) {
                p->aiSpeedTarget *= 1.4f;
            } else {
                p->aiSpeedTarget *= 1.1f;
            }
        } else if ((short) p->score_ptr->results_P1_Position == 1) {
            // Not racing for this slot: freeze steering, leave the target at base.
            p->aiSteerTarget = 0.0f;
        } else {
            // Tick the decision timer; on expiry reroll the interval and nudge the
            // target finishing position by +/-1, kept within +/-2 of the baseline.
            p->aiDecisionTimer -= (float) swrRace_deltaTimeSecs;
            if (p->aiDecisionTimer < 0.0f) {
                // rand() * 2^-31 gives [0,1); next reroll in ~8..18 seconds.
                p->aiDecisionTimer = (float) swrUtils_Rand() * 4.6566129e-10f * 10.0f + 8.0f;

                float r = (float) swrUtils_Rand() * 4.6566129e-10f;
                if (r < 0.15f) {
                    int newRank = p->aiRankTarget - 1; // try to move up a place
                    p->aiRankTarget = newRank;
                    if (newRank < 2 || newRank - p->aiRankBaseline > 2 || p->aiRankBaseline - newRank > 2) {
                        p->aiRankTarget = newRank + 1; // out of band: revert
                    }
                } else if (0.85f < r) {
                    int newRank = p->aiRankTarget + 1; // try to drop back a place
                    p->aiRankTarget = newRank;
                    if (newRank - p->aiRankBaseline > 2 || p->aiRankBaseline - newRank > 2) {
                        p->aiRankTarget = newRank - 1; // out of band: revert
                    }
                }
            }

            if (0.0f < ai_rank_speed_factor) {
                // Simplified rank-only pacing. Disabled in the shipped game:
                // ai_rank_speed_factor has no writer and stays 0.
                float base = p->aiSpeedTarget * 1.06f;
                p->aiSpeedTarget =
                    (1.0f - ((float) p->aiRankTarget - 1.0f) * ai_rank_speed_factor) * base;
            } else {
                // Full model: a cross-track steer target, plus a speed target derived
                // from the gap to the racing line, the target rank, and the spread band.
                float steer = (((float) p->aiRankTarget - 1.0f) * spreadScaled - 0.0008f) * invTrackLen;
                p->aiSteerTarget = steer;

                float v;
                if (spreadBand * 0.25f < p->aiLineOffset && (p->flags0 & 0x18000) != 0) {
                    float gap = (p->flags0 & 0x8000) != 0 ? p->rivalGapAhead : p->rivalGapBehind;
                    v = (0.0f < gap) ? gap * 10.3f : gap * 10.02f;
                } else {
                    v = (p->aiLineOffset - steer) * 10.0f;
                }

                float target = (v * 40.0f) / invTrackLen + 1.045f;
                if (1.6f < target) {
                    target = 1.6f;
                }
                if (target < 0.5f) {
                    target = 0.5f;
                }
                p->aiSpeedTarget = target;
            }
        }
    }

    // Slew the applied multiplier toward the target at 0.2/sec, never overshooting.
    if (p->multiplayerStats < p->aiSpeedTarget) {
        p->multiplayerStats += (float) (swrRace_deltaTimeSecs * 0.2);
        if (p->aiSpeedTarget < p->multiplayerStats) {
            p->multiplayerStats = p->aiSpeedTarget;
        }
    } else if (p->aiSpeedTarget < p->multiplayerStats) {
        p->multiplayerStats -= (float) (swrRace_deltaTimeSecs * 0.2);
        if (p->aiSpeedTarget > p->multiplayerStats) {
            p->multiplayerStats = p->aiSpeedTarget;
        }
    }
}

// Picks the speed multiplier source for one racer and commits it to speedMultiplier.
// AI racers (flags0 0x80) defer to swrRace_AI. 'Locl' splitscreen humans (flags0 0x20)
// with an active catchup field get a distance-based boost (capped at 1.25x); everyone
// else holds a neutral 1.0x.
// 0x0046ce30
void swrRace_UpdateCatchup(swrRace* player)
{
    swrScore* score = player->score_ptr;

    if ((player->flags0 & 0x20) == 0 || *(int*) &score->unkc == 0) {
        if ((player->flags0 & 0x80) != 0) {
            swrRace_AI((int) player);
        } else {
            player->multiplayerStats = 1.0f;
        }
    } else {
        player->multiplayerStats = 1.0f;
        if (1 < NumLocalPlayers() && 0.0f < player->rivalGapAhead) {
            float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
            float boost = (player->rivalGapAhead * 100.0f) / invTrackLen + 1.0f;
            player->multiplayerStats = boost;
            if (1.25f < boost) {
                player->multiplayerStats = 1.25f;
            }
        }
    }
    player->speedMultiplier = player->multiplayerStats;
}

// 0x00474cd0
void swrRace_TakeDamage(int player, int a, float b)
{
    // TODO
}

// 0x00476AC0
void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2)
{
    HANG("TODO");
}

// 0x00476ea0
void swrRace_UpdateSurfaceTag(swrRace* test)
{
    // TODO
}

// 0x004774f0
void swrRace_ApplyGravity(swrRace* player, float* a, float b)
{
    // Down direction: surface-relative on walls/tubes (flags1 0x400), else the world vector.
    float gx, gy, gz;
    uint32_t flags1 = player->flags1;
    if ((flags1 & 0x400) == 0)
    {
        gx = player->unk194_vec.x;
        gy = player->unk194_vec.y;
        gz = player->unk194_vec.z;
    }
    else
    {
        gx = -player->unk160.x;
        gy = -player->unk160.y;
        gz = -player->unk160.z;
    }

    // Distance to the hover plane, corrected for the pod's roll.
    float groundDist = b - player->podStats.intersectRadius;
    float hoverDelta = player->podStats.hoverHeight - player->podStats.intersectRadius;
    float vAz = player->transform.vA.z;
    if (vAz < 0.0f)
        vAz = -vAz;
    float rollTerm = *(float*)player->unk4 * vAz;
    if (3.0f < rollTerm)
        groundDist -= rollTerm - 3.0f;

    // Too-high-for-too-long watchdog forces a respawn.
    if (b <= 99999.0f)
    {
        player->fallTimer = 0.0f;
    }
    else
    {
        player->fallTimer += swrRace_deltaTimeSecs;
        if (3.0f < player->fallTimer)
            player->flags0 |= 0x1000;
    }

    // Airborne flag once high enough off the ground.
    if (b <= 30.0f)
        flags1 &= 0xfffffdffu;
    else
        flags1 |= 0x200;
    player->flags1 = flags1;

    // Integrate the vertical-velocity accumulator (fallValue).
    if (groundDist <= 12.0f)
    {
        player->fallValue += (1.0f - (12.0f - groundDist) / (12.0f - hoverDelta)) * swrRace_deltaTimeSecs;
        if (hoverDelta < groundDist && player->fallValue < 0.0f)
            player->fallValue *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    }
    else if (player->speedValue < 0.0f)
    {
        player->fallValue += swrRace_deltaTimeSecs * 2.0;   // stored constant is the double -2.0, applied as a subtract
    }
    else
    {
        player->fallValue += swrRace_deltaTimeSecs;
    }

    // fallRate = dt * unk190 * fallValue * 30, with a nose-down pitch boost.
    float fallRate = swrRace_deltaTimeSecs * player->unk190 * player->fallValue * 30.0f;
    player->fallRate = fallRate;
    if (player->pitch < 0.0f && 0.0f <= player->speedValue && 0.0f < fallRate)
        player->fallRate = (player->pitch * 0.9f + 1.0f) * fallRate;

    // Clamp the fall to the ground; on a hard landing dispatch the "HitBotm" event.
    if (player->fallRate <= groundDist)
    {
        player->flags0 &= 0xfeffffffu;
    }
    else
    {
        float impactRate = player->fallRate;
        float bounceMag = player->fallValue * 8.0f;
        player->fallRate = groundDist;
        if (0.0f < player->fallValue)
            player->fallValue = -(player->fallValue * 0.2f);
        if (4.0f < bounceMag && (player->flags0 & 0x1000000) == 0)
        {
            int subEvents[3];
            subEvents[0] = 0x48697474; // 'Hitt'
            subEvents[1] = 0x426f746d; // 'Botm'
            *(float*)&subEvents[2] = (impactRate / swrRace_deltaTimeSecs) * 0.5f;
            swrEvent_DispatchSubEvents(player, subEvents);
        }
        player->flags0 |= 0x1000000;
    }

    // Apply the fall along the down direction.
    a[0] += player->fallRate * gx;
    a[1] += player->fallRate * gy;
    a[2] += player->fallRate * gz;
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
    // Acceleration scale: 4.0 while boosting (flags0 0x800000) or over-throttled
    // (flags1 0x2000), otherwise 1.5.
    float accel = ((player->flags0 & 0x800000) != 0 || (player->flags1 & 0x2000) != 0) ? 4.0f : 1.5f;

    // swrScore.flag bit 3 (e.g. AI/replay) skips the fast idle-decay path below.
    bool scoreFlag = (player->score_ptr->flag & 8) != 0;

    if (player->gravityMultiplier <= 0.1f)
    {
        if (-0.1f <= player->gravityMultiplier)
        {
            // Near-zero throttle: coast accelThrust down.
            if (scoreFlag || 0.2f <= player->accelThrust)
                player->accelThrust *= stdMath_Decelerator(player->podStats.deceleration_interval, swrRace_deltaTimeSecs);
            else
                player->accelThrust *= stdMath_Decelerator(10.0f, swrRace_deltaTimeSecs);
        }
        else
        {
            // Reverse throttle below -0.1: integrate, then brake hard on overshoot.
            float v = swrRace_deltaTimeSecs * accel * player->gravityMultiplier + player->accelThrust;
            bool braking = -0.6f < player->gravityMultiplier;
            player->accelThrust = v;
            if (braking && v < player->gravityMultiplier * 0.5f)
                player->accelThrust *= stdMath_Decelerator(20.0f, swrRace_deltaTimeSecs);
        }
    }
    else
    {
        // Forward throttle above 0.1: integrate, then clamp via a throttle-dependent ceiling.
        float v = swrRace_deltaTimeSecs * accel * player->gravityMultiplier + player->accelThrust;
        bool below = player->gravityMultiplier < 0.99f;
        player->accelThrust = v;
        float ceiling = below ? player->gravityMultiplier / (1.0f - player->gravityMultiplier) : 10000.0f;
        if (ceiling < v)
            player->accelThrust *= stdMath_Decelerator(player->podStats.deceleration_interval, swrRace_deltaTimeSecs);
    }

    // Air brake.
    if ((player->flags0 & 0x200) != 0)
        player->accelThrust *= stdMath_Decelerator(player->podStats.airBrakeInv, swrRace_deltaTimeSecs);

    // Map the integrated throttle to a speed via the pod's accel/maxSpeed curve.
    float speed;
    if (player->accelThrust <= 0.0f)
        speed = -((-player->accelThrust * player->podStats.maxSpeed) / (player->podStats.acceleration - player->accelThrust));
    else
        speed = (player->accelThrust * player->podStats.maxSpeed) / (player->podStats.acceleration + player->accelThrust);
    speed *= player->speedMultiplier;

    // Terrain drag, applied once the pod is close to the ground.
    if (15.0f <= player->groundToPodMeasure)
    {
        player->flags1 &= 0xf7ffffff;
    }
    else
    {
        uint32_t f = player->flags1;
        if ((f & 0x8000000) == 0)
        {
            bool slow = player->terrainTractionMultiplier < 1.0f;
            player->flags1 = f | 0x8000000;
            if (slow)
                player->flags1 = f | 0x18000000;
        }
        speed *= player->terrainTractionMultiplier;
    }
    speed += player->iceTractionMultiplier;

    // Minimum-speed floor on certain surfaces.
    if ((player->flags0 & 0x4000000) != 0 && speed < 75.0f)
        speed = 75.0f;

    // Steep nose-down pitch scales the final speed.
    if ((player->flags0 & 0x80) != 0 && player->pitch < -0.5f)
    {
        if ((player->flags1 & 0x2000000) != 0)
            return speed * 1.9f;
        speed *= 1.3f;
    }
    return speed;
}

// 0x004788c0
void swrRace_UpdateHeat(swrRace* player)
{
    // TODO
}

// 0x00478a70
void swrRace_ApplyTraction(swrRace* player, float b, rdVector3* c, rdVector3* d)
{
    // Remove any part of velocityDir that opposes the (sign-of-b) input direction c.
    float dx = c->x, dy, dz;
    if (b <= 0.0f)
    {
        dx = -c->x;
        dy = -c->y;
        dz = -c->z;
    }
    else
    {
        dy = c->y;
        dz = c->z;
    }
    float dot = dz * player->velocityDir.z + dy * player->velocityDir.y + dx * player->velocityDir.x;
    if (dot < 0.0f)
    {
        dot = -dot;
        player->velocityDir.x += dx * dot;
        player->velocityDir.y += dy * dot;
        player->velocityDir.z += dz * dot;
    }

    // Desired velocity this frame.
    rdVector_Scale3(d, b, c);

    // Traction factor from grip stats; a multiplayer handicap can reduce or zero it.
    float grip = player->podStats.antiSkid * player->terrainSkidModifier * player->slide2;
    float traction = (1.0f - grip * grip) * 0.99666601f;
    if (1.0f < player->multiplayerStats)
    {
        if (player->multiplayerStats <= 2.0f)
            traction = (2.0f - player->multiplayerStats) * traction;
        else
            traction = 0.0f;
    }

    // Blend velocityDir between the desired velocity and its current value by traction.
    float dtf = swrRace_deltaTimeSecs;
    float keep = 1.0f - traction;
    player->velocityDir.x = (1.0f / dtf) * (d->x * dtf * keep + dtf * player->velocityDir.x * traction);
    player->velocityDir.y = (1.0f / dtf) * (d->y * dtf * keep + dtf * player->velocityDir.y * traction);
    player->velocityDir.z = (1.0f / dtf) * (d->z * dtf * keep + dtf * player->velocityDir.z * traction);

    // Output the normalized velocity scaled by |b|.
    d->x = player->velocityDir.x;
    d->y = player->velocityDir.y;
    d->z = player->velocityDir.z;
    rdVector_Normalize3Acc(d);
    if (b < 0.0f)
        b = -b;
    rdVector_Scale3(d, b, d);

    // Ease slide2 toward its target (1.0, lowered to 0.8 / x0.45 on certain surfaces).
    if ((player->flags1 & 0x10) == 0)
    {
        float target = 1.0f;
        if ((player->flags1 & 4) != 0)
            target = 0.8f;
        if ((player->flags1 & 8) != 0)
            target *= 0.45f;

        if (player->slide2 <= target)
        {
            if (player->slide2 < target)
            {
                // Stored rate constant is -2.0, applied as slide2 - dt*(-2).
                player->slide2 += swrRace_deltaTimeSecs * 2.0f;
                if (target < player->slide2)
                    player->slide2 = target;
            }
        }
        else
        {
            player->slide2 -= swrRace_deltaTimeSecs + swrRace_deltaTimeSecs;
            if (player->slide2 < target)
                player->slide2 = target;
        }
    }
}

// 0x0044acb0
int swrRace_CollideTrack(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal)
{
    HANG("TODO");
    return 0;
}

// 0x00478d80
void swrRace_MainSpeed(swrRace* player, rdVector3* b, rdVector3* c, rdVector3* d)
{
    rdVector3 vel;

    // Longitudinal speed + boost, run through traction into the frame velocity.
    float speed = swrRace_UpdateSpeed(player);
    speed += swrRace_ApplyBoost(player);
    swrRace_ApplyTraction(player, speed, d, &vel);

    // Flatten a too-steep climb (unless on a wall/repulsor surface).
    if ((player->flags1 & 0x400) == 0 && (player->flags0 & 0x2000000) == 0 && 0.0f < vel.z)
    {
        float horiz = vel.y * vel.y + vel.x * vel.x;
        if (horiz * 0.13690001f < vel.z * vel.z)
            vel.z = stdMath_Sqrt(horiz) * 0.2f;
    }

    // Fold in opponent-collision velocity, then bleed both collision velocities down.
    vel.x += player->velocityCollisionOpponent.x;
    vel.y += player->velocityCollisionOpponent.y;
    vel.z += player->velocityCollisionOpponent.z;
    player->velocityCollision.x *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollision.y *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollision.z *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.x *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.y *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    player->velocityCollisionOpponent.z *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);

    // Blend in the slope velocity (skipped while spun out / idle on the ground).
    if ((player->flags0 & 0x5000) == 0 &&
        (0.1f < player->gravityMultiplier || 0.1f < -player->gravityMultiplier || (player->flags0 & 0x2000) == 0))
    {
        float dot = vel.x * player->velocitySlope.x + vel.y * player->velocitySlope.y + vel.z * player->velocitySlope.z;
        float len;
        if (dot < 0.0f || (len = rdVector_Len3(&player->velocitySlope)) <= 1.0f)
        {
            vel.x += player->velocitySlope.x;
            vel.y += player->velocitySlope.y;
            vel.z += player->velocitySlope.z;
        }
        else
        {
            if (1.0f < speed)
            {
                float ratio = dot / (speed * 60.0f);
                if (0.0f < ratio)
                {
                    float dtr = swrRace_deltaTimeSecs * ratio;
                    player->accelThrust += dtr + dtr;
                }
            }
            float factor = (dot / len) * 0.01f;
            if (factor < 1.0f)
                factor = 1.0f;
            rdVector_Scale3Add3(&vel, &vel, factor, &player->velocitySlope);
        }
    }

    // Advance the position: c = b + dt * vel.
    rdVector_Scale3Add3(c, b, swrRace_deltaTimeSecs, &vel);

    // Once the race timer is past its limit (and not in a special state), or repulsor-locked,
    // freeze the move delta and bail.
    if (1.0 <= ((float)player->unk1998 - 400.0f) * 0.0016666667f &&
        (player->flags0 & 0x20) == 0 && (player->flags1 & 0x4000000) == 0)
    {
        player->unk154_vec.x = 0.0f;
        player->unk154_vec.y = 0.0f;
        player->unk154_vec.z = 0.0f;
        return;
    }
    if ((player->flags1 & 0x800000) != 0)
    {
        player->unk154_vec.x = 0.0f;
        player->unk154_vec.y = 0.0f;
        player->unk154_vec.z = 0.0f;
        return;
    }

    // Resolve track collisions (up to 6 passes), then record the resulting move delta.
    rdVector3 outNormal;
    float savedX = c->x, savedY = c->y, savedZ = c->z;
    int iter;
    int hit = swrRace_CollideTrack(c, b, player->model_unk, &outNormal);
    for (iter = 0; hit != 0 && iter < 6; iter++)
        hit = swrRace_CollideTrack(c, b, player->model_unk, &outNormal);
    if (0 < iter && (player->flags0 & 0x80) != 0)
        player->accelThrust *= stdMath_Decelerator(5.0f, swrRace_deltaTimeSecs);
    player->unk154_vec.x = c->x - savedX;
    player->unk154_vec.y = c->y - savedY;
    player->unk154_vec.z = c->z - savedZ;
}

// 0x004787f0
float swrRace_ApplyBoost(swrRace* player)
{
    if ((player->flags0 & 0x800000) == 0)
    {
        // Not boosting: bleed boostValue down, then snap tiny values to zero.
        if (0.0f < player->boostValue)
            player->boostValue *= stdMath_Decelerator(5.0f, swrRace_deltaTimeSecs);
        if (player->boostValue < 0.001f)
            player->boostValue = 0.0f;
    }
    else
    {
        // Boosting: charge boostValue at 1.5/sec.
        player->boostValue += swrRace_deltaTimeSecs * 1.5f;
    }

    // Consume the one-shot boost-start flag.
    if ((player->flags0 & 0x200) != 0)
        player->flags0 &= 0xff7fffff;

    // The stored divisor constant is -0.33, so the denominator is boostValue + 0.33.
    if (0.0f < player->boostValue)
        return (player->boostValue * player->podStats.boost_thrust) / (player->boostValue + 0.33f);
    return 0.0f;
}

// 0x0047b000
void swrRace_DeathSpeed(swrRace* player, float a, float b)
{
    uint32_t flags0 = player->flags0;
    // Ignore while already exploding/dying/respawning, or collision-disabled.
    if ((flags0 & 0x7000) != 0 || (player->flags1 & 0x2000000) != 0)
        return;
    if ((player->flags1 & 0x10000000) != 0)
    {
        player->flags1 &= 0xefffffff;
        return;
    }

    // Both impact components must clear their thresholds, and the pod must not be invincible.
    if (swrRace_DeathSpeedDrop < b && swrRace_DeathSpeedMin < a && swrRace_IsInvincible == 0)
    {
        if (200.0f <= player->speedValue && (flags0 & 0x80) == 0)
        {
            // Fast enough and not on a no-death surface: explode, spinning toward the turn direction.
            swrRace_Explode(player, (0.0f <= player->turnModifier) ? 2 : 1);
            player->gravityMultiplier = 5.0f;
            player->flags0 |= 0x800000;
        }
        else
        {
            // Otherwise just flag for a respawn instead of exploding.
            player->flags0 |= 0x1000;
        }
    }
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

// 0x004804c0
void swrRace_InitFrameTimer(void)
{
    // See swe1r-decomp
    HANG("TODO");
}

// 0x00480540
void swrRace_IncrementFrameTimer(void)
{
    // Per-frame timestep update. The original calls stdlib_timeGetTime (0x0048c490),
    // a thin wrapper around the winmm timeGetTime import; src/ reimpls call timeGetTime
    // directly (see stdControl.c). swr_FastMode swaps the measured delta for a fixed one.
    if (swr_FastMode == 0)
    {
        DWORD now = timeGetTime();
        swrRace_deltaTimeSecs = (double)(now - swr_systemTimeMs) * swrRace_msToSecondsScale;
        // dt_raw_d keeps the un-clamped delta (this copy precedes the max clamp below).
        swrRace_dt_raw_d = swrRace_deltaTimeSecs;
        if (swrRace_maxDeltaTimeSecs < swrRace_deltaTimeSecs)
        {
            swrRace_deltaTimeSecs = 0.1f;
        }
        swr_systemTimeMs = now;
    }
    else
    {
        swrRace_deltaTimeSecs = swr_fixedDeltaTimeSecs;
    }
    if (swrGui_Stopped != 0)
    {
        swrRace_deltaTimeSecs = 0.0;
    }
    if (swrRace_deltaTimeSecs <= swrRace_minDeltaTimeSecs)
    {
        swrRace_deltaTimeSecs = 0.002f;
    }
    swrRace_fdeltaTimeSecs = (float)swrRace_deltaTimeSecs;
    timetotal = timetotal + swrRace_deltaTimeSecs;
    frametotal = frametotal + 1;
}
