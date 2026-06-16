#include "swrRace.h"

#include "swrObj.h"
#include "swrModel.h"
#include "swrSpline.h"
#include "swrEvent.h"
#include "swrModel.h"
#include "macros.h"
#include "globals.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <Primitives/rdVector.h>
#include <Primitives/rdMatrix.h>
#include <Unknown/rdMatrixStack.h>

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

// Sets up the global ray-collision query state from `ray` (= {origin.xyz, dir.xyz, maxDist}),
// installs the per-face callbacks, resets the matrix stack, then recursively ray-tests the model's
// node tree (CollideNodeRecursiveRay, which latches the closest hit into the query globals). On a hit
// (closest <= maxDist) it fills outHit/outNormal and returns the hit distance; -1.0 on a miss. The hit
// node is published to swrRace_collisionHitNode.
// 0x00444d10
float swrRace_InitUnk(swrModel_Node* model, float* ray, rdVector3* outHit, rdVector3* outNormal)
{
    if (model == NULL) {
        swrModel_collisionResultDist = -1.0;
    } else {
        swrModel_collisionResultDist = ray[6] + 200.0f;// closest-hit accumulator, init past maxDist
        swrModel_collisionResultNode = NULL;
        swrModel_collisionRayMaxDist = ray[6];
        swrModel_collisionRayDir.x = ray[3];
        swrModel_collisionRayDir.y = ray[4];
        swrModel_collisionRayDir.z = ray[5];
        swrModel_collisionRayOrigin.x = ray[0];
        swrModel_collisionRayOrigin.y = ray[1];
        swrModel_collisionRayOrigin.z = ray[2];
        swrModel_collisionUnkE1c = 1;
        swrModel_meshCollisionFaceCallback = swrModel_MeshCollisionFaceCallback;
        swrModel_meshCollisionFaceCallbackIndexed = swrModel_MeshCollisionFaceCallbackIndexed;
        swrModel_collisionUnkE70 = 0;
        swrModel_collisionUnk250 = 0;
        rdMatrixStack44_Init();
        swrModel_CollideNodeRecursiveRay((swrModel_NodeTransformed*) model, ray, 0);
        if (swrModel_collisionResultDist <= ray[6]) {
            outHit->x = swrModel_collisionHitPoint.x;
            outHit->y = swrModel_collisionHitPoint.y;
            outHit->z = swrModel_collisionHitPoint.z;
            outNormal->x = swrModel_collisionHitNormal.x;
            outNormal->y = swrModel_collisionHitNormal.y;
            outNormal->z = swrModel_collisionHitNormal.z;
        } else {
            swrModel_collisionResultDist = -1.0;
        }
    }
    if (swrModel_collisionResultNode != NULL)
        swrRace_collisionHitNode = swrModel_collisionResultNode;
    return swrModel_collisionResultDist;
}

// Clears the collision-query "hit node" result before a ray query (the query latches it on hit).
// 0x00441020
void swrRace_ResetCollisionHit(void)
{
    swrRace_collisionHitNode = NULL;
}

// Returns the node hit by the most recent ray query (NULL if none).
// 0x00441030
swrModel_Node* swrRace_GetCollisionHit(void)
{
    return swrRace_collisionHitNode;
}

// TODO: look at 0x0045cf60

// Convert a pod's raw handling stats into the normalized 0..1 garage display bars
// (consumed by swrRace_VehicleStatisticsSubMenu and swrObjHang_ComputeUpgradedStats).
// Display only: the flight model reads the raw podStats directly, never this output.
// 0x00449330
void swrRace_ComputeStatBars(PodHandlingData* out_stats, PodHandlingData* stats)
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

// Bitmask of which engine sides have damaged/disabled parts (status bits 0x14):
// 0x1 = a left engine (parts 0..2), 0x2 = a right engine (parts 3..5).
// 0x0046a9c0
unsigned int swrRace_GetDamagedEngineSides(swrRace* player)
{
    unsigned int sides = 0;
    for (int i = 0; i < 6; i++) {
        if ((player->engineStatus[i] & 0x14) != 0) {
            sides |= (i < 3) ? 1 : 2;
        }
    }
    return sides;
}

// Handling bias from asymmetric engine damage: each badly damaged engine (health > 0.8)
// shifts the result by -0.33 (left, parts 0..2) or +0.33 (right, parts 3..5), so a
// lopsidedly damaged pod pulls to one side.
// 0x0046a9f0
float swrRace_GetEngineDamagePenalty(swrRace* player)
{
    float penalty = 0.0f;
    for (int i = 0; i < 6; i++) {
        if (0.8f < player->engineHealth[i]) {
            if (i < 3) {
                penalty -= 0.33f;
            } else {
                penalty += 0.33f;
            }
        }
    }
    return penalty;
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

// 0x0046b670
void swrRace_AI(int player)
{
    // TODO
}

// Accumulate collision/scrape damage into engine part `engineIndex`. The hit magnitude
// is scaled by podStats.damageImmunity (really a damage *multiplier*: higher = more
// fragile), capped at 1.0 (fully destroyed), recorded as that part's worst damage, and
// added to totalDamage. No-op while invincible, spun out (flags0 0x6000), or finished
// (flags1 0x2000000).
// 0x00474cd0
void swrRace_TakeDamage(int player, int engineIndex, float amount)
{
    swrRace* p = (swrRace*) player;

    if (swrRace_IsInvincible != 0) {
        return;
    }
    if ((p->flags0 & 0x6000) != 0 || (p->flags1 & 0x2000000) != 0) {
        return;
    }

    p->flags0 &= 0xff7fffff; // taking damage cancels an active boost
    float health = p->podStats.damageImmunity * amount + p->engineHealth[engineIndex];
    p->engineHealth[engineIndex] = health;
    if (1.0f < health) {
        p->engineHealth[engineIndex] = 1.0f;
    }
    p->engineStatus[engineIndex] |= 1;
    if (p->engineHealthMin[engineIndex] < p->engineHealth[engineIndex]) {
        p->engineHealthMin[engineIndex] = p->engineHealth[engineIndex];
    }
    p->totalDamage += amount;
}

// 0x00476AC0
void swrRace_ActivateTriggersInRange(swrRace* a, swrModel_TriggerDescription* a2)
{
    HANG("TODO");
}

// Eases *value toward target at `rate` units/sec (used for the traction/skid multipliers below).
static void swrRace_easeTraction(float* value, float target, double rate)
{
    if (target <= *value) {
        if (target < *value) {
            *value = *value - swrRace_deltaTimeSecs * rate;
            if (*value < target)
                *value = target;
        }
    } else {
        *value = *value + swrRace_deltaTimeSecs * rate;
        if (target < *value)
            *value = target;
    }
}

// Reads the terrain mesh's swrModel_Behavior tag and translates its bitfields into pod flags +
// traction targets each frame. behavior.unk1 & 0x20 sets flags1 0x400 (the surface-relative "magnet"
// gravity); vehicle_reaction bits drive zero-g/orbit (1/2), surface friction (4/8/0x10/0x20), wall
// reactions, reflections, triggers, etc. The clear mask 0xff63fb1e drops the per-frame tag bits up
// front so they re-latch only while the pod is over a tagged surface.
// 0x00476ea0
void swrRace_UpdateSurfaceTag(swrRace* test)
{
    float iceTarget = 0.0;
    float terrainTractionTarget = 1.0;
    float terrainSkidTarget = 1.0;

    if (((test->flags0 & 0x2000000) != 0) && (test->speedValue < 75.0f))
        iceTarget = 75.0f - test->speedValue;

    test->flags1 = test->flags1 & 0xff63fb1e;

    swrModel_Behavior* behavior = NULL;
    if (test->terrainModel != NULL)
        behavior = swrModel_MeshGetBehavior((swrModel_Mesh*) test->terrainModel);

    if (behavior != NULL) {
        uint32_t toggles = test->collisionToggles & ~behavior->unk20;
        test->collisionToggles = (((behavior->unk21 >> 8) | (toggles >> 8)) & 0xFFFFFF) << 8;

        if ((behavior->unk1 & 0x10) != 0)
            test->flags1 = test->flags1 | 0x80;
        if ((behavior->unk1 & 0x20) != 0)
            test->flags1 = test->flags1 | 0x400;// surface-relative "magnet" gravity
        if ((behavior->vehicle_reaction & 0x2000) != 0)
            test->flags1 = test->flags1 | 0x40000;
        if ((behavior->vehicle_reaction & 0x4000) != 0)
            test->flags1 = test->flags1 | 0x80000;
        if (((behavior->vehicle_reaction & 0x20000) != 0) && ((test->flags0 & 0x80) != 0) &&
            ((test->flags1 & 0x4000000) == 0))
            test->flags1 = test->flags1 | 0x800000;
        if ((behavior->vehicle_reaction & 0x8000) != 0)
            test->flags1 = test->flags1 | 0x100000;

        // debug hotkey: toggle the zero-g flag while held
        if (((swrRace_DebugFlag & 0x2000) != 0) && ((inRaceLocalPlayerInputBitset1[0] & 0x100) != 0) &&
            (((uint8_t) inRaceLocalPlayerInputBitset3[0] & 0x80) != 0))
            test->flags0 = test->flags0 ^ 0x2000000;

        if ((behavior->vehicle_reaction & 1) != 0)
            test->flags0 = test->flags0 | 0x2000000;
        if (((behavior->vehicle_reaction & 2) != 0) && ((test->flags0 & 0x2000000) != 0)) {
            // entering zero-g/orbit: seed velocityDir from the last move, clear the slide
            test->velocityDir.x = test->transform.vD.x - test->positionPrev.x;
            test->velocityDir.y = test->transform.vD.y - test->positionPrev.y;
            test->velocityDir.z = test->transform.vD.z - test->positionPrev.z;
            test->unk10_3 = 0x40400000;// 3.0f
            test->velocitySlope.x = 0.0;
            test->velocitySlope.y = 0.0;
            test->velocitySlope.z = 0.0;
            test->flags0 = (test->flags0 & 0xfdffffff) | 0x4000000;
        }

        if ((behavior->vehicle_reaction & 4) != 0)
            iceTarget = 200.0f;
        if ((behavior->vehicle_reaction & 8) != 0) {
            terrainTractionTarget = 0.75f;
            if ((test->flags0 & 0x2000000) != 0)
                test->flags0 = test->flags0 & 0xff7fffff;
        }
        if ((behavior->vehicle_reaction & 0x10) != 0) {
            terrainTractionTarget = 0.1f;
            test->flags0 = test->flags0 & 0xff7fffff;
        }
        if ((behavior->vehicle_reaction & 0x20) != 0)
            terrainSkidTarget = 0.2f;
        if ((test->flags1 & 0x2000000) != 0)
            terrainSkidTarget = 1.0f;
        if ((behavior->vehicle_reaction & 0x400) != 0)
            test->flags1 = test->flags1 | 1;
        if (behavior->triggers != NULL)
            swrRace_ActivateTriggersInRange(test, behavior->triggers);
        if (((behavior->vehicle_reaction & 0x1000) != 0) && (swrConfig_VIDEO_REFLECTIONS == 1))
            test->flags1 = test->flags1 | 0x40;
        if ((behavior->vehicle_reaction & 0x20000000) != 0)
            test->flags1 = test->flags1 | 0x20;
    }

    if (specialActiveTrigger != NULL)
        swrRace_ActivateTriggersInRange(test, specialActiveTrigger);

    swrRace_easeTraction(&test->iceTractionMultiplier, iceTarget, 25.0);
    swrRace_easeTraction(&test->terrainTractionMultiplier, terrainTractionTarget, 0.5);
    swrRace_easeTraction(&test->terrainSkidModifier, terrainSkidTarget, 0.5);

    test->unk11_1 = 0;
    if (((((float) test->unk1998 - 400.0f) * 0.0016666667f < 1.0f) || ((test->flags0 & 0x20) != 0) ||
         ((test->flags1 & 0x4000000) != 0)) &&
        (((test->flags1 & 0x80000) != 0) && ((test->flags1 & 0x200) == 0)))
        test->flags0 = test->flags0 | 0x1000;
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

// Normal-mode slope steering (no magnet). Projects world gravity (unk194_vec) onto the surface plane
// to accumulate the downhill slide into velocitySlope (force quadratic in the steer term), and drives
// unk8_1 (auto-tilt) from the downhill/facing alignment. Also publishes the slope angle to
// swrRace_slopeAngle. Bails near-flat / near-inverted surfaces (dot(normal, worldDown) outside
// [-0.995, 0.995]); out1 is scratch for the gradient, out2 the integrated slide.
// 0x004791d0
void swrRace_ApplySlopeSteering(swrRace* player, int velocity, int scrapeData, float groundDist,
                                rdVector3* normal, rdVector3* out1, rdVector3* out2)
{
    rdVector3 downhillAxis;
    rdVector3 slopeForce;
    rdVector3 surfDir;
    rdVector3 vbFlat;

    float dotND = normal->x * player->unk194_vec.x + normal->y * player->unk194_vec.y +
                  normal->z * player->unk194_vec.z;
    if ((dotND < -0.995) || (0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, 0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->unk8_1 = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->unk194_vec);
    rdVector_Cross3(out1, normal, &downhillAxis);
    rdVector_Normalize3Acc(out1);// out1 = normalized downhill gradient on the surface
    float slopeSin = out1->x * player->unk194_vec.x + out1->y * player->unk194_vec.y +
                     out1->z * player->unk194_vec.z;
    swrRace_slopeAngle = stdMath_ArcSin(slopeSin);

    float steerMag;
    if (groundDist <= 50.0f)
        steerMag = (1.0f - groundDist * 0.02f) * slopeSin;
    else
        steerMag = 0.0;

    float force = steerMag * steerMag * 400.0f;
    rdVector_Scale3(&slopeForce, -force, out1);
    rdVector_Scale3Add3(out2, &player->velocitySlope, swrRace_deltaTimeSecs + swrRace_deltaTimeSecs,
                        &slopeForce);
    float outLen = rdVector_Len3(out2);
    float absLen = (outLen < 0.0) ? -outLen : outLen;
    float absForce = (force < 0.0) ? -force : force;
    if (absForce < absLen) {
        float scale = force / outLen;
        if (scale < 0.0)
            scale = -scale;
        rdVector_Scale3(out2, scale, out2);
    }
    rdVector_Copy3(&player->velocitySlope, out2);

    surfDir.x = out1->x;
    surfDir.y = out1->y;
    surfDir.z = 0.0;
    vbFlat.x = player->transform.vB.x;
    vbFlat.y = player->transform.vB.y;
    vbFlat.z = 0.0;
    float surfLen = rdVector_Normalize3Acc(&surfDir);
    if (surfLen < 0.01f) {
        surfDir.x = -normal->x;
        surfDir.y = -normal->y;
        surfDir.z = -normal->z;
    }
    rdVector_Normalize3Acc(&vbFlat);
    float align = surfDir.x * vbFlat.x + surfDir.y * vbFlat.y + surfDir.z * vbFlat.z;
    float tiltScale = 0.0;
    if (0.0 <= align) {
        if (0.70700002f < align)
            align = (1.0f - align) * 2.5445292f * 0.70700002f;
        tiltScale = (surfDir.x * out1->x + surfDir.y * out1->y + surfDir.z * out1->z) * align;
        if (0.0 <= surfDir.y * vbFlat.x - surfDir.x * vbFlat.y)
            tiltScale = tiltScale * -2.0f;
        else
            tiltScale = tiltScale + tiltScale;
    }

    if (steerMag + 0.15f < 0.0) {
        float t = (steerMag + 0.15f) * 1.1764705f;
        player->unk8_1 = t * t * tiltScale * 600.0f;
        return;
    }
    player->unk8_1 = 0.0;
}

// Magnet-mode slope steering (flags1 0x400): keeps the pod glued to a tagged surface. Same gravity-on-
// surface velocitySlope build as the normal version but with a much stronger, speed-tiered steer term,
// and the auto-tilt (unk8_1) aligns the pod's facing to the downhill direction. Same near-flat /
// near-inverted bail. NOTE: the [-0.995, 0.995] gate + the speed tiers are the limits a "banking magnet"
// corkscrew mode would relax. velocity/scrapeData/groundDist are unused here (kept for signature parity).
// 0x00479550
void swrRace_ApplySlopeSteeringMagnet(swrRace* player, int velocity, int scrapeData, float groundDist,
                                      rdVector3* normal, rdVector3* out1, rdVector3* out2)
{
    rdVector3 downhillAxis;
    rdVector3 slopeForce;
    rdVector3 surfDir;
    rdVector3 vbFlat;

    float dotND = normal->x * player->unk194_vec.x + normal->y * player->unk194_vec.y +
                  normal->z * player->unk194_vec.z;
    if ((dotND < -0.995) || (0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, 0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->unk8_1 = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->unk194_vec);
    rdVector_Normalize3Acc(&downhillAxis);
    rdVector_Cross3(out1, normal, &downhillAxis);// out1 = downhill gradient on the surface
    float slopeSin = out1->x * player->unk194_vec.x + out1->y * player->unk194_vec.y +
                     out1->z * player->unk194_vec.z;
    float slopeAngle = stdMath_ArcSin(slopeSin);
    float steerMag = slopeAngle * -1.1111112f;

    if (200.0f <= player->speedValue) {
        if (250.0f <= player->speedValue) {
            if (300.0f <= player->speedValue) {
                if (350.0f <= player->speedValue)
                    steerMag = (steerMag - 80.0f) * 5.0f;
                else
                    steerMag = (steerMag - 60.0f) * 2.5f;
            } else {
                steerMag = (steerMag - 40.0f) * 1.6666666f;
            }
        } else {
            steerMag = (steerMag - 25.0f) * 1.3333334f;
        }
    }
    if (steerMag < 0.0)
        steerMag = 0.0;
    if (87.0f < slopeAngle)
        steerMag = steerMag + steerMag;

    rdVector_Scale3(&slopeForce, -steerMag, out1);
    rdVector_Scale3Add3(out2, &player->velocitySlope, swrRace_deltaTimeSecs + swrRace_deltaTimeSecs,
                        &slopeForce);
    float outLen = rdVector_Len3(out2);
    float absLen = (outLen < 0.0) ? -outLen : outLen;
    float absSteer = (steerMag < 0.0) ? -steerMag : steerMag;
    if (absSteer < absLen) {
        float scale = steerMag / outLen;
        if (scale < 0.0)
            scale = -scale;
        rdVector_Scale3(out2, scale, out2);
    }
    rdVector_Copy3(&player->velocitySlope, out2);

    surfDir.x = out1->x;
    surfDir.y = out1->y;
    surfDir.z = 0.0;
    vbFlat.x = player->transform.vB.x;
    vbFlat.y = player->transform.vB.y;
    vbFlat.z = 0.0;
    float surfLen = rdVector_Normalize3Acc(&surfDir);
    if (surfLen < 0.01f) {
        surfDir.x = -normal->x;
        surfDir.y = -normal->y;
        surfDir.z = -normal->z;
    }
    rdVector_Normalize3Acc(&vbFlat);
    float align = surfDir.x * vbFlat.x + surfDir.y * vbFlat.y + surfDir.z * vbFlat.z;
    if (0.0 <= align) {
        float a = stdMath_ArcSin(align);
        float side = vbFlat.x * downhillAxis.x + vbFlat.y * downhillAxis.y + vbFlat.z * downhillAxis.z;
        if (side <= 0.0)
            player->unk8_1 = -(a * slopeSin);
        else
            player->unk8_1 = -(-a * slopeSin);
    } else {
        player->unk8_1 = 0.0;
    }
}

// Casts a ray "down" (world unk194_vec, or -unk160 in magnet mode, started 2 units up) to find the
// ground. Tries the fast mesh ray (CollideRayWithMesh) then the full query (InitUnk); in magnet mode,
// retries once straight down (world gravity) if the surface-relative cast missed. Writes the surface
// normal to outSurfaceNormal (world-up on a miss) and the hit node to player->terrainModel. Returns the ground
// distance minus a 2-unit skin, or a large value (100000) when nothing was hit.
// 0x004772f0
float swrRace_RaycastGround(swrRace* player, rdVector3* pos, int* outSurfaceNormal)
{
    rdVector3 down;
    rdVector3 origin;
    rdVector3 outPoint;
    rdVector3 outNormal;
    float ray[7];
    float hitDist;

    if ((player->flags1 & 0x400) == 0) {
        down = player->unk194_vec;
    } else {
        down.x = -player->unk160.x;
        down.y = -player->unk160.y;
        down.z = -player->unk160.z;
    }
    rdVector_Scale3Add3(&origin, pos, -2.0f, &down);
    ray[0] = origin.x;
    ray[1] = origin.y;
    ray[2] = origin.z;
    ray[3] = down.x;
    ray[4] = down.y;
    ray[5] = down.z;
    ray[6] = 10000.0f;

    swrRace_ResetCollisionHit();
    if ((player->flags1 & 0x80) == 0)
        hitDist = swrModel_CollideRayWithMesh((swrModel_Mesh*) player->unkec_node, ray,
                                              (float*) &outPoint, (float*) &outNormal);
    else
        hitDist = -1.0f;

    if (hitDist < 0.0)
        hitDist = swrRace_InitUnk(player->model_unk, ray, &outPoint, &outNormal);

    if (((player->flags1 & 0x400) != 0) && (hitDist < 0.0)) {
        // surface-relative cast missed: retry straight down (world gravity)
        ray[3] = player->unk194_vec.x;
        ray[4] = player->unk194_vec.y;
        ray[5] = player->unk194_vec.z;
        hitDist = swrRace_InitUnk(player->model_unk, ray, &outPoint, &outNormal);
    }

    player->terrainModel = swrRace_GetCollisionHit();

    if (hitDist < 0.0) {
        ((float*) outSurfaceNormal)[0] = 0.0;
        ((float*) outSurfaceNormal)[1] = 0.0;
        ((float*) outSurfaceNormal)[2] = 1.0;
        player->thrust = -10000.0f;
        return 100000.0f;
    }

    ((float*) outSurfaceNormal)[0] = outNormal.x;
    ((float*) outSurfaceNormal)[1] = outNormal.y;
    ((float*) outSurfaceNormal)[2] = outNormal.z;
    player->thrust = outPoint.z;
    return hitDist - 2.0f;
}

// Per-frame ground-contact orchestrator. Raycasts the ground (RaycastGround) to get the surface
// normal, stores it as the pod's "up" in unk160, runs slope steering (magnet variant when flags1
// 0x400 is set), applies gravity, then resolves track/wall collision and hover pads. Returns the
// ground distance (also cached in groundToPodMeasure). The `up.z < 0.05` floor below is THE limit a
// vertical/inverted "magnet" corkscrew would have to lift -- it stops the surface normal from ever
// pointing sideways-past-vertical or downward.
// 0x00479e10
float swrRace_UpdateGroundContact(swrRace* player, float* velocity, int scrapeData, rdVector3* up, int hoverPadState)
{
    rdVector3 prevPos;
    rdVector3 slopeOut1;
    rdVector3 slopeOut2;
    rdVector3 wallDelta;
    rdVector3 collideNormal;
    rdMatrix44 splineMat;
    float groundDist;

    prevPos.x = velocity[0];
    prevPos.y = velocity[1];
    prevPos.z = velocity[2];

    const float progress = ((float) player->unk1998 - 400.0f) * 0.0016666667f;
    if ((progress < 1.0f) || ((player->flags0 & 0x20) != 0) || ((player->flags1 & 0x4000000) != 0)) {
        uint32_t flags1;
        if (((player->flags1 & 0x400000) == 0) || ((player->flags1 & 0x800000) == 0)) {
            groundDist = swrRace_RaycastGround(player, (rdVector3*) velocity, (int*) up);
            flags1 = player->flags1;
            if ((flags1 & 0x800000) == 0)
                flags1 = flags1 & 0xffbfffff;
            else
                flags1 = flags1 | 0x400000;
        } else {
            groundDist = velocity[2] - player->thrust;
            up->x = player->unk160.x;
            up->y = player->unk160.y;
            up->z = player->unk160.z;
            player->terrainModel = player->unkec_node;
            flags1 = player->flags1 | 0x20000000;
        }
        player->flags1 = flags1;

        // surface-relative magnet mode: keep the "up" normal from tipping past ~horizontal/inverted
        if (((flags1 & 0x400) != 0) && (up->z < 0.05f)) {
            up->z = 0.05f;
            rdVector_Normalize3Acc(up);
        }
        player->unk160.x = up->x;
        player->unk160.y = up->y;
        player->unk160.z = up->z;

        if (((player->flags0 & 0x5000) == 0) &&
            ((0.1f < player->gravityMultiplier) || (0.1f < -player->gravityMultiplier) ||
             ((player->flags0 & 0x2000) == 0))) {
            if ((player->flags1 & 0x400) == 0)
                swrRace_ApplySlopeSteering(player, (int) velocity, scrapeData, groundDist, up, &slopeOut1,
                                           &slopeOut2);
            else
                swrRace_ApplySlopeSteeringMagnet(player, (int) velocity, scrapeData, groundDist, up,
                                                 &slopeOut1, &slopeOut2);
        }

        if ((player->flags0 & 0x4000000) == 0)
            swrRace_ApplyGravity(player, velocity, groundDist);

        if (groundDist < 0.0)
            groundDist = 2.0f;

        if ((((uint8_t) player->flags0 & 0xf) == 2) && ((player->flags0 & 0x20) == 0) &&
            (0.0f <= progress && progress <= 1.0f)) {
            swrSpline_EvaluateAtOffset(&player->unk4_mat, &splineMat, 0.0);
            velocity[2] = progress * (splineMat.vD.z - velocity[2]) + velocity[2];
        }

        if ((player->flags1 & 0x800000) == 0) {
            if ((player->flags0 & 0x20) == 0) {
                swrRace_CollideBlockMove((rdVector3*) velocity, &prevPos, player->model_unk, &collideNormal);
            } else {
                rdVector3 before;
                before.x = velocity[0];
                before.y = velocity[1];
                before.z = velocity[2];
                swrRace_DetectWallScrape(player, velocity, (float*) scrapeData);
                wallDelta.x = player->unk154_vec.x + (velocity[0] - before.x);
                wallDelta.y = player->unk154_vec.y + (velocity[1] - before.y);
                wallDelta.z = player->unk154_vec.z + (velocity[2] - before.z);
                swrRace_ApplyWallCollision(player, &wallDelta, up);
            }
        }

        if (1.0f <= ((float) player->unk1998 - 40.0f) * 0.016666668f) {
            // no fresh hover-pad data: mark all four pads "no ground"
            float* pad = (float*) (player->unk4d0 + 0xdf8);
            for (int i = 0; i < 4; i++) {
                *pad = -100000.0f;
                pad += 0x10;
            }
        } else {
            groundDist = swrRace_UpdateHoverPads(player, (rdVector3*) velocity, *(int*) (hoverPadState + 8),
                                                 groundDist, &up->x);
        }
    } else {
        player->terrainModel = player->unkec_node;
        player->flags1 = player->flags1 | 0x20000000;
        if (((uint8_t) player->flags0 & 0xf) == 2) {
            swrSpline_EvaluateAtOffset(&player->unk4_mat, &splineMat, 0.0);
            velocity[2] = splineMat.vD.z;
        }
        groundDist = 2.0f;
        up->x = 0.0;
        up->y = 0.0;
        up->z = 1.0;
        if (((uint8_t) player->flags0 & 0xf) == 2)
            player->flags1 = player->flags1 | 2;
    }

    player->groundToPodMeasure = groundDist;
    return groundDist;
}

// 0x0046bd20
int swrRace_BoostCharge(int player)
{
    // TODO
    return 0;
}

// Extracts the pitch (out->y, measured from horizontal) and signed roll/bank (out->z) of a
// forward/right basis relative to a reference (down) vector. Angles are in degrees
// (stdMath_ArcCos). out->x is unused (0). Leaf used by swrRace_AlignToSurface.
// 0x00476390
void swrRace_ComputeTiltAngles(rdVector3* fwd, rdVector3* right, rdVector3* ref, rdVector3* out)
{
    rdVector3 refCrossFwd;
    rdVector3 rightCross;
    float len;

    out->x = 0.0;
    out->z = 0.0;
    out->y = stdMath_ArcCos(fwd->x * ref->x + fwd->y * ref->y + fwd->z * ref->z) - 90.0f;

    rdVector_Cross3(&refCrossFwd, ref, fwd);
    rdVector_Cross3(&rightCross, right, &refCrossFwd);
    len = rdVector_Len3(&refCrossFwd);
    if (len <= 0.01f)
        return;

    float roll = stdMath_ArcCos((right->x * refCrossFwd.x + right->y * refCrossFwd.y +
                                 right->z * refCrossFwd.z) /
                                len);
    if (0.0 < rightCross.x * fwd->x + rightCross.y * fwd->y + rightCross.z * fwd->z)
        out->z = -roll;
    else
        out->z = roll;
}

// Builds a surface-aligned basis (right = vB x up, fwd = up x right), measures the pod's
// heading/tilt error against it via swrRace_ComputeTiltAngles, and accumulates a correction into
// the turn input pRDot (->y heading, ->z tilt). In magnet mode (flags1 0x400) the surface-tilt
// alignment (out->z / bank) is clamped to +-85 deg. groundDist/hoverHi/hoverLo gate how strongly
// the correction applies as the pod nears the ground.
// 0x004764e0
void swrRace_AlignToSurface(swrRace* player, rdVector3* up, rdVector3* fwd_vB, rdVector3* vA_fallback,
                            rdVector3* down_ref, float groundDist, float hoverHi, float hoverLo, rdVector3* pRDot)
{
    rdVector3 surfRight;
    rdVector3 surfFwd;
    rdVector3 angles;
    float len;

    rdVector_Cross3(&surfRight, fwd_vB, up);
    len = rdVector_Len3(&surfRight);
    if (0.01f < len)
        rdVector_Scale3(&surfRight, 1.0f / len, &surfRight);
    else
        surfRight = *vA_fallback;

    rdVector_Cross3(&surfFwd, up, &surfRight);
    len = rdVector_Len3(&surfFwd);
    if (0.01f < len)
        rdVector_Scale3(&surfFwd, 1.0f / len, &surfFwd);
    else
        surfFwd = *fwd_vB;

    swrRace_ComputeTiltAngles(&surfFwd, &surfRight, down_ref, &angles);

    // magnet mode: clamp the surface-tilt (bank) alignment to +-85 deg
    if ((player->flags1 & 0x400) != 0) {
        if (85.0f < angles.z)
            angles.z = 85.0f;
        if (angles.z < -85.0f)
            angles.z = -85.0f;
    }

    float headingDelta = angles.y - pRDot->y;
    float headingGain = 0.33333334f;
    if ((angles.y < pRDot->y) || (headingGain = 0.5f, pRDot->y < angles.y))
        headingDelta = headingDelta * headingGain;

    float tiltDelta = (angles.z - pRDot->z) * 0.125f;

    if ((player->flags0 & 0x4000000) == 0) {
        float blend = (hoverHi - groundDist) / (hoverHi - hoverLo);
        if (blend <= 0.0) {
            tiltDelta = pRDot->z * -0.125f;
            headingDelta = 0.0;
            if (-37.0f < pRDot->y)
                headingDelta = swrRace_deltaTimeSecs * -22.0f;
            if ((player->pitch < 0.0) && (pRDot->y < -10.0f))
                headingDelta = headingDelta - swrRace_deltaTimeSecs * player->pitch * 20.0f;
        } else if (blend < 1.0f) {
            headingDelta = blend * headingDelta;
            tiltDelta = tiltDelta * blend;
        }
    }

    pRDot->y = headingDelta + pRDot->y;
    pRDot->z = tiltDelta + pRDot->z;
}

// Walk a model-node tree gathering up to 10 distinct mesh-group entries (deduped by
// their data pointer) into the swrRace_meshNodeCollection scratch list.
// 0x0046e750
void swrRace_CollectMeshNodes(swrModel_Node* node)
{
    if (swrRace_meshNodeCount >= 10 || node == NULL) {
        return;
    }
    if (swrModel_NodeGetFlags(node) == NODE_MESH_GROUP) {
        for (int i = 0; i < (int) node->num_children && swrRace_meshNodeCount < 10; i++) {
            swrModel_NodeType mesh = node->children.nodes[i]->type;
            if (mesh != 0 && *(int*) ((char*) mesh + 8) != 0) {
                bool dup = false;
                for (int j = 0; j < swrRace_meshNodeCount && !dup; j++) {
                    if (*(int*) ((char*) swrRace_meshNodeCollection[j] + 8) == *(int*) ((char*) mesh + 8)) {
                        dup = true;
                    }
                }
                if (!dup) {
                    swrRace_meshNodeCollection[swrRace_meshNodeCount] = mesh;
                    swrRace_meshNodeCount++;
                }
            }
        }
    } else if ((swrModel_NodeGetFlags(node) & NODE_HAS_CHILDREN) != 0) {
        for (int i = 0; i < (int) swrModel_NodeGetNumChildren(node); i++) {
            swrRace_CollectMeshNodes(node->children.nodes[i]);
        }
    }
}

// Recursively re-skin a node tree's mesh-group children by round-robining through the
// collected mesh list (up to 5 assignments).
// 0x0046e850
void swrRace_AssignRandomMeshNodes(swrModel_Node* node)
{
    if (swrRace_meshNodeAssignCount >= 5 || node == NULL) {
        return;
    }
    if (swrModel_NodeGetFlags(node) == NODE_MESH_GROUP) {
        for (int i = 0; i < (int) node->num_children; i++) {
            if (node->children.nodes[i]->type != 0) {
                swrRace_meshNodeRoundRobin = (swrRace_meshNodeRoundRobin + 1) % swrRace_meshNodeCount;
                node->children.nodes[i]->type = swrRace_meshNodeCollection[swrRace_meshNodeRoundRobin];
                swrRace_meshNodeAssignCount++;
            }
        }
    } else if ((swrModel_NodeGetFlags(node) & NODE_HAS_CHILDREN) != 0) {
        for (int i = 0; i < (int) swrModel_NodeGetNumChildren(node); i++) {
            swrRace_AssignRandomMeshNodes(node->children.nodes[i]);
        }
    }
}

// Collect the source pod's mesh-group nodes, then randomly reassign the destination
// (fireball) node's meshes from that pool, giving each engine-blowout a varied look.
// 0x0046e910
void swrRace_RandomizeMeshNodes(swrModel_Node* dst, swrModel_Node* src)
{
    swrRace_meshNodeCount = 0;
    swrRace_meshNodeAssignCount = 0;
    swrRace_CollectMeshNodes(src);
    if (0 < swrRace_meshNodeCount) {
        swrRace_AssignRandomMeshNodes(dst);
    }
}

// Spawn the engine-blowout fireball: re-skin the shared fireball node from the pod's
// meshes and place it at the given engine with a random orientation and scale. Gated on
// a free fx-animation slot (swrModel_AnyFxAnimDone).
// 0x0046e950
void swrRace_SpawnEngineFireball(swrRace* player, int engineSlot, rdVector3* pos, float scale)
{
    if (fireballNodePtr == NULL || fx_podasx_anim == NULL || swrModel_AnyFxAnimDone(fx_podasx_anim) == 0) {
        return;
    }

    int subEvent[4];
    subEvent[0] = 0x42697473; // 'Bits'
    swrEvent_CallF4(0x54657374, subEvent); // 'Test'
    player->unk324 = engineSlot;

    // Build a random orientation+scale basis for the fireball node.
    rdMatrix44 m;
    rdMatrix_SetIdentity44(&m);
    for (int k = 0; k < 3; k++) {
        float a = (float) swrUtils_Rand() * 4.6566129e-10f * 0.99f + 0.01f;
        if ((swrUtils_Rand() & 1) != 0) {
            a = -a;
        }
        (&m.vA.x)[k] = a;
        float b = (float) swrUtils_Rand() * 4.6566129e-10f * 0.99f + 0.01f;
        if ((swrUtils_Rand() & 1) != 0) {
            b = -b;
        }
        (&m.vB.x)[k] = b;
    }
    rdVector_Cross3((rdVector3*) &m.vC, (rdVector3*) &m.vA, (rdVector3*) &m.vB);
    rdVector_Cross3((rdVector3*) &m.vB, (rdVector3*) &m.vC, (rdVector3*) &m.vA);
    rdVector_Normalize3Acc((rdVector3*) &m.vA);
    rdVector_Normalize3Acc((rdVector3*) &m.vB);
    rdVector_Normalize3Acc((rdVector3*) &m.vC);
    float spread = scale * 1.5f - scale;
    rdVector_Scale3((rdVector3*) &m.vA, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vA);
    rdVector_Scale3((rdVector3*) &m.vB, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vB);
    rdVector_Scale3((rdVector3*) &m.vC, (float) swrUtils_Rand() * 4.6566129e-10f * spread + scale, (rdVector3*) &m.vC);

    swrModel_AnimationsResetToZero(fx_podasx_anim);
    swrModel_AnimationsResetToZero2(fx_podasx_anim, 3.0f);

    // When a valid engine slot is set, position the fireball at that engine's matrix;
    // otherwise use the caller-supplied point.
    if (player->unk324 >= 0) {
        pos = (rdVector3*) ((char*) player + (player->unk324 + 0xe) * 0x40);
    }
    rdVector_Copy3((rdVector3*) &m.vD, pos);

    swrModel_Node* src =
        (player->unk344_nodeArray == NULL) ? player->unk348_node : player->unk344_nodeArray[1];
    swrRace_RandomizeMeshNodes(fireballNodePtr, src);
    rdMatrix_Copy44(&swrRace_fireballTransform, &m);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*) fireballNodePtr, &m);
    swrModel_NodeModifyFlags(fireballNodePtr, 2, 3, 0x10, 2);
}

// 0x00477ad0
void swrRace_CalculateTiltFromTurn(int pEngine, rdVector4* pXformZ, float ZMotion, rdVector3* pRDot)
{
    swrRace* player = (swrRace*) pEngine;
    float hoverHi = player->podStats.hoverHeight * 1.5f;
    float hoverLo = (player->podStats.intersectRadius + player->podStats.intersectRadius +
                     player->podStats.hoverHeight) *
                    0.33333334f;

    // Outside magnet mode, lift the standing tilt target out of pRDot->z before re-aligning.
    if ((player->flags1 & 0x400) == 0)
        pRDot->z = pRDot->z - player->tiltAngleTarget;

    swrRace_AlignToSurface(player, (rdVector3*) pXformZ, (rdVector3*) &player->transform.vB,
                           (rdVector3*) &player->transform.vA, &player->unk194_vec, ZMotion, hoverHi,
                           hoverLo, pRDot);

    // Magnet mode (flags1 0x400) suppresses ALL of the player banking + manual tilt below; only the
    // surface alignment from swrRace_AlignToSurface reaches the tilt axis.
    if ((player->flags1 & 0x400) == 0) {
        pRDot->z = player->tiltAngleTarget + pRDot->z;

        // Bank-into-turn: ease tiltAngleTarget toward the turn-rate-driven lean (capped at 300 deg
        // on the ground / 70 deg airborne), then blend the change into pRDot->z.
        float prevTilt = player->tiltAngleTarget;
        float maxAngle = ((player->flags0 & 0x80) == 0) ? 70.0f : 300.0f;
        swrRace_SetAngleFromTurnRate(&player->tiltAngleTarget, player->turnRate,
                                     *(void**) &player->turnRateTarget, player->podStats.maxTurnRate,
                                     maxAngle);
        pRDot->z = pRDot->z - (player->tiltAngleTarget - prevTilt) * 0.2f;

        // Manual tilt (player holding a lean) pulls pRDot->z toward tiltManualMult * 80 deg.
        if (player->tiltManualMult != 0.0) {
            float mag = player->tiltManualMult;
            if (mag < 0.0)
                mag = -mag;
            pRDot->z = (player->tiltManualMult * 80.0f - pRDot->z) * mag + pRDot->z;
        }
    }

    player->tiltAngle = pRDot->z;
}

// Per-frame orientation update: rotates the pod's transform basis (vA/vB/vC) by the accumulated turn
// input (turnInput->z about vB via a vector-angle matrix, ->y pitch about the horizontal surface axis,
// ->x roll about Z), then stores the new position into vD. Above a progress threshold (and outside
// debug/zero-g) it takes a cheap yaw-only path. Re-normalizes the basis every 8 frames to fight drift.
// NOTE: address corrected 0x00477c27 -> 0x00477c30 (the former was a bogus {return;} with no xrefs).
// 0x00477c30
void swrRace_UpdateTurn2(swrRace* player, rdVector3* pos, rdVector3* turnInput)
{
    rdMatrix44 m;
    float vAx = player->transform.vA.x;
    float vAy = player->transform.vA.y;
    float vAz = player->transform.vA.z;
    float vBx = player->transform.vB.x;
    float vBy = player->transform.vB.y;
    float vBz = player->transform.vB.z;
    float vCx = player->transform.vC.x;
    float vCy = player->transform.vC.y;
    float vCz = player->transform.vC.z;

    if ((((float) player->unk1998 - 400.0f) * 0.0016666667f < 1.0f) || ((player->flags0 & 0x20) != 0) ||
        ((player->flags1 & 0x4000000) != 0)) {
        // full 3-axis update: build a horizontal axis (hx, hy) from vB (fall back to vC near-vertical)
        float hx = -vBx;
        float hy = vBy;
        float h = stdMath_Sqrt(hx * hx + vBy * vBy);
        if (h < 0.1f) {
            hx = -vCx;
            hy = vCy;
            h = stdMath_Sqrt(hx * hx + vCy * vCy);
        }
        hy = hy / h;
        hx = hx / h;

        rdMatrix_BuildFromVectorAngle44(&m, turnInput->z, vBx, vBy, vBz);

        // pitch rotation about the (hx, hy, 0) axis
        float ps, pc;
        stdMath_SinCos(turnInput->y, &ps, &pc);
        float hx2 = hx * hx;
        float r00 = pc * hx2 + hy * hy;
        float r11 = pc * hy * hy + hx2;
        float r01 = (1.0f - pc) * hx * hy;
        float r02 = hy * ps;
        float r12 = -(hx * ps);
        float r20 = -r12;
        float r21 = -r02;

        float a0 = m.vA.z * r20 + m.vA.y * r01 + m.vA.x * r00;
        float a1 = m.vA.z * r21 + m.vA.y * r11 + m.vA.x * r01;
        float a2 = pc * m.vA.z + m.vA.y * r02 + m.vA.x * r12;
        float b0 = m.vB.z * r20 + m.vB.y * r01 + m.vB.x * r00;
        float b1 = m.vB.z * r21 + m.vB.y * r11 + m.vB.x * r01;
        float b2 = pc * m.vB.z + m.vB.y * r02 + m.vB.x * r12;
        float c0 = m.vC.z * r20 + m.vC.y * r01 + m.vC.x * r00;
        float c1 = m.vC.z * r21 + m.vC.y * r11 + m.vC.x * r01;
        float c2 = pc * m.vC.z + m.vC.y * r02 + m.vC.x * r12;

        // roll rotation about Z
        float rs, rc;
        stdMath_SinCos(turnInput->x, &rs, &rc);
        float a0r = rc * a0 - rs * a1;
        float a1r = rs * a0 + rc * a1;
        float b0r = rc * b0 - rs * b1;
        float b1r = rs * b0 + rc * b1;
        float c0r = rc * c0 - rs * c1;
        float c1r = rs * c0 + rc * c1;

        player->transform.vA.x = vAz * c0r + vAy * b0r + vAx * a0r;
        player->transform.vA.y = vAz * c1r + vAy * b1r + vAx * a1r;
        player->transform.vA.z = vAz * c2 + vAy * b2 + vAx * a2;
        player->transform.vB.x = vBz * c0r + vBy * b0r + vBx * a0r;
        player->transform.vB.y = vBz * c1r + vBy * b1r + vBx * a1r;
        player->transform.vB.z = vBz * c2 + vBy * b2 + vBx * a2;
        player->transform.vC.x = vCz * c0r + vCy * b0r + vCx * a0r;
        player->transform.vC.y = vCz * c1r + vCy * b1r + vCx * a1r;
        player->transform.vC.z = vCz * c2 + vCy * b2 + vCx * a2;
    } else {
        // cheap yaw-only update (roll about Z by turnInput->x)
        float rs, rc;
        stdMath_SinCos(turnInput->x, &rs, &rc);
        player->transform.vA.x = rc * vAx - rs * vAy;
        player->transform.vA.y = rc * vAy + rs * vAx;
        player->transform.vB.x = rc * vBx - rs * vBy;
        player->transform.vB.y = rc * vBy + rs * vBx;
        player->transform.vA.z = vAz;
        player->transform.vC.x = rc * vCx - rs * vCy;
        player->transform.vB.z = vBz;
        player->transform.vC.z = vCz;
        player->transform.vC.y = rc * vCy + rs * vCx;
    }

    player->unk1e6c = player->unk1e6c - 1;
    if (player->unk1e6c < 0) {
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vA);
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vB);
        rdVector_Normalize3Acc((rdVector3*) &player->transform.vC);
        player->unk1e6c = 8;
    }
    player->transform.vD.x = pos->x;
    player->transform.vD.y = pos->y;
    player->transform.vD.z = pos->z;
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

// Per-frame engine-temperature model. The gauge runs 0..100: boosting drains it at
// heatRate, idling recovers it at coolRate, and a spinout drains it fast (biasing which
// engine fails). When it bottoms out, a random engine part overheats and blows.
// 0x004788c0
void swrRace_UpdateHeat(swrRace* player)
{
    int spinDir = 0; // -1 / 0 / +1 spinout-tilt bias for which engine part fails

    if ((player->flags1 & 0x40000) != 0) {
        // Spun out: drain fast regardless of throttle; tilt direction biases the failure.
        player->engineTemp -= (float) (swrRace_deltaTimeSecs * 20.0);
        if (player->tiltManualMult < -0.5f) {
            spinDir = -1;
        } else if (0.5f < player->tiltManualMult) {
            spinDir = 1;
        }
    } else if ((player->flags0 & 0x800000) != 0) {
        player->engineTemp -= (float) (swrRace_deltaTimeSecs * player->podStats.heatRate);
    } else {
        player->engineTemp += (float) (swrRace_deltaTimeSecs * player->podStats.coolRate);
    }

    if (100.0f <= player->engineTemp) {
        player->engineTemp = 100.0f;
    }
    if (0.0f < player->engineTemp) {
        return;
    }

    // Overheated: pick an engine part (left/right half biased by spin direction) and blow it.
    player->engineTemp = 0.0f;
    int part;
    if (spinDir < 0) {
        part = (int) ((float) swrUtils_Rand() * 4.6566129e-10f * 3.0f);
    } else if (spinDir > 0) {
        part = 3 - (int) ((float) swrUtils_Rand() * 4.6566129e-10f * -3.0f);
    } else {
        part = (int) ((float) swrUtils_Rand() * 4.6566129e-10f * 6.0f);
    }

    if ((player->engineStatus[part] & 8) == 0) {
        rdVector3 origin = {0.0f, 0.0f, 0.0f};
        swrRace_SpawnEngineFireball(player, 2 - part / 3, &origin, 0.1f);
    }
    player->engineStatus[part] |= 8;
    player->flags0 &= 0xff7fffff;
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

// 0x0044abc0
int swrRace_CollideBlockMove(rdVector3* curPos, rdVector3* prevPos, swrModel_Node* model, rdVector3* outNormal)
{
    HANG("TODO");
}

// 0x00477940
void swrRace_DetectWallScrape(swrRace* player, float* velocity, float* scrapeOut)
{
    HANG("TODO");
}

// 0x00479920
void swrRace_ApplyWallCollision(swrRace* player, rdVector3* normal, rdVector3* dir)
{
    HANG("TODO");
}

// 0x00476740
float swrRace_UpdateHoverPads(swrRace* player, rdVector3* pos, int padFlags, float groundDist, float* up)
{
    HANG("TODO");
}
