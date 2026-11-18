#include "swrObj.h"

#include "globals.h"
#include "engine_config.h"
#include "swrAssetBuffer.h"
#include "swrEvent.h"
#include "swrSprite.h"
#include "swrModel.h"
#include "swrSound.h"
#include "swrCam.h"
#include "swrText.h"
#include "swrMultiplayer.h"
#include "swrUI.h"
#include "swrRender.h"
#include "swrViewport.h"
#include "swrRace.h"
#include "swrSpline.h"
#include "swrWeather.h"
#include "swrPlayerHUD.h"
#include "Primitives/rdVector.h"
#include "Primitives/rdMatrix.h"
#include "General/stdMath.h"
#include "Main/swrControl.h"
#include "Unknown/rdMatrixStack.h"

#include <macros.h>
#include <General/utils.h>
#include <Win95/Window.h>
#include <string.h>

// 0x004336d0
void swrObjHang_SetHangar2State(swrObjHang_STATE state)
{
    if (g_objHang2 != NULL)
        swrObjHang_SetMenuState(g_objHang2, state);
}

// 0x004336a0
void swrObjHang_SetHangar2Splash(void)
{
    if (g_objHang2 == NULL)
        swrObjHang_SetMenuState(NULL, swrObjHang_STATE_SPLASH);
    else if (g_objHang2->menuScreen != swrObjHang_STATE_SPLASH)
        swrObjHang_SetMenuState(g_objHang2, swrObjHang_STATE_SPLASH);
}

// 0x004336f0
void swrObjHang_SetHangar2(swrObjHang* hang)
{
    g_objHang2 = hang;
}

// 0x00433700
void swrObjHang_SetUnused(void)
{
    if (g_objHang2 != NULL) {
        swrObjHang_unused_state = g_objHang2->menuScreen;
    }
    swrObjHang_unused_unk = -1;
}

// 0x004360e0
void DrawTracks(swrObjHang* hang, char param_2)
{
    HANG("TODO");
}

// 0x00440990
int swrUI_DebugColorsEqual_Maybe(char* a, char* b)
{
    if ((swrRace_DebugFlag & swrRace_DEBUGFLAG_NAME_CHECKS) == 0)
        return 0;
    if (a[0] == b[0] && a[1] == b[1] && a[2] == b[2])
        return 1;
    return 0;
}

// 0x004409d0
int compare3Chars(char* a, char* b)
{
    if (a[0] == b[0] && a[1] == b[1] && a[2] == b[2])
        return 1;
    return 0;
}

// 0x00440a00
char GetRequiredPlaceToProceed(char circuitIdx, char trackIdx)
{
    char res;

    if (('\x02' < circuitIdx) || (res = '\x04', '\x05' < trackIdx)) {
        res = '\x03';
    }
    return res;
}

// 0x00440a20
int isTrackUnlocked(char circuitId, char trackId)
{
    const uint8_t Bits = trackId * 2;
    uint8_t beat = (g_aBeatTrackPlace[circuitId] >> Bits) & 3;
    const uint8_t reqPlace = GetRequiredPlaceToProceed(circuitId, trackId);
    const bool bNextTrackSelectable = swrRace_UnlockDataBase[circuitId + 1] & (1 << (trackId + 1));

    if ((reqPlace > 3 || beat != 0) && (circuitId > 2 || bNextTrackSelectable)) {
        return 0;
    }
    return 1;
}

// 0x00440aa0
bool isTrackPlayable(swrObjHang* hang, char circuitIdx, char trackIdx)
{
    char tmp = swrRace_UnlockDataBase[circuitIdx + 1];
    if ((multiplayer_enabled != 0) && (circuitIdx < '\x03')) {
        return true;
    }
    if (hang->isTournamentMode == '\0') {
        tmp = g_aBeatTracksGlobal[circuitIdx];
    }
    return ((char)(1 << (trackIdx)) & tmp) != 0;
}

// 0x00440af0
int VerifySelectedTrack(swrObjHang* hang, int selectedTrackIdx)
{
    int playableIdx = -1;
    int track;

    for (track = 0; track < g_aTracksInCircuits[hang->circuitIdx]; track++) {
        if (isTrackPlayable(hang, hang->circuitIdx, (char)track)) {
            playableIdx++;
            if (playableIdx == selectedTrackIdx)
                return track;
        }
    }
    return -1;
}

// 0x00445680
void swrObjJudge_PollPause()
{
    if (pauseDisabled == 0)
        pollPauseInput();
}

// 0x00445690
int GetPauseState()
{
    return pauseState;
}

// 0x004456a0
float GetPauseMenuScrollInOut(void)
{
    return InRace_PauseMenu_ScrollInOut;
}

// 0x004456B0
int requestPause()
{
    int ev[4];

    if (pauseDisabled != 0)
        return pauseDisabled;
    if (multiplayer_enabled != 0) {
        swrRace_netPauseNoticeFade = 1.0f; // net play can't pause: show the notice instead
        return multiplayer_enabled;
    }
    swrSound_RewindChannels();
    playASound(0x4e, 6, 0.25f, 1.0f, 0);
    pauseState = 2;
    ev[0] = 'Paws';
    ev[1] = 1;
    swrEvent_CallF4('All!', ev);
    swrRace_OpenInRaceMenu();
    swrControl_StopAllForceEffects(1);
    return 0; // EXE returns whatever StopAllForceEffects left in EAX; callers ignore it
}

// 0x00445780
void requestUnpause(void)
{
    if (pauseDisabled == 0) {
        playASound(0x4d, 6, 0.25f, 1.0f, 0);
        pauseState = 3;
    }
}

// 0x004457b0
void enablePause(void)
{
    pauseDisabled = 0;
    pauseEnabledFlag = 1;
}

// 0x004457d0
void pollPauseInput(void)
{
    swrObjJdge* jdge;

    if (pauseState != 0)
        return;
    jdge = (swrObjJdge*)swrEvent_GetItem('Jdge', 0);
    if (jdge == NULL)
        return;
    if ((jdge->obj.flags & 0x1000) == 0) {
        if (swrObjJdge_CheckIfPauseRequested() != 0)
            requestPause();
    } else if ((swrRace_DebugFlag & 1) != 0 &&
               ((inRaceLocalPlayerInputBitset1[0] & 0x200) != 0 || (inRaceLocalPlayerInputBitset1[1] & 0x200) != 0) &&
               (pauseState == 1 || (inRaceLocalPlayerInputBitset3[0] & 0x400) != 0)) {
        requestPause();
    }
}

// 0x00450e30
void swrObj_Free(swrObj* obj)
{
    int subEvents[8];

    if (obj != NULL && (obj->flags & 0x100) == 0) {
        subEvents[0] = 0x46726565; // 'Free'
        swrEvent_DispatchSubEvents(obj, subEvents);
        *((uint8_t*)&obj->flags + 1) |= 1; // mark freed (flags |= 0x100)
    }
}

// 0x00451020
void swrObjcMan_UpdatePreRaceSweepTimer(swrObjcMan* cman, float targetValue)
{
    float prev = swrObjcMan_preRaceSweepTimer;
    swrRace* pod = cman->unkf4_objTest;

    if (targetValue == -1.0f)
        swrObjcMan_preRaceSweepTimer = targetValue;
    if (targetValue == -2.0f) {
        if (swrObjcMan_preRaceSweepTimer != -1.0f)
            swrObjcMan_preRaceSweepTimer = (float)(swrObjcMan_preRaceSweepTimer + swrRace_deltaTimeSecs);
    } else if (swrObjcMan_preRaceSweepTimer < targetValue) {
        swrObjcMan_preRaceSweepTimer = targetValue;
    }
    if (swrObjcMan_preRaceSweepTimer == -1.0f)
        return;
    // binder ignition; Neva Kee has no binder
    if (swrObjcMan_preRaceSweepTimer >= 6.0f && prev < 6.0f && targetValue < 100.0f && pod != NULL && *pod->score_ptr->pilotId != SWR_PILOT_NEVA_KEE)
        playASound(0x74, 6, 0.25f, 0.5f, 0);
    if (swrObjcMan_preRaceSweepTimer < 6.0f) {
        swrRace_energyBinderTime = 0.0f;
        return;
    }
    if (pod != NULL && (pod->flags0 & swrObjTest_FLAG0_LOCAL) != 0)
        swrRace_energyBinderTime = (float)(swrRace_energyBinderTime + swrRace_deltaTimeSecs);
}

// 50 - (phase mod 100), floored toward -inf; the caller takes |x| for a 0..50 triangle wave.
static float lightPulseWave(float phase)
{
    float scaled = phase * 0.01f;
    if (scaled < 0.0f)
        scaled = scaled - 0.999999f;
    int period = (int)scaled;
    return 50.0f - (phase - (float)period * 100.0f);
}

// 0x00451160
void swrObjcMan_UpdateLighting(swrObjcMan* cman, swrRace* pod)
{
    rdVector3 flashDir;
    rdVector3 flashColor;
    rdVector3 ambient;
    rdVector3 color;
    int changed = 0;

    if (pod->current_light_index < 0)
        return;
    if ((cman->unk2e4_flag & swrObjcMan_LIGHTFLAG_REFRESH) != 0) {
        cman->unk2e4_flag &= ~swrObjcMan_LIGHTFLAG_REFRESH;
        changed = 1;
    }
    if ((cman->unk2e4_flag & swrObjcMan_LIGHTFLAG_FADE) != 0) {
        if ((cman->unk2e4_flag & swrObjcMan_LIGHTFLAG_SNAP) != 0) {
            cman->unk2e4_flag &= ~(swrObjcMan_LIGHTFLAG_SNAP | swrObjcMan_LIGHTFLAG_FADE | swrObjcMan_LIGHTFLAG_FADE_SNAPSHOT);
            cman->ambientColor = cman->light.ambientColor;
            cman->lightColor = cman->light.lightColor;
            cman->lightVector = cman->light.lightVector;
            rdVector_Normalize3Acc(&cman->lightVector);
            changed = 1;
        } else {
            if ((cman->unk2e4_flag & swrObjcMan_LIGHTFLAG_FADE_SNAPSHOT) != 0) {
                cman->unk2e4_flag &= ~swrObjcMan_LIGHTFLAG_FADE_SNAPSHOT;
                cman->fadeFromVector = cman->lightVector;
                cman->fadeFromColor = cman->lightColor;
                cman->fadeFromAmbient = cman->ambientColor;
            }
            cman->lightVector = cman->light.lightVector;
            cman->lightColor = cman->light.lightColor;
            cman->ambientColor = cman->light.ambientColor;
        }
    }
    if ((cman->unk2e4_flag & swrObjcMan_LIGHTFLAG_RAW_VECTOR) != 0) {
        // point light: light.lightVector is a position
        cman->lightVector.x = pod->transform.vD.x - cman->light.lightVector.x;
        cman->lightVector.y = pod->transform.vD.y - cman->light.lightVector.y;
        cman->lightVector.z = pod->transform.vD.z - cman->light.lightVector.z;
        rdVector_Normalize3Acc(&cman->lightVector);
        changed = 1;
    }
    unsigned int flags = cman->unk2e4_flag;
    if ((flags & swrObjcMan_LIGHTFLAG_PULSE) != 0) {
        // brightness pulses as the pod moves along lightVector2
        float phase = cman->light.lightVector2.x * pod->transform.vD.x + cman->light.lightVector2.y * pod->transform.vD.y + cman->light.lightVector2.z * pod->transform.vD.z;
        float wave = lightPulseWave(phase);
        if (wave < 0.0f)
            wave = -wave;
        wave = wave * 0.02f;
        cman->lightColor.x = cman->light.lightColor.x * wave;
        cman->lightColor.y = cman->light.lightColor.y * wave;
        cman->lightColor.z = cman->light.lightColor.z * wave;
        changed = 1;
    }
    if ((flags & swrObjcMan_LIGHTFLAG_FADE) != 0) {
        float t = (float)(cman->unk398_ms - (swrRace_deltaTimeSecs + swrRace_deltaTimeSecs));
        cman->unk398_ms = t;
        if (t < 0.0f) {
            flags &= ~swrObjcMan_LIGHTFLAG_FADE;
            cman->unk398_ms = 0.0f;
            cman->unk2e4_flag = flags;
        }
        float fade = cman->unk398_ms;
        cman->ambientColor.x = fade * cman->fadeFromAmbient.x + (1.0f - fade) * cman->ambientColor.x;
        cman->ambientColor.y = fade * cman->fadeFromAmbient.y + (1.0f - fade) * cman->ambientColor.y;
        cman->ambientColor.z = fade * cman->fadeFromAmbient.z + (1.0f - fade) * cman->ambientColor.z;
        cman->lightColor.x = fade * cman->fadeFromColor.x + (1.0f - fade) * cman->lightColor.x;
        cman->lightColor.y = fade * cman->fadeFromColor.y + (1.0f - fade) * cman->lightColor.y;
        cman->lightColor.z = fade * cman->fadeFromColor.z + (1.0f - fade) * cman->lightColor.z;
        cman->lightVector.x = fade * cman->fadeFromVector.x + (1.0f - fade) * cman->lightVector.x;
        cman->lightVector.y = fade * cman->fadeFromVector.y + (1.0f - fade) * cman->lightVector.y;
        cman->lightVector.z = fade * cman->fadeFromVector.z + (1.0f - fade) * cman->lightVector.z;
        changed = 1;
    }

    flags = cman->unk2e4_flag;
    if ((flags & swrObjcMan_LIGHTFLAG_SPARK_FLASH) != 0) {
        // scrape sparks: a random warm flash from the spark toward the pod
        float level = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.5f - -0.5f;
        flashDir.x = pod->transform.vD.x - pod->scrapeSparkXf.vD.x;
        flashDir.y = pod->transform.vD.y - pod->scrapeSparkXf.vD.y;
        flashDir.z = pod->transform.vD.z - pod->scrapeSparkXf.vD.z;
        flashColor.x = level * 200.0f;
        flashColor.y = level * 200.0f;
        flashColor.z = level * 255.0f;
        rdVector_Normalize3Acc(&flashDir);
        cman->unk2e4_flag |= swrObjcMan_LIGHTFLAG_SPARK_FLASH_ACTIVE;
        SetAlternativeLightColorsAndDirection3(pod->current_light_index, 1, &flashColor.x, &flashDir);
    } else if ((flags & swrObjcMan_LIGHTFLAG_SPARK_FLASH_ACTIVE) != 0) {
        cman->unk2e4_flag = flags & ~swrObjcMan_LIGHTFLAG_SPARK_FLASH_ACTIVE;
        // retail passes these uninitialized; light_type2 = 0 ignores them
        SetAlternativeLightColorsAndDirection3(pod->current_light_index, 0, &flashColor.x, &flashDir);
    }

    if (!changed)
        return;
    if (pod->lightColorMode == 0) {
        SetLightColorsAndDirection2(pod->current_light_index, &cman->ambientColor, &cman->lightColor, &cman->lightVector);
        return;
    }
    // per-local-player tint: drop two of the ambient channels
    ambient = cman->ambientColor;
    color = cman->lightColor;
    if (pod->lightColorMode == 1) {
        ambient.x = 0.0f;
        ambient.y = 0.0f;
    } else {
        ambient.y = 0.0f;
        ambient.z = 0.0f;
    }
    SetLightColorsAndDirection2(pod->current_light_index, &ambient, &color, &cman->lightVector);
}

// 0x00451800
void swrObjcMan_LoadLightingFromBehavior(swrObjcMan* cman, swrRace* pod, void* meshBehavior)
{
    swrModel_Behavior* behavior = (swrModel_Behavior*)meshBehavior;
    swrObjcMan_Light* light;

    if (behavior != NULL && behavior->light_flags != 0) {
        light = (behavior->light_flags & swrModel_Behavior_LIGHTFLAG_SET_DEFAULT) ? &cman->lightDefault : &cman->light;
        light->ambientColor.x = behavior->ambient_color[0];
        light->ambientColor.y = behavior->ambient_color[1];
        light->ambientColor.z = behavior->ambient_color[2];
        light->lightColor.x = behavior->light_color[0];
        light->lightColor.y = behavior->light_color[1];
        light->lightColor.z = behavior->light_color[2];
        light->lightVector.x = behavior->light_vector[0];
        light->lightVector.y = behavior->light_vector[1];
        light->lightVector.z = behavior->light_vector[2];
        light->lightVector2.x = behavior->light_vector2[0];
        light->lightVector2.y = behavior->light_vector2[1];
        light->lightVector2.z = behavior->light_vector2[2];
        rdVector_Normalize3Acc(&light->lightVector2);
        if (behavior->light_flags & swrModel_Behavior_LIGHTFLAG_RAW_VECTOR) {
            light->flags |= swrObjcMan_LIGHTFLAG_RAW_VECTOR;
        } else {
            light->flags &= ~swrObjcMan_LIGHTFLAG_RAW_VECTOR;
            rdVector_Normalize3Acc(&light->lightVector);
        }
        if (behavior->light_flags & swrModel_Behavior_LIGHTFLAG_PULSE)
            light->flags |= swrObjcMan_LIGHTFLAG_PULSE;
        else
            light->flags &= ~swrObjcMan_LIGHTFLAG_PULSE;
        if (light == &cman->lightDefault)
            cman->light = cman->lightDefault;
    } else {
        cman->light = cman->lightDefault;
    }

    cman->unk2e4_flag = (cman->unk2e4_flag & ~(swrObjcMan_LIGHTFLAG_PULSE | swrObjcMan_LIGHTFLAG_RAW_VECTOR)) | cman->light.flags;
    cman->unk2e4_flag |= 0x3;
    // fsub of the -1.0 double at 0x004acdd8
    cman->unk398_ms = swrRace_deltaTimeSecs + swrRace_deltaTimeSecs - -1.0;
}

// 0x00451a80
void swrObjcMan_UpdateTerrainVisuals(swrObjcMan* cman)
{
    swrRace* pod = cman->unkf4_objTest;
    swrModel_Behavior* behavior;

    cman->fog_flag &= ~swrObjcMan_VIEWFLAGS_NO_WEATHER;
    if (pod == NULL)
        return;

    if (pod->terrainModel != NULL) {
        behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)pod->terrainModel);
    } else {
        if ((pod->flags1 & swrObjTest_FLAG1_RESPAWN_RELIGHT) == 0)
            goto updateLightFlags;
        behavior = cman->surfaceBehavior;
    }

    if (behavior != NULL && (behavior->vehicle_reaction & swrVehicleReaction_NSnw) != 0)
        cman->fog_flag |= swrObjcMan_VIEWFLAGS_NO_WEATHER;
    if (behavior == cman->surfaceBehavior && (pod->flags1 & swrObjTest_FLAG1_RESPAWN_RELIGHT) == 0)
        goto updateLightFlags;

    pod->flags1 &= ~swrObjTest_FLAG1_RESPAWN_RELIGHT;
    cman->surfaceBehavior = behavior;
    swrObjcMan_LoadLightingFromBehavior(cman, pod, behavior);
    if (NumLocalPlayers() <= 1)
        swrSound_SetUpdateFlag_Maybe(behavior != NULL && (behavior->unk18 & 1) != 0 ? 0x7f : 0);
    if (behavior == NULL)
        goto updateLightFlags;

    if ((behavior->unk1 & 2) != 0)
        cman->fog_flag |= swrObjcMan_VIEWFLAGS_NO_SKYBOX;
    if ((behavior->unk1 & 4) != 0)
        cman->fog_flag &= ~swrObjcMan_VIEWFLAGS_NO_SKYBOX;

    if ((behavior->fog_flags & swrModel_Behavior_FOGFLAG_DISTANCE) != 0) {
        cman->fog_flag |= swrObjcMan_VIEWFLAGS_FOG_DISTANCE;
        cman->fogDistTarget = (float)(short)behavior->fog_end;
        if (NumLocalPlayers() > 1) {
            if ((behavior->fog_flags & swrModel_Behavior_FOGFLAG_COLOR) == 0)
                goto updateVisualFlags;
            if (cman->fogDistTarget > 1200.0f)
                cman->fogDistTarget = 1200.0f;
            if ((pod->flags0 & 0xf) != 2)
                cman->fogDist = cman->fogDistTarget;
        }
    }
    if ((behavior->fog_flags & swrModel_Behavior_FOGFLAG_COLOR) != 0) {
        if ((short)behavior->fog_start > 0)
            cman->fog_flag |= swrObjcMan_VIEWFLAGS_FOG_START;
        else
            cman->fog_flag &= ~swrObjcMan_VIEWFLAGS_FOG_START;
        cman->fogStartDistTarget = (float)(short)behavior->fog_start;
        if (cman->fogStartDistTarget > 999.0f)
            cman->fogStartDistTarget = 999.0f;
        cman->fog_r_target = behavior->fog_color[0];
        cman->fog_g_target = behavior->fog_color[1];
        cman->fog_b_target = behavior->fog_color[2];
    }
updateVisualFlags:
    // faithful: the low byte of the result is cleared
    cman->visual_flag &= ~behavior->unk20;
    cman->visual_flag = (behavior->unk21 | cman->visual_flag) & 0xffffff00;

updateLightFlags:
    if ((pod->flags0 & (swrObjTest_FLAG0_SCRAPE_SPARK_R | swrObjTest_FLAG0_SCRAPE_SPARK_L)) != 0)
        cman->unk2e4_flag |= 0x10;
    else
        cman->unk2e4_flag &= ~0x10;
    if ((pod->flags1 & swrObjTest_FLAG1_RESPAWN_RELIGHT) != 0)
        cman->unk2e4_flag |= 0x40;
    if (cman->unk2e4_flag != 0)
        swrObjcMan_UpdateLighting(cman, pod);
    pod->flags1 &= ~swrObjTest_FLAG1_RESPAWN_RELIGHT;
}

// 0x00451cd0
void swrObjcMan_F0(swrObjcMan* cman)
{
    if (cman->mode_type == 0 || cman->metaCamIndex_count < 0)
        return;
    swrObjcMan_UpdatePreRaceSweepTimer(cman, -2.0f);
    if (cman->mode_type != 1 && cman->mode_type == 5 && cman->unkf4_objTest != NULL)
        cman->unkf4_objTest->flags0 |= swrObjTest_FLAG0_POD_HIDDEN;
    if (multiplayer_enabled != 0 && &swrScoresPtr[playerNumber] != NULL)
        cman->unkf4_objTest = swrScoresPtr[playerNumber].obj_test_ptr;
}

// 0x00451d40
void swrObjcMan_F2(swrObjcMan* cman)
{
    if (cman->mode_type != 0 && cman->metaCamIndex_count >= 0)
        swrObjcMan_UpdateTerrainVisuals(cman);
}

// 0x00451d60
void swrObjcMan_CommitStagedCamera(swrObjcMan* cman, int mode)
{
    cman->mode_type = mode;
    cman->stagingTransform = cman->unk20_mat;
    cman->stagingTransformFocus = cman->focusTransform_mat;
}

// 0x00451ec0
void swrObjcMan_RestoreMode(swrObjcMan* cman)
{
    int mode = cman->mode_respawn;
    if (mode != 2 && mode != 1) {
        cman->mode_type = mode;
        return;
    }
    swrObjcMan_CommitStagedCamera(cman, mode);
}

// 0x00451ef0
void swrObjcMan_UpdatePreRaceSweep(swrObjcMan* cman)
{
    rdMatrix44 podXf;
    rdMatrix44 m;
    rdVector3 cockpit;
    rdVector3 engine;
    rdVector3 chase;
    rdVector3 eyes[4];
    rdVector3 focuses[4];
    rdVector3 focus;
    rdVector3 eye;
    rdVector3 dirFrom;
    rdVector3 dirTo;
    float sinBlend;
    float cosBlend;
    float blend;
    int stage;
    int finished = 0;

    swrRace* pod = cman->unkf4_objTest;
    cman->fov = -1.0f;
    if (pod != NULL) {
        rdMatrix_Copy44(&podXf, &pod->transform);
        podXf.vD.z = pod->unk11_1 + podXf.vD.z;
        cman->animTimer_ms = (float)(cman->animTimer_ms + swrRace_deltaTimeSecs);
        int pilot = *pod->score_ptr->pilotId;
        const swrRacerVisualData* visual = &swrRacer_PodVisualData[pilot];
        rdVector_Copy3(&cockpit, &visual->hoverPadOffsetA);
        rdVector_Add3(&cockpit, &cockpit, &visual->sweepCockpitOffset);
        rdVector_Copy3(&engine, &visual->hoverPadOffsetB);
        rdVector_Add3(&engine, &engine, &visual->sweepEngineOffset);
        engine.x = engine.x * 0.3;
        chase.x = visual->sweepEndX;
        chase.y = visual->chaseCamTrail;
        chase.z = visual->chaseCamHeight;
        chase.z = pod->unk19b4 * 0.75 + chase.z;
        chase.y = chase.y * -1.0f;
        rdVector_Scale3(&chase, 0.75f, &chase);

        // four eye/focus keyframes in pod space; the last is the chase-camera position
        rdVector_Copy3(&eyes[0], &cockpit);
        eyes[0].x = eyes[0].x - -2.0;
        eyes[0].y = eyes[0].y - 2.0;
        eyes[0].z = eyes[0].z - 1.0;
        if (pilot == SWR_PILOT_NEVA_KEE) {
            eyes[0].x = eyes[0].x - -2.0;
            eyes[0].y = eyes[0].y - 2.0;
            eyes[0].z = eyes[0].z - -4.0;
        }
        rdMatrix_Transform3(&eyes[0], &eyes[0], &podXf);
        rdVector_Copy3(&focuses[0], &cockpit);
        focuses[0].z = focuses[0].z - 2.0f;
        rdMatrix_Transform3(&focuses[0], &focuses[0], &podXf);
        rdVector_Copy3(&eyes[1], &cockpit);
        eyes[1].x = eyes[1].x - 0.5;
        eyes[1].y = eyes[1].y - -2.5;
        eyes[1].z = eyes[1].z - 1.0;
        if (pilot == SWR_PILOT_NEVA_KEE) {
            eyes[1].y = eyes[1].y - -2.0;
            eyes[1].z = eyes[1].z - -4.0;
        }
        rdMatrix_Transform3(&eyes[1], &eyes[1], &podXf);
        rdVector_Copy3(&focuses[1], &cockpit);
        focuses[1].z = focuses[1].z - 2.0f;
        rdMatrix_Transform3(&focuses[1], &focuses[1], &podXf);
        rdVector_Copy3(&eyes[2], &engine);
        eyes[2].y = eyes[2].y - -5.0f;
        eyes[2].z = eyes[2].z - -0.5f;
        rdMatrix_Transform3(&eyes[2], &eyes[2], &podXf);
        rdVector_Copy3(&focuses[2], &cockpit);
        rdMatrix_Transform3(&focuses[2], &focuses[2], &podXf);
        rdVector_Copy3(&eyes[3], &chase);
        rdMatrix_Transform3(&eyes[3], &eyes[3], &podXf);
        rdVector_Set3(&focuses[3], 0.0f, 0.0f, chase.z);
        rdMatrix_Transform3(&focuses[3], &focuses[3], &podXf);

        // 3 s per leg for the first two, 2 s for the last
        if (cman->animTimer_ms < 3.0) {
            stage = 0;
            blend = cman->animTimer_ms * 0.3333333333333333;
        } else if (cman->animTimer_ms < 6.0) {
            stage = 1;
            blend = (cman->animTimer_ms - 3.0) * 0.3333333333333333;
        } else if (cman->animTimer_ms < 8.0) {
            stage = 2;
            blend = (cman->animTimer_ms - 6.0) * 0.5;
        } else {
            stage = 2;
            blend = 1.0f;
            finished = 1;
        }
        if (blend < 0.0)
            blend = 0.0f;
        if (blend > 1.0)
            blend = 1.0f;
        // ease in/out
        stdMath_SinCos(blend * 180.0f - 90.0f, &sinBlend, &cosBlend);
        blend = sinBlend * 0.5f - -0.5f;

        rdVector_Set3(&focus, 0.0f, 0.0f, 0.0f);
        rdVector_Scale3Add3(&focus, &focus, (float)(1.0 - blend), &focuses[stage]);
        rdVector_Scale3Add3(&focus, &focus, blend, &focuses[stage + 1]);
        // orbit the focus point: interpolate yaw, pitch and distance between the two eyes
        rdVector_Sub3(&dirFrom, &eyes[stage], &focus);
        rdVector_Sub3(&dirTo, &eyes[stage + 1], &focus);
        float distFrom = rdVector_Normalize3Acc(&dirFrom);
        float distTo = rdVector_Normalize3Acc(&dirTo);
        float yawFrom = stdMath_ArcTan2(-dirFrom.x, dirFrom.y);
        float yawTo = stdMath_ArcTan2(-dirTo.x, dirTo.y);
        float pitchFrom = stdMath_ArcSin(dirFrom.z);
        float pitchTo = stdMath_ArcSin(dirTo.z);
        rdMatrix_SetRotation44(&m, (yawTo - yawFrom) * blend + yawFrom, (pitchTo - pitchFrom) * blend + pitchFrom, 0.0f);
        rdVector_Scale3Add3(&eye, &focus, (distTo - distFrom) * blend + distFrom, (rdVector3*)&m.vB);
        rdMatrix_SetIdentity44(&m);
        rdVector_Copy3((rdVector3*)&m.vD, &eye);
        rdMatrix_Copy44(&cman->unk20_mat, &m);
        rdMatrix_SetIdentity44(&m);
        rdVector_Copy3((rdVector3*)&m.vD, &focus);
        rdMatrix_Copy44(&cman->focusTransform_mat, &m);
    }
    if (finished)
        swrObjcMan_CommitStagedCamera(cman, 1);
}

static void swrObjcMan_SetTranslationMatrix(rdMatrix44* m, const rdVector3* t)
{
    m->vA.x = 1.0f, m->vA.y = 0.0f, m->vA.z = 0.0f, m->vA.w = 0.0f;
    m->vB.x = 0.0f, m->vB.y = 1.0f, m->vB.z = 0.0f, m->vB.w = 0.0f;
    m->vC.x = 0.0f, m->vC.y = 0.0f, m->vC.z = 1.0f, m->vC.w = 0.0f;
    m->vD.x = t->x, m->vD.y = t->y, m->vD.z = t->z, m->vD.w = 1.0f;
}

// 0x00452600
void swrObjcMan_UpdateDeathCamera(swrObjcMan* cman)
{
    swrSplineCursor* cursor = &cman->deathCamCursor;
    rdMatrix44* frame = &cman->unk1e4_mat;
    rdVector3* deathPos = (rdVector3*)&cman->unk15c[0];
    rdVector3* deathLookAt = (rdVector3*)&cman->unk15c[3];
    swrRace* pod = cman->unkf4_objTest;
    // faithful: any other stage leaves these uninitialized in the original
    rdVector3 eye = { 0 };
    rdVector3 focus = { 0 };
    rdVector3 dir;
    double timer;
    float blend;

    if (pod == NULL) {
        swrObjcMan_RestoreMode(cman);
        return;
    }

    timer = cman->animTimer_ms - swrRace_deltaTimeSecs;
    cman->animTimer_ms = timer;
    if (cman->animStage == 0) {
        if (timer < 0.0f) {
            cman->animTimer_ms = 1.5f;
            cman->animStage = 2;
            *cursor = pod->splineCursor;
            cursor->segmentT -= 0.8500000007450581;
            cursor->velocity = 0.0f;
            swrSpline_EvaluateToMatrix(cursor, frame);
            cursor->velocity = 0.53333336f;
            blend = 1.0f;
        } else {
            blend = 1.0 - timer;
        }
        rdVector_Sub3(&dir, deathLookAt, deathPos);
        rdVector_Normalize3Acc(&dir);
        rdVector_Scale3Add3(&eye, deathPos, blend * 30.0f, &dir);
        memcpy(cman->unk0_0, &eye, sizeof(eye));
        rdVector_Copy3(&focus, deathPos);
    } else if (cman->animStage == 2) {
        if (timer < 0.0f) {
            cman->animTimer_ms = 0.0f;
            cman->animStage = 3;
        }
        swrSpline_EvaluateToMatrix(cursor, frame);
        rdVector_Copy3(&focus, (rdVector3*)&pod->transform.vD);
        eye.x = frame->vD.x;
        eye.y = frame->vD.y;
        eye.z = frame->vD.z;
    } else if (cman->animStage == 3) {
        pod->respawnInvincibilityTimer = 3.0f;
        pod->flags0 = (pod->flags0 & ~swrObjTest_FLAG0_DEAD) | swrObjTest_FLAG0_RESPAWN_INVINC;
        swrObjcMan_RestoreMode(cman);
        eye.x = cman->unk20_mat.vD.x;
        eye.y = cman->unk20_mat.vD.y;
        eye.z = cman->unk20_mat.vD.z;
        focus.x = cman->focusTransform_mat.vD.x;
        focus.y = cman->focusTransform_mat.vD.y;
        focus.z = cman->focusTransform_mat.vD.z;
    }

    swrObjcMan_SetTranslationMatrix(&cman->unk20_mat, &eye);
    swrObjcMan_SetTranslationMatrix(&cman->focusTransform_mat, &focus);
}

// 0x004528b0
void swrObjcMan_UpdateFirstPersonCamera(swrObjcMan* cman)
{
    swrRace* pod = cman->unkf4_objTest;
    swrTranslationRotation cockpit;
    rdMatrix44 view;
    float height;
    int zeroG;

    if (pod == NULL)
        return;

    zeroG = (pod->flags0 & (swrObjTest_FLAG0_ZON | swrObjTest_FLAG0_ZOFF)) != 0;
    cman->fov = 100.0f;
    if (cman->mode_type == 5)
        cman->fov = 120.0f;

    rdMatrix_Copy44(&view, &pod->transform);
    view.vD.z = pod->unk11_1 + view.vD.z;
    height = (pod->collisionWidth - 3.0f) * 0.5f;
    if (cman->mode_type != 5) {
        height = height * 1.9f;
        if (*pod->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
            height = height * 0.3f;
    }
    if (*pod->score_ptr->pilotId == SWR_PILOT_NEVA_KEE)
        rdVector_Scale3Add3((rdVector3*)&view.vD, (rdVector3*)&view.vD, height, (rdVector3*)&view.vC);
    else if (!zeroG)
        view.vD.z = pod->transform.vC.z * height + view.vD.z;
    if (*pod->score_ptr->pilotId == SWR_PILOT_DUD_BOLT)
        rdVector_Scale3Add3((rdVector3*)&view.vD, (rdVector3*)&view.vD, 3.0f, (rdVector3*)&view.vB);

    if (pod->flags1 & (swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT)) {
        rdMatrix_ExtractTransform(&pod->cockpitXf, &cockpit);
        rdMatrix_AddRotationFromVectorAngle44Before(&view, cockpit.yaw_roll_pitch.z, 0.0f, 1.0f, 0.0f, &view);
    }

    rdMatrix_Copy44(&cman->unk20_mat, &view);
    rdMatrix_Copy44(&cman->focusTransform_mat, &view);
    if (pod->flags0 & swrObjTest_FLAG0_LOOK_BACK) {
        rdVector_Scale3Add3((rdVector3*)&cman->focusTransform_mat.vD, (rdVector3*)&view.vD, -1.0f, (rdVector3*)&view.vB);
        rdVector_Scale3((rdVector3*)&cman->unk20_mat.vB, -1.0f, (rdVector3*)&cman->unk20_mat.vB);
        rdVector_Scale3((rdVector3*)&cman->unk20_mat.vA, -1.0f, (rdVector3*)&cman->unk20_mat.vA);
        return;
    }
    rdVector_Scale3Add3((rdVector3*)&cman->focusTransform_mat.vD, (rdVector3*)&view.vD, 1.0f, (rdVector3*)&view.vB);
}

// 0x00452aa0
void swrObjcMan_UpdateChaseCamera(swrObjcMan* cman)
{
    swrRace* pod = cman->unkf4_objTest;
    rdMatrix44 podXf;
    rdMatrix44 m;
    rdVector3 toCam;
    rdVector3 toFocus;
    rdVector3 lookAt;
    rdVector3 camPos;
    swrTranslationRotation podTr;
    float trail;
    float height;
    float lookHeight;
    float roll;

    if (pod == NULL)
        return;
    int isRemote = (pod->flags0 & swrObjTest_FLAG0_LOCAL) == 0;
    if (!isRemote && pod->speedValue < 50.0f) {
        // a slow local pod drags the camera back behind it
        rdVector_Scale3Add3((rdVector3*)&cman->stagingTransform.vD, (rdVector3*)&cman->stagingTransform.vD, (float)(swrRace_deltaTimeSecs * -20.0), (rdVector3*)&pod->transform.vB);
    }
    int zeroG = (pod->flags0 & (swrObjTest_FLAG0_ZON | swrObjTest_FLAG0_ZOFF)) != 0;
    cman->fov = 100.0f;
    const swrRacerVisualData* visual = &swrRacer_PodVisualData[*pod->score_ptr->pilotId];
    if (!zeroG) {
        trail = visual->chaseCamTrail;
        height = visual->chaseCamHeight + pod->unk19b4 * 0.75;
    } else {
        cman->chaseTrail = visual->chaseCamTrail;
        cman->chaseHeight = visual->chaseCamHeight;
        cman->chaseHeight = cman->chaseHeight + pod->unk19b4 * 0.75;
        height = cman->chaseHeight;
        trail = cman->chaseTrail;
    }
    lookHeight = height;
    if (cman->mode_type == 2) {
        // far chase view
        trail = trail + trail;
        if (trail > 30.0f)
            trail = 30.0f;
        height = height + height;
        if (height > 15.0f)
            height = 15.0f;
        lookHeight = 8.0f;
    }
    float speedScale = (pod->speedValue - 200.0f) * 0.002631578947368421;
    if (speedScale < 0.0)
        speedScale = 0.0f;
    if (speedScale > 1.0)
        speedScale = 1.0f;
    speedScale = speedScale * 0.3 - -0.75;
    trail = trail * speedScale;
    height = height * speedScale;
    lookHeight = lookHeight * speedScale;
    if (NumLocalPlayers() == 2)
        trail = trail * 1.3f;

    toFocus.x = cman->stagingTransformFocus.vD.x - cman->stagingTransform.vD.x;
    toFocus.y = cman->stagingTransformFocus.vD.y - cman->stagingTransform.vD.y;
    toFocus.z = cman->stagingTransformFocus.vD.z - cman->stagingTransform.vD.z;
    rdVector_Normalize3Acc(&toFocus);
    // pull in when the camera looks along the pod, push out when it looks across
    swrRace* target = cman->unkf4_objTest;
    float facing = target->transform.vB.z * toFocus.z + target->transform.vB.x * toFocus.x + target->transform.vB.y * toFocus.y;
    trail = ((1.0f - facing) * 0.5f - -1.0f) * trail;
    if (!zeroG) {
        trail = (trail + cman->chaseTrail) * 0.5f;
        height = (height + cman->chaseHeight) * 0.5f;
        cman->chaseTrail = trail;
        cman->chaseHeight = height;
    }

    rdMatrix_Copy44(&podXf, &cman->unkf4_objTest->transform);
    podXf.vD.z = podXf.vD.z + pod->unk11_1;
    rdMatrix_Copy44(&m, &podXf);
    rdVector_Sub3(&toCam, (rdVector3*)&cman->stagingTransform.vD, (rdVector3*)&m.vD);
    if (!zeroG) {
        toCam.z = 0.0f;
        rdVector_Len3(&toCam);
        rdVector_Normalize3Acc(&toCam);
        if (isRemote) {
            // spectated pods: fixed side/front offsets, cycled by swrObjcMan_spectatorCamIndex
            switch (swrObjcMan_spectatorCamIndex) {
            case 0:
                m.vD.x = m.vD.x - trail * -0.9f;
                break;
            case 1:
                m.vD.y = m.vD.y - trail * -0.8f;
                break;
            case 2:
                m.vD.x = m.vD.x - trail * 0.6f;
                break;
            default:
                m.vD.y = m.vD.y - trail * 0.7f;
                break;
            }
            m.vD.z = height + m.vD.z;
        } else {
            rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, trail, &toCam);
            m.vD.z = height + m.vD.z;
        }
        rdVector_Copy3(&camPos, (rdVector3*)&m.vD);
        lookAt.x = podXf.vD.x;
        lookAt.y = podXf.vD.y;
        lookAt.z = lookHeight + podXf.vD.z;
        rdVector_Scale3Add3(&lookAt, &lookAt, (float)(pod->slide * 20.0), (rdVector3*)&podXf.vB);
    } else {
        // zero-g: trail within the pod's own plane, offset along its up axis
        float up = toCam.x * podXf.vC.x + toCam.y * podXf.vC.y + toCam.z * podXf.vC.z;
        rdVector_Scale3Add3(&toCam, &toCam, -up, (rdVector3*)&podXf.vC);
        rdVector_Len3(&toCam);
        rdVector_Normalize3Acc(&toCam);
        rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, trail, &toCam);
        rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, height, (rdVector3*)&podXf.vC);
        rdVector_Copy3(&camPos, (rdVector3*)&m.vD);
        lookAt.x = podXf.vD.x;
        lookAt.y = podXf.vD.y;
        lookAt.z = podXf.vD.z;
        rdVector_Scale3Add3(&lookAt, &lookAt, lookHeight, (rdVector3*)&podXf.vC);
    }
    if (!zeroG && podXf.vB.z < 0.0) {
        // nose-down: lift the camera
        float lift = podXf.vB.z * podXf.vB.z * 30.0f;
        if (lift > 20.0)
            lift = 20.0f;
        camPos.z = camPos.z + lift;
    }

    rdMatrix_ExtractTransform(&cman->unkf4_objTest->transform, &podTr);
    roll = podTr.yaw_roll_pitch.z * 0.0055555557f;
    if (!zeroG) {
        // cubic ease on small rolls, a quarter of the pod's roll once that is larger
        float cubic = roll * roll * roll * 180.0f;
        float cubicAbs = cubic < 0.0f ? -cubic : cubic;
        float quarter = podTr.yaw_roll_pitch.z * 0.25;
        float quarterAbs = quarter < 0.0 ? -quarter : quarter;
        roll = cubicAbs > quarterAbs ? cubic : quarter;
    } else {
        roll = roll * 180.0f;
    }
    rdMatrix_SetRotation44(&m, 0.0f, 0.0f, roll);
    rdVector_Copy3((rdVector3*)&m.vD, &camPos);
    rdMatrix_Copy44(&cman->stagingTransform, &m);
    rdMatrix_Copy44(&m, &cman->unkf4_objTest->transform);
    rdVector_Copy3((rdVector3*)&m.vD, &lookAt);
    rdMatrix_Copy44(&cman->stagingTransformFocus, &m);
    cman->unk20_mat = cman->stagingTransform;
    cman->focusTransform_mat = cman->stagingTransformFocus;

    if ((pod->flags0 & swrObjTest_FLAG0_LOOK_BACK) != 0) {
        rdMatrix_Copy44(&podXf, &pod->transform);
        podXf.vD.z = podXf.vD.z + pod->unk11_1;
        rdMatrix_Copy44(&cman->unk20_mat, &podXf);
        rdMatrix_Copy44(&cman->focusTransform_mat, &podXf);
        rdVector_Scale3((rdVector3*)&cman->unk20_mat.vB, -1.0f, (rdVector3*)&cman->unk20_mat.vB);
        rdVector_Scale3((rdVector3*)&cman->unk20_mat.vA, -1.0f, (rdVector3*)&cman->unk20_mat.vA);
        rdVector_Scale3Add3((rdVector3*)&cman->focusTransform_mat.vD, (rdVector3*)&cman->focusTransform_mat.vD, -1.0f, (rdVector3*)&podXf.vB);
        rdVector_Scale3Add3((rdVector3*)&cman->unk20_mat.vD, (rdVector3*)&cman->unk20_mat.vD, pod->collisionWidth + pod->collisionWidth, (rdVector3*)&podXf.vB);
        rdVector_Scale3Add3((rdVector3*)&cman->focusTransform_mat.vD, (rdVector3*)&cman->focusTransform_mat.vD, pod->collisionWidth * 0.2f, (rdVector3*)&podXf.vC);
        rdVector_Scale3Add3((rdVector3*)&cman->unk20_mat.vD, (rdVector3*)&cman->unk20_mat.vD, pod->collisionWidth * 0.2f, (rdVector3*)&podXf.vC);
    }
}

// 0x004533a0
void swrObjcMan_UpdateSplineCamera(swrObjcMan* cman)
{
    swrSplineCursor* cursor = &cman->splineCamCursor;
    swrRace* pod = cman->unkf4_objTest;
    rdMatrix44 podXf;
    rdMatrix44 behind;
    rdMatrix44 eye;
    float dx, dy, dz;
    float lenSq, dotPod, dotSpline, t;

    if (pod == NULL) {
        cman->unkf4_objTest = swrEvent_FindObjectById(0x54657374, 0); // 'Test'
        return;
    }

    rdMatrix_Copy44(&podXf, &pod->transform);
    podXf.vD.z = pod->unk11_1 + podXf.vD.z;
    *cursor = pod->splineCursor;
    cursor->velocity = 0.0f;
    swrSpline_EvaluateToMatrix(cursor, &cman->unkb4_mat);

    // project the pod onto the spline tangent and step the cursor back to match
    swrSpline_EvaluateAtOffset(cursor, &behind, -0.01f);
    dx = behind.vD.x - cman->unkb4_mat.vD.x;
    dy = behind.vD.y - cman->unkb4_mat.vD.y;
    dz = behind.vD.z - cman->unkb4_mat.vD.z;
    dotPod = dx * podXf.vD.x + dy * podXf.vD.y + dz * podXf.vD.z;
    lenSq = dx * dx + dy * dy + dz * dz;
    dotSpline = dy * cman->unkb4_mat.vD.y + (dz * cman->unkb4_mat.vD.z + dx * cman->unkb4_mat.vD.x);
    if (lenSq > 0.001) {
        t = (dotPod - dotSpline) / lenSq;
        if (t > 1.0f)
            t = 1.0f;
    } else {
        t = 0.0f;
    }
    cursor->segmentT = cursor->segmentT - t * 0.01f;
    swrSpline_EvaluateToMatrix(cursor, &cman->unkb4_mat);

    rdMatrix_Copy44(&eye, &cman->unkb4_mat);
    eye.vD.z = podXf.vD.z - -5.0;
    eye.vD.x = eye.vD.x - -7.0;
    rdMatrix_Copy44(&cman->unk20_mat, &eye);
    rdMatrix_Copy44(&eye, &cman->unkf4_objTest->transform);
    rdMatrix_Copy44(&cman->focusTransform_mat, &eye);
    cman->fov = 60.0f;
}

// 0x004535c0
void swrObjcMan_UpdateSplineGuideMarker(swrObjcMan* cman)
{
    swrRace* pod;
    rdMatrix44 view;
    rdMatrix44 arrow;
    float sideOffset;
    float pulse;

    // pulse phase runs -1..1, then wraps
    if (NumLocalPlayers() == 1) {
        swrObjcMan_guideArrowPhase = swrObjcMan_guideArrowPhase - swrRace_deltaTimeSecs * -3.0;
        sideOffset = 2.0f;
    } else {
        sideOffset = 1.5f;
        swrObjcMan_guideArrowPhase = 3.0f / NumLocalPlayers() * swrRace_deltaTimeSecs + swrObjcMan_guideArrowPhase;
    }
    if (swrObjcMan_guideArrowPhase > 1.0f)
        swrObjcMan_guideArrowPhase = -1.0f;

    pod = cman->unkf4_objTest;
    if (pod == NULL || !(pod->flags0 & swrObjTest_FLAG0_GUIDE_ARROW) || pod->guideArrowNode == NULL)
        return;

    // camera basis: vA right, vB forward, vC up
    rdMatrix_SetIdentity44(&view);
    rdVector_Sub3((rdVector3*)&view.vB, (rdVector3*)&cman->focusTransform_mat.vD, (rdVector3*)&cman->unk20_mat.vD);
    rdVector_Copy3((rdVector3*)&view.vC, (rdVector3*)&cman->unk20_mat.vC);
    rdVector_Cross3((rdVector3*)&view.vA, (rdVector3*)&view.vB, (rdVector3*)&view.vC);
    rdVector_Cross3((rdVector3*)&view.vC, (rdVector3*)&view.vA, (rdVector3*)&view.vB);
    rdVector_Normalize3Acc((rdVector3*)&view.vA);
    rdVector_Normalize3Acc((rdVector3*)&view.vB);
    rdVector_Normalize3Acc((rdVector3*)&view.vC);
    rdVector_Copy3((rdVector3*)&view.vD, (rdVector3*)&cman->unk20_mat.vD);

    if (pod->guideArrowNode != NULL)
        swrModel_NodeModifyFlags(pod->guideArrowNode, 2, 3, 0x10, 2);
    pulse = swrObjcMan_guideArrowPhase;
    if (pulse < 0.0f)
        pulse = -pulse;
    swrModel_NodeSetColorsOnAllMaterials(pod->guideArrowNode, 0, 0, 0x59, 0x8c, 0x36, (int)((1.0f - pulse) * 255.0f));

    // arrow basis: forward toward the guide target, flattened to the ground plane
    rdMatrix_SetIdentity44(&arrow);
    rdVector_Sub3((rdVector3*)&arrow.vB, &pod->guideArrowTarget, (rdVector3*)&pod->transform.vD);
    arrow.vB.z = 0.0f;
    rdVector_Normalize3Acc((rdVector3*)&arrow.vB);
    rdVector_Cross3((rdVector3*)&arrow.vA, (rdVector3*)&arrow.vB, (rdVector3*)&arrow.vC);
    rdVector_Cross3((rdVector3*)&arrow.vC, (rdVector3*)&arrow.vA, (rdVector3*)&arrow.vB);
    rdVector_Normalize3Acc((rdVector3*)&arrow.vA);
    rdVector_Normalize3Acc((rdVector3*)&arrow.vC);
    rdMatrix_ScaleBasis44(&arrow, -0.015f, 0.015f, -0.0075f, &arrow);

    // in front of the camera, bobbing along the arrow's forward axis
    rdVector_Copy3((rdVector3*)&arrow.vD, (rdVector3*)&view.vD);
    rdVector_Scale3Add3((rdVector3*)&arrow.vD, (rdVector3*)&arrow.vD, 5.0f, (rdVector3*)&view.vB);
    rdVector_Scale3Add3((rdVector3*)&arrow.vD, (rdVector3*)&arrow.vD, sideOffset, (rdVector3*)&view.vC);
    rdVector_Scale3Add3((rdVector3*)&arrow.vD, (rdVector3*)&arrow.vD, 0.0f, (rdVector3*)&view.vA);
    rdVector_Scale3Add3((rdVector3*)&arrow.vD, (rdVector3*)&arrow.vD, swrObjcMan_guideArrowPhase * 100.0, (rdVector3*)&arrow.vB);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)pod->guideArrowNode, &arrow);
}

static void swrObjcMan_StepFogChannel(unsigned int* channel, int target)
{
    int value = (int)*channel;
    if (value > target) {
        *channel = (int)(value - swrRace_deltaTimeSecs * 195.0);
        if ((int)*channel < target)
            *channel = target;
    } else if (value < target) {
        *channel = (int)(value + swrRace_deltaTimeSecs * 195.0);
        if ((int)*channel > target)
            *channel = target;
    }
}

// 0x004538d0
void swrObjcMan_UpdateFogAndViewport(swrObjcMan* cman)
{
    float nearClip;
    float farClip;
    float fov;
    float camParam6;
    int fogEnabled;
    int fogStartInt;
    unsigned int flags;
    double step;
    swrViewportFog* viewportFog;

    if (swrObjcMan_holdClipPlanes != 0) {
        nearClip = swrObjcMan_heldNearClip;
        farClip = swrObjcMan_heldFarClip;
    } else {
        if ((cman->fog_flag & swrObjcMan_VIEWFLAGS_FOG_DISTANCE) == 0) {
            farClip = -1.0f;
        } else {
            if (cman->fogDistTarget > 0.0f) {
                if (cman->fogDist > cman->fogDistTarget) {
                    step = cman->fogDist - swrRace_deltaTimeSecs * 2000.0;
                    cman->fogDist = step;
                    if (step < cman->fogDistTarget) {
                        cman->fogDist = cman->fogDistTarget;
                        cman->fogDistTarget = -1.0f;
                    }
                } else {
                    step = cman->fogDist - swrRace_deltaTimeSecs * -2000.0;
                    cman->fogDist = step;
                    if (step > cman->fogDistTarget) {
                        cman->fogDist = cman->fogDistTarget;
                        cman->fogDistTarget = -1.0f;
                    }
                }
            }
            farClip = cman->fogDist;
        }
        nearClip = cman->nearClip;
        swrObjcMan_heldNearClip = nearClip;
        swrObjcMan_heldFarClip = farClip;
    }

    if (swrObjcMan_holdFov != 0) {
        fov = swrObjcMan_heldFov;
    } else {
        fov = cman->fov;
        swrObjcMan_heldFov = fov;
    }

    camParam6 = cman->unk2b8;
    if (swrObjcMan_holdFog != 0) {
        fogEnabled = swrObjcMan_heldFogEnabled;
        fogStartInt = swrObjcMan_heldFogStart;
    } else {
        fogEnabled = cman->fog_flag & swrObjcMan_VIEWFLAGS_FOG_START;
        if (fogEnabled != 0 && cman->fogStartDistTarget >= 0.0f) {
            if (cman->fogStartDist > cman->fogStartDistTarget) {
                step = cman->fogStartDist - swrRace_deltaTimeSecs * 5.0;
                cman->fogStartDist = step;
                if (step < cman->fogStartDistTarget) {
                    cman->fogStartDist = cman->fogStartDistTarget;
                    cman->fogStartDistTarget = -1.0f;
                }
            } else {
                step = cman->fogStartDist - swrRace_deltaTimeSecs * -5.0;
                cman->fogStartDist = step;
                if (step > cman->fogStartDistTarget) {
                    cman->fogStartDist = cman->fogStartDistTarget;
                    cman->fogStartDistTarget = -1.0f;
                }
            }
        }
        fogStartInt = (int)cman->fogStartDist;
        swrObjcMan_heldFogEnabled = fogEnabled;
        swrObjcMan_heldFogStart = fogStartInt;
    }

    if (fov >= 0.0 || camParam6 >= 0.0 || nearClip >= 0.0 || farClip >= 0.0) {
        if (swrObjJdge_splitscreenWideFov != 0 && (swrViewport_array[2].flag & 1) != 0)
            swrViewport_SetCameraParameters(cman->metaCamIndex_count, 120.0f, -1.0f, nearClip, farClip, camParam6);
        else
            swrViewport_SetCameraParameters(cman->metaCamIndex_count, fov, -1.0f, nearClip, farClip, camParam6);
    }

    flags = cman->fog_flag;
    if ((flags & swrObjcMan_VIEWFLAGS_SNAP_FOG_COLOR) != 0) {
        cman->fog_r = cman->fog_r_target;
        cman->fog_g = cman->fog_g_target;
        cman->fog_b = cman->fog_b_target;
    } else {
        swrObjcMan_StepFogChannel(&cman->fog_r, (int)cman->fog_r_target);
        swrObjcMan_StepFogChannel(&cman->fog_g, (int)cman->fog_g_target);
        swrObjcMan_StepFogChannel(&cman->fog_b, (int)cman->fog_b_target);
    }

    // faithful: the color snap request is only consumed while fog is on
    if (fogEnabled != 0) {
        cman->fog_flag = flags & ~swrObjcMan_VIEWFLAGS_SNAP_FOG_COLOR;
        rdModel_SetFogEnabled_Maybe(1);
        SetFogParameters(fogStartInt, 1000, cman->fog_r, cman->fog_g, cman->fog_b, 0xff);
        SetClearColor(cman->fog_r, cman->fog_g, cman->fog_b);
    } else {
        rdModel_SetFogEnabled_Maybe(0);
    }
    swrObjJdge_ToggleSkyboxVisibility_Maybe((int)&cman->unk20_mat.vD, cman->fog_flag);

    if (swrObjJdge_splitscreenActive == 0)
        return;
    viewportFog = &swrPlayerHUD_viewportFog[cman->metaCamIndex_count];
    viewportFog->skyboxVisible = (cman->fog_flag & swrObjcMan_VIEWFLAGS_NO_SKYBOX) == 0;
    if (fogEnabled == 0) {
        viewportFog->enabled = 0;
        return;
    }
    viewportFog->enabled = 1;
    viewportFog->start = fogStartInt;
    viewportFog->r = cman->fog_r;
    viewportFog->g = cman->fog_g;
    viewportFog->b = cman->fog_b;
}

// 0x00453e00
void swrObjcMan_UpdateCamera(swrObjcMan* cman)
{
    swrRace* pod;
    swrTranslationRotation current;
    swrTranslationRotation lookAt;
    rdMatrix44 view;
    int value;

    if (cman->mode_type == 0 || cman->metaCamIndex_count < 0)
        return;

    pod = cman->unkf4_objTest;
    if (pod != NULL) {
        if (swrRace_creditsMode != 0) {
            cman->mode_type = 4;
            pod->flags0 &= ~swrObjTest_FLAG0_LOOK_BACK;
        } else if (!(pod->flags0 & swrObjTest_FLAG0_LOCAL)) {
            // auto-cycling spectator cam: hold each mode 3..10 s
            swrObjcMan_spectatorCamTimer -= swrRace_deltaTimeSecs;
            if (swrObjcMan_spectatorCamTimer <= 0.0f) {
                swrObjcMan_spectatorCamTimer = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 7.0f + 3.0f;
                // summed unrounded on the x87 stack before __ftol
                swrObjcMan_spectatorCamIndex = (int)((double)swrObjcMan_spectatorCamIndex + (double)swrUtils_Rand() * SWR_CTL_RAND_NORM * 7.0f) % 7;
                cman->mode_type = swrObjcMan_SpectatorCamModes[swrObjcMan_spectatorCamIndex];
                pod->flags0 &= ~swrObjTest_FLAG0_LOOK_BACK;
                if (swrObjcMan_spectatorCamIndex == 6)
                    pod->flags0 |= swrObjTest_FLAG0_LOOK_BACK;
            }
        }
    }

    cman->unk2b8 = 100.0f;
    cman->nearClip = 0.5f;
    switch (cman->mode_type) {
    case 1:
    case 2:
        swrObjcMan_UpdateChaseCamera(cman);
        break;
    case 4:
    case 5:
        swrObjcMan_UpdateFirstPersonCamera(cman);
        break;
    case 6:
        swrObjcMan_UpdateSplineCamera(cman);
        break;
    case 7:
        swrObjcMan_UpdatePreRaceSweep(cman);
        break;
    case 8:
    case 9:
        swrObjcMan_UpdateDeathCamera(cman);
        break;
    }

    rdMatrix_ExtractTransform(&cman->unk20_mat, &current);
    BuildLookAtTransform(&current.translation, (rdVector3*)&cman->focusTransform_mat.vD, &view, &lookAt, current.yaw_roll_pitch.z);
    rdMatrix_Copy44(&cman->unk20_mat, &view);

    // camStateIndex holds the camera's mesh behavior, not an index
    if (!swrCam_IsBehaviorActiveViewportCamera_Maybe((swrModel_Behavior*)cman->camStateIndex))
        return;

    value = swrRace_creditsMode != 0 ? (int)0xffffff00 : (int)cman->visual_flag;
    swrViewport_SetNodeFlags(swrViewport_Get(cman->metaCamIndex_count), 4, value);
    swrViewport_SetNodeFlags(swrViewport_Get(cman->metaCamIndex_count), 3, cman->visual_flag);
    swrObjcMan_UpdateFogAndViewport(cman);
    if (cman->fog_flag & swrObjcMan_VIEWFLAGS_NO_WEATHER)
        swrWeather_Disable();
    else
        swrWeather_Enable();
    swrObjcMan_UpdateSplineGuideMarker(cman);
}

// 0x00454060
void DrawTerrainTypeDebugText(void* meshBehavior)
{
    static const struct
    {
        unsigned int flag;
        const char* name;
    } reactions[] = {
        { swrVehicleReaction_ZOn, "ZOn  " }, { swrVehicleReaction_ZOff, "ZOff " }, { swrVehicleReaction_Fast, "Fast " }, { swrVehicleReaction_Slow, "Slow " }, { swrVehicleReaction_Swst, "Swst " }, { swrVehicleReaction_Slip, "Slip " }, { swrVehicleReaction_Dust, "Dust " }, { swrVehicleReaction_Snow, "Snow " }, { swrVehicleReaction_Wet, "Wet  " }, { swrVehicleReaction_Ruff, "Ruff " }, { swrVehicleReaction_Swmp, "Swmp " }, { swrVehicleReaction_NSnw, "NSnw " }, { swrVehicleReaction_Mirr, "Mirr " }, { swrVehicleReaction_Lava, "Lava " }, { swrVehicleReaction_Fall, "Fall " }, { swrVehicleReaction_Soft, "Soft " }, { swrVehicleReaction_NRSp, "NRSp " }, { swrVehicleReaction_Flat, "Flat " }, { swrVehicleReaction_Side, "Side " },
    };
    swrModel_Behavior* behavior = (swrModel_Behavior*)meshBehavior;
    char text[64];
    int len = 0;

    if (behavior == NULL)
        return;

    // the original appends with sprintf(text, "%sZOn  ", text) per set flag
    text[0] = '\0';
    for (int i = 0; i < (int)(sizeof(reactions) / sizeof(reactions[0])); i++) {
        if (behavior->vehicle_reaction & reactions[i].flag)
            len += sprintf(text + len, "%s", reactions[i].name);
    }
    if (text[0] != '\0')
        swrText_CreateColorlessEntry1(20, 200, text);
}

// 0x004542e0
void swrObjcMan_F3(swrObjcMan* cman)
{
    swrObjcMan_UpdateCamera(cman);
    if (cman->camShake.z > 0.0f) {
        // compared unrounded on the x87 stack, stored as float
        double offset = cman->camShake.x + cman->camShake.y * swrRace_deltaTimeSecs;
        cman->camShake.x = offset;
        if (offset > cman->camShake.z || -offset > cman->camShake.z) {
            cman->camShake.y = -cman->camShake.y;
            cman->camShake.x = cman->camShake.x > 0.0f ? cman->camShake.z : -cman->camShake.z;
        }
        cman->focusTransform_mat.vD.z += cman->camShake.x;
        cman->unk20_mat.vD.z += cman->camShake.x * 0.5f;
        playASound(7, 7, 0.25f, 1.0f, 1);
    }

    if (cman->mode_type != 0 && cman->metaCamIndex_count >= 0 && debug_showSurfaceFlags != 0)
        DrawTerrainTypeDebugText(cman->surfaceBehavior);
}

// 0x004543f0
int swrObjcMan_F4(swrObjcMan* cman, int* subEvents, int p3)
{
    HANG("TODO");
    return 0;
}

// 0x00454920
void swrObjScene_ResetViewports(void)
{
    swrViewport_SetViewport(0, 8, 8, 312, 232);
    swrViewport_SetViewport(1, 8, 8, 312, 232);
    swrViewport_Enable(1, 7);
    swrViewport_SetCameraParameters(1, 85.0f, -1.0f, -1.0f, -1.0f, -1.0f);
    swrSprite_SetVisible(-0xc9, 0);
}

// 0x00454990
void swrObjScene_Exit(swrObjScen* scene, int event)
{
    int ev[16];

    swrObjScene_ResetViewports();
    swrSound_SetUpdateFlag_Maybe(0);
    swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
    swrSprite_ResetAllSprites();
    swrModel_ClearSceneAnimations();
    swrViewport_SetRootNodeForAllViewports(NULL);
    *((unsigned char*)&scene->obj.flags + 1) |= 0x10;
    swr_noop2(); // EXE passes (1)
    swrSound_ResetRequestedVoices(); // via the 0x4269b0 thunk
    ev[0] = event;
    swrEvent_CallF4('All!', ev);
    swrEvent_ClearObjs('Scen');
}

// 0x00454a10
void swrObjScene_F0(swrObjScen* scene)
{
    swrObjScene_Exit(scene, 'Abrt');
}

// 0x00454a30
int swrObjScene_F4(swrObjScen* scene, int* subEvents)
{
    switch (*subEvents) {
    case 'Load':
        scene->unk8 = 0;
        scene->unkc = 0;
        scene->unk50 = 0;
        rdMatrix_SetIdentity44(&scene->unk84_mat);
        rdMatrix_SetIdentity44(&scene->unkb28_mat);
        scene->unkc4 = 0;
        // fall through
    case 'RSet': {
        int ev[16];
        ev[0] = 'Slep';
        swrEvent_CallF4('Scen', ev);
        return 1;
    }

    case 'Begn':
        swr_noop2(); // EXE passes (scene, subEvents[1])
        swrScene_SetObjectsLoaded();
        return 1;

    case 'Slep':
        *((unsigned char*)&scene->obj.flags + 1) |= 0x10;
        return 1;

    case 'Wake':
        *((unsigned char*)&scene->obj.flags + 1) &= ~0x10;
        swrSound_ResetRequestedVoices(); // via the 0x4269b0 thunk, which drops its arg 7
        swr_noop2();
        return 1;

    default:
        return 0;
    }
}

// 0x00454D10
void swrObjHang_InitSceneRootNode()
{
    swrModel_NodeInit(&someUnkRootNode, NODE_BASIC);
    someUnkRootNode.num_children = sizeof(swrScene_ChildNodes) / sizeof(swrScene_ChildNodes[0]);
    someUnkRootNode.children.nodes = swrScene_ChildNodes;
}

// 0x00454cc0
void swrModel_clearSceneModelsAndChildren(void)
{
    for (int slot = SWR_SCENE_PERSISTENT_MODEL_SLOTS; slot < SWR_SCENE_MODEL_SLOT_COUNT; slot++) {
        swrModel_Header* header = swr_sceneModels[slot];
        if (header != NULL) {
            for (int child = 0; child < SWR_SCENE_MODEL_SLOT_COUNT; child++) {
                if (swrScene_ChildNodes[child] == header->entries[0].node)
                    swrScene_ChildNodes[child] = NULL;
            }
            swr_sceneModels[slot] = NULL;
        }
    }
    swrModel_ClearSceneAnimations();
}

// 0x00454d40
void swrObjHang_SetMenuState(swrObjHang* hang, swrObjHang_STATE state)
{
    int uiId;
    const char* stateName;
    char stateNameBuf[256];

    rdroid_g_curRenderOptions2 = RDROID_BACKFACE_CULLING_ENABLED;
    if (hang == NULL) {
        while (true) {
        }
    }
    if (hang->flag == 0) {
        while (true) {
        }
    }
    if ((hang->flag & swrObjHang_FLAG_ACTIVE) != 0) {
        swrObjHang_screenTransitionDir = 0;
        hang->menuScreenPrev = hang->menuScreen;
        hang->menuScreen = state;
        hang->roomPrev = hang->room;
        swrObjHang_state2 = ~swrObjHang_STATE_LEGAL;
        swrObjHang_menuJustEntered = 1;
        hang->unk54 = 0;
        hang->unk58 = 0;
        hang->unk5c = 1;
        if (swrObjHang_fadeState != 0 || hang->room == Cantina ||
            (hang->menuScreenPrev != swrObjHang_STATE_MAIN_MENU && hang->menuScreen != swrObjHang_STATE_MAIN_MENU)) {
            if (hang->menuScreen != swrObjHang_STATE_LEGAL) {
                swrObjHang_LoadScreenAssets(hang);
                swrObjHang_SetupScreenScene(hang);
            }
            swrObjHang_menuRepeatTimer = 0.0f;
            swrObjHang_menuRepeatCount = 0;
            swrObjHang_menuRepeatDir = 0;
            hang->flag |= swrObjHang_FLAG_SCREEN_SET_UP;
        }
    }

    if (someUI != NULL)
        swrUI_RunCallbacks2(someUI, 0);
    someUI = NULL;
    if (multiplayer_enabled == 0) {
        uiId = -1;
        switch (state) {
        case swrObjHang_STATE_MAIN_MENU:
            uiId = swrUI_WINDOW_HANGAR_MAIN_MENU;
            break;
        case swrObjHang_STATE_JUNKYARD:
            uiId = swrUI_WINDOW_HANGAR_JUNKYARD;
            break;
        case swrObjHang_STATE_WATTO:
            uiId = swrUI_WINDOW_HANGAR_WATTO;
            break;
        case swrObjHang_STATE_LOOK_AT_VEHICLE:
            uiId = swrUI_WINDOW_HANGAR_LOOK_AT_VEHICLE;
            break;
        case swrObjHang_STATE_SELECT_VEHICLE:
            swrControl_menuAcceptGuard = 1;
            uiId = swrUI_WINDOW_HANGAR_SELECT_VEHICLE;
            break;
        case swrObjHang_STATE_SELECT_PLANET:
            uiId = swrUI_WINDOW_HANGAR_SELECT_PLANET;
            break;
        case swrObjHang_STATE_SELECT_TRACK:
            uiId = swrUI_WINDOW_HANGAR_SELECT_TRACK;
            break;
        default:
            break;
        }
        if (uiId != -1)
            someUI = swrUI_GetById(NULL, uiId);
        if (someUI != NULL)
            swrUI_RunCallbacks2(someUI, 1);
    }

    swrControl_menuAcceptPressedEdge = 0;
    swrControl_acceptPressedEdge = 0;
    swrUI_menuButtonStatePrev = 0;
    swrUI_menuButtonState = 0;
    swrObjHang_SetHangar2(hang);
    if (swrMultiplayer_IsMultiplayerEnabled() != 0 && swrMultiplayer_IsHost() != 0) {
        if (state == swrObjHang_STATE_MAIN_MENU)
            swrObjHang_someState = swrObjHang_STATE_MAIN_MENU;
        else if (state == swrObjHang_STATE_SELECT_PLANET)
            swrObjHang_someState = swrObjHang_STATE_SELECT_PLANET;
        else if (state == swrObjHang_STATE_SELECT_TRACK)
            swrObjHang_someState = swrObjHang_STATE_SELECT_TRACK;
        else
            swrObjHang_someState = swrObjHang_STATE_MP_OTHER_SCREEN;
        swr_noop2();
        swrMultiplayer_BroadcastPlayerState();
    }

    // Debug leftover: the state name is formatted into a local and never used.
    switch (hang->menuScreen) {
    case swrObjHang_STATE_LEGAL:
        stateName = "LEGAL";
        break;
    case swrObjHang_STATE_SPLASH:
        stateName = "SPLASH";
        break;
    case swrObjHang_STATE_ENTER_NAME:
        stateName = "ENTER_NAME";
        break;
    case swrObjHang_STATE_MAIN_MENU:
        stateName = "MAIN_MENU";
        break;
    case swrObjHang_STATE_JUNKYARD:
        stateName = "JUNKYARD";
        break;
    case swrObjHang_STATE_POST_RACE_INFO:
        stateName = "POST_RACE_INFO";
        break;
    case swrObjHang_STATE_WATTO:
        stateName = "WATTO";
        break;
    case swrObjHang_STATE_LOOK_AT_VEHICLE:
        stateName = "LOOK_AT_VEHICLE";
        break;
    case swrObjHang_STATE_SELECT_VEHICLE:
        stateName = "SELECT_VEHICLE";
        break;
    case swrObjHang_STATE_SELECT_PLANET:
        stateName = "SELECT_PLANET";
        break;
    case swrObjHang_STATE_SELECT_TRACK:
        stateName = "SELECT_TRACK";
        break;
    default:
        stateName = "(Unknown state)";
        break;
    }
    sprintf(stateNameBuf, "%s", stateName);

    switch (hang->menuScreen) {
    case swrObjHang_STATE_SPLASH:
    case swrObjHang_STATE_ENTER_NAME:
    case swrObjHang_STATE_POST_RACE_INFO:
    case swrObjHang_STATE_SELECT_VEHICLE:
    case swrObjHang_STATE_SELECT_PLANET:
    case swrObjHang_STATE_SELECT_TRACK:
        swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_NO_PIT_DROID_CHATTER);
        break;
    default:
        swrSound_ClearSfxFlag(0, swrSound_HANGSFXFLAG_NO_PIT_DROID_CHATTER);
        break;
    }
    if (hang->menuScreen == swrObjHang_STATE_JUNKYARD) {
        if (hang->roomPrev != Junkyard) {
            swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING);
            swrSound_ClearSfxFlag(0, swrSound_HANGSFXFLAG_IN_WATTO_SHOP);
        }
    } else if (hang->menuScreen == swrObjHang_STATE_WATTO &&
               (hang->roomPrev != Shop || hang->menuScreenPrev == swrObjHang_STATE_MAIN_MENU)) {
        swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING);
        swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_IN_WATTO_SHOP);
    }
    swrObjHang_lastMenuScreen = hang->menuScreen;
    if (swrObjHang_unused_unk != -1)
        hang->activeMenu = swrObjHang_unused_unk;
}

// Leaves the name-entry screen: commit the profile and return to the previous menu.
// 0x004367c0
void swrObjHang_UpdateEnterName(swrObjHang* hang)
{
    swrSaveProfile* profile;
    int i;

    if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_VEHICLE)
        swrRace_aProfiles[hang->current_player_for_vehicle_selection].pilotId = 0;
    profile = &swrRace_aProfiles[hang->current_player_for_vehicle_selection];
    if (profile->linkedToSave == 1)
        swrRace_CopyProfileToSave((char)profile->saveSlot, hang->current_player_for_vehicle_selection);
    swrRace_SaveCurrentProfile();
    swrObjHang_nameEntrySelection = -1;
    for (i = 0; i < 8; i++)
        swrObjHang_nameEntryBuffer[i] = 0;
    swrObjHang_nameEntryStateA = 0;
    swrObjHang_nameEntryStateB = 0;
    swrObjHang_SetMenuState(hang, hang->menuScreenPrev);
}

// 0x004565e0
void swrObjHang_OrderHoloRacerIcons(int planetIdx)
{
    int ids[5] = { -1, -1, -1, -1, -1 };
    float keys[5] = { 0.0f, 0.0f, 0.0f, 0.0f, 0.0f };
    swrPlanetInfo* planet = &swrPlanetTable[planetIdx];
    int count = planet->sunMoonSpriteEnd - planet->sunMoonSpriteStart + 1;
    int slotCount = count + 2;
    int front = 0;
    int back = count + 1;
    int cursor = 0;
    float sinAngle;
    float cosAngle;

    // moons facing the camera go first, the rest fill from the back
    for (int k = planet->sunMoonSpriteStart; k <= planet->sunMoonSpriteEnd; k++) {
        stdMath_SinCos(swrObjHang_holoMoons[k].angle, &sinAngle, &cosAngle);
        if (cosAngle * swrObjHang_holoMoons[k].orbit.y > 0.0f) {
            keys[front] = swrObjHang_holoMoons[k].scale;
            ids[front] = k - planet->sunMoonSpriteStart + INGAME_MODELID_pln_moon_part0;
            front++;
        } else {
            keys[back] = swrObjHang_holoMoons[k].scale;
            ids[back] = k - planet->sunMoonSpriteStart + INGAME_MODELID_pln_moon_part0;
            back--;
        }
    }
    ids[front++] = planetIdx + INGAME_MODELID_pln_tatooine_part;
    ids[front++] = INGAME_MODELID_pln_coruscant_cld_part;

    // faithful: both sorts swap ids only, never keys, and the front sort stops two short of the planet
    for (int a = 0; a < front - 3; a++) {
        for (int j = a + 1; j < front - 2; j++) {
            if (keys[a] < keys[j]) {
                int tmp = ids[a];
                ids[a] = ids[j];
                ids[j] = tmp;
            }
        }
    }
    for (int a = back; a < count + 1; a++) {
        for (int j = a + 1; j < slotCount; j++) {
            if (keys[a] > keys[j]) {
                int tmp = ids[a];
                ids[a] = ids[j];
                ids[j] = tmp;
            }
        }
    }

    // rewrite the scene's child list so these models render in the sorted order
    for (int n = 0; n < SWR_SCENE_MODEL_SLOT_COUNT; n++) {
        for (int i = 0; i < slotCount; i++) {
            if (swr_sceneModels[ids[i]]->entries[0].node == swrScene_ChildNodes[n]) {
                swrScene_ChildNodes[n] = swr_sceneModels[ids[cursor]]->entries[0].node;
                cursor++;
                break;
            }
        }
    }
}

// 0x00456800
void DrawHoloPlanet(swrObjHang* hang, int planetIdx, float scale)
{
    float planetScale = scale * 0.1f;
    swrModel_NodeTransformed* node;
    rdMatrix44 xf;
    rdVector3 pos;
    float sinAngle;
    float cosAngle;
    float s;

    for (int i = 0; i < 8; i++) {
        swrPlanetInfo* planet = &swrPlanetTable[i];
        float angle = planet->spinSpeed * swrRace_fdeltaTimeSecs + planet->spinAngle;
        planet->spinAngle = angle;
        if (angle > 360.0f)
            planet->spinAngle = angle - 360.0f;
        if (planet->spinAngle < 0.0f)
            planet->spinAngle = planet->spinAngle - -360.0f;
        angle = planet->unk18 * swrRace_fdeltaTimeSecs + planet->unk14;
        planet->unk14 = angle;
        if (angle > 360.0f)
            planet->unk14 = angle - 360.0f;
        if (planet->unk14 < 0.0f)
            planet->unk14 = planet->unk14 - -360.0f;
        // hide every planet; the selected one is shown again below
        if (swrPlanetHoloModelNodes[i] != NULL && ((swrModel_Header*)swrPlanetHoloModelNodes[i])->entries[0].node != NULL)
            swrModel_NodeModifyFlags(((swrModel_Header*)swrPlanetHoloModelNodes[i])->entries[0].node, 2, -4, 0x10, 3);
    }

    for (int i = 0; i < 19; i++) {
        // faithful: every moon advances twice per frame
        for (int pass = 0; pass < 2; pass++) {
            float angle = swrRace_fdeltaTimeSecs * swrObjHang_holoMoons[i].speed + swrObjHang_holoMoons[i].angle;
            swrObjHang_holoMoons[i].angle = angle;
            if (angle > 360.0f)
                swrObjHang_holoMoons[i].angle = angle - 360.0f;
            if (swrObjHang_holoMoons[i].angle < 0.0f)
                swrObjHang_holoMoons[i].angle = swrObjHang_holoMoons[i].angle - -360.0f;
        }
    }

    swrObjHang_OrderHoloRacerIcons(planetIdx);
    swrObjHang_UpdateHoloBillboardMatrix();

    node = (swrModel_NodeTransformed*)((swrModel_Header*)swrPlanetHoloModelNodes[planetIdx])->entries[0].node;
    if (node != NULL) {
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        rdMatrix_Copy44(&xf, &swrObjHang_holoCameraMatrix);
        rdVector_Copy3(&pos, &maybeUICameraPlacements[36].position2);
        rdMatrix_AddRotationFromVectorAngle44After(&xf, &xf, swrPlanetTable[planetIdx].spinAngle, swrObjHang_cameraMatrix.vC.x, swrObjHang_cameraMatrix.vC.y, swrObjHang_cameraMatrix.vC.z);
        rdMatrix_AddRotationFromVectorAngle44After(&xf, &xf, swrPlanetTable[planetIdx].orientationAngle, swrObjHang_cameraMatrix.vB.x, swrObjHang_cameraMatrix.vB.y, swrObjHang_cameraMatrix.vB.z);
        if (planetIdx == 6)
            s = (float)(planetScale * 1.5);
        else
            s = swrObjHang_holoPlanetScale * planetScale;
        rdMatrix_ScaleBasis44(&xf, s, s, s, &xf);
        rdVector_Copy3((rdVector3*)&xf.vD, &pos);
        swrModel_NodeSetTransform(node, &xf);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }

    for (int k = swrPlanetTable[planetIdx].sunMoonSpriteStart; k <= swrPlanetTable[planetIdx].sunMoonSpriteEnd; k++) {
        swrHoloMoon* moon = &swrObjHang_holoMoons[k];
        node = (swrModel_NodeTransformed*)swr_sceneModels[INGAME_MODELID_pln_moon_part0 + k - swrPlanetTable[planetIdx].sunMoonSpriteStart]->entries[0].node;
        if (node == NULL)
            continue;
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        rdMatrix_Copy44(&xf, &swrObjHang_holoCameraMatrix);
        rdVector_Copy3(&pos, &maybeUICameraPlacements[36].position2);
        stdMath_SinCos(moon->angle, &sinAngle, &cosAngle);
        rdVector_Scale3Add3(&pos, &pos, moon->orbit.x * sinAngle * scale, (rdVector3*)&swrObjHang_cameraMatrix.vA);
        rdVector_Scale3Add3(&pos, &pos, cosAngle * scale * moon->orbit.y, (rdVector3*)&swrObjHang_cameraMatrix.vB);
        rdVector_Scale3Add3(&pos, &pos, moon->orbit.z * cosAngle * scale, (rdVector3*)&swrObjHang_cameraMatrix.vC);
        rdMatrix_AddRotationFromVectorAngle44After(&xf, &xf, moon->angle, swrObjHang_cameraMatrix.vC.x, swrObjHang_cameraMatrix.vC.y, swrObjHang_cameraMatrix.vC.z);
        rdMatrix_AddRotationFromVectorAngle44After(&xf, &xf, swrPlanetTable[planetIdx].orientationAngle, swrObjHang_cameraMatrix.vB.x, swrObjHang_cameraMatrix.vB.y, swrObjHang_cameraMatrix.vB.z);
        s = moon->scale * scale;
        rdMatrix_ScaleBasis44(&xf, s, s, s, &xf);
        rdVector_Copy3((rdVector3*)&xf.vD, &pos);
        swrModel_NodeSetTransform(node, &xf);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }
}

// 0x00456c70
void DrawTrackPreview(void* unused, int TrackID, float param_3)
{
    HANG("TODO");
}

// Step cameraState by dir to the next placement in the same group (placement.unk1), wrapping
// over the 40 placements; wrap = 0 refuses to leave the group or the table instead.
// 0x0045bde0
void swrObjHang_NavigateMenu(swrObjHang* hang, short dir, int wrap)
{
    HangCameraState current = hang->cameraState;
    int next = current + dir;
    int moved = 0;

    if (wrap == 0) {
        if (next < 0 || next > HangCameraState_CantinaEntryCutscene)
            return;
        if ((short)maybeUICameraPlacements[next].unk1 != (short)maybeUICameraPlacements[current].unk1)
            return;
    }
    next -= dir;
    do {
        next += dir;
        if (next < 0)
            next = HangCameraState_CantinaEntryCutscene;
        else if (next > HangCameraState_CantinaEntryCutscene)
            next = 0;
    } while ((short)maybeUICameraPlacements[next].unk1 != (short)maybeUICameraPlacements[current].unk1);

    if (maybeUICameraPlacements[next].unk2 != 0 && (!rdVector_AreSame3(&maybeUICameraPlacements[next].position1, &maybeUICameraPlacements[current].position1) || !rdVector_AreSame3(&maybeUICameraPlacements[next].position2, &maybeUICameraPlacements[hang->cameraState].position2))) {
        moved = 1;
        swrObjHang_SetHoloCameraTarget(&maybeUICameraPlacements[next].position1, &maybeUICameraPlacements[next].position2, 1, 0, 0);
    }
    hang->cameraState = next;
    if (moved)
        swrObjHang_PositionPlayerPuppets(hang);
}

// 0x0045bee0
void swrObjHang_FocusMenuItem(swrObjHang* hang, int itemIndex, swrObjHang_STATE nextState, int resetCamera)
{
    hang->cameraState = itemIndex;
    swrObjHang_SetHoloCameraTarget(&maybeUICameraPlacements[itemIndex].position1,
                                   &maybeUICameraPlacements[itemIndex].position2, 1, 0, resetCamera);
    if (nextState != ~swrObjHang_STATE_LEGAL)
        swrObjHang_state2 = nextState;
}

// 0x00457140
void swrObjHang_PositionHoloNode(int nodeIndex, float x, float y, float scale)
{
    swrModel_NodeTransformed* node;
    rdVector3 pos;
    float nodeScale;
    rdMatrix44 mat;
    rdMatrix44 cam;
    swrTranslationRotation tr;

    x = x - -18.0f;
    y = y - 20.0f;
    nodeScale = scale * 0.01f * 4.0f;
    node = (swrModel_NodeTransformed*)swr_sceneModels[SWROBJHANG_HOLO_MODEL_SLOT_BASE + nodeIndex]->entries[0].node;
    if (node == NULL)
        return;

    swrModel_NodeModifyFlags((swrModel_Node*)node, 2, -4, 0x10, 3);
    swrObjHang_UpdateHoloBillboardMatrix();
    rdMatrix_Copy44(&cam, &swrObjHang_cameraMatrix);
    rdVector_Copy3(&pos, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Scale3Add3(&pos, &pos, x, (rdVector3*)&swrObjHang_cameraMatrix.vA);
    rdVector_Scale3Add3(&pos, &pos, 126.0f, (rdVector3*)&swrObjHang_cameraMatrix.vB);
    rdVector_Scale3Add3(&pos, &pos, y, (rdVector3*)&swrObjHang_cameraMatrix.vC);
    rdVector_Copy3(&tr.translation, &pos);
    rdVector_Set3(&tr.yaw_roll_pitch, 0.0f, 0.0f, 0.0f);
    rdMatrix_SetTransform44(&mat, &tr);
    rdMatrix_AddRotationFromVectorAngle44After(&mat, &mat, 0.0f, cam.vC.x, cam.vC.y, cam.vC.z);
    rdMatrix_AddRotationFromVectorAngle44After(&mat, &mat, 0.0f, cam.vB.x, cam.vB.y, cam.vB.z);
    rdMatrix_AddRotationFromVectorAngle44After(&mat, &mat, 0.0f, cam.vC.x, cam.vC.y, cam.vC.z);
    rdMatrix_ScaleBasis44(&mat, nodeScale, nodeScale, nodeScale, &mat);
    rdVector_Copy3((rdVector3*)&mat.vD, &pos);
    swrModel_NodeSetTransform(node, &mat);
    swrModel_NodeModifyFlags((swrModel_Node*)node, 2, 3, 0x10, 2);
}

// 0x00434ea0
void swrObjHang_UpdateLoadScreen(swrObjHang* hang)
{
    swrObjHang_LoadScreen(hang, hang->unk68_type != 0, 1);
}

// 0x00440de0
int getInRaceInputBufferEntry_Maybe(int index)
{
    return swrObjHang_extraSplashPages[index];
}

// 0x00435240
void swrObjHang_UpdateSplashScreen(swrObjHang* hang)
{
    swrUI_unk* page;
    swrUI_unk* starWarsItem;
    swrUI_unk* racerItem;
    short backdrop;

    swrObjHang_splashFrameCounter++;
    if (swrObjHang_splashFrameCounter > 30)
        swrObjHang_splashFrameCounter = 0;
    swrUI_RunCallbacks2(swrUI_GetUI1(), 1);
    if (swrUI_GetPageStackDepth() == 0)
        swrUI_PushMenuPage(swrUI_WINDOW_SPLASH);
    hang->isTournamentMode = swrObjHang_pendingTournamentMode;

    if (swrObjHang_splashSkipToVehicleIntro != 0) {
        swrObjHang_splashSkipToVehicleIntro = 0;
        hang->num_local_players = 1;
        swrObjHang_state2 = swrObjHang_STATE_VEHICLE_SELECT_INTRO;
        swrObjHang_fadeState = -1;
        return;
    }

    if (swrObjHang_splashSceneSetUp == 0) {
        swrObjHang_splashSceneSetUp = 1;
        swrObjHang_SetupScreenScene(hang);
    }
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_fadeState = 1;
        swr_noop2();
        swrObjHang_attractDemoTimer = 30.0f;
        for (int i = 0; i < 12; i++)
            swrObjHang_splashPageSequence[i] = -1;
        swrObjHang_titleDropTimer = 2.0f;
        swrObjHang_episodeFadeTimer = 1.0f;
        swrObjHang_racerSlideTimer = 1.0f;
        swrObjHang_splashPageSequence[0] = 0;
        swrObjHang_splashPageSequence[1] = 1;
        swrObjHang_splashPageSequence[2] = 2;
        swrObjHang_splashPageCount = 3;
        if (getInRaceInputBufferEntry_Maybe(1) != 0)
            swrObjHang_splashPageSequence[(int)swrObjHang_splashPageCount++] = 3;
    }

    // title intro: STAR/WARS drop in, then "Episode I" fades in, then RACER slides in
    swrObjHang_titleDropTimer -= swrRace_fdeltaTimeSecs;
    if (swrObjHang_titleDropTimer <= 0.0f)
        swrObjHang_titleDropTimer = 0.0f;
    if (swrObjHang_titleDropTimer <= 0.0f) {
        swrObjHang_episodeFadeTimer -= swrRace_fdeltaTimeSecs;
        if (swrObjHang_episodeFadeTimer <= 0.0f)
            swrObjHang_episodeFadeTimer = 0.0f;
    }
    if (swrObjHang_episodeFadeTimer <= 0.5f) {
        swrObjHang_racerSlideTimer -= swrRace_fdeltaTimeSecs * 5.0f;
        if (swrObjHang_racerSlideTimer <= 0.0f)
            swrObjHang_racerSlideTimer = 0.0f;
    }

    if (swrObjHang_fadeState == 0) {
        if (swrObjHang_attractDemoTimer <= 0.0f) {
            swrObjHang_attractDemoTimer = 30.0f;
            hang->demo_mode = 2;
            swrObjHang_fadeState = -1;
        }
        swrSound_SetMusicFade(1);
    }

    page = swrUI_GetCurrentPage();
    // menu input bits 0x4 (held) / 0x80 (pressed) are unidentified
    if (page->id == swrUI_WINDOW_SPLASH && (swrUI_localPlayersInputDownBitset[0] & 0x4) != 0 && (swrUI_localPlayersInputPressedBitset[0] & 0x80) != 0) {
        hang->showDeveloperPhoto = hang->showDeveloperPhoto == 0;
        g_objHang2 = hang;
    }

    backdrop = hang->showDeveloperPhoto ? 0x4d : swrUISprite_greyedsplash_tga; // 0x4d = developer photo
    if (page->id != swrUI_WINDOW_SPLASH)
        backdrop = (page->id & 1) + swrUISprite_podhangar_backdrop_tga;
    if (page->id == swrUI_WINDOW_HANGAR_SELECT_VEHICLE)
        backdrop = swrUISprite_podhangar_backdrop_tga;
    swrSprite_SetPos(backdrop, 0, 0);
    swrSprite_SetDim(backdrop, 0.5f, 1.0f);
    if (hang->showDeveloperPhoto)
        swrSprite_SetDim(backdrop, 1.0f, 1.0f);
    swrSprite_SetVisible(backdrop, 1);
    swrSprite_SetColor(backdrop, 0xff, 0xff, 0xff, 0xfe);
    swrSprite_SetFlag(backdrop, 0x10000);
    // faithful: overrides the 0.5 width set above
    swrSprite_SetDim(backdrop, 1.0f, 1.0f);

    starWarsItem = swrUI_GetById(page, 0x272a);
    swrUI_RunCallbacks2(starWarsItem, 0);
    racerItem = swrUI_GetById(page, 0x272b);
    swrUI_RunCallbacks2(racerItem, 0);
    if (hang->showDeveloperPhoto)
        return;

    swrSprite_SetPos(swrUISprite_STAR_tga, 12, (short)(int)(18.0f - swrObjHang_titleDropTimer * 100.0f));
    swrSprite_SetVisible(swrUISprite_STAR_tga, 1);
    swrSprite_SetColor(swrUISprite_STAR_tga, 0xff, 0xff, 0xff, 0xfe);
    swrSprite_SetFlag(swrUISprite_STAR_tga, 0x10000);
    swrSprite_SetPos(swrUISprite_WARS_tga, 155, (short)(int)(18.0f - swrObjHang_titleDropTimer * 100.0f));
    swrSprite_SetVisible(swrUISprite_WARS_tga, 1);
    swrSprite_SetColor(swrUISprite_WARS_tga, 0xff, 0xff, 0xff, 0xfe);
    if (swrObjHang_titleDropTimer <= 0.0f)
        swrUI_RunCallbacks2(starWarsItem, 1);
    swrSprite_SetFlag(swrUISprite_WARS_tga, 0x10000);

    swrSprite_SetPos(swrUISprite_episode1_tga, 14, 51);
    swrSprite_SetVisible(swrUISprite_episode1_tga, 1);
    swrSprite_SetColor(swrUISprite_episode1_tga, 0xff, 0xff, 0xff, (uint8_t)(int)((1.0f - swrObjHang_episodeFadeTimer) * 254.0f));
    swrSprite_SetFlag(swrUISprite_episode1_tga, 0x10000);

    swrSprite_SetPos(swrUISprite_RACER_tga, (short)(int)(12.0f - swrObjHang_racerSlideTimer * 320.0f), 70);
    swrSprite_SetVisible(swrUISprite_RACER_tga, 1);
    swrSprite_SetColor(swrUISprite_RACER_tga, 0xff, 0xff, 0xff, 0xfe);
    if (swrObjHang_racerSlideTimer <= 0.0f)
        swrUI_RunCallbacks2(racerItem, 1);
    swrSprite_SetFlag(swrUISprite_RACER_tga, 0x10000);
}

// 0x00436860
void swrObjHang_UpdateMainMenu(swrObjHang* hang)
{
    if (swrObjHang_menuJustEntered != 0)
        hang->activeMenu = 0;

    if (hang->activeMenu != 0 && swrObjHang_state2 == ~swrObjHang_STATE_LEGAL) {
        swrRace_AudioVideoSettings(hang);
        return;
    }
    swrRace_MainMenu(hang);
}

static void computeSelectedPartStats(swrObjHang* hang);

// 0x0043abc0
void swrObjHang_UpdateJunkyard(swrObjHang* hang)
{
    char text[256];
    char* partName;
    char* format;
    int width;
    int selectionChanged = 0;
    char dir = 0;

    if (swrObjHang_UpdateScreenTransition(hang, swrObjHang_menuJustEntered, 0x14) != 0)
        return;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_junkyardOpenDetail = 0;
        swrObjHang_junkyardReturnCamera = 0;
        swrObjHang_screenSlideOffset = -300.0f;
        swrObjHang_partDetailActive = 0;
        swrObjHang_partDetailClosing = 0;
        swrObjHang_cameraMoveParity = 0;
        swrObjHang_LayoutVehicleSelectIcons(hang);
        swrRace_MenuSelectedItem = swrObjHang_junkyardStock[hang->cameraState - SWR_JUNKYARD_PLACEMENT_FIRST].partType;
        computeSelectedPartStats(hang);
        swrRace_ComputeUpgradePrices();
        if (swrObjHang_IsCameraMoving(hang) != 0)
            swrObjHang_FocusMenuItem(hang, hang->cameraState, ~swrObjHang_STATE_LEGAL, 0);
        else
            swrObjHang_cameraMoveMode = 5;
    }

    if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_FADED_IN) != 0 && swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING) != 0) {
        swrSound_ClearSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING);
        if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_JUNKYARD_INTRO_PLAYED) == 0) {
            swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_JUNKYARD_INTRO_PLAYED);
            swrSound_PlaySfxThrottled(2, 0, 0x35, NULL);
        } else {
            swrSound_PlayRandomSfx(2, 0, 0x1f, 0x25, 0x2f, 0x33, 0x37, NULL);
        }
    }

    swrRace_DrawPartShopScreen(hang);
    if (hang->cameraState != HangCameraState__unk_3)
        swrRace_VehicleStatisticsSubMenu(hang, 20.0f, 135.0f);
    if ((swrObjHang_cameraMoveParity == 0 || swrObjHang_cameraMoveActive != 0) && hang->cameraState != HangCameraState__unk_3) {
        partName = swrText_Translate((char*)upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index].name);
        format = swrText_Translate(g_pTxtPartNameFormat);
        sprintf(text, format, partName);
        swrText_CreateTextEntry1(0xa0, 0x19, 0x32, -1, -1, -1, text);
        swrRace_MenuCanScrollRight = 1;
        swrRace_MenuCanScrollLeft = 1;
        swrText_GetStringWidthByFont(text, 0);
        width = swrText_GetStringWidthByFont(text, 0);
        // the original also pushes width as a third argument, which the callee never reads
        swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - (double)width * 0.5), 0x1a);
    }
    swrRace_UpdatePartMenuLayout(hang);
    swrRace_UpdateStatPartModels(); // the original pushes hang; the callee takes no argument

    // the camera arrived at the slot: open the detail view
    if (swrObjHang_cameraMoveParity != 0 && swrObjHang_cameraMoveActive == 0 && swrObjHang_partDetailActive == 0 && swrObjHang_junkyardReturnCamera == 0)
        swrObjHang_junkyardOpenDetail = 1;
    if (swrObjHang_junkyardOpenDetail != 0) {
        swrObjHang_partLayoutDirty = 1;
        swrObjHang_partDetailActive = 1;
        swrRace_upgradeUnaffordable = 0;
        swrObjHang_junkyardOpenDetail = 0;
    }
    if (swrObjHang_cameraMoveParity != 0 && swrObjHang_partLerpActive == 0 && swrObjHang_junkyardReturnCamera != 0) {
        swrObjHang_junkyardReturnCamera = 0;
        swrObjHang_BeginCameraMove(hang, 0);
    }

    // faithful: dir and selectionChanged carry over between players
    for (int player = 0; player < hang->num_local_players; player++) {
        if (swrObjHang_cameraMoveActive != 0 || swrObjHang_screenTransitionDir != 0)
            return;
        if (swrControl_menuAcceptPressedEdge != 0) {
            playUISound(0x54);
            if (swrObjHang_cameraMoveParity == 0) {
                swrObjHang_BeginCameraMove(hang, 1);
                if (hang->cameraState == HangCameraState__unk_3) {
                    swrObjHang_fadeState = -1;
                    swrObjHang_state2 = swrObjHang_STATE_WATTO;
                    return;
                }
            } else {
                if (swrRace_upgradeUnaffordable == 0)
                    swrObjHang_SwapSelectedPart(hang);
                swrObjHang_partLayoutDirty = 1;
                swrRace_upgradeUnaffordable = 0;
                swrObjHang_partDetailActive = 0;
                swrObjHang_partDetailClosing = 1;
                swrObjHang_screenTransitionDir = -1;
                swrObjHang_junkyardReturnCamera = 1;
            }
        }
        if (swrMultiplayer_menuOverlayActive == 0 && swrControl_cancelPressedEdge != 0) {
            playUISound(0x4d);
            if (swrObjHang_partDetailActive != 0) {
                swrObjHang_partLayoutDirty = 1;
                swrObjHang_partDetailActive = 0;
                swrObjHang_partDetailClosing = 1;
                swrRace_upgradeUnaffordable = 0;
                swrObjHang_screenTransitionDir = -1;
                swrObjHang_junkyardReturnCamera = 1;
            } else {
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
            }
        }
        swrRace_MenuNavRightActive = 0;
        swrRace_MenuNavLeftActive = 0;
        if (swrObjHang_cameraMoveParity == 0 && swrObjHang_partDetailActive == 0) {
            int input = swrUI_localPlayersInputDownBitset[player];
            if ((input & swrUI_INPUT_MENU_LEFT) != 0) {
                if (swrObjHang_cameraMoveMode == 5 || swrObjHang_cameraMoveMode == 0)
                    dir = -1;
                swrRace_MenuNavLeftActive = 1;
            }
            if ((input & swrUI_INPUT_MENU_RIGHT) != 0) {
                if (swrObjHang_cameraMoveMode == 5 || swrObjHang_cameraMoveMode == 0)
                    dir = 1;
                swrRace_MenuNavRightActive = 1;
            }
        }
        if (dir != 0) {
            swrObjHang_NavigateMenu(hang, dir, 1);
            if (hang->cameraState != HangCameraState__unk_3)
                selectionChanged = 1;
            playUISound(0x58);
        }
        if (selectionChanged) {
            swrRace_MenuSelectedItem = swrObjHang_junkyardStock[hang->cameraState - SWR_JUNKYARD_PLACEMENT_FIRST].partType;
            computeSelectedPartStats(hang);
            swrRace_ComputeUpgradePrices();
        }
    }
}

// 0x0043c6f0
void swrObjHang_UpdateVehicleSelectIntro(swrObjHang* hang)
{
    rdVector3 lookAt;
    swrObjElmo* elmo;
    float elmoHeight;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrSound_RewindChannels();
        swrObjHang_vehicleIntroStep = 0;
        swrObjHang_vehicleIntroTimer = 3.0f;
        swrObjHang_SetHoloCameraTarget(&maybeUICameraPlacements[38].position2, &maybeUICameraPlacements[39].position2, 1, 0, 0);
        swrObjHang_vehicleIntroPlanet = (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 8.0f);
    }
    swrUI_Front_DispatchPageCallbacks_Maybe(0, 0);
    elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', hang->elmoEntityIndex);
    elmoHeight = elmo->unkbc * 0.8f;
    if (swrObjHang_vehicleIntroStep > 1)
        swrObjHang_StepTransition(-3.3f);
    if (swrObjHang_vehicleIntroStep == 3 && swrObjHang_vehicleIntroTimer > 0.0f) {
        hang->elmoFocusPosition.z = elmoHeight - 60.0f;
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, &hang->elmoFocusPosition);
        swrObjHang_vehicleIntroTimer -= swrRace_fdeltaTimeSecs;
    }
    for (int i = 0; i < hang->num_local_players; i++) {
        if (swrControl_menuAcceptPressedEdge != 0 || swrControl_cancelPressedEdge != 0) {
            // faithful: elmoEntityIndex is -1 after the first skip, so later players index slot -1
            swrRace_SetEngineNodeTranslation((void**)swr_sceneModels[hang->elmoEntityIndex], &swrObjElmo_waypoints[9]);
            swrObjElmo_SetAnimState(elmo, 0);
            hang->elmoEntityIndex = -1;
            swrRace_Transition = 0.0f;
            swrObjHang_state2 = swrObjHang_STATE_SELECT_VEHICLE;
        }
    }
    if (swrRace_Transition > 0.0f)
        DrawHoloPlanet(hang, swrObjHang_vehicleIntroPlanet, swrRace_Transition * 0.4f);

    if (swrObjHang_state2 != swrObjHang_STATE_SELECT_VEHICLE) {
        if (swrObjHang_vehicleIntroStep == 0 && swrObjHang_vehicleIntroTimer > 0.0f) {
            swrObjHang_vehicleIntroTimer -= swrRace_fdeltaTimeSecs;
            if (swrObjHang_vehicleIntroTimer <= 0.0f) {
                swrObjHang_SetHoloCameraTarget(&maybeUICameraPlacements[38].position2, &maybeUICameraPlacements[36].position2, 1, 0, 0);
                swrObjHang_vehicleIntroStep = 1;
            }
        }
        if (swrObjHang_cameraMoveMode == 0) {
            if (swrObjHang_vehicleIntroStep == 1) {
                swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[hang->elmoEntityIndex], &lookAt);
                lookAt.z = elmoHeight - 60.0f;
                swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrix.vD, &lookAt, 1, 0, 0);
                rdVector_Copy3(&elmo->moveTarget, &swrObjElmo_waypoints[1]);
                elmo->moveTarget.y = -320.0f;
                swrObjElmo_SetAnimState(elmo, elmo->kind == swrObjElmo_KIND_PIT_DROID ? 6 : 0x14);
                swrObjHang_vehicleIntroStep = 2;
            }
            if (swrObjHang_cameraMoveMode == 0 && swrObjHang_vehicleIntroStep == 2) {
                swrObjHang_vehicleIntroTimer = 5.0f;
                swrObjHang_vehicleIntroStep = 3;
            }
        }
        if (swrObjHang_vehicleIntroTimer <= 0.0f && swrObjHang_vehicleIntroStep == 3) {
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrix.vD, &maybeUICameraPlacements[36].position2, 1, 0, 0);
            swrObjHang_vehicleIntroStep = 4;
        }
        if (swrObjHang_cameraMoveMode != 0)
            return;
        if (swrObjHang_vehicleIntroStep == 4) {
            swrObjHang_SetHoloCameraTarget(&maybeUICameraPlacements[36].position1, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, 1, 0, 0);
            swrObjHang_vehicleIntroStep = 5;
        }
        if (swrObjHang_cameraMoveMode != 0 || swrObjHang_vehicleIntroStep != 5)
            return;
    }
    swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_VEHICLE);
}

// 0x0043ca30
void swrObjHang_UpdateTauntScene(swrObjHang* hang)
{
    rdMatrix44 podTransform;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_tauntTimer = 5.0f;
        swrObjHang_tauntFavoriteSpoken = 0;
        swrObjHang_tauntReplySpoken = 0;
        // faithful: the shots computed from the puppets here are overwritten by the fixed poses below
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PILOT_PUPPETS], &swrObjHang_tauntShot2LookAt);
        rdVector_Copy3(&swrObjHang_tauntShot1Eye, &swrObjHang_tauntShot2LookAt);
        swrObjHang_tauntShot2LookAt.z = (float)((double)swrRacer_PodData[(int)hang->vehiclePlayer].float20 * 0.6667 - 157.0);
        swrObjHang_tauntShot1Eye.z = (float)((double)swrRacer_PodData[2].float20 * 0.6667 - 157.0);
        swrObjHang_tauntShot1Eye.x -= -60.0f;
        swrObjHang_tauntShot1Eye.y -= -70.0f;
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PILOT_PUPPETS + 1], &swrObjHang_tauntShot1LookAt);
        rdVector_Copy3(&swrObjHang_tauntShot2Eye, &swrObjHang_tauntShot1LookAt);
        swrObjHang_tauntShot1LookAt.z = (float)((double)swrRacer_PodData[2].float20 * 0.6667 - 157.0);
        swrObjHang_tauntShot2Eye.z = (float)((double)swrRacer_PodData[(int)hang->vehiclePlayer].float20 * 0.6667 - 157.0);
        swrObjHang_tauntShot2Eye.x -= -60.0f;
        swrObjHang_tauntShot2Eye.y -= 70.0f;
        rdVector_Set3(&swrObjHang_tauntShot1Eye, 296.0f, -206.0f, -68.0f);
        rdVector_Set3(&swrObjHang_tauntShot2LookAt, -315.0f, 365.0f, -82.0f);
        rdVector_Set3(&swrObjHang_tauntShot2Eye, 315.0f, -566.0f, -70.0f);
        rdVector_Set3(&swrObjHang_tauntShot1LookAt, 0.0f, -680.0f, -68.0f);
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrix.vD, &swrObjHang_tauntShot1Eye);
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, &swrObjHang_tauntShot1LookAt);
    }
    playASound(0x1b, 7, 0.05f, 0.8f, 1);
    if (swrObjHang_tauntTimer >= 0.0f) {
        swrObjHang_tauntTimer -= swrRace_fdeltaTimeSecs * 0.5f;
        if (swrObjHang_tauntTimer <= 0.0f)
            swrObjHang_fadeState = -1;
    }

    for (int i = 0; i < 2; i++) {
        // the two display-pod positions are 0x28 bytes apart
        rdVector3* pos = (rdVector3*)((char*)&swrObjHang_displayPodPos + i * 0x28);
        if (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS + i] == NULL)
            continue;
        pos->x = 0.0f;
        pos->y = (float)(i * -2500.0);
        pos->z = 50.0f;
        // faithful: both overrides hit the first pod whatever i is
        if (hang->vehiclePlayer == 7)
            swrObjHang_displayPodPos.y = 200.0f;
        if (hang->vehiclePlayer == 0x11)
            swrObjHang_displayPodPos.y = 400.0f;
        rdMatrix_SetRotation44(&podTransform, 0.0f, 0.0f, 0.0f);
        rdVector_Set3((rdVector3*)&podTransform.vD, pos->x, pos->y, pos->z);
        swrRace_AnimateDisplayPod((swrModel_Node**)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS + i], &podTransform, 0, 70.0f, 70.0f, 70.0f, -157.0f, 1, 1.0f, 1.0f);
    }

    if (swrControl_menuAcceptPressedEdge != 0 || swrControl_cancelPressedEdge != 0) {
        swrObjHang_tauntTimer = 0.0f;
        swrObjHang_fadeState = -1;
    }
    if (swrObjHang_tauntTimer < 4.5f && swrObjHang_tauntTimer > 2.75f) {
        if (swrObjHang_tauntFavoriteSpoken == 0) {
            swrObjHang_tauntFavoriteSpoken = 1;
            swrObjElmo_SetAnimStateById(SWR_SCENE_SLOT_PILOT_PUPPETS + 1, 0x18);
            playASound((char)g_aTrackInfos[hang->track_index].FavoritePilot + 0xb7, 7, 0.25f, 1.0f, 0);
        }
        swrText_CreateTextEntry1(0xa0, 200, 0x78, -0x56, -0x56, -1, swrObjHang_pilotTauntText[(char)g_aTrackInfos[hang->track_index].FavoritePilot]);
    }
    if (swrObjHang_tauntTimer < 2.5f && swrObjHang_tauntTimer > 0.25f) {
        if (swrObjHang_tauntReplySpoken == 0) {
            swrObjHang_tauntReplySpoken = 1;
            swrObjElmo_SetAnimStateById(SWR_SCENE_SLOT_PILOT_PUPPETS, 0x18);
            rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrix.vD, &swrObjHang_tauntShot2Eye);
            rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, &swrObjHang_tauntShot2LookAt);
            playASound(swrRace_UnlockDataBase[0] + 0xb7, 7, 0.25f, 1.0f, 0);
        }
        swrText_CreateTextEntry1(0xa0, 200, -0x56, -0x56, 0, -1, swrObjHang_pilotTauntText[(int)swrRace_UnlockDataBase[0]]);
    }
}

// 0x0043ceb0
void swrObjHang_UpdatePlanetSelectIntro(swrObjHang* hang)
{
    swrModel_NodeTransformed* node;
    swrTranslationRotation pose;
    rdMatrix44 xf;
    float volume;
    float bobSin;
    float bobCos;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_planetIntroTimer = 33.0f;
        swrObjHang_planetIntroStep = 0;
        for (int i = 0; i < 3; i++) {
            // reads vehiclePlayer, vehicleOpponent[0], vehicleOpponent[1]
            swrObjHang_planetIntroOrbitSpeed[i] = swrRacer_PodData[(int)(&hang->vehiclePlayer)[i]].float20;
            swrObjHang_planetIntroOrbitAngle[i] = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 360.0f;
        }
        rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, 0.0f, 0.0f, -100.0f);
        rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrix.vD, 300.0f, 0.0f, -100.0f);
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        swrSound_ClearSfxFlag(0, swrSound_HANGSFXFLAG_PODIUM_LINE_PLAYED);
        swrSound_PlaySfxThenDelayed(3, 0, swrObjHang_circuitIntroSfx[(int)hang->circuitIdx], 5, 0, swrObjJdge_tauntSoundIdsDelayed[(int)hang->podiumCharacters[0]]);
    }

    if (swrSound_IsSfxOnCooldown(3, 0) == 0 && swrSound_IsSfxOnCooldown(5, 0) == 0) {
        volume = 1.0f;
        if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_PODIUM_LINE_PLAYED) == 0) {
            swrSound_PlaySfxThrottled(1, hang->podiumCharacters[0], 0xf, NULL);
            swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_PODIUM_LINE_PLAYED);
        }
    } else {
        volume = 0.75f;
    }
    playASound(5, 6, 0.25f, volume, 1);

    rdVector_Set3(&pose.translation, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&pose.yaw_roll_pitch, 0.0f, 0.0f, 0.0f);

    switch (swrObjHang_planetIntroStep) {
    case 0:
        if (swrObjHang_planetIntroTimer < 32.0f) {
            swrObjHang_holoCameraMatrixTarget.vD.z -= -125.0f;
            swrObjHang_planetIntroStep++;
            swrObjHang_cameraMatrixTarget.vD.z -= -150.0f;
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    case 1:
        if (swrObjHang_planetIntroTimer < 30.0f) {
            swrObjHang_planetIntroStep++;
            rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 0.0f, 0.0f, 25.0f);
            rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, -500.0f, 250.0f, 150.0f);
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    case 2:
        if (swrObjHang_planetIntroTimer < 23.0f) {
            swrObjHang_planetIntroStep++;
            rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, -500.0f, -200.0f, 50.0f);
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    case 3:
        if (swrObjHang_planetIntroTimer < 20.0f) {
            swrObjHang_planetIntroStep++;
            rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 0.0f, -150.0f, -25.0f);
            rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, 800.0f, -400.0f, 0.0f);
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    case 4:
        if (swrObjHang_planetIntroTimer < 14.0f) {
            swrObjHang_planetIntroStep++;
            rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 0.0f, 150.0f, -50.0f);
            rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, 100.0f, 300.0f, -25.0f);
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    case 5:
        if (swrObjHang_planetIntroTimer < 9.0f) {
            swrObjHang_planetIntroStep++;
            rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 0.0f, 0.0f, 25.0f);
            rdVector_Set3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, -5000.0f, -2000.0f, 1000.0f);
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 1, 0, 1);
        }
        break;
    default:
        break;
    }

    if (swrObjHang_planetIntroTimer >= 0.0f) {
        swrObjHang_planetIntroTimer -= swrRace_fdeltaTimeSecs;
        if (swrObjHang_planetIntroTimer <= 0.0f) {
            swrObjHang_fadeState = -1;
            if (swrRace_creditsMode == 0)
                swrObjHang_state2 = swrObjHang_STATE_SELECT_PLANET;
        }
    }

    node = (swrModel_NodeTransformed*)swr_sceneModels[INGAME_MODELID_loc_awards_part]->entries[0].node;
    if (node != NULL) {
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        rdMatrix_SetTransform44(&xf, &pose);
        rdMatrix_ScaleBasis44(&xf, 0.4f, 0.4f, 0.4f, &xf);
        swrModel_NodeSetTransform(node, &xf);
        swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
    }

    rdVector_Set3(&pose.yaw_roll_pitch, -75.0f, 0.0f, 0.0f);
    for (int place = 0; place < 3; place++) {
        swrObjElmo* pilot;
        float angle = swrObjHang_planetIntroOrbitAngle[place] - swrObjHang_planetIntroOrbitSpeed[place] * swrRace_fdeltaTimeSecs * -0.5f;
        swrObjHang_planetIntroOrbitAngle[place] = angle;
        if (angle > 360.0f)
            swrObjHang_planetIntroOrbitAngle[place] = angle - 360.0f;
        stdMath_SinCos(swrObjHang_planetIntroOrbitAngle[place], &bobSin, &bobCos);
        pilot = (swrObjElmo*)swrEvent_GetItem('Elmo', SWR_SCENE_SLOT_PILOT_PUPPETS + place);
        pilot->position.z = (float)place * -50.0f - bobSin * -15.0f;
        swrRace_SetEngineNodeTranslation((void**)pilot->unk30_nodes, &pilot->position);

        // the award platform under the pilot, then the place number
        for (int part = 0; part < 2; part++) {
            int slot = (part == 0 ? SWR_SCENE_SLOT_AWARD_PLATFORMS : INGAME_MODELID_award_first_part) + place;
            node = (swrModel_NodeTransformed*)swr_sceneModels[slot]->entries[0].node;
            if (node == NULL)
                continue;
            swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
            rdMatrix_SetTransform44(&xf, &pose);
            rdMatrix_ScaleBasis44(&xf, 0.1f, 0.1f, 0.1f, &xf);
            rdVector_Copy3((rdVector3*)&xf.vD, &pilot->position);
            swrModel_NodeSetTransform(node, &xf);
            swrModel_NodeModifyFlags(&node->node, 2, 3, 0x10, 2);
        }
    }

    if ((swrControl_menuAcceptPressedEdge != 0 || swrControl_cancelPressedEdge != 0) && swrRace_DebugLevel > 0 && swrUI_DebugColorsEqual_Maybe(swrRace_aProfiles[0].name, swrObjHang_planetIntroSkipInitials) != 0)
        swrObjHang_planetIntroTimer = 0.0f;
}

// 0x0043d4e0
void swrObjHang_UpdateResultsIntro(void)
{
    rdMatrix44 podTransform;
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_resultsIntroTimer = 12.0f;
        swrObjHang_resultsIntroCameraSet = 0;
        rdVector_Set3(&swrObjHang_resultsPodPose.translation, 0.0f, 1200.0f, 50.0f);
        rdVector_Set3(&swrObjHang_resultsPodPose.yaw_roll_pitch, 0.0f, 0.0f, 0.0f);
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PIT_DROIDS], (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        swrObjHang_holoCameraMatrix.vD.z = -97.0f;
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        swrObjHang_cameraMatrix.vD.y += 500.0f;
        playASound(0xa1, 7, 0.25f, 0.8f, 0);
    }

    if (swrObjHang_resultsIntroTimer <= 10.0 && swrObjHang_resultsIntroCameraSet == 0) {
        swrObjHang_resultsIntroCameraSet = 1;
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrixStart.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 0.0f, 0.0f, 0.0f);
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixStart.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        swrObjHang_cameraMatrixTarget.vD.x += 500.0f;
        swrObjHang_cameraMoveMode = 1;
    }

    swrObjHang_resultsPodPose.translation.y -= swrRace_fdeltaTimeSecs * 100.0f;
    swrModel_Header* pod = swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS];
    if (pod != NULL) {
        rdMatrix_SetTransform44(&podTransform, &swrObjHang_resultsPodPose);
        swrRace_AnimateDisplayPod((swrModel_Node**)pod, &podTransform, 0, 70.0f, 70.0f, 70.0f, -157.0f, 1, 0.0f, 0.0f);
        if (pod->entries[0x3b].node != NULL)
            swrModel_NodeModifyFlags(pod->entries[0x3b].node, 2, 3, 0x10, 2);
    }

    if (swrObjHang_fadeState == -1)
        return;
    int expired = 0;
    if (swrObjHang_resultsIntroTimer >= 0.0f) {
        swrObjHang_resultsIntroTimer -= swrRace_fdeltaTimeSecs;
        expired = swrObjHang_resultsIntroTimer <= 0.0f;
    }
    if (!expired) {
        if (swrControl_menuAcceptPressedEdge == 0 && swrControl_cancelPressedEdge == 0)
            return;
        swrObjHang_resultsIntroTimer = 0.0f;
    }
    swrObjHang_fadeState = -1;
    swrObjHang_state2 = swrObjHang_STATE_POST_RACE_INFO;
}

// 0x0043e330
int swrObjHang_FadeOutAndAdvance(swrObjHang* hang)
{
    int done = 0;
    swrObjHang_fadeDone = 0;
    if (swrObjHang_fadeOutAlpha < 255.0f) {
        swrObjHang_fadeOutAlpha += swrRace_fdeltaTimeSecs * 849.99994f;
    } else {
        swrObjHang_fadeOutHoldFrames--;
        done = swrObjHang_fadeOutHoldFrames <= 0;
        swrObjHang_fadeOutAlpha = 255.0f;
    }
    if (swrObjHang_fadeOutAlpha > 255.0f) {
        swrObjHang_fadeOutHoldFrames = 3;
        swrObjHang_fadeOutAlpha = 255.0f;
    }
    swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t)(int)swrObjHang_fadeOutAlpha);
    if (!done)
        return 0;

    swrObjHang_fadeOutAlpha = 0.0f;
    if (swrObjHang_state2 != ~swrObjHang_STATE_LEGAL) {
        if (swrObjHang_state2 == swrObjHang_STATE_SPLASH && hang->menuScreen == swrObjHang_STATE_VEHICLE_SELECT_INTRO) {
            swrObjElmo* elmo = swrEvent_GetItem('Elmo', hang->elmoEntityIndex);
            if (elmo != NULL)
                swrObjElmo_SetAnimState(elmo, 0);
        }
        swrObjHang_fadeState = 1;
        swrObjHang_cameraMoveActive = 0;
        swr_noop2();
        swrSound_ResetRequestedVoices();
        swrRace_SaveCurrentProfile();
        swrObjHang_SetMenuState(hang, swrObjHang_state2);
        return 0;
    }

    swrSprite_SetVisible(-0x67, 0);
    swrObjHang_fadeDone = 1;
    swrObjHang_fadeState = 0;
    swr_noop2();
    swrSound_ResetRequestedVoices();
    swrRace_SaveCurrentProfile();
    return 1;
}

// 0x0043e490
int swrObjHang_FadeScreenFlash_Maybe(void)
{
    int done = 0;
    if (swrObjHang_fadeInAlpha == 255.0f || swrObjHang_fadeInDelayFrames > 0) {
        swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
        swrObjHang_fadeInDelayFrames--;
        if (swrObjHang_fadeInDelayFrames > 0)
            return 0;
    }

    if (swrObjHang_fadeInAlpha > 0.0f) {
        swrObjHang_fadeInAlpha -= swrRace_fdeltaTimeSecs * 849.99994f;
    } else {
        swrObjHang_fadeInHoldFrames--;
        done = swrObjHang_fadeInHoldFrames <= 0;
        swrObjHang_fadeInAlpha = 0.0f;
    }
    if (swrObjHang_fadeInAlpha < 0.0f) {
        swrObjHang_fadeInHoldFrames = 3;
        swrObjHang_fadeInAlpha = 0.0f;
    }
    swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t)(int)swrObjHang_fadeInAlpha);
    if (!done)
        return 0;

    swrSprite_SetVisible(-0x67, 0);
    swrObjHang_fadeInAlpha = 255.0f;
    swrObjHang_fadeInDelayFrames = 3;
    swrObjHang_fadeDone = 1;
    swrObjHang_fadeState = 0;
    return 1;
}

// 0x00457410
void swrObjHang_LoadScreen(swrObjHang* hang, int rosterArg, int noBroadcast)
{
    swrControl_uiInputActive = 1;
    swrControl_ClearDeviceState(1);
    swrControl_StopForceEffect(swrForceEffect_AUTO_CENTER);
    swrUI_ResetProgressBar();
    swrEvent_FreeObjs('Elmo');
    swrUI_UpdateProgressBar(10);
    swrEvent_ClearObjs('Elmo');
    swrUI_UpdateProgressBar(20);
    resetOverlayDrawQueues();
    swrUI_UpdateProgressBar(30);
    swrSprite_SetVisible(-0x67, 0);
    hang->room = HangRoom_None;
    swrSprite_ResetAllSprites();
    swrUI_UpdateProgressBar(40);
    swrModel_ClearLoadedModels();
    swrUI_UpdateProgressBar(50);
    swrViewport_SetRootNodeForAllViewports(NULL);
    // rosterArg is a plain int the original forwards untouched into the roster builders' pointer slot
    swrObjHang_StartRace(hang, (int*)rosterArg, noBroadcast);
    swrUI_UpdateProgressBar(98);

    int message = 'Stop';
    swrEvent_CallF4('Hang', &message);
    message = 'Wake';
    if (hang->unk68_type >= 0) {
        swrEvent_CallF4('Scen', &message);
        return;
    }

    char planet = g_aTrackInfos[hang->track_index].PlanetIdx;
    if ((swrRace_saveData.profiles[0].planetIntrosSeen & (1 << planet)) == 0 && multiplayer_enabled == 0 && swrRace_creditsMode == 0 && hang->demo_mode == 0) {
        // tests save slot 0's mask but records into the live profile
        Window_PlayCinematic(swrObjHang_cinematicFiles[planet]);
        swrRace_aProfiles[0].planetIntrosSeen |= 1 << g_aTrackInfos[hang->track_index].PlanetIdx;
    }
    swrEvent_CallF4('Jdge', &message);
}

// 0x004575a0
void swrObjHang_ShowAllSceneNodes(void)
{
    for (int i = 0; i < SWR_SCENE_MODEL_SLOT_COUNT; i++) {
        if (swr_sceneModels[i] != NULL && swr_sceneModels[i]->entries[0].node != NULL)
            swrModel_NodeModifyFlags(swr_sceneModels[i]->entries[0].node, 2, -4, 0x10, 3);
    }
}

// 0x004575d0
void swrObjHang_ShowPartNodes(swrObjHang* hang)
{
    if (hang->loc_cantina_part_model != NULL)
        swrModel_NodeModifyFlags(hang->loc_cantina_part_model, 2, 3, 0x10, 2);
    if (hang->holo_proj02_part_model != NULL)
        swrModel_NodeModifyFlags(hang->holo_proj02_part_model, 2, 3, 0x10, 2);
    if (swrObjHang_cameraMoveMode == 5)
        swrObjHang_cameraMoveMode = 0;
}

// 0x00457620
void swrObjHang_F0(swrObjHang* hang)
{
    int loadNext = 0;
    if (hang->flag & swrObjHang_FLAG_ACTIVE) {
        swr_noop4();
        if (hang->flag & swrObjHang_FLAG_UNK_2)
            hang->flag &= ~swrObjHang_FLAG_UNK_2;
        hang->unk60 = 0;
        swrObjHang_TickHolotableSpin_Maybe();
        swrControl_uiInputActive = 0;
        swrControl_PlayForceEffect(swrForceEffect_AUTO_CENTER, -1, -1, -1);
        for (int player = 0; player < 4; player++)
            swrUI_UpdatePlayerMenuInput(player);

        if (multiplayer_enabled != 0)
            swrObjHang_skipTournamentIntro = 1;
        if (swrUI_pendingInputDown != 0) {
            swrUI_localPlayersInputDownBitset[0] = swrUI_pendingInputDown;
            swrUI_pendingInputDown = 0;
        }
        if (swrUI_pendingInputPressed != 0) {
            swrUI_localPlayersInputPressedBitset[0] = swrUI_pendingInputPressed;
            swrUI_pendingInputPressed = 0;
        }
        swrRace_menuSpriteCount = 0;
        swrRace_statBarSpriteCount = 0;

        swr_noop4();
        swrObjHang_ShowAllSceneNodes();
        for (int sprite = 0; sprite < SWROBJHANG_MENU_SPRITE_COUNT; sprite++)
            swrSprite_SetVisible(sprite, 0);

        if (swrObjHang_unlockAllCheat != 0 || (swrRace_DebugFlag & swrRace_DEBUGFLAG_UNLOCK_ALL))
            swrRace_CheatUnlockAll();

        swrObjHang_partSpinAngle += swrRace_fdeltaTimeSecs * 40.0f;
        if (swrObjHang_partSpinAngle > 360.0f)
            swrObjHang_partSpinAngle -= 360.0f;

        swr_noop4();
        swrObjHang_menuTextPulsePhase += swrRace_fdeltaTimeSecs;
        while (swrObjHang_menuTextPulsePhase > 1.0f)
            swrObjHang_menuTextPulsePhase -= 1.0f;

        switch (hang->menuScreen) {
        case swrObjHang_STATE_LEGAL:
            swrObjHang_UpdateLegalScreen(hang);
            break;
        case swrObjHang_STATE_SPLASH:
            swrObjHang_UpdateSplashScreen(hang);
            break;
        case swrObjHang_STATE_ENTER_NAME:
            swrObjHang_ShowPartNodes(hang);
            swrObjHang_UpdateEnterName(hang);
            break;
        case swrObjHang_STATE_MAIN_MENU:
            switch (hang->room) {
            case Shop:
                if (hang->loc_wattoo_part_model != NULL)
                    swrModel_NodeModifyFlags(hang->loc_wattoo_part_model, 2, 3, 0x10, 2);
                swrRace_UpdatePartMenuLayout(hang);
                swrRace_UpdateStatPartModels();
                swrObjHang_UpdateMainMenu(hang);
                break;
            case Junkyard:
                if (hang->loc_junkyard_part_model != NULL)
                    swrModel_NodeModifyFlags(hang->loc_junkyard_part_model, 2, 3, 0x10, 2);
                swrRace_UpdateStatPartModels();
                swrObjHang_UpdateMainMenu(hang);
                break;
            case Hangar:
                if (hang->hangar18_part_model != NULL)
                    swrModel_NodeModifyFlags(hang->hangar18_part_model, 2, 3, 0x10, 2);
                swrObjHang_UpdateLookAtVehicle(hang);
                swrObjHang_UpdateMainMenu(hang);
                break;
            case Cantina:
                swrObjHang_ShowPartNodes(hang);
                swrObjHang_UpdateMainMenu(hang);
                break;
            default:
                swrObjHang_UpdateMainMenu(hang);
                break;
            }
            break;
        case swrObjHang_STATE_JUNKYARD:
            if (hang->loc_junkyard_part_model != NULL)
                swrModel_NodeModifyFlags(hang->loc_junkyard_part_model, 2, 3, 0x10, 2);
            swrObjHang_UpdateJunkyard(hang);
            break;
        case swrObjHang_STATE_POST_RACE_INFO:
            swrObjHang_ShowPartNodes(hang);
            swrRace_ResultsMenu(hang);
            break;
        case swrObjHang_STATE_WATTO:
            if (hang->loc_wattoo_part_model != NULL)
                swrModel_NodeModifyFlags(hang->loc_wattoo_part_model, 2, 3, 0x10, 2);
            swrObjHang_UpdateWattoShop(hang);
            break;
        case swrObjHang_STATE_LOOK_AT_VEHICLE:
            if (hang->hangar18_part_model != NULL)
                swrModel_NodeModifyFlags(hang->hangar18_part_model, 2, 3, 0x10, 2);
            swrObjHang_UpdateLookAtVehicle(hang);
            break;
        case swrObjHang_STATE_SELECT_VEHICLE:
            swrObjHang_ShowPartNodes(hang);
            swrRace_SelectVehicle(hang);
            break;
        case swrObjHang_STATE_SELECT_PLANET:
            swrObjHang_ShowPartNodes(hang);
            swrRace_CourseSelectionMenu();
            break;
        case swrObjHang_STATE_SELECT_TRACK:
            swrObjHang_ShowPartNodes(hang);
            swrRace_CourseInfoMenu(hang);
            break;
        case swrObjHang_STATE_LOAD_SCREEN:
            swrObjHang_UpdateLoadScreen(hang);
            return;
        case swrObjHang_STATE_TAUNT_SCENE:
            if (hang->hangar18_part_model != NULL)
                swrModel_NodeModifyFlags(hang->hangar18_part_model, 2, 3, 0x10, 2);
            swrObjHang_UpdateTauntScene(hang);
            break;
        case swrObjHang_STATE_PLANET_SELECT_INTRO:
            swrObjHang_UpdatePlanetSelectIntro(hang);
            break;
        case swrObjHang_STATE_RESULTS_INTRO:
            if (hang->hangar18_part_model != NULL)
                swrModel_NodeModifyFlags(hang->hangar18_part_model, 2, 3, 0x10, 2);
            swrObjHang_UpdateResultsIntro();
            break;
        case swrObjHang_STATE_VEHICLE_SELECT_INTRO:
            swrObjHang_ShowPartNodes(hang);
            swrObjHang_UpdateVehicleSelectIntro(hang);
            break;
        default:
            break;
        }

        swr_noop4();
        // scene slot 2, header entry 2 stays hidden in the hangar
        if (hang->room == Hangar && swr_sceneModels[2]->entries[2].node != NULL)
            swrModel_NodeModifyFlags(swr_sceneModels[2]->entries[2].node, 2, -4, 0x10, 3);

        swr_noop4();
        if (swrObjHang_fadeState == 1 && swrObjHang_FadeScreenFlash_Maybe() != 0)
            swrSound_SetSfxFlag(0, 0x10);

        swr_noop4();
        if (swrObjHang_fadeState == -1) {
            swrSound_ClearSfxFlag(0, 0x10);
            loadNext = swrObjHang_FadeOutAndAdvance(hang);
        }

        swr_noop4();
        if (swrObjHang_screenTransitionDir == 0) {
            switch (swrObjHang_cameraMoveMode) {
            case 1:
            case 2:
                swrObjHang_UpdateHoloCamera(hang);
                break;
            case 3:
                swrObjHang_LerpHoloCamera(hang);
                break;
            case 5:
                swrObjHang_UpdateIdleCamera(hang);
                break;
            default:
                break;
            }
        }

        swr_noop4();
        swrObjHang_TickMenuRepeatDelay_Maybe();
        if (hang->room == Cantina) {
            swrObjHang_UpdateCantinaHolotable(hang->menuScreen);
            if (swrRace_Transition > 0.0f && hang->menuScreen != swrObjHang_STATE_SPLASH)
                playUISound(0x4f);
        }
    }

    if (loadNext != 0)
        swrObjHang_LoadScreen(hang, 1, 0);
    swr_noop4();
}

// 0x00457b00
void swrObjHang_F2(swrObjHang* hang)
{
    if ((hang->flag & swrObjHang_FLAG_ACTIVE) == 0)
        return;

    if (swrObjHang_inspectCameraTimer >= 5.0f && hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE)
        swrObjHang_CycleInspectCamera(hang);

    if (swrObjHang_lookAtMenuFade > 0.0 && hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
        swrObjHang_UpdateHoloCameraTarget(hang, hang->cameraState);
        if (hang->activeMenu == 1)
            swrRace_DrawUpgradesPanel(hang);
    }

    if (hang->elmoEntityIndex != -1)
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[hang->elmoEntityIndex], &hang->elmoFocusPosition);
}

// 0x00457b90
void swrObjHang_F3(swrObjHang* hang)
{
    swrViewport_Get(1);
    if ((hang->flag & swrObjHang_FLAG_ACTIVE) == 0)
        return;

    swrRender_frameClearFlags |= swrRender_FRAME_CLEAR_COLOR;
    SetClearColor(0, 0, 0);
    if (hang->unk60)
        swrObjHang_UpdateLookAtVehicle(hang);
}

// 0x00457bd0
void swrObjHang_LoadAllPilotSprites(void)
{
    swrSpriteTexture* tex;
    swrRacerData* data;
    short id;

    id = 0;
    data = (swrRacerData*)&swrRacer_PodData[0].pilot_spriteId;
    do {
        tex = swrSprite_LoadTexture_(data->id);
        swrSprite_NewSprite(id, tex);
        swrSprite_NewSprite(id + 0x17, tex);
        swrSprite_NewSprite(id + 0x2e, tex);
        id = id + 1;
        data = data + 1;
    } while (id < 0x17);
}

// 0x00433760
void swrObjHang_EnterMultiplayerMenu_Maybe(void)
{
    if (multiplayer_enabled != 0) {
        swrUI_RunCallbacks2(swrUI_GetById(NULL, swrUI_WINDOW_MP_RACE_SETUP), 0);
        swrUI_PushMenuPage(swrUI_WINDOW_MP_RACER_LIST);
        swrUI_RunCallbacks2(swrUI_GetById(NULL, swrUI_WINDOW_MP_RACER_LIST), 0);
        swrMain_raceActiveForUi = 0;
    }
    swrObjHang_state2 = ~swrObjHang_STATE_LEGAL;
    swrObjHang_fadeState = -1;
}

// N64 boot legal/logo sequence, unreachable on PC: nothing enters swrObjHang_STATE_LEGAL, and
// swrObjHang_F4's 'Strt' path does this sequence's exit (black overlay, fadeState 1, state 14) directly.
// 0x00434ec0
void swrObjHang_UpdateLegalScreen(swrObjHang* hang)
{
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_legalPage++;
        if (swrObjHang_legalPage == 2) {
            playASound(0x74, 6, 0.25f, 0.5f, 0);
            time_ms_unk = 2.5f;
        }
        swrObjHang_legalFadeAlpha = 255.0f;
    }
    hang->unk68_type = 0x15;
    swrObjHang_state2 = swrObjHang_STATE_LOAD_SCREEN;

    if (swrObjHang_legalPage == 0) {
        if (swrObjHang_legalDelayFrames > 0) {
            swrObjHang_legalDelayFrames--;
        } else {
            swrText_CreateColorlessEntry1(0x1e, 0x1e, swrText_Translate(g_pTxtLegalTitle));
            swrText_CreateColorlessEntry1(0x1e, 0x32, swrText_Translate(g_pTxtLegalLucasArts));
            swrText_CreateColorlessEntry1(0x1e, 0x3c, swrText_Translate(g_pTxtLegalLucasfilm));
            swrText_CreateColorlessEntry1(0x1e, 0x46, swrText_Translate(g_pTxtLegalAuthorization));
            swrText_CreateColorlessEntry1(0x1e, 0x5a, swrText_Translate(g_pTxtLegalLogo1));
            swrText_CreateColorlessEntry1(0x1e, 0x64, swrText_Translate(g_pTxtLegalLogo2));
            swrText_CreateColorlessEntry1(0x1e, 0x6e, swrText_Translate(g_pTxtLegalLogo3));
            swrText_CreateColorlessEntry1(0x1e, 0x82, swrText_Translate(g_pTxtLegalNintendo));
            swrText_CreateColorlessEntry1(0x1e, 0xb4, swrText_Translate(g_pTxtLegalExpansionPak));
            swrSprite_SetPos(0x52, 0xb4, 100);
            swrSprite_SetDim(0x52, 1.0f, 1.0f);
            swrSprite_SetVisible(0x52, 1);
        }
    } else if (swrObjHang_legalPage == 1) {
        swrSprite_SetPos(0x50, 0x57, 0x2e);
        swrSprite_SetDim(0x50, 1.0f, 1.0f);
        swrSprite_SetVisible(0x50, 1);
    } else if (swrObjHang_legalPage == 2) {
        if (swrObjHang_fadeState != 1 || swrObjHang_legalFadingOut != 0) {
            swrObjHang_legalFadeAlpha = swrObjHang_legalFadeAlpha - swrRace_fdeltaTimeSecs * 255.0f;
            if (swrObjHang_legalFadeAlpha < 0.0f) {
                swrObjHang_legalFadeAlpha = 0.0f;
                if (swrObjHang_legalFadingOut != 0) {
                    swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
                    swrObjHang_SetMenuState(hang, swrObjHang_state2);
                    return;
                }
            }
        }
        swrSprite_SetPos(0x56, 0x34, 0);
        swrSprite_SetDim(0x56, 1.0f, 1.0f);
        if (swrObjHang_legalFadingOut == 0)
            swrSprite_SetVisible(0x56, 1);
        swrSprite_SetColor(0x56, 0xff, 0xff, 0xff, (uint8_t)(int)swrObjHang_legalFadeAlpha);
        if (swrObjHang_fadeState != 1) {
            swrSprite_SetPos(0x55, 0x52, 0xf);
            swrSprite_SetDim(0x55, 1.0f, 1.0f);
            swrSprite_SetVisible(0x55, 1);
            swrSprite_SetColor(0x55, 0xff, 0xff, 0xff, swrObjHang_legalFadingOut != 0 ? (uint8_t)(int)swrObjHang_legalFadeAlpha : 0xff);
        }
    }

    if (swrObjHang_fadeState == 0 && 0.0f < time_ms_unk)
        time_ms_unk = time_ms_unk - swrRace_fdeltaTimeSecs;
    if (time_ms_unk <= 0.0f) {
        time_ms_unk = 1.3f;
        if (swrObjHang_legalPage < 2) {
            swrObjHang_fadeState = -1;
            return;
        }
        swrObjHang_legalFadingOut = 1;
        swrObjHang_legalFadeAlpha = 255.0f;
    }
}

// 0x00433720
void swrObjHang_OnSelectVehicle_Maybe(void)
{
    swrObjHang_SetMenuState(g_objHang2, swrObjHang_STATE_SELECT_VEHICLE);
    swrControl_menuAcceptGuard = 1;
}

// 0x00433740
void swrObjHang_OnSelectPlanet_Maybe(void)
{
    swrObjHang_SetUnused();
    swrObjHang_SetMenuState(g_objHang2, swrObjHang_STATE_SELECT_PLANET);
}

// 0x004337d0
void swrObjHang_SetState5_Maybe(void)
{
    swrObjHang_displayPodResetFrames = SWR_DISPLAY_POD_RESET_FRAMES;
}

// Bob a display-pod part along its up axis and roll it about its forward axis.
static void displayPodWobble(rdMatrix44* m, float bob, float angle)
{
    rdVector3 axis;
    rdVector_Scale3Add3((rdVector3*)&m->vD, (rdVector3*)&m->vD, bob, (rdVector3*)&m->vC);
    rdVector_Copy3(&axis, (rdVector3*)&m->vB);
    rdVector_Normalize3Acc(&axis);
    rdMatrix_AddRotationFromVectorAngle44Before(m, angle, axis.x, axis.y, axis.z, m);
}

// Flatten a part's shadow quad onto the floor below the part.
static void displayPodShadow(swrModel_Node* shadow, rdMatrix44* m, float scaleX, float scaleY, float scaleZ, float floorZ)
{
    rdVector3 pos;
    rdVector_Copy3(&pos, (rdVector3*)&m->vD);
    rdMatrix_SetDiagonal44(m, scaleX, scaleY, scaleZ);
    rdVector_Copy3((rdVector3*)&m->vD, &pos);
    m->vD.z = floorZ;
    rdMatrix_ScaleBasis44(m, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, m);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)shadow, m);
    swrModel_NodeModifyFlags(shadow, 2, 3, 0x10, 2);
}

// Stretch one cockpit->engine cable between the two anchors (X mirrored for the left side).
static void displayPodCable(swrModel_Node** nodes, int cable, int engine, int mirror, const swrRacerVisualData* visual, float scaleX, float scaleZ, int animated)
{
    rdMatrix44 cockpitMat;
    rdMatrix44 engineMat;
    rdMatrix44 cableMat;
    rdVector3 cockpitEnd;
    rdVector3 engineEnd;
    rdVector3 anchor;
    rdVector3 dir;
    rdVector3 zero0;
    rdVector3 zero1;

    swrModel_NodeGetTransform((swrModel_NodeTransformed*)nodes[5], &cockpitMat);
    rdVector_Copy3(&cockpitEnd, (rdVector3*)&cockpitMat.vD);
    swrModel_NodeGetTransform((swrModel_NodeTransformed*)nodes[engine], &engineMat);
    rdVector_Copy3(&engineEnd, (rdVector3*)&engineMat.vD);
    rdVector_Copy3(&anchor, &visual->cableCockpitAnchor);
    if (mirror)
        anchor.x = -anchor.x;
    rdMatrix_Multiply3(&anchor, &anchor, &cockpitMat);
    rdVector_Add3(&cockpitEnd, &anchor, &cockpitEnd);
    rdVector_Copy3(&anchor, &visual->cableEngineAnchor);
    if (mirror)
        anchor.x = -anchor.x;
    rdMatrix_Multiply3(&anchor, &anchor, &engineMat);
    rdVector_Add3(&engineEnd, &anchor, &engineEnd);
    rdVector_Sub3(&dir, &cockpitEnd, &engineEnd);
    float length = rdVector_Len3(&dir);
    rdVector_Normalize3Acc(&dir);

    rdMatrix_SetTranslation44(&cableMat, cockpitEnd.x, cockpitEnd.y, cockpitEnd.z);
    rdVector_Copy3((rdVector3*)&cableMat.vB, &dir);
    rdVector_Set3((rdVector3*)&cableMat.vC, 0.0f, 0.0f, 1.0f);
    rdVector_Cross3((rdVector3*)&cableMat.vA, (rdVector3*)&cableMat.vB, (rdVector3*)&cableMat.vC);
    rdVector_Cross3((rdVector3*)&cableMat.vC, (rdVector3*)&cableMat.vA, (rdVector3*)&cableMat.vB);
    rdMatrix_ScaleBasis44(&cableMat, scaleX * SWR_POD_MODEL_UNIT_SCALE, length * 0.01f, scaleZ * SWR_POD_MODEL_UNIT_SCALE, &cableMat);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[cable], &cableMat);
    if (swrObjHang_displayPodResetFrames > 0) {
        rdVector_Set3(&zero0, 0.0f, 0.0f, 0.0f);
        rdVector_Set3(&zero1, 0.0f, 0.0f, 0.0f);
        float amplitude = 1.3f;
        if (animated == 0)
            amplitude = 0.5f;
        swrModel_DeformPoddConnectionMesh(nodes[cable], &zero0, &zero1, amplitude, 1.0f, 0.0f, 50.0f, 0);
    }
    if (nodes[cable] != NULL)
        swrModel_NodeModifyFlags(nodes[cable], 2, 3, 0x10, 2);
}

// 0x004337e0
void swrRace_AnimateDisplayPod(swrModel_Node** nodes, rdMatrix44* transform, int useRacerScale, float scaleX, float scaleY, float scaleZ, float floorZ, int animated, float exhaustLeft, float exhaustRight)
{
    float sinPhase[8];
    float cosPhase[8];
    rdMatrix44 base;
    rdMatrix44 m;
    rdVector3 offset;
    rdVector3 rotated;

    if (nodes == NULL)
        return;
    int pilot = (int)nodes[0x3c];
    const swrRacerVisualData* visual = &swrRacer_PodVisualData[pilot];
    if (animated != 0) {
        for (unsigned int i = 0; i < 8; i++)
            stdMath_SinCos((float)(((int)i * 0.01 + 0.1) * timetotal * 360.0), &sinPhase[i], &cosPhase[i]);
    }
    if (useRacerScale != 0) {
        float racerScale = *(float*)swrRacer_PodData[pilot].unk1c;
        if (racerScale < 0.3 || racerScale > 5.0f)
            racerScale = 1.0f;
        scaleX = racerScale * scaleX;
        scaleY = racerScale * scaleY;
        scaleZ = racerScale * scaleZ;
    }
    swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)nodes[5], poddLodDistances1);
    swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)nodes[1], poddLodDistances2);
    swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)nodes[2], poddLodDistances2);
    swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)nodes[3], poddLodDistances2);
    swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)nodes[4], poddLodDistances2);
    // mirrored parts: flip the culling winding
    if (nodes[0x3e] != NULL)
        nodes[0x3e]->flags_5 |= 1;
    if (nodes[2] != NULL)
        nodes[2]->flags_5 |= 1;
    if (nodes[4] != NULL)
        nodes[4]->flags_5 |= 1;
    rdMatrix_Copy44(&base, transform);
    rdMatrix_ScaleBasis44(&base, scaleX, scaleY, scaleZ, &base);
    swrModel_NodeSelector* lodSwitch = (swrModel_NodeSelector*)nodes[0];
    if (lodSwitch != NULL) {
        swrModel_NodeSetSelectedChildNode(lodSwitch, 0);
        swrModel_NodeModifyFlags((swrModel_Node*)lodSwitch, 2, 3, 0x10, 2);
    }

    if ((swrRace_DebugFlag & 0x80) != 0 && (inRaceLocalPlayerInputBitset3[1] & 0x400) != 0) {
        if (lodSwitch != NULL) {
            swrModel_NodeSetSelectedChildNode(lodSwitch, 1);
            swrModel_NodeModifyFlags((swrModel_Node*)lodSwitch, 2, 3, 0x10, 2);
        }
        swrModel_Node* debugModel = nodes[0x4a];
        if (debugModel == NULL)
            return;
        rdMatrix_Copy44(&m, &base);
        rdMatrix_ScaleBasis44(&m, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, SWR_POD_MODEL_UNIT_SCALE, &m);
        if (animated != 0)
            rdVector_Scale3Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, sinPhase[3] * 0.2f, (rdVector3*)&m.vC);
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)debugModel, &m);
        swrModel_NodeModifyFlags(debugModel, 2, 3, 0x10, 2);
        return;
    }

    if (nodes[1] != NULL) {
        rdMatrix_Copy44(&m, &base);
        rdVector_Copy3(&offset, &visual->hoverPadOffsetB);
        rdMatrix_Multiply3(&rotated, &offset, &m);
        rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &rotated);
        if (animated != 0)
            displayPodWobble(&m, sinPhase[3] * 0.2f, sinPhase[1] * 5.0f);
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[1], &m);
        swrModel_NodeModifyFlags(nodes[1], 2, 3, 0x10, 2);
        if (nodes[3] != NULL) {
            rdVector_Copy3(&offset, &swrRace_secondEngineOffset);
            rdMatrix_Multiply3(&rotated, &offset, &base);
            rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &rotated);
            if (animated != 0)
                displayPodWobble(&m, sinPhase[3] * 0.2f, sinPhase[1] * 5.0f);
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[3], &m);
            swrModel_NodeModifyFlags(nodes[3], 2, 3, 0x10, 2);
        }
        if (nodes[0x3e] != NULL)
            displayPodShadow(nodes[0x3e], &m, scaleX, scaleY, scaleZ, floorZ);
    }

    if (nodes[2] != NULL) {
        rdMatrix_Copy44(&m, &base);
        rdVector_Copy3(&offset, &visual->hoverPadOffsetB);
        offset.x = -offset.x;
        rdMatrix_Multiply3(&rotated, &offset, &m);
        rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &rotated);
        if (animated != 0)
            displayPodWobble(&m, sinPhase[4] * 0.2f, sinPhase[2] * 5.0f);
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[2], &m);
        swrModel_NodeModifyFlags(nodes[2], 2, 3, 0x10, 2);
        if (nodes[4] != NULL) {
            rdVector_Copy3(&offset, &swrRace_secondEngineOffset);
            offset.x = -offset.x;
            rdMatrix_Multiply3(&rotated, &offset, &base);
            rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &rotated);
            if (animated != 0)
                displayPodWobble(&m, sinPhase[2] * 0.2f, sinPhase[0] * 5.0f);
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[4], &m);
            swrModel_NodeModifyFlags(nodes[4], 2, 3, 0x10, 2);
        }
        if (nodes[0x3f] != NULL)
            displayPodShadow(nodes[0x3f], &m, scaleX, scaleY, scaleZ, floorZ);
    }

    if (nodes[5] != NULL) {
        rdMatrix_Copy44(&m, &base);
        rdVector_Copy3(&offset, &visual->hoverPadOffsetA);
        rdMatrix_Multiply3(&rotated, &offset, &m);
        rdVector_Add3((rdVector3*)&m.vD, (rdVector3*)&m.vD, &rotated);
        if (animated != 0) {
            m.vD.z = (float)(swrRacer_PodData[pilot].unk24[0] * 10) + scaleZ * 1.5f + floorZ;
            displayPodWobble(&m, sinPhase[5] * 0.1f, sinPhase[1] * 10.0f);
        }
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[5], &m);
        swrModel_NodeModifyFlags(nodes[5], 2, 3, 0x10, 2);
        if (offset.y == 0.0f) {
            // no cockpit offset: the engines ride on the cockpit transform
            if (nodes[1] != NULL)
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[1], &m);
            if (nodes[2] != NULL)
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)nodes[2], &m);
        }
        if (nodes[0x40] != NULL)
            displayPodShadow(nodes[0x40], &m, scaleX, scaleY, scaleZ, floorZ);
    }

    swrRace_UpdateEngineExhaust(NULL, nodes, exhaustLeft, exhaustRight);
    for (int i = 6; i <= 0xd; i++) {
        if (nodes[i] != NULL)
            swrModel_NodeModifyFlags(nodes[i], 2, -4, 0x10, 3);
    }
    if (swrObjHang_displayPodResetFrames > 0)
        swrObjHang_displayPodResetFrames--;
    if (nodes[0xa] != NULL)
        displayPodCable(nodes, 0xa, 1, 0, visual, scaleX, scaleZ, animated);
    if (nodes[0xb] != NULL)
        displayPodCable(nodes, 0xb, 2, 1, visual, scaleX, scaleZ, animated);
    if (nodes[0xc] != NULL)
        displayPodCable(nodes, 0xc, 3, 0, visual, scaleX, scaleZ, animated);
    if (nodes[0xd] != NULL)
        displayPodCable(nodes, 0xd, 4, 1, visual, scaleX, scaleZ, animated);
    if (swrObjHang_displayPodResetFrames == 4)
        ComputeModelViewBounds();
    if (nodes[0x3b] != NULL)
        swrModel_NodeModifyFlags(nodes[0x3b], 2, -4, 0x10, 3);
    if ((swrRace_DebugFlag & 0x80) != 0 && (inRaceLocalPlayerInputBitset3[1] & 0x1000) != 0 && nodes[0x3b] != NULL)
        swrModel_NodeModifyFlags(nodes[0x3b], 2, 3, 0x10, 2);
}

// 0x0043da90
int swrObjHang_UpdateScreenTransition(swrObjHang* hang, int startSlide, int targetOffset)
{
    int done;
    int advance;
    float offset;

    advance = 1;
    if (startSlide != 0) {
        if (hang->menuScreen == swrObjHang_STATE_WATTO || hang->menuScreen == swrObjHang_STATE_JUNKYARD)
            return 0;
        swrObjHang_screenSlideOffset = -300.0f;
        swrObjHang_screenTransitionDir = 1;
        swrObjHang_state2 = ~swrObjHang_STATE_LEGAL;
        advance = 0;
    }
    if (swrObjHang_screenTransitionDir == 0 || !advance)
        return 0;

    done = 0;
    offset = swrObjHang_screenSlideOffset - (float)swrObjHang_screenTransitionDir * swrRace_fdeltaTimeSecs * -300.0f * 4.0;
    swrObjHang_screenSlideOffset = offset;
    if (offset <= -300.0f) {
        swrObjHang_screenSlideOffset = -300.0f;
        done = 1;
    }
    if ((float)targetOffset <= swrObjHang_screenSlideOffset) {
        swrObjHang_screenSlideOffset = (float)targetOffset;
        done = 1;
    }
    if (done) {
        swrObjHang_screenTransitionDir = 0;
        if (swrObjHang_state2 != ~swrObjHang_STATE_LEGAL && swrObjHang_fadeState == 0 && swrObjHang_cameraMoveMode == 0) {
            swrObjHang_SetMenuState(hang, swrObjHang_state2);
            return 1;
        }
    }
    return 0;
}

// 0x0045b210
void swrObjHang_AssignRacerCameras(swrObjHang* hang)
{
    int camId = 0;
    for (int i = 0; i < hang->num_players; i++) {
        swrScore* score = &swrScores[i];
        if (score->identifier == 'Locl' || (score->flag & 0x20) != 0) {
            int subEvents[3];
            subEvents[0] = 'NAsn';
            subEvents[1] = camId + 1;
            subEvents[2] = (int)score->obj_test_ptr;
            swrEvent_DispatchSubEvents(swrEvent_FindObjectById('cMan', camId), subEvents);
            camId++;
        }
    }
}

// 0x0045b290
void swrObjHang_StartRace(swrObjHang* hang, int* rosterArg, int noBroadcast)
{
    // 'Begn' payload; field order matches the reads in swrObjJdge_F4 / the Scen handler.
    struct
    {
        int event;
        void* roster; // Scen path: hang->unk68_type
        int numRacers;
        int planetIdx;
        int trackModelId;
        int splineId;
        int camSplineId;
        int planetTrackNumber;
        int countdown;
        int numLaps;
        float recordLapTime;
        float record3LapTime;
        int aiSpeed;
        int mirror;
        int recordPilot;
    } begin;
    TrackInfo* track;
    int record;

    swrObjHang_ResetCameraAssignments_Maybe();
    swrObjHang_InitCameraAssignments(hang);
    swrUI_UpdateProgressBar(60);

    if (hang->demo_mode == 2) {
        hang->num_local_players = 1;
        hang->num_players = 3;
        do {
            do {
                hang->track_index = (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)ELFSAVE_NB_TRACKS);
            } while (hang->track_index == swrRace_TRACK_VENGEANCE);
        } while (g_aTrackInfos[hang->track_index].trackID == -1 || g_aTrackInfos[hang->track_index].planetTrackNumber != 0);
    }
    if (swrRace_creditsMode != 0) {
        if (hang->flag & swrObjHang_FLAG_CREDITS_PLAYLIST)
            hang->track_index = swrObjHang_creditsTracks[swrObjHang_creditsTrackCursor];
        hang->demo_mode = 1;
        swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_RACE_STARTED;
    }
    if (swrMultiplayer_IsMultiplayerEnabled()) {
        swrMultiplayer_SetRacerListDisplay(1, 10, 120);
        hang->isTournamentMode = 0;
        hang->num_local_players = (char)swrMultiplayer_GetActivePlayerCount();
        hang->num_players = (char)swrMultiplayer_GetActivePlayerCount() + (char)multiplayer_numAiRacers;
        hang->track_index = (char)multiplayer_track_select;
        hang->numLaps = (char)multiplayer_laps;
    }
    // faithful: the credits override runs twice
    if (swrRace_creditsMode != 0) {
        hang->demo_mode = 1;
        hang->track_index = swrObjHang_creditsTracks[swrObjHang_creditsTrackCursor];
        swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_RACE_STARTED;
    }
    swrUI_UpdateProgressBar(70);

    if (swrMultiplayer_IsMultiplayerEnabled())
        begin.roster = swrObjHang_BuildRosterMultiplayer(hang, rosterArg);
    else
        begin.roster = swrObjHang_BuildRosterSinglePlayer(hang, rosterArg);

    begin.numRacers = hang->num_players;
    if (hang->demo_mode == 2)
        begin.numRacers = 3;
    else if (swrRace_creditsMode != 0)
        begin.numRacers = 2;

    track = &g_aTrackInfos[hang->track_index];
    begin.camSplineId = -1;
    begin.countdown = 0;
    begin.planetIdx = (char)track->PlanetIdx;
    begin.trackModelId = track->trackID;
    begin.splineId = track->splineID;
    begin.planetTrackNumber = (char)track->planetTrackNumber;
    if (hang->demo_mode == 2)
        begin.countdown = 30;
    else if (swrRace_creditsMode != 0)
        begin.countdown = 1000000;

    begin.numLaps = hang->numLaps;
    if (hang->isTournamentMode)
        begin.numLaps = 3;
    record = hang->track_index * 2 + hang->bMirror;
    begin.recordLapTime = swrRace_saveData.recordLapTimes[record];
    begin.record3LapTime = swrRace_saveData.record3LapTimes[record];
    begin.aiSpeed = hang->AISpeed - 2;
    if (hang->isTournamentMode)
        begin.aiSpeed = 0;
    begin.mirror = hang->bMirror;
    begin.recordPilot = swrRace_saveData.record3LapPilots[record];

    if (begin.trackModelId == -1 || begin.splineId == -1) {
        track = &g_aTrackInfos[swrRace_TRACK_MON_GAZZA_SPEEDWAY];
        begin.planetIdx = (char)track->PlanetIdx;
        begin.trackModelId = track->trackID;
        begin.splineId = track->splineID;
        begin.planetTrackNumber = (char)track->planetTrackNumber;
    }

    if (noBroadcast == 0 && swrMultiplayer_IsMultiplayerEnabled() && hang->demo_mode != 2 && swrMultiplayer_IsHost())
        swrMultiplayer_BroadcastRoster((int)hang, &begin);

    swrUI_UpdateProgressBar(80);
    swrMultiplayer_SetNetworkTick(1);
    begin.event = 'Begn';
    swrUI_UpdateProgressBar(90);

    if (hang->unk68_type < 0) {
        // EXE calls the 0x4269b0 thunk, which drops its arg
        swrSound_ResetRequestedVoices();
        swrEvent_CallF4('Jdge', &begin);
        swrObjHang_AssignRacerCameras(hang);
        return;
    }
    swrAssetBuffer_ResetToIndex(1);
    swrEvent_AllocateAndLoadObjs('Scen', 1);
    begin.roster = (void*)hang->unk68_type;
    swrEvent_CallF4('Scen', &begin);
}

// 0x0045b5d0
void swrObjHang_InitCameraAssignments(swrObjHang* hang)
{
    char numLocal = hang->num_local_players;
    for (int i = 0; i < 4; i++)
        swrObjHang_localCameraSlots[i] = -1;
    for (int i = 0; i < numLocal; i++)
        swrObjHang_localCameraSlots[i] = i;
}

// Shared tail of both roster builders: mark the racer slot FindPlayerRacerSlot picks.
static void swrObjHang_MarkPlayerRacerSlot(swrObjHang* hang)
{
    int playerSlot = swrObjHang_FindPlayerRacerSlot(hang);
    for (int i = 0; i < hang->num_players; i++) {
        if (i == playerSlot)
            swrScores[i].flag |= 0x20;
        else
            swrScores[i].flag &= ~0x20;
    }
}

// Common per-slot score header written by both roster builders.
static void swrObjHang_InitRosterScore(swrScore* score, int slot, int identifier, swrSaveProfile* profile, int pilot)
{
    *(int*)&score->time_unk = slot;
    score->identifier = identifier;
    ((char*)&score->sfxChannel)[0] = 0;
    ((char*)&score->sfxChannel)[1] = 0;
    score->localPlayerProfile = profile;
    score->unk14 = slot;
    score->pilotId = (int*)&swrRacer_PodData[pilot];
}

// EXE also copies the slot indices into a dead local int[20]; `out` is only NULL-checked.
// 0x0045b610
void* swrObjHang_BuildRosterMultiplayer(swrObjHang* hang, int* out)
{
    char* slotPilots = &hang->vehiclePlayer; // vehicleOpponent[] follows it directly

    if (out == NULL)
        return swrScores;

    for (int i = 0; i < SWR_MAX_RACERS; i++)
        swrScores[i].identifier = 0;

    for (int i = 0; i < hang->num_players; i++) {
        swrScore* score = &swrScores[i];
        int identifier;
        swrSaveProfile* profile;

        slotPilots[i] = (char)swrMultiplayer_GetRacerId(i);
        if (!swrMultiplayer_IsHost()) {
            identifier = i == playerNumber ? 'Locl' : 'REMO';
            profile = i == playerNumber ? &swrRace_aProfiles[i] : NULL;
        } else if (i == playerNumber) {
            identifier = 'Locl';
            profile = &swrRace_aProfiles[i];
            swrMultiplayer_SetRosterEntry(i, identifier);
        } else {
            identifier = swrMultiplayer_IsPlayerActive(i) ? 'REMO' : 'AAII';
            profile = NULL;
            swrMultiplayer_SetRosterEntry(i, identifier);
        }
        swrObjHang_InitRosterScore(score, i, identifier, profile, slotPilots[i]);
        score->podStats = swrRacer_PodHandlingData[(int)slotPilots[i]];
    }

    swrObjHang_MarkPlayerRacerSlot(hang);
    swrUI_RefreshRoot();
    return swrScores;
}

// EXE also copies the slot indices into a dead local int[20]; `out` is only NULL-checked.
// 0x0045b7d0
void* swrObjHang_BuildRosterSinglePlayer(swrObjHang* hang, int* out)
{
    char* slotPilots = &hang->vehiclePlayer; // vehicleOpponent[] follows it directly
    // faithful: the 28-bit base mask already allows every pilot
    uint32_t allowedPilots = 0xfffffff;

    if (out == NULL)
        return swrScores;

    for (int i = 0; i < hang->num_local_players; i++)
        allowedPilots |= swrRace_aProfiles[i].pilotsUnlocked;
    if (hang->demo_mode == 2)
        hang->vehiclePlayer = (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)SWR_PILOT_COUNT);
    hang->num_local_players = 1;

    // draw distinct opponents; slot 1 gets the track's favorite pilot unless the player took it
    for (int i = 1; i < hang->num_players;) {
        int retry = 0;
        slotPilots[i] = (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)SWR_PILOT_COUNT);
        if (i == 1 && slotPilots[0] != g_aTrackInfos[hang->track_index].FavoritePilot) {
            slotPilots[1] = g_aTrackInfos[hang->track_index].FavoritePilot;
        } else {
            for (int j = 0; j < i; j++) {
                if (slotPilots[i] == slotPilots[j])
                    retry = 1;
                if (((1u << (slotPilots[i] & 0x1f)) & allowedPilots) == 0)
                    retry = 1;
            }
        }
        if (!retry)
            i++;
    }

    for (int i = 0; i < hang->num_players; i++) {
        swrScore* score = &swrScores[i];
        int pilot = slotPilots[i];
        int identifier = i < hang->num_local_players ? 'Locl' : 'AAII';
        if (hang->demo_mode != 0)
            identifier = 'AAII';
        swrObjHang_InitRosterScore(score, i, identifier, identifier == 'Locl' ? &swrRace_aProfiles[i] : NULL, pilot);

        if (identifier == 'AAII') {
            score->podStats = swrRacer_AI_PodHandlingData;
            score->podStats.hoverHeight = swrRacer_PodHandlingData[pilot].hoverHeight;
            score->podStats.bumpMass = swrRacer_PodHandlingData[pilot].bumpMass;
            score->podStats.intersectRadius = swrRacer_PodHandlingData[pilot].intersectRadius;
        } else {
            swrSaveProfile* profile = (swrSaveProfile*)score->localPlayerProfile;
            char upgradeLevels[SWR_UPGRADE_CATEGORY_COUNT];
            char upgradeHealths[SWR_UPGRADE_CATEGORY_COUNT];
            for (int k = 0; k < SWR_UPGRADE_CATEGORY_COUNT; k++) {
                upgradeLevels[k] = profile != NULL ? profile->upgradeLevels[k] : 0;
                upgradeHealths[k] = profile != NULL ? profile->upgradeHealths[k] : -1;
            }
            swrRace_ApplyUpgradesToStats(&score->podStats, &swrRacer_PodHandlingData[pilot], upgradeLevels, upgradeHealths);
            swrRace_ComputeStatBars((PodHandlingData*)swrRace_statBarsBase, &swrRacer_PodHandlingData[pilot]);
            swrRace_ComputeStatBars((PodHandlingData*)swrRace_statBarsCurrent, &score->podStats);
        }
    }

    swrObjHang_MarkPlayerRacerSlot(hang);
    swrUI_RefreshRoot();
    return swrScores;
}

// 0x0045bb60
void swrObjHang_ResetCameraAssignments_Maybe(void)
{
    for (int i = 0; i < 4; i++)
        swrObjHang_resetCameraSlots[i] = -1;
}

// 0x0045bab0
int swrObjHang_FindPlayerRacerSlot(swrObjHang* hang)
{
    // hang->vehiclePlayer is slot 0; vehicleOpponent[] follows it directly.
    const char* slotPilots = &hang->vehiclePlayer;
    int favorite = g_aTrackInfos[hang->track_index].FavoritePilot;
    int slot = -1;
    int i;

    if (hang->demo_mode == 0) {
        for (i = 0; i < hang->num_players; i++) {
            if (slotPilots[i] == favorite && swrScores[i].identifier == 'AAII')
                slot = i;
        }
        if (slot == -1) {
            for (i = 0; i < hang->num_players; i++) {
                if (swrScores[i].identifier == 'AAII')
                    return i;
            }
        }
    } else {
        for (i = 0; i < hang->num_players; i++) {
            if (slotPilots[i] == favorite)
                slot = i;
        }
        if (slot == -1)
            return 0;
    }
    return slot;
}

// 0x004584a0
void swrObjHang_InitTrackSprites(swrObjHang* hang, int initTracks)
{
    int circuit;
    int track;
    int place;
    short id;
    swrSpriteTexture* tex;

    for (id = SWROBJHANG_WHITESQUARE_SPRITE_FIRST; id < SWROBJHANG_WHITESQUARE_SPRITE_END; id++)
        swrSprite_NewSprite(id, hang->sprite_whitesquare_rgb);
    if (initTracks == 0)
        return;

    for (circuit = 0; circuit < SWR_CIRCUIT_COUNT; circuit++) {
        for (track = 0; track < SWR_TRACKS_PER_CIRCUIT; track++) {
            place = ((short)g_aBeatTrackPlace[circuit] >> (track * 2)) & 3;
            id = (short)(SWROBJHANG_TRACK_GRID_SPRITE_BASE + circuit * SWR_TRACKS_PER_CIRCUIT + track);
            swrSprite_NewSprite(id, hang->award_wdw_blue_rgb);
            swrSprite_SetFlag(id, swrSprite_FLAG_UNK_8000);
            switch (circuit) {
            case 0:
                swrSprite_SetColor(id, 0x32, 0xff, 0xff, 0xfe);
                break;
            case 1:
                swrSprite_SetColor(id, 0x44, 0xff, 0x3e, 0xfe);
                break;
            case 2:
                swrSprite_SetColor(id, 0xa3, 0xbe, 0x11, 0xfe);
                break;
            case 3:
                swrSprite_SetColor(id, 0x9d, 0x59, 0x20, 0xfe);
                break;
            }
            if (!isTrackPlayable(hang, (char)circuit, (char)track))
                swrSprite_SetColor(id, 0x80, 0x80, 0x80, 0xfe);
            if (hang->isTournamentMode != 0) {
                tex = NULL;
                switch (place) {
                case 1:
                    tex = hang->award_third_rgb;
                    break;
                case 2:
                    tex = hang->award_second_rgb;
                    break;
                case 3:
                    tex = hang->award_first_rgb;
                    break;
                }
                if (tex != NULL)
                    swrSprite_NewSprite(id, tex);
            }
            swrSprite_NewSprite(id + SWROBJHANG_TRACK_GRID_SELECT_OFFSET, hang->award_wdw_select_blue_rgb);
            swrSprite_SetFlag(id + SWROBJHANG_TRACK_GRID_SELECT_OFFSET, swrSprite_FLAG_UNK_8000);
            swrSprite_SetColor(id + SWROBJHANG_TRACK_GRID_SELECT_OFFSET, 0xa3, 0xbe, 0x11, 0xfe);
        }
    }
}

static void loadPilotPuppet(int pilot, int slot)
{
    swrModel_LoadPuppet(swrRacer_PodData[pilot].puppet_modelId, slot, swrObjElmo_KIND_PILOT, swrRacer_PodData[pilot].float20);
}

static void loadPodModel(int pilot, int slot)
{
    swrModel_LoadModelIntoScene(swrRacer_PodData[pilot].pod_modelID, swrRacer_PodData[pilot].pod_alt_modelID, SWR_SCENE_SLOT_POD_MODELS + slot, false);
    if (swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS + slot] != NULL)
        swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS + slot]->entries[SWR_SCENE_POD_PILOT_ENTRY].value = pilot;
}

// 0x004586e0
void swrObjHang_LoadScreenAssets(swrObjHang* hang)
{
    char* pods = &hang->vehiclePlayer;
    swrSpriteTexture* tex;
    int pilot;

    switch (hang->menuScreen) {
    case swrObjHang_STATE_SPLASH:
    case swrObjHang_STATE_ENTER_NAME:
    case swrObjHang_STATE_MAIN_MENU:
    case swrObjHang_STATE_POST_RACE_INFO:
    case swrObjHang_STATE_SELECT_VEHICLE:
    case 10:
    case 11:
    case swrObjHang_STATE_SELECT_PLANET:
    case swrObjHang_STATE_SELECT_TRACK:
    case swrObjHang_STATE_VEHICLE_SELECT_INTRO:
        hang->room = Cantina;
        break;
    case swrObjHang_STATE_JUNKYARD:
        hang->room = Junkyard;
        break;
    case swrObjHang_STATE_WATTO:
        hang->room = Shop;
        break;
    case swrObjHang_STATE_LOOK_AT_VEHICLE:
    case swrObjHang_STATE_TAUNT_SCENE:
    case swrObjHang_STATE_RESULTS_INTRO:
        hang->room = Hangar;
        break;
    case swrObjHang_STATE_LOAD_SCREEN:
        return;
    case swrObjHang_STATE_PLANET_SELECT_INTRO:
        hang->room = HangRoom_Awards;
        break;
    default:
        hang->room = HangRoom_None;
        break;
    }
    if (hang->roomPrev == Cantina && hang->room == Cantina)
        return;
    if (hang->roomPrev != hang->room)
        swrDisplay_SkipNextFrameUpdate = 1;

    swrObjHang_CullElmoAssets(2);
    for (int id = 0; id < 0xb8; id++) {
        // sprites 0xa2..0xb7 (the menu selector set) survive a screen change
        if ((id < 0xa2 || id > 0xb7) && id != 0xf9 && id != 0xfa)
            swrSprite_NewSprite((short)id, NULL);
    }
    swrModel_ClearSceneAnimations();
    swrModel_clearSceneModelsAndChildren();

    if (hang->room == Cantina) {
        swrModel_tileReadOneRowUp = 1;
        tex = swrSprite_GetTextureFromTGA("data\\images\\greyedsplash.tga", 0x50);
        swrModel_tileReadOneRowUp = 0;
        swrSprite_NewSprite(0x50, tex);
        swrSprite_NewSprite(0x4d, swrSprite_GetTextureFromTGA("data\\images\\settings_btn_strch_sel.tga", 0x4d));
        swrSprite_NewSprite(0x4e, swrSprite_GetTextureFromTGA("data\\images\\podhangar_backdrop.tga", 0x4e));
        swrSprite_NewSprite(0x4f, swrSprite_GetTextureFromTGA("data\\images\\podhangar_backdrop2.tga", 0x4f));
        swrSprite_NewSprite(0x51, swrSprite_GetTextureFromTGA("data\\images\\episode1.tga", 0x51));
        swrSprite_NewSprite(0x54, swrSprite_GetTextureFromTGA("data\\images\\racer.tga", 0x54));
        swrSprite_NewSprite(0x52, swrSprite_GetTextureFromTGA("data\\images\\star.tga", 0x52));
        swrSprite_NewSprite(0x53, swrSprite_GetTextureFromTGA("data\\images\\wars.tga", 0x53));
        swrUI_Front_LoadUIElements();
        swrUI_Front_LoadPlanetModels();
        swrUI_Front_LoadMapPartModels();
        swrSprite_NewSprite(0x45, swrSprite_LoadTexture_(swrSprite_int_planet_tat_rgb));
        swrSprite_NewSprite(0x46, swrSprite_LoadTexture_(swrSprite_int_planet_a_rgb));
        swrSprite_NewSprite(0x47, swrSprite_LoadTexture_(swrSprite_int_planet_b_rgb));
        swrSprite_NewSprite(0x48, swrSprite_LoadTexture_(swrSprite_int_planet_c_rgb));
        swrSprite_NewSprite(0x49, swrSprite_LoadTexture_(swrSprite_int_planet_d_rgb));
        swrSprite_NewSprite(0x4a, swrSprite_LoadTexture_(swrSprite_int_planet_e_rgb));
        swrSprite_NewSprite(0x4b, swrSprite_LoadTexture_(swrSprite_int_planet_f_rgb));
        swrSprite_NewSprite(0x4c, swrSprite_LoadTexture_(swrSprite_int_planet_j_rgb));
        swrModel_LoadModelIntoScene(MODELID_coin_part, -1, INGAME_MODELID_coin_part, false);
        swrObjHang_LoadAllPilotSprites();
        swrModel_LoadModelIntoScene(MODELID_flag2_part, -1, INGAME_MODELID_flag2_part, false);

        // a random unlocked pilot sits in the cantina
        do {
            pilot = 1 - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -22.0f);
        } while (((1 << pilot) & swrRace_unlockedPilotsMask) == 0);
        swrModel_LoadPuppet(swrRacer_PodData[pilot].puppet_modelId, SWR_SCENE_SLOT_CANTINA_PILOT, swrObjElmo_KIND_PILOT, swrRacer_PodData[pilot].float20);
        if ((swrRace_unlockedPilotsMask & SWR_CANTINA_PILOT_POOL) == 0) {
            do {
                pilot = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (float)SWR_PILOT_COUNT);
            } while ((swrRace_unlockedPilotsMask & (1 << pilot)) != 0);
            swrModel_LoadPuppet(swrRacer_PodData[pilot].puppet_modelId, SWR_SCENE_SLOT_CANTINA_GUEST, swrObjElmo_KIND_PILOT, swrRacer_PodData[pilot].float20);
        } else {
            swrModel_LoadPuppet(MODELID_char_pitdroid_puppet, SWR_SCENE_SLOT_CANTINA_GUEST, swrObjElmo_KIND_PIT_DROID, -1.0f);
        }
        swrModel_LoadPuppet(MODELID_char_npc_bartender_puppet, 0x16, swrObjElmo_KIND_BARTENDER, -1.0f);
        swrModel_LoadPuppet(MODELID_char_npc_jawa_puppet, 0x17, swrObjElmo_KIND_JAWA, -1.0f);

        hang->sprite_whitesquare_rgb = swrSprite_LoadTexture_(swrSprite_whitesquare_rgb);
        for (int i = 0; i < 4; i++)
            swrSprite_NewSprite((short)(i + 0x82), hang->sprite_whitesquare_rgb);
        hang->award_first_rgb = swrSprite_LoadTexture_(swrSprite_award_first_rgb);
        hang->award_second_rgb = swrSprite_LoadTexture_(swrSprite_award_second_rgb);
        hang->award_third_rgb = swrSprite_LoadTexture_(swrSprite_award_third_rgb);
        hang->award_wdw_blue_rgb = swrSprite_LoadTexture_(swrSprite_award_wdw_blue_rgb);
        hang->award_wdw_select_blue_rgb = swrSprite_LoadTexture_(swrSprite_award_window_ylw_rgb);
        swrSprite_NewSprite(0x62, swrSprite_LoadTexture_(swrSprite_award_wdw_select_blue_rgb));
        swrSprite_SetFlag(0x62, swrSprite_FLAG_UNK_8000);
        swrSprite_SetColor(0x62, 0x32, 0xff, 0xff, 0xfe);
        swrObjHang_CullElmoAssets(3);
        // only the first pod's pilot (the loop bound is 1 in the original)
        for (int k = 0; k < 1; k++)
            loadPilotPuppet(pods[k], SWR_SCENE_SLOT_PILOT_PUPPETS + k);
        swrAssetBuffer_CheckOverflow();
        return;
    }

    switch (hang->menuScreen) {
    case swrObjHang_STATE_JUNKYARD:
    case swrObjHang_STATE_WATTO:
        swrUI_Front_LoadUIElements();
        swrUI_Front_LoadPartsUIElements();
        swrModel_LoadModelIntoScene(MODELID_coin_part, -1, INGAME_MODELID_coin_part, false);
        LoadUpgradeModelsIntoScene_Maybe(hang);
        swrModel_LoadPuppet(MODELID_char_watto_puppet, 0x15, swrObjElmo_KIND_WATTO, -1.0f);
        for (int k = 0; k < hang->num_local_players; k++)
            loadPilotPuppet(pods[k], SWR_SCENE_SLOT_PILOT_PUPPETS + k);
        for (int i = 0; i < SWR_MAX_PIT_DROIDS - (int)(uint8_t)swrRace_nbPitDroids; i++)
            swrModel_LoadPuppet(MODELID_char_pitdroid_puppet, SWR_SCENE_SLOT_PIT_DROIDS + i, swrObjElmo_KIND_PIT_DROID, -1.0f);
        for (int i = 0; i < 4; i++)
            swrModel_LoadModelIntoScene(MODELID_shadow_square_part, -1, SWR_SCENE_SLOT_SHADOW_SQUARES + i, false);
        swrModel_LoadPuppet(MODELID_char_npc_jawa_puppet, 0x17, swrObjElmo_KIND_JAWA, -1.0f);
        swrModel_LoadPuppet(MODELID_char_npc_jarjar_puppet, 0x1b, swrObjElmo_KIND_JARJAR, -1.0f);
        swrModel_LoadPuppet(MODELID_char_npc_quigon_puppet, 0x19, swrObjElmo_KIND_QUIGON, -1.0f);
        swrModel_LoadPuppet(MODELID_char_npc_r2d2_puppet, 0x18, swrObjElmo_KIND_R2D2, -1.0f);
        swrModel_LoadPuppet(MODELID_char_npc_c3po_puppet, 0x1a, swrObjElmo_KIND_C3PO, -1.0f);
        if (compare3Chars(swrRace_aProfiles[0].name, swrObjHang_dewbackCheatInitials) != 0) {
            swrModel_LoadPuppet(MODELID_char_dewback_puppet, 0x13, swrObjElmo_KIND_DEWBACK, -1.0f);
        } else if (compare3Chars(swrRace_aProfiles[0].name, swrObjHang_rontoCheatInitials) != 0) {
            swrModel_LoadPuppet(MODELID_char_ronto_puppet, 0x14, swrObjElmo_KIND_RONTO, -1.0f);
        }
        break;
    case swrObjHang_STATE_LOOK_AT_VEHICLE:
        swrUI_Front_LoadUIElements();
        swrUI_Front_LoadWindowUIElements();
        for (int k = 0; k < hang->num_local_players; k++)
            loadPodModel(pods[k], k);
        swrModel_LoadModelIntoScene(MODELID_moneybox1_part, -1, INGAME_MODELID_moneybox1_part, false);
        swrModel_LoadModelIntoScene(MODELID_moneybox2_part, -1, INGAME_MODELID_moneybox2_part, false);
        swrModel_LoadModelIntoScene(MODELID_moneybox3_part, -1, INGAME_MODELID_moneybox3_part, false);
        swrModel_LoadModelIntoScene(MODELID_moneybox2_part, -1, INGAME_MODELID_moneybox2_0_part, false);
        for (int i = 0; i < 4; i++) {
            swrModel_LoadModelIntoScene(MODELID_hovcart_part, -1, INGAME_MODELID_hovcart_part_0 + i, false);
            swrModel_LoadModelIntoScene(MODELID_shadow_circle_part, -1, SWR_SCENE_SLOT_SHADOW_CIRCLES + i, false);
            swrModel_LoadModelIntoScene(MODELID_shadow_square_part, -1, SWR_SCENE_SLOT_SHADOW_SQUARES + i, false);
        }
        swrModel_LoadModelIntoScene(MODELID_beamanim_vlec, -1, INGAME_MODELID_beamanim_vlec, true);
        for (int i = 0; i < 4; i++)
            swrModel_LoadModelIntoScene(MODELID_sparky_part, -1, INGAME_MODELID_sparky_part_0 + i, true);
        for (int k = 0; k < hang->num_local_players; k++)
            loadPilotPuppet(pods[k], SWR_SCENE_SLOT_PILOT_PUPPETS + k);
        for (int i = 0; i < (int)(uint8_t)swrRace_nbPitDroids; i++)
            swrModel_LoadPuppet(MODELID_char_pitdroid_puppet, SWR_SCENE_SLOT_PIT_DROIDS + i, swrObjElmo_KIND_PIT_DROID, -1.0f);
        LoadUpgradeModelsIntoScene_Maybe(hang);
        swrModel_LoadModelIntoScene(MODELID_char_pitdroid_puppet, -1, INGAME_MODELID_char_pitdroid_puppet, false);
        swrModel_LoadPuppet(MODELID_char_dewback_puppet, 0x13, swrObjElmo_KIND_DEWBACK, -1.0f);
        swrModel_LoadPuppet(MODELID_char_ronto_puppet, 0x14, swrObjElmo_KIND_RONTO, -1.0f);
        break;
    case swrObjHang_STATE_TAUNT_SCENE:
        tex = swrSprite_LoadTexture_(swrSprite_whitesquare_rgb);
        for (int k = 0; k < 2; k++) {
            swrSprite_NewSprite((short)(k + 0x82), tex);
            pilot = k == 0 ? pods[0] : (char)g_aTrackInfos[hang->track_index].FavoritePilot;
            loadPilotPuppet(pilot, SWR_SCENE_SLOT_PILOT_PUPPETS + k);
            loadPodModel(pilot, k);
        }
        break;
    case swrObjHang_STATE_PLANET_SELECT_INTRO:
        for (int place = 0; place < 3; place++) {
            loadPilotPuppet(hang->podiumCharacters[place], SWR_SCENE_SLOT_PILOT_PUPPETS + place);
            swrModel_LoadModelIntoScene(MODELID_award_platform_part, -1, SWR_SCENE_SLOT_AWARD_PLATFORMS + place, false);
        }
        swrModel_LoadModelIntoScene(MODELID_award_first_part, -1, INGAME_MODELID_award_first_part, false);
        swrModel_LoadModelIntoScene(MODELID_award_second_part, -1, INGAME_MODELID_award_second_part, false);
        swrModel_LoadModelIntoScene(MODELID_award_third_part, -1, INGAME_MODELID_award_third_part, false);
        swrModel_LoadModelIntoScene(MODELID_loc_awards_part, -1, INGAME_MODELID_loc_awards_part, false);
        break;
    case swrObjHang_STATE_RESULTS_INTRO:
        tex = swrSprite_LoadTexture_(swrSprite_whitesquare_rgb);
        for (int k = 0; k < 2; k++)
            swrSprite_NewSprite((short)(k + 0x82), tex);
        loadPodModel((char)g_aTrackInfos[hang->track_index].FavoritePilot, 0);
        swrModel_LoadPuppet(MODELID_char_pitdroid_puppet, SWR_SCENE_SLOT_PIT_DROIDS, swrObjElmo_KIND_PIT_DROID, -1.0f);
        break;
    default:
        break;
    }
    swrAssetBuffer_CheckOverflow();
}

// 0x00459150
void swrObjHang_SetupScreenScene(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0045a040
int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5)
{
    HANG("TODO");
    return 0;
}

// 0x0045a460
void swrUI_UpdatePlayerMenuInput(int player)
{
    swrUI_localPlayersInputPressedBitset[player] = 0;
    if (swrObjHang_fadeDone == 0)
        return;

    // the original unrolls this over bits 0x1..0x800000
    for (unsigned int bit = 0x1; bit <= 0x800000; bit <<= 1)
        swrUI_AccumulateMenuInputBit(player, inRaceLocalPlayerInputBitset3[player] & bit, bit);

    int down = swrUI_localPlayersInputDownBitset[player];
    if (down & 0x40000)
        swrUI_menuHorizontalDir[player] = 0;
    else if (down & swrUI_INPUT_MENU_LEFT)
        swrUI_menuHorizontalDir[player] = -1;
    else if (down & swrUI_INPUT_MENU_RIGHT)
        swrUI_menuHorizontalDir[player] = 1;

    if (down & 0x80000)
        swrUI_menuVerticalDir[player] = 0;
    else if (down & swrUI_INPUT_MENU_UP)
        swrUI_menuVerticalDir[player] = -1;
    else if (down & swrUI_INPUT_MENU_DOWN)
        swrUI_menuVerticalDir[player] = 1;

    int pressed = swrUI_localPlayersInputPressedBitset[player];
    if ((pressed & 0x100000) && swrUI_menuHorizontalDir[player] == -1)
        swrUI_localPlayersInputDownBitset[player] = down | swrUI_INPUT_MENU_LEFT;
    if ((pressed & 0x200000) && swrUI_menuHorizontalDir[player] == 1)
        swrUI_localPlayersInputDownBitset[player] |= swrUI_INPUT_MENU_RIGHT;
    if ((pressed & 0x400000) && swrUI_menuVerticalDir[player] == -1)
        swrUI_localPlayersInputDownBitset[player] |= swrUI_INPUT_MENU_UP;
    if ((pressed & 0x800000) && swrUI_menuVerticalDir[player] == 1)
        swrUI_localPlayersInputDownBitset[player] |= swrUI_INPUT_MENU_DOWN;
}

// 0x0045a7f0
void swrUI_AccumulateMenuInputBit(int player, int held, unsigned int mask)
{
    if (held == 0) {
        swrUI_localPlayersInputDownBitset[player] &= ~mask;
        return;
    }
    if ((swrUI_localPlayersInputDownBitset[player] & mask) == 0)
        swrUI_localPlayersInputPressedBitset[player] |= mask;
    swrUI_localPlayersInputDownBitset[player] |= mask;
}

// 0x0045a840
void swrObjHang_LayoutVehicleSelectIcons(swrObjHang* hang)
{
    int count;
    int middle;
    int angle;
    float s;
    float c;

    for (int i = 0; i < SWR_SHOP_LIST_CAPACITY; i++) {
        rdVector_Set3(&uiUpgradeInfos2[i].vector1, 0.0f, 0.0f, 0.0f);
        if (i < SWR_HANGAR_ICON_COUNT)
            rdVector_Set3(&uiUpgradeInfos[i].vector1, 0.0f, 0.0f, 0.0f);
    }
    count = swrRace_MenuMaxSelection;

    if (hang->room == Shop) {
        // parts on a ring around Watto's counter
        middle = (int)((float)(count + 1) * 0.5f);
        swrRace_MenuSelectedItem = middle;
        if (count == 0) {
            swrRace_MenuSelectedItem = -1;
            return;
        }
        if (swrObjHang_shopFocusTypePending == 1) {
            for (int i = 0; i < count - 1; i++) {
                if ((char)upgradeInfos[(char)uiUpgradeInfos2[i].index].type == swrObjHang_hangarUpgradeType) {
                    swrRace_MenuSelectedItem = i;
                    break;
                }
            }
        }
        // the ring is laid out from the middle item even when a part type was preselected
        angle = (middle + 9) * 10;
        for (int i = 0; i < count; i++, angle -= 10) {
            swrUIUpgradeInfo* icon = &uiUpgradeInfos2[i];
            stdMath_SinCos((float)angle, &s, &c);
            icon->vector1.x = 12.0f - c * -256.0f;
            icon->vector1.y = -116.0f - s * -256.0f;
            icon->vector1.z = 106.0f;
            rdVector_Copy3(&icon->vector2, &icon->vector1);
            icon->yawDegrees = stdMath_ArcTan2(icon->vector1.x - 12.0f, -116.0f - icon->vector1.y) - 90.0f;
            stdMath_SinCos((1.5f - swrObjHang_shopSwingPhase) * 360.0f, &s, &c);
            count = swrRace_MenuMaxSelection;
            icon->tiltDegrees = c * swrObjHang_shopSwingLean * 45.0f;
        }
    }
    if (hang->room == Junkyard) {
        for (int slot = 0; slot < SWR_JUNKYARD_SLOT_COUNT; slot++) {
            char type = swrObjHang_junkyardStock[slot].partType;
            if (type != -1) {
                swrUICameraPlacement* placement = &maybeUICameraPlacements[SWR_JUNKYARD_PLACEMENT_FIRST + slot];
                uiUpgradeInfos2[type].vector1.x = placement->position2.x;
                uiUpgradeInfos2[type].vector1.y = placement->position2.y;
                uiUpgradeInfos2[type].vector1.z = -130.0f;
                uiUpgradeInfos2[type].tiltDegrees = 0.0f;
                uiUpgradeInfos2[type].yawDegrees = 0.0f;
            }
        }
    }
    if (hang->room == Hangar) {
        // installed parts in two columns on the hangar wall; the slot past the last part faces sideways
        for (int i = 0; i < count + 1; i++) {
            swrUIUpgradeInfo* icon = &uiUpgradeInfos[i];
            icon->vector1.x = 7.7f - (float)(i % 2) * -4.3f;
            icon->vector1.y = 40.0f;
            icon->vector1.z = 9.0f - (float)(i / 2) * 3.8f;
            icon->tiltDegrees = 0.0f;
            icon->yawDegrees = 0.0f;
            if (i == count) {
                icon->vector1.z = icon->vector1.z - 4.1f;
                icon->yawDegrees = 90.0f;
            }
        }
    }

    for (int i = 0; i < SWR_SHOP_LIST_CAPACITY; i++) {
        rdVector_Copy3(&uiUpgradeInfos2[i].vector2, &uiUpgradeInfos2[i].vector1);
        rdVector_Copy3(&uiUpgradeInfos2[i].vector3, &uiUpgradeInfos2[i].vector1);
        if (i < SWR_HANGAR_ICON_COUNT) {
            // the original seeds the hangar icons from uiUpgradeInfos2, not their own vector1
            rdVector_Copy3(&uiUpgradeInfos[i].vector2, &uiUpgradeInfos2[i].vector1);
            rdVector_Copy3(&uiUpgradeInfos[i].vector3, &uiUpgradeInfos2[i].vector1);
        }
    }
}

// 0x0045cd50
void swrObjHang_GenerateJunkyardStock(swrObjHang* hang)
{
    for (int i = 0; i < SWR_JUNKYARD_SLOT_COUNT; i++) {
        swrObjHang_junkyardStock[i].partType = -1;
        // the slot's camera framing is only enabled once a part lands in it
        *(short*)&maybeUICameraPlacements[SWR_JUNKYARD_PLACEMENT_FIRST + i].unk1 = -1;
        swrObjHang_junkyardStock[i].level = 1 - (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -5.0f);
        swrObjHang_junkyardStock[i].health = 102 - (char)(int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -129.0f);
    }
    for (int part = 0; part < SWR_JUNKYARD_PART_COUNT; part++) {
        int slot;
        do {
            slot = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 16.0f);
        } while (swrObjHang_junkyardStock[slot].partType != -1);
        swrObjHang_junkyardStock[slot].partType = (char)part;
        *(short*)&maybeUICameraPlacements[SWR_JUNKYARD_PLACEMENT_FIRST + slot].unk1 = 4;
    }
}

// 0x0045ce90
void swrObjHang_CullElmoAssets(int assetCheckpoint)
{
    swrAssetBuffer_ResetToIndex(assetCheckpoint);
    for (int index = 0; index < SWR_ELMO_POOL_SIZE; index++) {
        swrObjElmo* elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', index);
        if (elmo == NULL)
            continue;
        if (swrAssetBuffer_InBounds((char*)elmo->unk30_nodes) && swrAssetBuffer_InBounds((char*)elmo->unk34))
            continue;
        if ((elmo->obj.flags & swrObj_FLAG_FREED) == 0)
            elmo->obj.flags |= swrObj_FLAG_FREED;
    }
}

// 0x0045cf60
void swrObjHang_ComputeUpgradedStats(int podIndex, int upgradeSlot, char upgradeLevel, char upgradeHealth)
{
    PodHandlingData* baseStats = &swrRacer_PodHandlingData[podIndex];
    char upgradeLevels[8];
    char upgradeHealths[8];

    // The garage previews stats through racer slot 0: aim it at the active profile and the
    // selected pod's static data, then run the upgrade math on that slot's handling copy.
    swrScores[0].localPlayerProfile = swrRace_aProfiles;
    swrScores[0].pilotId = (int*)&swrRacer_PodData[podIndex];
    swrScores[0].podStats = *baseStats;

    for (int i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++) {
        upgradeLevels[i] = (&swrRace_traction_upgrade_level)[i];
        upgradeHealths[i] = (&swrRace_traction_upgrade_health)[i];
        if (multiplayer_enabled != 0) {
            upgradeLevels[i] = 0;
            upgradeHealths[i] = -1;
        }
    }

    swrRace_ApplyUpgradesToStats(&swrScores[0].podStats, baseStats, upgradeLevels, upgradeHealths);
    swrRace_ComputeStatBars((PodHandlingData*)swrRace_statBarsBase, baseStats);
    swrRace_ComputeStatBars((PodHandlingData*)swrRace_statBarsCurrent, &swrScores[0].podStats);

    for (int i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++) {
        swrRace_statBarsPreview[i] = swrRace_statBarsCurrent[i];
        swrRace_statBarChanged[i] = 0;
    }

    if (upgradeSlot == -1)
        return;

    upgradeLevels[upgradeSlot] = upgradeLevel;
    upgradeHealths[upgradeSlot] = upgradeHealth;
    swrRace_ApplyUpgradesToStats(&swrScores[0].podStats, baseStats, upgradeLevels, upgradeHealths);
    swrRace_ComputeStatBars((PodHandlingData*)swrRace_statBarsPreview, &swrScores[0].podStats);

    // Dead in the original: the locals are refilled from the profile but never read again.
    for (int i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++) {
        upgradeLevels[i] = ((swrSaveProfile*)swrScores[0].localPlayerProfile)->upgradeLevels[i];
        upgradeHealths[i] = ((swrSaveProfile*)swrScores[0].localPlayerProfile)->upgradeHealths[i];
    }
    swrRace_statBarChanged[upgradeSlot] = 1;
}

// 0x0045d0b0
void swrObjJdge_Clear(swrObjJdge* jdge, int event)
{
    if (swrJdge_Cleared == 0) {
        swrJdge_Cleared = 1;
        swrModel_ClearSceneAnimations();
        jdge->raceTimer_ms = 0.5;
        jdge->event = event;
        jdge->flag = (jdge->flag & 0xfffffff6U) | 6;
        swrEvent_FreeObjs(0x54657374);
        swrEvent_FreeObjs(0x546f7373);
        swrEvent_FreeObjs(0x536d6f6b);
        swrEvent_FreeObjs(0x54726967);
        swrEvent_FreeObjs(0x43687372);
    }
}

// 0x0045d130
void swrObjJdge_ScrollCredits(swrObjJdge* jdge, int restartScroll)
{
    char text[256];
    char** page;
    int lineCount;
    float scroll;
    int y;
    int i;
    int color;

    scroll = restartScroll != 0 ? 0.0f : swrObjJdge_creditsScrollState;
    y = (int)(240.0f - scroll * 24.0f);
    swrObjJdge_creditsScrollState = (float)(scroll + swrRace_deltaTimeSecs);

    switch (swrObjJdge_creditsHudCycleIndex) {
    case 1:
        page = swrObjJdge_creditsPage1;
        lineCount = SWR_CREDITS_PAGE1_LINES;
        break;
    case 2:
        page = swrObjJdge_creditsPage2;
        lineCount = SWR_CREDITS_PAGE2_LINES;
        break;
    case 3:
        page = swrObjJdge_creditsPage3;
        lineCount = SWR_CREDITS_PAGE3_LINES;
        break;
    case 4:
        page = swrObjJdge_creditsPage4;
        lineCount = SWR_CREDITS_PAGE4_LINES;
        break;
    case 5:
        page = swrObjJdge_creditsPage5;
        lineCount = SWR_CREDITS_PAGE5_LINES;
        break;
    default:
        page = NULL; // EXE walks garbage pointers here; no caller passes another index
        lineCount = 0;
        break;
    }

    // Each line's spacing and style come from the PREVIOUS entry: "" = section header,
    // a leading '\\' = gap line, anything else = a regular name.
    for (i = 0; i + 1 < lineCount; i++) {
        char lead = page[i][0];
        if (lead == '\0') {
            y += 40;
        } else if (lead == '\\') {
            y += 24;
        } else {
            y += 12;
        }
        if (y <= -10 || y >= 250)
            continue;
        if (lead == '\0') {
            sprintf(text, "~f4~o~c%s", page[i + 1]);
            color = 0xbe;
        } else {
            sprintf(text, "~k~c%s", page[i + 1]);
            color = 0xff;
        }
        for (char* c = text; *c != '\0'; c++) {
            if (*c == '\\')
                *c = ' ';
        }
        swrText_CreateTextEntry1(0xa0, y, color, color, -1, -1, text);
    }

    if (y > 0)
        return;
    if (swrObjJdge_creditsHudCycleIndex != 5 && swrObjJdge_creditsHudCycled == 0) {
        swrObjJdge_Clear(jdge, 'Fini');
        return;
    }
    swrObjJdge_Clear(jdge, 'Abrt');
}

// 0x0045D350
int NumLocalPlayers()
{
    if (firstLocalPlayer == NULL) {
        return 0;
    }
    if (secondLocalPlayer == NULL) {
        return 1;
    }
    if (thirdLocalPlayer == NULL) {
        return 2;
    }
    return (fourthLocalPlayer != NULL) + 3;
}

// 0x0045D390
double swrRace_GetLapProgressIfAvailable()
{
    // -1.0 = "no lap progress available" (no active Test race object or no local player)
    if (swrEvent_GetItem('Test', 0) == NULL)
        return -1.0f;
    if (firstLocalPlayer == NULL)
        return -1.0f;
    return swrRace_LapProgress(&firstLocalPlayer->obj_test_ptr->splineCursor);
}

// 0x0045D3D0
int GetLocalPlayerNumberFromScore(swrScore* score)
{
    if (firstLocalPlayer == score) {
        return 0;
    }
    if (secondLocalPlayer == score) {
        return 1;
    }
    if (thirdLocalPlayer == score) {
        return 2;
    }
    return fourthLocalPlayer == score ? 3 : -1;
}

// Placement metric: lap count + fraction of the current lap (spline progress, wrap-corrected).
// 0x0045d410
float swrObjJdge_GetRacerProgress(swrScore* score)
{
    float lapCompMax = score->obj_test_ptr->lapCompMax;
    float wrap = lapCompMax - score->obj_test_ptr->lapComp;
    if (wrap < 0.0f)
        wrap = -wrap;
    if (0.5f < wrap)
        wrap = 1.0f - wrap;
    float progress = ((float)score->results_P1_Lap + lapCompMax) - wrap;
    if (progress < 0.0f)
        progress = 0.0f;
    return progress;
}

// Sort key for standings: finished racers rank by (maxRaceTime - total time); others by progress.
// 0x0045d480
float swrObjJdge_GetRacerRankValue(swrScore* score)
{
    if ((score->flag & 2) == 0)
        return swrObjJdge_GetRacerProgress(score);
    return swrObjJdge_maxRaceTime - score->results_P1_total_time;
}

// Assigns finishing positions and the per-pod progress-gap fields (all in laps: see types.h).
// For each racer it stores the gap to the race leader (gapToLeader), the signed gap to the local
// player(s) (gapToLocalPlayer1/gapToLocalPlayer2, -100.0 when no local player), and the gap to the
// pace-setter (gapToPacer, measured against the AI_SIMPLE track-favorite pod). It also tags the two
// AI nearest to local player 1 (AI_TETHER_LOCAL1) and, in 2-player, to local player 2
// (AI_TETHER_LOCAL2); swrRace_AI paces those pods directly on their gap to that player.
// 0x0045d4a0
void swrObjJdge_UpdateStandings(swrObjJdge* jdge)
{
    float rankValues[20];
    float leaderProgress = -1.0f;
    float firstLocalRank = 0.0f, secondLocalRank = 0.0f, firstPlaceRank = 0.0f;
    int firstLocalIdx = 0, secondLocalIdx = 0;

    // pass 1: reset each racer's position + rival-arrow flags, compute its rank value
    for (int i = 0; i < jdge->num_players; i++) {
        swrScore* score = &swrScoresPtr[i];
        *(short*)&score->results_P1_Position = -1;
        score->obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_TETHER_LOCAL1;
        score->obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_TETHER_LOCAL2;
        float rank = swrObjJdge_GetRacerRankValue(score);
        rankValues[i] = rank;
        if (score == firstLocalPlayer) {
            firstLocalRank = rank;
            firstLocalIdx = i;
        }
        if (score == secondLocalPlayer) {
            secondLocalRank = rank;
            secondLocalIdx = i;
        }
        if ((score->obj_test_ptr->flags0 & swrObjTest_FLAG0_AI_SIMPLE) != 0) {
            leaderProgress = rank;
            if ((score->flag & 2) != 0)
                leaderProgress = swrObjJdge_GetRacerProgress(score);
        }
    }

    // nearest rivals ahead (aGap*/aheadIdx*) and behind (bGap*/behindIdx*) of the local player(s)
    float aGapA = 10000.0f, aGapB = 10000.0f, aGapC = 10000.0f;
    float bGapA = 10000.0f, bGapB = 10000.0f, bGapC = 10000.0f;
    int aheadIdx1 = -1, aheadIdx2 = -1;
    int behindIdx1 = -1, behindIdx2 = -1;
    int pos = 1;

    // order the two local players so firstLocal* is the higher-ranked one
    if (secondLocalPlayer != NULL && firstLocalRank <= secondLocalRank) {
        int tmpIdx = secondLocalIdx;
        float tmpRank = secondLocalRank;
        secondLocalIdx = firstLocalIdx;
        secondLocalRank = firstLocalRank;
        firstLocalIdx = tmpIdx;
        firstLocalRank = tmpRank;
    }

    // pass 2: repeatedly take the highest remaining rank value -> assign place + gap displays
    for (int processed = 0; processed < jdge->num_players; processed++) {
        int maxIdx = -1;
        float best = 0.0f;
        for (int i = 0; i < jdge->num_players; i++) {
            if (best < rankValues[i]) {
                best = rankValues[i];
                maxIdx = i;
            }
        }
        if (maxIdx == -1)
            continue;

        if ((swrScoresPtr[maxIdx].flag & 2) != 0)
            rankValues[maxIdx] = swrObjJdge_GetRacerProgress(&swrScoresPtr[maxIdx]);
        if (pos == 1)
            firstPlaceRank = rankValues[maxIdx];

        swrRace* pod = swrScoresPtr[maxIdx].obj_test_ptr;
        pod->gapToLeader = firstPlaceRank - rankValues[maxIdx];

        if (firstLocalPlayer == NULL) {
            pod->gapToLocalPlayer1 = -100.0f; // no local player sentinel
        } else if (secondLocalPlayer == NULL) {
            if (firstLocalIdx == maxIdx) {
                pod->gapToLocalPlayer1 = 0;
            } else {
                float gap = firstLocalRank - rankValues[maxIdx];
                bool neg = gap < 0.0f;
                pod->gapToLocalPlayer1 = gap;
                if (neg)
                    gap = -gap;
                if (aGapA <= gap) {
                    if (aGapB > gap) {
                        aGapC = aGapB;
                        aGapB = gap;
                        aheadIdx2 = maxIdx;
                    }
                } else {
                    aGapC = aGapB;
                    aheadIdx2 = aheadIdx1;
                    aGapB = aGapA;
                    aGapA = gap;
                    aheadIdx1 = maxIdx;
                }
            }
        } else if (firstLocalIdx == maxIdx) {
            pod->gapToLocalPlayer1 = 0;
            pod->gapToLocalPlayer2 = secondLocalRank - firstLocalRank;
        } else if (secondLocalIdx == maxIdx) {
            pod->gapToLocalPlayer2 = 0;
            pod->gapToLocalPlayer1 = firstLocalRank - secondLocalRank;
        } else {
            float gapP1 = firstLocalRank - rankValues[maxIdx];
            float gapP2 = secondLocalRank - rankValues[maxIdx];
            bool neg = gapP1 < 0.0f;
            pod->gapToLocalPlayer1 = gapP1;
            pod->gapToLocalPlayer2 = gapP2;
            if (neg)
                gapP1 = -gapP1;
            if (aGapA <= gapP1) {
                if (aGapB <= gapP1) {
                    if (gapP1 < aGapC)
                        aGapC = gapP1;
                } else {
                    aGapC = aGapB;
                    aGapB = gapP1;
                    aheadIdx2 = maxIdx;
                }
            } else {
                aGapC = aGapB;
                aheadIdx2 = aheadIdx1;
                aGapB = aGapA;
                aGapA = gapP1;
                aheadIdx1 = maxIdx;
            }
            if (gapP2 < 0.0f)
                gapP2 = -gapP2;
            if (bGapA <= gapP2) {
                if (bGapB > gapP2) {
                    bGapC = bGapB;
                    bGapB = gapP2;
                    behindIdx2 = maxIdx;
                }
            } else {
                bGapC = bGapB;
                behindIdx2 = behindIdx1;
                bGapB = bGapA;
                bGapA = gapP2;
                behindIdx1 = maxIdx;
            }
        }

        pod->gapToPacer = leaderProgress - rankValues[maxIdx];
        rankValues[maxIdx] = 0.0f;
        *(short*)&swrScoresPtr[maxIdx].results_P1_Position = (short)pos;
        pos++;
    }

    // tag the two nearest rivals behind (2-player only) and ahead of the local player(s)
    if (secondLocalPlayer != NULL) {
        if (behindIdx1 != -1 && rankValues[behindIdx1] < (float)jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx1].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_TETHER_LOCAL2;
        if (behindIdx2 != -1 && rankValues[behindIdx2] < (float)jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx2].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_TETHER_LOCAL2;
    }
    if (aheadIdx1 != -1 && rankValues[aheadIdx1] < (float)jdge->num_laps - 0.1f) {
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_TETHER_LOCAL1;
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_TETHER_LOCAL2;
    }
    if (aheadIdx2 != -1 && rankValues[aheadIdx2] < (float)jdge->num_laps - 0.1f) {
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_TETHER_LOCAL1;
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_TETHER_LOCAL2;
    }
}

// 0x0045dd80
void swrObjJdge_TeardownRace(swrObjJdge* jdge, int event)
{
    int ev[16];
    int i;

    swrUI_ResetProgressBar();
    swrPlayerHUD_lightStreakParam = 1500.0f;
    swrSound_ResetMusic();
    for (i = 0; i < 20; i++)
        swrSound_ClearSfxFlag(i, 0xff0000);
    swrUI_UpdateProgressBar(10);
    swrObjJdge_singleLocalViewport = 1;
    swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
    for (i = 0; i < jdge->num_players; i++) {
        if (swrScoresPtr[i].obj_test_ptr != NULL)
            swrScoresPtr[i].lastRaceDamage = swrScoresPtr[i].obj_test_ptr->totalDamage;
        swrScoresPtr[i].obj_test_ptr = NULL;
    }
    swrUI_UpdateProgressBar(20);
    swrEvent_ClearObjs('Test');
    swrEvent_ClearObjs('Toss');
    swrEvent_ClearObjs('Smok');
    swrEvent_ClearObjs('Trig');
    swrEvent_ClearObjs('Chsr');
    swrUI_UpdateProgressBar(30);
    swrSound_ResetRequestedVoices(); // via the 0x4269b0 thunk, which drops its arg 1
    swrObjJdge_UpdateViewportLayout(jdge, 1);
    swrUI_UpdateProgressBar(40);
    swrSound_SetUpdateFlag_Maybe(0);
    swrModel_Node1 = NULL;
    swrModel_Node3 = NULL;
    swrModel_Node2 = NULL;
    swrModel_Node4 = NULL;
    swrObjJdge_splitscreenActive = 0;
    swrUI_UpdateProgressBar(50);
    swrPlayerHUD_Enable();
    ResetLightStreakSprites();
    swrWeather_ResetParticles();
    swrUI_UpdateProgressBar(60);
    ResetSunAndLensFlareSprites();
    ResetPlayerSpriteValues();
    swrUI_UpdateProgressBar(70);
    swrSprite_ResetAllSprites();
    swrScene_ClearTextureAnim_Maybe();
    GameSettingFlags &= ~GAME_SETTING_MIRROR;
    swrViewport_SetRootNodeForAllViewports(NULL);
    swrUI_UpdateProgressBar(80);
    swrCam_CamState_InitMainMat4(1, 0, NULL, 0);
    swrCam_CamState_InitMainMat4(5, 0, NULL, 0);
    if ((swrObjJdge_teardownFlags & 2) != 0 && event == 'Fini') {
        // restart the track in place; nothing in the retail binary sets this bit
        swrObjJdge_InitTrack(jdge, swrScoresPtr);
        swrScene_SetObjectsLoaded();
        jdge->flag = (jdge->flag & ~swrObjJdge_STATE_MASK) | 3; // EXE: & ~0xc | 3
        return;
    }
    swrUI_UpdateProgressBar(90);
    *((unsigned char*)&jdge->obj.flags + 1) |= 0x10;
    ev[0] = 'RSet';
    swrEvent_CallF4('cMan', ev);
    swrUI_UpdateProgressBar(98);
    if (lowMemoryRacerCount != 0)
        event = 'Abrt';
    ev[0] = event;
    swrEvent_CallF4('All!', ev);
}

// 0x0045dfe0
void swrObjJdge_StartPostRaceSequence(swrObjJdge* jdge)
{
    int subEvent[2];
    int flag;

    swrControl_uiInputActive = 1;
    swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
    swrSound_SetMusicFade(1);
    swrObjJdge_postRaceHudState = 1;
    swrPlayerHUD_lightStreakParam = 1500.0f;

    subEvent[0] = 'Swee';
    subEvent[1] = 0;
    swrEvent_CallF4('cMan', subEvent);

    flag = jdge->flag;
    jdge->flag = flag & 0xfffffff0;
    jdge->raceTimer_ms = 3.2f;
    if ((flag & 0x20) == 0) {
        flag = (flag & 0xfffffff0) | 0xf00;
    } else {
        flag = flag & 0xfffff0f0;
    }
    jdge->flag = flag;

    if ((jdge->flag & 0x20) == 0) {
        enablePause();
    } else {
        jdge->raceTimer_ms = -1.0f;
    }
    swrObjJdge_UpdateViewportLayout(jdge, 4);
    if ((jdge->flag & 0x20) == 0) {
        swrSprite_SetColor(-0x67, 0, 0, 0, 0);
    }
    if (swrMultiplayer_IsMultiplayerEnabled() != 0 && (jdge->flag & 0x60) == 0) {
        swrMultiplayer_InitPlayerStatus(1);
    }

    for (int i = 0; i < jdge->num_players; i++) {
        swrRace* racer = swrScoresPtr[i].obj_test_ptr;
        if (racer != NULL) {
            racer->flags1 &= ~swrObjTest_FLAG1_BOOST_START_CANCEL;
            // set the flags0 low-nibble race state to post-race (clears RACING == 2)
            racer->flags0 = (racer->flags0 & ~swrObjTest_FLAG0_STATE_MASK) | swrObjTest_FLAG0_STATE_POSTRACE;
        }
    }
}

// 0x0045E120
int KeyDownForPlayer1Or2(int inputMask)
{
    // during the credits, swallow input until the HUD-cycle key has been pressed
    if (swrRace_creditsMode != 0 && swrObjJdge_creditsHudCycled == 0)
        return 0;
    if (numLocalPlayers < 2) {
        inputMask = inputMask & inRaceLocalPlayerInputBitset1[0];
    } else {
        // splitscreen: while paused only the player who paused keeps control;
        // otherwise the first of the two players to press claims the input
        if (GetPauseState() != 0)
            return inRaceLocalPlayerInputBitset1[playerNumberInitiatingPause] & inputMask;
        if ((inputMask & inRaceLocalPlayerInputBitset1[0]) != 0) {
            playerNumberInitiatingPause = 0;
            return 1;
        }
        if ((inRaceLocalPlayerInputBitset1[1] & inputMask) != 0) {
            playerNumberInitiatingPause = 1;
            return 1;
        }
    }
    return inputMask;
}

// Cycle the HUD layout when the toggle key is pressed (modes 0-4 single-screen, 4-7 splitscreen).
// 0x0045e1a0
void swrObjJdge_CycleHudMode(swrObjJdge* jdge)
{
    if (KeyDownForPlayer1Or2(0x40) != 0) {
        if (numLocalPlayers < 2) {
            jdge->hud_mode++;
            if (swrObjJdge_HUDMODE_OFF < jdge->hud_mode)
                jdge->hud_mode = swrObjJdge_HUDMODE_GAP_ARROWS;
        } else {
            jdge->hud_mode++;
            if (swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME < jdge->hud_mode)
                jdge->hud_mode = swrObjJdge_HUDMODE_OFF;
        }
    }
}

// 0x0045e200
void swrObjJdge_F0(swrObjJdge* jdge)
{
    if (swrRace_creditsMode == 0)
        swrObjJdge_CycleHudMode(jdge);

    switch (jdge->flag & 0xf) {
    case 0: // pre-race countdown (wait for networked players, then fire 'Go!!')
        swrRace_InitFireEffects(jdge->planetId, 1);
        if (swrMultiplayer_IsMultiplayerEnabled() != 0 && (jdge->flag & 0x60) == 0) {
            swrMultiplayer_SetPlayerStatusBit(1, 1);
            swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0546/Waiting for racers..."), 2.0f);
        }
        if ((jdge->flag & 0x60) == 0 && swrMultiplayer_IsMultiplayerEnabled() != 0 && swrMultiplayer_PollPlayerStatus(1) == 0)
            return;

        jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
        for (int i = 0; i < jdge->num_players; i++) {
            swrRace* pod = swrScoresPtr[i].obj_test_ptr;
            if (pod != NULL) {
                if (jdge->raceTimer_ms <= 0.05f || 0.3f <= jdge->raceTimer_ms)
                    pod->flags1 &= ~swrObjTest_FLAG1_BOOST_START_WINDOW;
                else
                    pod->flags1 |= swrObjTest_FLAG1_BOOST_START_WINDOW;
            }
        }
        if (jdge->raceTimer_ms < 0.0f) {
            jdge->raceTimer_ms = 0.0f;
            if (swrMultiplayer_IsMultiplayerEnabled() != 0 && (jdge->flag & 0x60) == 0) {
                swrObjJdge_goAcknowledged = 0;
                swrMultiplayer_InitPlayerStatus(2);
            }
            jdge->flag = (jdge->flag & 0xfffffff1) | 1;
            int go[16];
            go[0] = 'Go!!';
            for (int i = 0; i < jdge->num_players; i++) {
                if (swrScoresPtr[i].obj_test_ptr != NULL) {
                    swrScoresPtr[i].flag |= 1;
                    swrEvent_DispatchSubEvents(swrScoresPtr[i].obj_test_ptr, go);
                }
            }
        }
        break;

    case 1: // "Go!" hold -> racing
        if ((jdge->flag & 0x20) == 0) {
            if (multiplayer_enabled == 0 || swrObjJdge_goAcknowledged != 0) {
                jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
                swrRace_InitFireEffects(jdge->planetId, 0);
                return;
            }
            swrMultiplayer_SetPlayerStatusBit(2, 1);
            swrText_ShowTimedMessage(swrText_Translate("/MONDOTEXT_H_0547/Go Go Go..."), 2.0f);
            if (swrMultiplayer_PollPlayerStatus(2) != 0) {
                swrObjJdge_goAcknowledged = 1;
                return;
            }
        } else {
            // intro/demo countdown: bail out on timeout or local input
            jdge->countdownTimer_ms -= (float)swrRace_deltaTimeSecs;
            jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
            if ((swrRace_creditsMode == 0 || swrObjJdge_creditsHudCycled != 0) && (jdge->countdownTimer_ms < 0.0f || inRaceLocalPlayerInputBitset1[0] != 0 || inRaceLocalPlayerInputBitset1[1] != 0)) {
                swrObjJdge_Clear(jdge, 'Abrt');
                return;
            }
        }
        break;

    case 2: // racing -> finish ('Fini')
        swrControl_uiInputActive = 0;
        swrMain_raceActiveForUi = 1;
        jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
        if (KeyDownForPlayer1Or2(0x201) != 0) {
            swrObjJdge_Clear(jdge, 'Fini');
            swrObjJdge_finishTriggered = 1;
        } else {
            if (swrControl_acceptReleasedEdge == 0)
                return;
            if (swrObjJdge_finishTriggered == 0) {
                swrObjJdge_Clear(jdge, 'Fini');
                swrObjJdge_finishTriggered = 1;
            }
        }
        if (swrControl_acceptReleasedEdge != 0 && swrObjJdge_finishTriggered != 0) {
            swrControl_acceptReleasedEdge = 0;
            swrObjJdge_finishTriggered = 0;
            return;
        }
        break;

    case 3: // finish hold (clamp the timer to a 3s window)
        jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
        if (3.0f < jdge->raceTimer_ms) {
            do
                jdge->raceTimer_ms -= 3.0f;
            while (3.0f < jdge->raceTimer_ms);
        }
        if (KeyDownForPlayer1Or2(1) != 0 || (jdge->flag & 0x60) != 0) {
            swrObjJdge_StartPostRaceSequence(jdge);
            swrSound_ResetMusic();
            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
            return;
        }
        break;

    case 4: // post-race camera sweep -> results
    {
        uint32_t flags = jdge->flag;
        if (KeyDownForPlayer1Or2(0x201) != 0 || (flags & 0x60) != 0 || swrControl_acceptPressedEdge != 0) {
            swrObjJdge_StartPostRaceSequence(jdge);
            swrSound_ResetMusic();
            swrRace_resultsScreenActive = 1;
            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
            return;
        }
        bool advance = false;
        if (jdge->camSweepState == NULL) {
            advance = true;
        } else {
            if (jdge->camSweepCursor.endFlag == 0)
                jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
            else if ((flags & 0x80) != 0)
                jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
            else {
                jdge->raceTimer_ms = 0.0f;
                jdge->flag = flags | 0x80;
            }
            // fly-by camera reached the end of its path: linger half a second, then results
            if (jdge->camSweepCursor.endFlag != 0 && 0.5f < jdge->raceTimer_ms)
                advance = true;
        }
        if (advance) {
            swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
            jdge->raceTimer_ms = 9.1f;
            jdge->flag = (jdge->flag & 0xfffffff5) | 5;
            swrObjJdge_UpdateViewportLayout(jdge, 3);
            swrViewport_SetCameraParameters(1, 100.0f, -1.0f, -1.0f, -1.0f, -1.0f);
            int sweep[16];
            sweep[0] = 'Swee';
            sweep[1] = 1;
            swrEvent_CallF4('cMan', sweep);
            swrSound_ResetRequestedVoices();
            swrObjJdge_postRaceDelay = 2.0f;
            return;
        }
        break;
    }

    case 5: // results screen (+ post-race taunt SFX)
        swrRace_resultsScreenActive = 1;
        if (KeyDownForPlayer1Or2(0x201) != 0 || swrControl_acceptPressedEdge != 0) {
            swrObjJdge_StartPostRaceSequence(jdge);
            swrSound_ResetMusic();
            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
        } else {
            jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
            if (jdge->raceTimer_ms < 0.0f) {
                swrObjJdge_StartPostRaceSequence(jdge);
                swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
            }
        }
        if (0.0f < swrObjJdge_postRaceDelay)
            swrObjJdge_postRaceDelay -= (float)swrRace_deltaTimeSecs;
        if (swrObjJdge_postRaceDelay <= 0.0f && NumLocalPlayers() < 2 && 1 < jdge->num_players && swrSound_TestSfxFlag(0, 0x200000) == 0) {
            // play the winner's taunt if our racer is on the hangar roster
            char* hang = swrEvent_GetItem('Hang', 0);
            bool onRoster = false;
            for (int i = 0; i < hang[0x72]; i++) {
                if (hang[0x73 + i] == swrObjJdge_localRacerId)
                    onRoster = true;
            }
            int taunt = swrObjJdge_tauntSoundIds[swrObjJdge_localRacerId];
            if (taunt != 0 && 0.0f <= (float)swrUtils_Rand() * 4.6566129e-10f && onRoster) {
                if (0 < taunt)
                    swrSound_PlaySfxThrottled(5, 0, taunt, NULL);
                else
                    swrSound_PlaySfxThrottled(7, 0, -taunt, NULL);
                swrSound_SetSfxFlag(0, 0x200000);
                return;
            }
            swrSound_PlaySfxThenDelayed(5, 0, 1, 5, 0, swrObjJdge_tauntSoundIdsDelayed[swrObjJdge_localRacerId]);
            swrSound_SetSfxFlag(0, 0x200000);
            return;
        }
        break;

    case 6: // teardown
        if (jdge->raceTimer_ms < 0.0f) {
            swrMultiplayer_SetNetworkTick(0);
            if (multiplayer_enabled != 0) {
                swrUI_unk* page = swrUI_GetById(NULL, swrUI_WINDOW_MP_RACER_LIST);
                swrUI_RunCallbacks2(page, 1);
            }
            swrObjJdge_TeardownRace(jdge, jdge->event);
            return;
        }
        jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
        break;
    }
}

// 0x0045e970
void swrObjJdge_UpdateSplineGuideNodes(int nodeOwner, swrScore* score)
{
    swrModel_Node** markers = ((swrObjJdge*)nodeOwner)->splineMarkers;
    rdMatrix44 mats[7]; // the EXE evaluates 7 points but only places 6 markers
    float offset = -0.01f;
    int i;

    for (i = 0; i < 7; i++) {
        swrSpline_EvaluateAtOffset(&score->obj_test_ptr->splineCursor, &mats[i], offset);
        offset -= (i < 2) ? -0.01f : -0.03f;
    }
    for (i = 0; i < 6; i++) {
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)markers[i], &mats[i]);
        if (markers[i] != NULL)
            swrModel_NodeModifyFlags(markers[i], 2, 3, 0x10, 2);
        swrModel_NodeSetColorsOnAllMaterials(markers[i], -1, -1, 0, 0xff, 0, -1);
    }
}

// Race-tick judge update. Lap times are sub-frame accurate: swrRace_UpdateRaceProgress reports the
// portion of the frame delta spent BEFORE the line crossing, which closes out the finished lap, and
// the remainder (raw unclamped delta minus that) accrues to the new lap. State 1 re-arms while any
// local player still races; the state-2 pass then zeroes the race timer and extrapolates unfinished
// racers' totals from their progress.
// 0x0045ea30
void swrObjJdge_F2(swrObjJdge* jdge)
{
    swrScore* score;
    swrRace* pod;
    float* lapTimes;
    float crossTime;
    float rank;
    float frameRemainder;
    int lap;
    int crossed;
    int i;

    if ((jdge->flag & 0xf) == 4 && jdge->camSweepState != NULL)
        swrSpline_EvaluateToMatrix(&jdge->camSweepCursor, &jdge->camSweepTransform);

    if ((jdge->flag & 0xf) == 1) {
        swrSpline_EvaluateToMatrix(&jdge->cursor, &jdge->camBaseMat);
        // provisionally advance to state 2 ("all local racers finished");
        // re-armed back to state 1 below while a local player is still racing
        jdge->flag = (jdge->flag & ~0xd) | 2;
        for (i = 0; i < jdge->num_players; i++) {
            score = &swrScoresPtr[i];
            if ((score->flag & 1) == 0 || (score->flag & 2) != 0) {
                if ((score->flag & 2) != 0)
                    swrRace_UpdateRaceProgress(score->obj_test_ptr, &crossTime);
                continue;
            }
            pod = score->obj_test_ptr;
            crossed = swrRace_UpdateRaceProgress(pod, &crossTime);
            if (debug_showSplineMarkers != 0)
                swrObjJdge_UpdateSplineGuideNodes((int)jdge, score);
            lapTimes = &score->results_P1_Lap1;
            if (crossed) {
                if (jdge->planetId == 1) {
                    // Ando Prime: escalate the blizzard when the first lap completes
                    if (jdge->planet_track_number == 0) {
                        if (score->results_P1_Lap == 0) {
                            swrWeather_SetVelocity(25.0f, 45.0f);
                            swrWeather_SetParticleCap(20);
                        } else {
                            swrWeather_SetParticleCap(60);
                            swrWeather_SetVelocity(20.0f, 60.0f);
                            SetSunSpriteAlpha_Maybe(0, 0x80);
                        }
                    } else if (jdge->planet_track_number == 1) {
                        if (score->results_P1_Lap == 0) {
                            swrWeather_SetParticleCap(60);
                            swrWeather_SetVelocity(20.0f, 60.0f);
                            SetSunSpriteAlpha_Maybe(0, 0x80);
                        } else {
                            swrWeather_SetParticleCap(80);
                            swrWeather_SetVelocity(10.0f, 90.0f);
                            swrWeather_SetStretchFactor(1.0f);
                            SetSunSpriteAlpha_Maybe(0, 0x14);
                        }
                    } else if (jdge->planet_track_number == 2) {
                        if (score->results_P1_Lap == 0) {
                            swrWeather_SetParticleCap(80);
                            swrWeather_SetVelocity(10.0f, 60.0f);
                            SetSunSpriteAlpha_Maybe(0, 0x40);
                        } else {
                            swrWeather_SetParticleCap(80);
                            swrWeather_SetVelocity(10.0f, 90.0f);
                            swrWeather_SetStretchFactor(1.0f);
                            SetSunSpriteAlpha_Maybe(0, 0x14);
                        }
                    }
                }
                // close out the finished lap with the pre-crossing slice of this frame
                score->results_P1_total_time += crossTime;
                lap = score->results_P1_Lap;
                lapTimes[lap] += crossTime;
                if ((pod->flags0 & swrObjTest_FLAG0_LOCAL) != 0 && lapTimes[lap] < jdge->best_lap_time_ms)
                    jdge->best_lap_time_ms = lapTimes[lap];
                lap++;
                score->results_P1_Lap = lap;
                if (lap == jdge->num_laps) {
                    if ((pod->flags0 & swrObjTest_FLAG0_LOCAL) != 0) {
                        pod->flags1 |= swrObjTest_FLAG1_FORCE_GROUND;
                        swrControl_StopAllForceEffects(0);
                        swrRace_resultsScreenActive = 0;
                        if (lapTimes[jdge->num_laps - 1] <= jdge->best_lap_time_ms) {
                            // final lap tied/beat the session best: fanfare (0x27) once
                            if (swrSound_TestSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE) == 0) {
                                if ((short)score->results_P1_Position == 1)
                                    swrSound_PlaySfxThenDelayed(1, *score->pilotId, 0xf, 6, 0, 0x27);
                                else if ((short)score->results_P1_Position < 5)
                                    swrSound_PlaySfxThrottled(6, 0, 0x27, NULL);
                                else
                                    swrSound_PlaySfxThenDelayed(1, *score->pilotId, 0x10, 6, 0, 0x27);
                                swrSound_SetSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE);
                            }
                        } else {
                            // announcer line by finishing position (0xf = won, 0x10 = trailing)
                            if ((short)score->results_P1_Position == 1)
                                swrSound_PlaySfxThrottled(1, *score->pilotId, 0xf, NULL);
                            else if (4 < (short)score->results_P1_Position)
                                swrSound_PlaySfxThrottled(1, *score->pilotId, 0x10, NULL);
                        }
                    }
                    score->flag |= 2;
                    swrMultiplayer_SendEvent(-1, 1, 'fini', 0, 0.0f, 0.0f, 0.0, NULL, NULL, 0);
                    pod->flags0 &= ~swrObjTest_FLAG0_LOCAL;
                    pod->flags0 &= ~(swrObjTest_FLAG0_CAN_CHARGE_BOOST | swrObjTest_FLAG0_BOOSTING);
                    pod->flags0 |= swrObjTest_FLAG0_AI;
                    pod->flags1 |= swrObjTest_FLAG1_FINISHED;
                } else {
                    lapTimes[lap] = 0.0f;
                }
            } else {
                crossTime = 0.0f;
            }
            if ((score->flag & 2) == 0) {
                // the rest of the frame delta accrues to the (possibly new) current lap;
                // timing uses the raw, unclamped delta, capped at 3000s
                frameRemainder = (float)swrRace_dt_raw_d - crossTime;
                score->results_P1_total_time += frameRemainder;
                if (3000.0f < score->results_P1_total_time)
                    score->results_P1_total_time = 3000.0f;
                lap = score->results_P1_Lap;
                lapTimes[lap] += frameRemainder;
                if (3000.0f < lapTimes[lap])
                    lapTimes[lap] = 3000.0f;
                if (firstLocalPlayer == NULL || score == firstLocalPlayer || score == secondLocalPlayer || score == thirdLocalPlayer || score == fourthLocalPlayer)
                    jdge->flag = (jdge->flag & ~0xe) | 1;
            }
        }
        swrObjJdge_UpdateStandings(jdge);
        swrObjJdge_PlayPassingVoiceLines(jdge);
        if ((jdge->flag & 0xf) == 2) {
            // every local racer just finished: freeze the race timer and extrapolate
            // unfinished racers' totals from their lap progress
            jdge->raceTimer_ms = 0.0f;
            for (i = 0; i < jdge->num_players; i++) {
                score = &swrScoresPtr[i];
                rank = swrObjJdge_GetRacerRankValue(score);
                if (rank < (float)jdge->num_laps) {
                    score->results_P1_total_time = (score->results_P1_total_time / rank) * (float)jdge->num_laps;
                    score->obj_test_ptr->flags0 &= ~(swrObjTest_FLAG0_CAN_CHARGE_BOOST | swrObjTest_FLAG0_BOOSTING);
                    score->obj_test_ptr->flags1 |= swrObjTest_FLAG1_FINISHED;
                }
            }
        }
    } else if ((jdge->flag & 0xf) == 2) {
        for (i = 0; i < jdge->num_players; i++)
            swrRace_UpdateRaceProgress(swrScoresPtr[i].obj_test_ptr, &crossTime);
    } else if ((jdge->flag & 0xf) != 6) {
        for (i = 0; i < jdge->num_players; i++)
            swrRace_UpdateRaceProgress(swrScoresPtr[i].obj_test_ptr, &crossTime);
    }
}

// When a local racer's place changes, the pod it swapped with (if close and AI-driven) taunts:
// losing a place plays the passer's gloat, gaining one plays the passed racer's complaint.
// 0x0045ef70
void swrObjJdge_PlayPassingVoiceLines(swrObjJdge* jdge)
{
    swrScore* score;
    swrScore* other;
    swrRace* otherPod;
    short pos;
    short prev;
    int variant;
    int i;
    int j;

    for (i = 0; i < jdge->num_players; i++) {
        score = &swrScoresPtr[i];
        pos = (short)score->results_P1_Position;
        prev = swrObjJdge_prevRacePositions[i];
        if ((score->obj_test_ptr->flags0 & swrObjTest_FLAG0_LOCAL) != 0 && pos > 0 && prev != pos) {
            int lost = prev < pos;
            if ((lost && (pos == 2 || (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f)) || (!lost && (pos == 1 || (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f))) {
                variant = -1;
                other = NULL;
                for (j = 0; j < jdge->num_players; j++) {
                    other = &swrScoresPtr[j];
                    short otherPos = (short)other->results_P1_Position;
                    if (otherPos > 0 && other != score && otherPos == pos + (lost ? -1 : 1)) {
                        variant = *other->pilotId;
                        break;
                    }
                }
                if (variant != -1) {
                    otherPod = other->obj_test_ptr;
                    if ((otherPod->flags0 & swrObjTest_FLAG0_LOCAL) == 0 && (otherPod->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0 && otherPod->lodDistance < 500.0 && multiplayer_enabled == 0) {
                        rdVector3* at = (rdVector3*)&otherPod->transform.vD;
                        if (!lost) {
                            swrSound_PlayRandomSfx(1, variant, 0x15, 0x01, 0x17, 0x03, 0x14, at);
                        } else if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5f) {
                            // 0x11 is skipped for variant 14 (its first slot is 0x12 too)
                            swrSound_PlayRandomSfx(1, variant, variant == 0xe ? 0x12 : 0x11, 0x12, 0x13, 0x14, 0x15, at);
                        } else {
                            swrSound_PlayRandomSfx(1, variant, 0x17, 0x17, 0x18, 0x19, 0x03, at);
                        }
                    }
                }
            }
        }
        swrObjJdge_prevRacePositions[i] = pos;
    }
}

// 0x0045fe70
void swrObjJdge_DrawSpeedDialHud_Maybe(int racer, int score, short x, short y, int playerIdx)
{
    HANG("TODO");
}

// 0x004603f0
void swrObjJdge_LayoutHudFrameSprites_Maybe(unsigned int mode)
{
    HANG("TODO");
}

// Per-frame in-race HUD draw, dispatched by hud_mode: the racer-position indicators in one of several
// layouts -- catch-up gap arrows (0), a rectangular progress ring (1), a rotated minimap (2/3), or
// splitscreen position lists (5/7) -- plus the minimap fade. numLocalPlayers + hud_mode pick the layout.
// 0x0045f230
void swrObjJdge_DrawRaceHUD(swrObjJdge* jdge)
{
    int minimapActive = 0;
    if (numLocalPlayers == 0)
        return;

    // clamp hud_mode into the range valid for the current player count
    if (numLocalPlayers < 2) {
        if (swrObjJdge_HUDMODE_OFF < jdge->hud_mode)
            jdge->hud_mode = swrObjJdge_HUDMODE_MINIMAP_FAR;
    } else if (jdge->hud_mode < swrObjJdge_HUDMODE_OFF) {
        jdge->hud_mode = swrObjJdge_HUDMODE_SPLIT_COLUMN;
    }

    swrObjJdge_HUDMODE mode = jdge->hud_mode;
    if (mode == swrObjJdge_HUDMODE_GAP_ARROWS) {
        // catch-up gap arrows: each rival's arrow is offset from the leader by the lap-fraction gap
        float leaderLapComp = 0.0f;
        if (1 < jdge->num_players) {
            for (int i = 0; i < jdge->num_players; i++) {
                swrScore* s = &swrScoresPtr[i];
                if ((s->flag & 1) != 0 && (s->flag & 2) == 0 && s->identifier == 'Locl')
                    leaderLapComp = s->obj_test_ptr->lapComp;
            }
            float scale = swrSpline_GetTrackLength();
            if (0.0f < scale && 0 < jdge->num_players) {
                for (int i = 0; i < jdge->num_players; i++) {
                    swrScore* s = &swrScoresPtr[i];
                    if (scale <= 0.0f || (s->flag & 1) == 0 || (s->flag & 2) != 0)
                        continue;
                    float gap = leaderLapComp - s->obj_test_ptr->lapComp;
                    if (0.5f < gap)
                        gap -= 1.0f;
                    if (gap < -0.5f)
                        gap -= -1.0f;
                    gap = gap * scale * 0.022222222f - -119.0f;
                    if (*s->pilotId == -1 || gap > 164.0f || gap < 74.0f)
                        continue;
                    short sprite = (short)(0x2b + i);
                    uint8_t a;
                    if (s == firstLocalPlayer) {
                        swrSprite_SetVisible(sprite, 1);
                        swrSprite_SetPos(sprite, 0x112, (short)(int)(gap - 1.0f));
                        swrSprite_SetDim(sprite, 0.75f, 0.75f);
                        a = 0xdc;
                    } else {
                        swrSprite_SetVisible(sprite, 1);
                        swrSprite_SetPos(sprite, 0x114, (short)(int)gap);
                        swrSprite_SetDim(sprite, 0.5f, 0.5f);
                        a = 0x80;
                    }
                    swrSprite_SetColor(sprite, 0xff, 0xff, 0xff, a);
                    if (s->results_P1_Position > 0) {
                        char buf[16];
                        sprintf(buf, "~f4~s%d", (int)(short)s->results_P1_Position);
                        int b = (s == firstLocalPlayer) ? 0 : -1;
                        swrText_CreateTextEntry1(0x11c, (int)gap, -1, -1, b, -1, buf);
                    }
                }
            }
        }
    } else if (mode == swrObjJdge_HUDMODE_PROGRESS_RING) {
        // rectangular progress ring: map lap progress onto a screen-space rectangle outline
        for (int i = 0; i < jdge->num_players; i++) {
            swrScore* s = &swrScoresPtr[i];
            if ((s->flag & 1) == 0 || (s->flag & 2) != 0)
                continue;
            float p = s->obj_test_ptr->lapComp * 920.0f;
            float x, y;
            if (0.0f <= p && p <= 260.0f) {
                x = p - -20.0f;
                y = 15.0f;
            } else if (260.0f < p && p <= 460.0f) {
                x = 280.0f;
                y = (p - 260.0f) - -15.0f;
            } else if (460.0f < p && p <= 720.0f) {
                x = 280.0f - (p - 460.0f);
                y = 215.0f;
            } else {
                x = 20.0f;
                y = 215.0f - (p - 720.0f);
            }
            if (*s->pilotId == -1)
                continue;
            short sprite = (short)(0x2b + i);
            swrSprite_SetColor(sprite, -1, -1, -1, -1);
            swrSprite_SetVisible(sprite, 1);
            swrSprite_SetPos(sprite, (short)(int)x, (short)(int)y);
            swrSprite_SetDim(sprite, 1.0f, 1.0f);
            if (1 < jdge->num_players && s->results_P1_Position > 0) {
                char buf[16];
                char* fmt;
                int tx, ty, tb;
                if (s == firstLocalPlayer) {
                    fmt = "~f3~o%d";
                    tx = (int)(x - 1.0f);
                    ty = (int)(y - 3.0f);
                    tb = 0;
                } else {
                    fmt = "~f4~o%d";
                    tx = (int)x;
                    ty = (int)y;
                    tb = -1;
                }
                sprintf(buf, fmt, (int)(short)s->results_P1_Position);
                swrText_CreateTextEntry1(tx, ty, -1, -1, tb, -1, buf);
            }
        }
    } else if (mode == swrObjJdge_HUDMODE_MINIMAP_FAR || mode == swrObjJdge_HUDMODE_MINIMAP_NEAR) {
        // rotated minimap: project the track spline, start markers, rivals and the local player onto
        // a small radar oriented to the camera, then dot them in.
        minimapActive = 1;
        rdVector3 viewPos;
        viewPos.x = swrViewport_array[1].model_matrix.vD.x;
        viewPos.y = swrViewport_array[1].model_matrix.vD.y;
        viewPos.z = swrViewport_array[1].model_matrix.vD.z;
        rdVector3 dir;
        dir.x = swrViewport_array[1].model_matrix.vB.x;
        dir.y = swrViewport_array[1].model_matrix.vB.y;
        dir.z = 0.0f;
        rdVector_Normalize3Acc(&dir);
        float rotA = -dir.x;
        float rotB = dir.y;

        float zoomRange, density;
        if (mode == swrObjJdge_HUDMODE_MINIMAP_FAR) {
            zoomRange = 1500.0f;
            density = (jdge->planetId == 1 && jdge->planet_track_number == 3) ? 3.0f : 5.0f;
        } else {
            zoomRange = 500.0f;
            density = 8.0f;
        }
        float signedRange = (GameSettingFlags & 0x4000) ? -zoomRange : zoomRange;

        rdVector2 trackPoints[170];
        int count = swrSpline_CollectNearbyPoints(jdge->unk2c_spline, &viewPos.x, zoomRange, 0xaa, trackPoints, density);
        if (0 < count) {
            if (0xaa < count)
                count = 0xaa;
            for (int k = 0; k < count; k++) {
                float px = (trackPoints[k].x * 25.0f) / signedRange;
                float py = (trackPoints[k].y * 25.0f) / zoomRange;
                float sx = py * rotA + px * rotB;
                float sy = px * dir.x + py * dir.y;
                AddDotToMiniMap(0, (short)(int)(sx - -264.0f), (short)(int)(82.0f - sy));
            }
        }

        // 4 evenly spaced start-line markers along the spline's forward axis
        for (int m = 0; m < 4; m++) {
            float t = ((float)m - 1.5f) * zoomRange * 0.05f;
            float wy = (t * jdge->unk80_mat.vA.y + jdge->unk80_mat.vD.y) - viewPos.y;
            float px = ((t * jdge->unk80_mat.vA.x + jdge->unk80_mat.vD.x) - viewPos.x) * 25.0f / signedRange;
            float py = (wy * 25.0f) / zoomRange;
            float sx = py * rotA + px * rotB;
            float sy = px * dir.x + py * dir.y;
            if (sx < 25.0f && -sx < 25.0f && sy < 25.0f && -sy < 25.0f)
                AddDotToMiniMap(1, (short)(int)(sx - -264.0f), (short)(int)(82.0f - sy));
        }

        // rival racers
        for (int i = 0; i < jdge->num_players; i++) {
            swrScore* s = &swrScoresPtr[i];
            if (s == firstLocalPlayer || (s->flag & 1) == 0 || (s->flag & 2) != 0)
                continue;
            swrRace* pod = s->obj_test_ptr;
            float px = ((pod->transform.vD.x - viewPos.x) * 25.0f) / signedRange;
            float py = ((pod->transform.vD.y - viewPos.y) * 25.0f) / zoomRange;
            float sx = py * rotA + px * rotB;
            float sy = px * dir.x + py * dir.y;
            if (sx < 25.0f && -sx < 25.0f && sy < 25.0f && -sy < 25.0f) {
                char type = (jdge->hud_mode == swrObjJdge_HUDMODE_MINIMAP_FAR) ? 2 : 3;
                AddDotToMiniMap(type, (short)(int)(sx - -264.0f), (short)(int)(82.0f - sy));
            }
        }

        // local player on top
        if (firstLocalPlayer != NULL && (firstLocalPlayer->flag & 1) != 0) {
            swrRace* pod = firstLocalPlayer->obj_test_ptr;
            float px = ((pod->transform.vD.x - viewPos.x) * 25.0f) / signedRange;
            float py = ((pod->transform.vD.y - viewPos.y) * 25.0f) / zoomRange;
            float sx = py * rotA + px * rotB;
            float sy = px * dir.x + py * dir.y;
            if (sx < 25.0f && -sx < 25.0f && sy < 25.0f && -sy < 25.0f)
                AddDotToMiniMap(4, (short)(int)(sx - -264.0f), (short)(int)(82.0f - sy));
        }
    } else if (mode == swrObjJdge_HUDMODE_SPLIT_COLUMN || mode == swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME) {
        // splitscreen: a per-player vertical progress column with a position number
        for (int i = 0; i < jdge->num_players; i++) {
            swrScore* s = &swrScoresPtr[i];
            if ((s->flag & 1) == 0 || (s->flag & 2) != 0)
                continue;
            float q = (swrObjJdge_GetRacerProgress(s) > 0.0f) ? s->obj_test_ptr->lapComp * 900.0f : 0.0f;
            float xBase;
            if (s == secondLocalPlayer)
                xBase = 120.0f;
            else {
                xBase = 108.0f;
                if (s != firstLocalPlayer)
                    xBase = 114.0f;
            }
            float y = q * 0.28901735f - -20.0f;
            if (*s->pilotId != -1 && (s->obj_test_ptr->flags1 & (swrObjTest_FLAG1_FORCE_GROUND | swrObjTest_FLAG1_ON_LAVA)) == 0) {
                short sprite = (short)(0x2b + i);
                swrSprite_SetVisible(sprite, 1);
                swrSprite_SetPos(sprite, (short)(int)xBase, (short)(int)y);
                swrSprite_SetDim(sprite, 1.0f, 1.0f);
            }
            if (s->results_P1_Position > 0) {
                char buf[16];
                int tx, ty, tr, tg, tb;
                if (s == firstLocalPlayer) {
                    tx = (int)(xBase - 1.0f);
                    ty = (int)(y - 2.0f);
                    tr = -1;
                    tg = -1;
                    tb = 0;
                } else if (s == secondLocalPlayer) {
                    tx = (int)(xBase - 1.0f);
                    ty = (int)(y - 2.0f);
                    tr = 0;
                    tg = -1;
                    tb = -1;
                } else {
                    tx = (int)xBase;
                    ty = (int)(y - 1.0f);
                    tr = -0x42;
                    tg = -0x42;
                    tb = -0x42;
                }
                sprintf(buf, "~f3~o%d", (int)(short)s->results_P1_Position);
                swrText_CreateTextEntry1(tx, ty, tr, tg, tb, -1, buf);
            }
        }
    }

    // ramp the minimap alpha up while it is the active layout, down otherwise
    if (minimapActive != 0) {
        miniMapAlpha = miniMapAlpha - (float)(swrRace_deltaTimeSecs * -2.0);
        if (1.0f < miniMapAlpha)
            miniMapAlpha = 1.0f;
    } else {
        miniMapAlpha = miniMapAlpha - (float)(swrRace_deltaTimeSecs + swrRace_deltaTimeSecs);
        if (miniMapAlpha < 0.0f)
            miniMapAlpha = 0.0f;
    }
}

// Pause-menu accent bar (sprite 0x1a): slides down + fades in as the pause menu scrolls in.
// 0x00460320
void swrObjJdge_DrawHudBar(void)
{
    float scroll = GetPauseMenuScrollInOut();
    if (scroll <= 0.0f) {
        swrSprite_SetVisible(0x1a, 0);
        return;
    }
    swrSprite_SetVisible(0x1a, 1);
    float posY = 90.0f - (1.0f - scroll) * 80.0f;
    swrSprite_SetPos(0x1a, 0xa0, (short)(int)posY);
    swrSprite_SetDim(0x1a, 32.5f, 3.90625f);
    swrSprite_SetColor(0x1a, 0, 0x37, 0x47, (uint8_t)(int)(scroll * 254.0f));
    swrSprite_AddDirtyRect(0x5f, (short)(int)(posY - 30.0f), 0xdc, (short)(int)(posY + 30.0f));
}

// Splitscreen divider (sprite 0x17): a black horizontal bar between the two stacked viewports.
// 0x004610f0
void swrObjJdge_DrawSplitDivider(void)
{
    swrSprite_SetVisible(0x17, 1);
    swrSprite_SetPos(0x17, 0, 0x76);
    swrSprite_SetDim(0x17, 320.0f, 4.0f);
    swrSprite_SetColor(0x17, 0, 0, 0, 0xff);
    swrSprite_AddDirtyRect(0x14, 0x75, 300, 0x7b);
}

// Hide the per-racer in-race engine UI sprites (the layout depends on splitscreen + which local player).
// 0x00461150
void swrObjJdge_HideEngineUI(swrScore* score)
{
    if (NumLocalPlayers() == 2 && score != secondLocalPlayer) {
        for (int i = 0; i < 6; i++)
            swrSprite_SetVisible((short)(i + 0x23), 0);
        swrSprite_SetVisible(0x29, 0);
        swrSprite_SetVisible(0x2a, 0);
        return;
    }
    for (int i = 0; i < 6; i++)
        swrSprite_SetVisible((short)(i + 0x1b), 0);
    swrSprite_SetVisible(0x21, 0);
    swrSprite_SetVisible(0x22, 0);
}

// 0x00462a70
int swrObjJdge_IsRacerRacing(swrObjJdge* jdge, swrRace* racer)
{
    swrModel_Behavior* behavior;

    // On planet 1 / track 3, a racer sitting inside this region over terrain tagged
    // with behavior bit 0x8 is treated as no longer racing.
    if (jdge->planetId == 1 && jdge->planet_track_number == 3 && swrObjJdge_notRacingZoneMinX < racer->transform.vD.x && racer->transform.vD.x < swrObjJdge_notRacingZoneMaxX && swrObjJdge_notRacingZoneMinY < racer->transform.vD.y && racer->transform.vD.y < swrObjJdge_notRacingZoneMaxY && racer->terrainModel != NULL && (behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)racer->terrainModel)) != NULL && (behavior->unk1 & 8) != 0) {
        return 0;
    }

    if ((racer->flags1 & swrObjTest_FLAG1_FINISHED) == 0 && (4 < racer->checkpointCount || racer->speedValue < swrObjJdge_notRacingSpeedThreshold)) {
        return 1;
    }
    return 0;
}

// Per-racer HUD update: end-of-race stats when finished, the spline guide node + engine UI while
// racing, the lap timer, and the flashing "Ka-pow." banner while a boost is active.
// 0x00462b20
void swrObjJdge_UpdatePlayerHUD(swrObjJdge* jdge, swrScore* score)
{
    if (score == NULL)
        return;

    swrRace* racer = score->obj_test_ptr;
    int nodeIdx = (score != firstLocalPlayer) + 0xd;

    if ((racer->flags1 & swrObjTest_FLAG1_FINISHED) != 0) {
        swrRace_InRaceEndStatistics(jdge, score);
        racer->flags0 &= ~swrObjTest_FLAG0_GUIDE_ARROW;
        if (someRootNodeChildNodes[nodeIdx] != NULL)
            swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, -4, 0x10, 3);
        swrObjJdge_HideEngineUI(score);
        return;
    }

    if ((jdge->flag & 0xf) == 1) {
        if (swrObjJdge_IsRacerRacing(jdge, racer) == 0) {
            racer->flags0 &= ~swrObjTest_FLAG0_GUIDE_ARROW;
            if (someRootNodeChildNodes[nodeIdx] != NULL)
                swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, -4, 0x10, 3);
        } else {
            if (someRootNodeChildNodes[nodeIdx] != NULL)
                swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, 3, 0x10, 2);
            racer->flags0 |= swrObjTest_FLAG0_GUIDE_ARROW;
            rdMatrix44 guideMat;
            swrSpline_EvaluateAtOffset(&racer->splineCursor, &guideMat, 0.5f);
            rdVector_Copy3(&racer->guideArrowTarget, (rdVector3*)&guideMat.vD);
            racer->guideArrowNode = someRootNodeChildNodes[nodeIdx];
        }
    }

    swrRace_InRaceTimer(score, jdge);
    int engineUiSlot = (NumLocalPlayers() == 2 && score != secondLocalPlayer) ? 1 : 0;
    swrRace_InRaceEngineUI(score, engineUiSlot);

    if ((racer->flags0 & swrObjTest_FLAG0_RESET) != 0) {
        // boost active: green channel jitters with rand() while running, holds at 191 while paused
        float green;
        if (pauseState == 0)
            green = (float)swrUtils_Rand() * 4.656612873077393e-10f * 255.0f;
        else
            green = 191.0f;
        swrText_CreateTextEntry1(0xa0, 0x50, -1, (int)green, 0, -1, swrText_Translate("~c~sKa-pow."));
    }
}

// 0x00462D40
int swrObjJdge_CheckIfPauseRequested()
{
    int pausePressed;
    swrObjJdge* jdge;

    pausePressed = KeyDownForPlayer1Or2(0x200); // 0x200 = pause/start button mask
    jdge = (swrObjJdge*)swrEvent_GetItem('Jdge', 0);
    if ((jdge->flag & 0x20) != 0) // non-pausable phase flag
        return 0;
    // states 2,4,5,6 (finish / post-race sweep / results / cleanup) cannot be paused
    switch (jdge->flag & 0xf) {
    case 2:
    case 4:
    case 5:
    case 6:
        return 0;
    default:
        return pausePressed;
    }
}

// Random 0..254 color channel for a flickering countdown light; held at a constant while paused.
static int swrObjJdge_CountdownLightColor(void)
{
    if (pauseState == 0)
        return (int)((float)swrUtils_Rand() * 4.656612873077393e-10f * 255.0f);
    return (int)191.25f;
}

// Countdown lights: as the start timer falls through its three 1-second windows, one light sprite
// (0xa3 red 3-2s / 0xa2 orange 2-1s / 0xa1 yellow 1-0s) flickers in with a random color, growing and
// fading by how far into the window it is; the start-line spline markers are tinted by stage; and the
// start gantry model pulses green during the idle/demo (state 1) hold.
// 0x00462da0
void swrObjJdge_UpdateCountdownLights(swrObjJdge* jdge)
{
    swrSprite_SetVisible(0xa1, 0);
    swrSprite_SetVisible(0xa2, 0);
    swrSprite_SetVisible(0xa3, 0);

    if ((jdge->flag & 0xf) == 0) {
        float t = jdge->raceTimer_ms;

        if (2.0f < t && t < 3.0f) {
            int r = swrObjJdge_CountdownLightColor();
            int g = swrObjJdge_CountdownLightColor();
            int b = swrObjJdge_CountdownLightColor();
            float size = t - 2.0f;
            swrSprite_SetVisible(0xa3, 1);
            swrSprite_SetPos(0xa3, 0xa0, 100);
            swrSprite_SetDim(0xa3, size + size, size + size);
            swrSprite_SetColor(0xa3, r, g, b, (int)(size * 254.0f));
            swrModel_NodeSetColorsOnAllMaterials(jdge->unk28_model, -1, -1, 0xff, 0, 0, 0xff);
            if ((jdge->flag & 0x100) != 0) {
                playASound(0x59, 7, 0.25f, 1.0f, 0);
                jdge->flag &= ~0x100;
            }
        } else if (1.0f < t && t < 2.0f) {
            int r = swrObjJdge_CountdownLightColor();
            int g = swrObjJdge_CountdownLightColor();
            int b = swrObjJdge_CountdownLightColor();
            float size = t - 1.0f;
            swrSprite_SetVisible(0xa2, 1);
            swrSprite_SetPos(0xa2, 0xa0, 100);
            swrSprite_SetDim(0xa2, size + size, size + size);
            swrSprite_SetColor(0xa2, r, g, b, (int)(size * 254.0f));
            swrModel_NodeSetColorsOnAllMaterials(jdge->unk28_model, -1, -1, 0xff, 0x80, 0, 0xff);
            if ((jdge->flag & 0x200) != 0) {
                playASound(0x59, 7, 0.25f, 1.0f, 0);
                jdge->flag &= ~0x200;
            }
        } else if (0.0f < t && t < 1.0f) {
            int r = swrObjJdge_CountdownLightColor();
            int g = swrObjJdge_CountdownLightColor();
            int b = swrObjJdge_CountdownLightColor();
            swrSprite_SetVisible(0xa1, 1);
            swrSprite_SetPos(0xa1, 0xa0, 100);
            swrSprite_SetDim(0xa1, t + t, t + t);
            swrSprite_SetColor(0xa1, r, g, b, (int)(t * 254.0f));
            swrModel_NodeSetColorsOnAllMaterials(jdge->unk28_model, -1, -1, 0xff, 0xff, 0, 0xff);
            if ((jdge->flag & 0x400) != 0) {
                playASound(0x59, 7, 0.25f, 1.0f, 0);
                jdge->flag &= ~0x400;
            }
        }

        // start-line spline markers, tinted by countdown stage
        swrModel_Node* lastNode;
        int lastR, lastG;
        if (t <= 2.5f) {
            if (t <= 2.0f) {
                if (t <= 1.0f) {
                    swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[1], -1, -1, 0xff, 0xff, 0, -1);
                    lastNode = jdge->splineMarkers[4];
                    lastR = 0xff;
                    lastG = 0xff;
                } else {
                    swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[0], -1, -1, 0xff, 0, 0, -1);
                    lastNode = jdge->splineMarkers[5];
                    lastR = 0xff;
                    lastG = 0;
                }
            } else {
                swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[0], -1, -1, 0, 0, 0, -1);
                swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[1], -1, -1, 0, 0, 0, -1);
                swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[2], -1, -1, 0, 0, 0, -1);
                swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[3], -1, -1, 0, 0, 0, -1);
                swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[4], -1, -1, 0, 0, 0, -1);
                lastNode = jdge->splineMarkers[5];
                lastR = 0;
                lastG = 0;
            }
        } else {
            swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[0], -1, -1, 0xff, 0, 0, -1);
            swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[1], -1, -1, 0xff, 0, 0, -1);
            swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[2], -1, -1, 0xff, 0, 0, -1);
            swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[3], -1, -1, 0xff, 0, 0, -1);
            swrModel_NodeSetColorsOnAllMaterials(jdge->splineMarkers[4], -1, -1, 0xff, 0, 0, -1);
            lastNode = jdge->splineMarkers[5];
            lastR = 0xff;
            lastG = 0;
        }
        swrModel_NodeSetColorsOnAllMaterials(lastNode, -1, -1, lastR, lastG, 0, -1);
    }

    // idle/demo hold: pulse the start gantry green (state 1), hold it dark (state 3)
    if ((jdge->flag & 0xf) == 1) {
        int a = (int)((float)swrUtils_Rand() * 4.656612873077393e-10f * 127.0f - (-128.0f));
        swrModel_NodeSetColorsOnAllMaterials(jdge->unk28_model, -1, -1, 0, 0xff, 0, a);
    }
    if ((jdge->flag & 0xf) == 3) {
        swrModel_NodeSetColorsOnAllMaterials(jdge->unk28_model, -1, -1, 0, 0xff, 0, 0);
    }
}

// Place each racer's blip on the minimap during the "Go" phase: a generic dot for everyone, plus a
// position-numbered dot (negated for local players in splitscreen) once a racer has a valid position.
// 0x004634a0
void swrObjJdge_UpdateMinimap(swrObjJdge* jdge)
{
    if ((jdge->flag & 0xf) != 1 || (jdge->flag & 0x20) != 0)
        return;

    for (int i = 0; i < jdge->num_players; i++) {
        swrScore* score = &swrScoresPtr[i];
        swrRace* pod = score->obj_test_ptr;
        SetPlayerSpritePositionOnMap(pod->obj.id, (rdVector3*)&pod->transform.vD, -9999);

        if ((pod->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0 && (pod->flags1 & swrObjTest_FLAG1_FINISHED) == 0 && (short)score->results_P1_Position > 0) {
            int markerValue;
            if (score == firstLocalPlayer || score == secondLocalPlayer) {
                if (numLocalPlayers < 2)
                    continue;
                markerValue = -(int)(short)score->results_P1_Position;
            } else {
                markerValue = (int)(short)score->results_P1_Position;
            }
            SetPlayerSpritePositionOnMap(pod->obj.id, (rdVector3*)&pod->transform.vD, markerValue);
        }
    }
}

// 0x00463580
void swrObjJdge_F3(swrObjJdge* jdge)
{
    rdVector3 mapPos = { 0.0f, 0.0f, 0.0f };

    if (swrRace_creditsMode == 0) {
        if ((jdge->flag & 0xf) != 6) {
            uint32_t state = jdge->flag & 0xf;
            if (state == 1 || state == 2) {
                bool finalLap = false;
                if (1 < jdge->num_laps) {
                    if (firstLocalPlayer != NULL && jdge->num_laps <= firstLocalPlayer->results_P1_Lap + 1)
                        finalLap = true;
                    if (secondLocalPlayer != NULL && jdge->num_laps <= secondLocalPlayer->results_P1_Lap + 1)
                        finalLap = true;
                }
                if (swrRace_music_enabled != 0) {
                    if (0.0f < GetPauseMenuScrollInOut() || (jdge->flag & 0xf) == 6) {
                        swrSound_SetMusicFade(0); // NOTE: the call site passes a 2nd arg (planetId); swrSound.h proto is 1-arg
                        swrObjJdge_musicFadedForPause = 1;
                    } else {
                        if (swrObjJdge_musicFadedForPause != 0) {
                            swrObjJdge_musicFadedForPause = 0;
                            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
                        }
                        if (finalLap) {
                            swrSound_SetMusicFade(1);
                        } else if (NumLocalPlayers() < 1) {
                            swrSound_SetMusicFade(1);
                        } else if (swrObjJdge_postRaceHudState != 0) {
                            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 1);
                            swrSound_SetMusicFade(1);
                        }
                    }
                }
            }
            swrObjJdge_unkCa0c = 0;
        }
    } else {
        swrObjJdge_ScrollCredits(jdge, 0);
        if (swrObjJdge_creditsHudCycleIndex == 2)
            playASound(0x90, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_creditsHudCycleIndex == 3)
            playASound(0x8e, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_creditsHudCycleIndex == 4)
            playASound(0x91, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_creditsHudCycleIndex == 5)
            playASound(0x8f, 7, 0.25f, 1.0f, 1);
        else
            playASound(0x8f, 7, 0.25f, 1.0f, 1);
    }

    swrObjJdge_DrawHudBar();

    // fade the transition-overlay sprite (-0x67) by a timer ramp that depends on the race state
    uint32_t state = jdge->flag & 0xf;
    bool fadeApplied = false;
    float fadeValue = 0.0f;
    if (state == 4) {
        if (jdge->raceTimer_ms <= 0.0f)
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
        else {
            fadeValue = jdge->raceTimer_ms * 2.0f;
            fadeApplied = true;
        }
    } else if (state == 5) {
        if (jdge->raceTimer_ms <= 8.8f)
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
        else {
            fadeValue = 1.0f - (9.1f - jdge->raceTimer_ms) * 3.3333333f;
            fadeApplied = true;
        }
    } else if (state == 1 && (jdge->flag & 0x20) != 0) {
        if (0.3f <= jdge->raceTimer_ms)
            swrSprite_SetVisible(-0x67, 0);
        else {
            fadeValue = (0.3f - jdge->raceTimer_ms) * 3.3333333f;
            fadeApplied = true;
        }
    } else if (state == 6) {
        if (0.5f < jdge->raceTimer_ms) {
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
            return;
        }
        if (jdge->raceTimer_ms <= 0.25f) {
            swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
            return;
        }
        swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t)(int)((0.5f - jdge->raceTimer_ms) * 4.0f * 255.0f));
        return;
    }
    if (fadeApplied)
        swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t)(int)(fadeValue * 255.0f));

    // blink the low-memory racer-count warning text
    swrObjJdge_lowMemTextBlink = (swrObjJdge_lowMemTextBlink == 0);
    if ((jdge->flag & 0xf) != 1 && lowMemoryRacerCount != 0 && swrObjJdge_lowMemTextBlink) {
        char buffer[128];
        char* text = swrText_Translate("~sLow Memory: %d Racers");
        sprintf(buffer, text, lowMemoryRacerCount);
        swrText_CreateColorlessEntry1(100, 100, buffer);
    }

    swrObjJdge_UpdateViewportLayout(jdge, 0);

    // place each racer's minimap sprite + build the standings-by-position table
    swrScore* byPosition[20];
    for (int i = 0; i < 20; i++)
        byPosition[i] = NULL;
    for (int i = 0; i < jdge->num_players; i++) {
        SetPlayerSpritePositionOnMap(i, &mapPos, -9999);
        short p = *(short*)&swrScoresPtr[i].results_P1_Position;
        if (0 < p)
            byPosition[p - 1] = &swrScoresPtr[i];
    }
    for (int i = 0; i < jdge->num_players; i++)
        swrSprite_SetVisible((short)(i + 0x2b), 0);
    swrSprite_SetVisible(0x19, 0);

    state = jdge->flag & 0xf;
    if (state != 4 && 1 < numLocalPlayers)
        swrObjJdge_DrawSplitDivider();
    if (state != 3 && state != 4 && state != 5) {
        if (firstLocalPlayer != NULL)
            swrObjJdge_UpdatePlayerHUD(jdge, firstLocalPlayer);
        if (secondLocalPlayer != NULL)
            swrObjJdge_UpdatePlayerHUD(jdge, secondLocalPlayer);
        if ((jdge->flag & 0xf) != 2) {
            swrObjJdge_DrawRaceHUD(jdge);
            swrObjJdge_UpdateMinimap(jdge);
        }
        swrObjJdge_UpdateCountdownLights(jdge);
    }
}

// 0x00463a50
int swrObjJdge_F4(swrObjJdge* jdge, int* subEvents, int p3)
{
    switch (*subEvents) {
    case 'Begn': // race start: latch the race config from the sub-event payload
        swr_FastMode = 0;
        swrRace_DebugFlag = 0;
        swrControl_uiInputActive = 0;
        swrJdge_Cleared = 0;
        jdge->num_players = subEvents[2];
        jdge->planetId = subEvents[3];
        jdge->unk1b0_modelId = subEvents[4];
        jdge->unk1b4_splineId = subEvents[5];
        jdge->cam_splineId = subEvents[6];
        jdge->planet_track_number = subEvents[7];
        jdge->countdownTimer_ms = (float)subEvents[8];
        jdge->num_laps = subEvents[9];
        jdge->best_lap_time_ms = *(float*)(p3 + 0x28);
        jdge->recordLap3_ms = *(float*)(p3 + 0x2c);
        jdge->aiSpeedSetting = subEvents[0xc];
        if (subEvents[0xd] == 1)
            GameSettingFlags |= 0x4000;
        else
            GameSettingFlags &= ~0x4000;
        jdge->flag &= ~0x80;
        swrObjJdge_localRacerId = subEvents[0xe];
        if (jdge->countdownTimer_ms <= 0.0f)
            jdge->flag &= ~0x20;
        else
            jdge->flag |= 0x20;
        swrObjJdge_InitTrack(jdge, (swrScore*)subEvents[1]);
        if (firstLocalPlayer == NULL)
            jdge->flag |= 0x40;
        else
            jdge->flag &= ~0x40;
        swrScene_SetObjectsLoaded();
        jdge->flag = (jdge->flag & 0xfffffff4) | 4;
        jdge->raceTimer_ms = 0.5f;
        swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
        swrObjJdge_postRaceHudState = 0;
        swrSound_SelectPlanetIntroMusic(jdge->planetId);
        swrObjJdge_UpdateViewportLayout(jdge, 2);
        if (jdge->planetId == 3 && jdge->planet_track_number == 1)
            swrPlayerHUD_lightStreakParam = 10000.0f;
        if (swrRace_creditsMode != 0) {
            swrObjJdge_creditsHudCycleIndex++;
            if (swrObjJdge_creditsHudCycleIndex == 6) {
                swrObjJdge_creditsHudCycleIndex = 1;
                swrObjJdge_creditsHudCycled = 1;
            }
            jdge->hud_mode = swrObjJdge_HUDMODE_OFF;
            swrObjJdge_creditsScrollState = 0;
        }
        return 1;

    case 'Load': // allocate-time reset of all per-race state
        swrCam_CamState_InitMainMat4(1, 1, &jdge->camBaseMat, 0);
        jdge->flag = 0;
        jdge->raceTimer_ms = 0.0f;
        jdge->unk30 = 0;
        jdge->unk2c_spline = NULL;
        jdge->camBaseMat.vA.x = 1.0f;
        jdge->camBaseMat.vA.y = 0.0f;
        jdge->camBaseMat.vA.z = 0.0f;
        jdge->camBaseMat.vA.w = 0.0f;
        jdge->camBaseMat.vB.x = 0.0f;
        jdge->camBaseMat.vB.y = 1.0f;
        jdge->camBaseMat.vB.z = 0.0f;
        jdge->camBaseMat.vB.w = 0.0f;
        jdge->camBaseMat.vC.x = 0.0f;
        jdge->camBaseMat.vC.y = 0.0f;
        jdge->camBaseMat.vC.z = 1.0f;
        jdge->camBaseMat.vC.w = 0.0f;
        jdge->camBaseMat.vD.x = 0.0f;
        jdge->camBaseMat.vD.y = 0.0f;
        jdge->camBaseMat.vD.z = 0.0f;
        jdge->camBaseMat.vD.w = 1.0f;
        for (int i = 0; i < 6; i++)
            jdge->splineMarkers[i] = NULL;
        jdge->unk28_model = NULL;
        jdge->unk1d8 = 0;
        jdge->unk1dc = 0;
        jdge->camSweepState = NULL;
        // camSweepTransform = identity, written field by field as the original does
        jdge->camSweepTransform.vA.x = 1.0f;
        jdge->camSweepTransform.vA.y = 0.0f;
        jdge->camSweepTransform.vA.z = 0.0f;
        jdge->camSweepTransform.vA.w = 0.0f;
        jdge->camSweepTransform.vB.x = 0.0f;
        jdge->camSweepTransform.vB.y = 1.0f;
        jdge->camSweepTransform.vB.z = 0.0f;
        jdge->camSweepTransform.vB.w = 0.0f;
        jdge->camSweepTransform.vC.x = 0.0f;
        jdge->camSweepTransform.vC.y = 0.0f;
        jdge->camSweepTransform.vC.z = 1.0f;
        jdge->camSweepTransform.vC.w = 0.0f;
        jdge->camSweepTransform.vD.x = 0.0f;
        jdge->camSweepTransform.vD.y = 0.0f;
        jdge->camSweepTransform.vD.z = 0.0f;
        jdge->camSweepTransform.vD.w = 1.0f;
        jdge->cam_spline = NULL;
        jdge->camSweepAnim = NULL;
        jdge->viewportMode = swrObjJdge_VIEWPORT_NONE;
        jdge->unk1e4 = 0.0f;
        jdge->hud_mode = swrObjJdge_HUDMODE_MINIMAP_FAR;
        jdge->unk128[0] = 0;
        jdge->unk128[1] = 0;
        jdge->unk128[2] = 0;
        jdge->unk128[3] = 0;
        // fall through: 'Load' and 'RSet' both re-sleep every Jdge entity
    case 'RSet': {
        swr_noop2();
        int ev[16];
        ev[0] = 'Slep';
        swrEvent_CallF4('Jdge', ev);
        return 1;
    }

    case 'Join': // if we are the session host, broadcast the master-claim event
        if ((jdge->flag & 0x10) != 0) {
            int ev[16];
            ev[0] = 'Mstr';
            swrEvent_Broadcast('Jdge', ev);
        }
        return 1;

    case 'Mstr':
        jdge->flag &= ~0x10;
        return 1;

    case 'Paws': // pause-menu result: abort or restart the race
        if (subEvents[1] < 0) {
            if (subEvents[2] == 1)
                swrObjJdge_Clear(jdge, 'Abrt');
            else if (subEvents[2] == 2)
                swrObjJdge_Clear(jdge, 'RStr');
        }
        return 1;

    case 'Slep':
        *((unsigned char*)&jdge->obj.flags + 1) |= 0x10;
        return 1;

    case 'Wake':
        *((unsigned char*)&jdge->obj.flags + 1) &= ~0x10;
        return 1;

    case 'JAsn': // resolve a score's finish-time to its pod object, then forward the sub-event
        *subEvents = 'NAsn';
        for (int i = 0; i < jdge->num_players; i++) {
            if (swrScoresPtr[i].time_unk == (float)subEvents[2]) {
                subEvents[2] = (int)swrScoresPtr[i].obj_test_ptr;
                swrEvent_DispatchSubEvents((void*)subEvents[3], subEvents);
                break;
            }
        }
        return 1;

    default:
        return 0;
    }
}

// Viewport rects are in the 320x240 virtual screen.
// 0x0045dad0
void swrObjJdge_UpdateViewportLayout(swrObjJdge* jdge, int mode)
{
    int numLocal;

    if (mode != swrObjJdge_VIEWPORT_NONE) {
        jdge->viewportMode = mode;
        jdge->unk1e4 = 0.0f;
    }
    if (jdge->viewportMode == swrObjJdge_VIEWPORT_NONE || jdge->viewportMode == swrObjJdge_VIEWPORT_RACE_APPLIED)
        return;
    if (jdge->viewportMode == swrObjJdge_VIEWPORT_RACE_ONCE) {
        jdge->viewportMode = swrObjJdge_VIEWPORT_RACE_APPLIED;
        jdge->unk1e4 = 1.0f;
    }

    swrViewport_SetViewport(0, 8, 8, 312, 232);
    swrViewport_Enable(2, -1);
    if ((jdge->flag & (swrObjJdge_FLAG_NON_PAUSABLE | swrObjJdge_FLAG_SPECTATE)) == 0) {
        numLocal = NumLocalPlayers();
        swrSprite_SetVisible(-0xc9, 0);
        switch (jdge->viewportMode) {
        case swrObjJdge_VIEWPORT_FULLSCREEN:
            swrViewport_Enable(1, 5);
            swrViewport_SetViewport(1, 8, 8, 312, 232);
            swrViewport_SetCameraParameters(1, 100.0f, -1.0f, -1.0f, -1.0f, -1.0f);
            jdge->viewportMode = swrObjJdge_VIEWPORT_NONE;
            return;
        case swrObjJdge_VIEWPORT_LETTERBOX:
            swrViewport_Enable(1, 5);
            swrViewport_SetViewport(1, 8, 48, 312, 192);
            swrViewport_SetViewport(0, 8, 48, 312, 192);
            swrViewport_SetCameraParameters(1, 45.0f, -1.0f, nearClipDistance, drawDistance, -1.0f);
            return;
        case swrObjJdge_VIEWPORT_RACE:
        case swrObjJdge_VIEWPORT_RACE_ONCE:
        case swrObjJdge_VIEWPORT_RACE_APPLIED:
            swrViewport_Enable(1, 7);
            if (numLocal != 1 && numLocal != 0) {
                if (numLocal != 2)
                    return;
                swrViewport_Enable(2, 8);
                swrViewport_SetViewport(1, 8, 8, 312, 119);
                swrViewport_SetViewport(2, 8, 121, 312, 232);
                if (swrObjJdge_splitscreenWideFov != 0) {
                    swrViewport_SetCameraParameters(1, 120.0f, -1.0f, -1.0f, -1.0f, -1.0f);
                    swrViewport_SetCameraParameters(2, 120.0f, -1.0f, -1.0f, -1.0f, -1.0f);
                    return;
                }
                swrViewport_SetCameraParameters(1, 100.0f, -1.0f, -1.0f, -1.0f, -1.0f);
                swrViewport_SetCameraParameters(2, 100.0f, -1.0f, -1.0f, -1.0f, -1.0f);
                return;
            }
            break;
        default:
            return;
        }
    } else {
        swrViewport_Enable(1, 7);
    }
    swrViewport_SetViewport(1, 8, 8, 312, 232);
    swrViewport_SetCameraParameters(1, 100.0f, -1.0f, -1.0f, -1.0f, -1.0f);
}

// 0x00463FF0
int SetPlanetIdAndTrackNumber(int planetId, int trackNumber)
{
    PlanetID = planetId;
    PlanetTrackNumber = trackNumber;
    return planetId;
}

// 0x004651F0
void swrObjJdge_AddTriggersToScene(swrObjJdge* a1)
{
    swrEvent_AllocateAndLoadObjs('Trig', 30);
    swrEvent_FreeObjs('Trig');
    someRootNodeChildNodes[4] = swrObjTrig_LoadAndInitializeTriggerModels(a1->planetId, a1->planet_track_number, (swrModel_NodeTransformed*)a1->unk30);
}

// 0x00465230
void swrObjToss_AddDustKickModelsToScene()
{
    swrModel_Header* header;
    swrModel_Node* node;
    int i;

    swrEvent_AllocateAndLoadObjs('Toss', 16);
    swrEvent_FreeObjs('Toss');
    for (i = 0; i < 16; i++) {
        node = &dustKickChildNodeArray[i].node;
        header = swrModel_LoadFromId(MODELID_dustkick1_vlec);
        if (header == NULL) {
            dustKickChildNodes[i] = NULL;
            continue;
        }
        swrModel_NodeInit(node, NODE_TRANSFORMED_WITH_PIVOT);
        node->num_children = 1;
        node->children.nodes = &dustKickChildNodeArray2[i];
        dustKickChildNodeArray2[i] = header->entries[0].node;
        dustKickChildNodes[i] = node;
        swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
    }
    swrModel_NodeInit(&dustKickRootNode, NODE_BASIC);
    dustKickRootNode.num_children = 16;
    dustKickRootNode.children.nodes = dustKickChildNodes;
    someRootNodeChildNodes[6] = &dustKickRootNode;
    swrObjToss_SetDustKickChildNodesPtr(dustKickChildNodes);
}

// 0x00465310
void swrObjSmok_AddFireballModelsToScene()
{
    swrModel_Header* header;
    swrModel_Node* node;
    int i;

    swrEvent_AllocateAndLoadObjs('Smok', 8);
    swrEvent_FreeObjs('Smok');
    for (i = 0; i < 40; i++) {
        node = &fireballChildNodeArray[i].node;
        header = swrModel_LoadFromId(MODELID_fireball_1_part);
        if (header == NULL) {
            fireballChildNodes[i] = NULL;
            continue;
        }
        swrModel_NodeInit(node, NODE_TRANSFORMED_WITH_PIVOT);
        node->num_children = 1;
        node->children.nodes = &fireballChildNodeArray2[i];
        fireballChildNodeArray2[i] = header->entries[0].node;
        fireballChildNodes[i] = node;
        swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
    }
    swrModel_NodeInit(&fireballRootNode, NODE_BASIC);
    fireballRootNode.num_children = 40;
    fireballRootNode.children.nodes = fireballChildNodes;
    someRootNodeChildNodes[7] = &fireballRootNode;
    swrObjSmok_SetFireballChildNodesPtr(fireballChildNodes);
}

// 0x004653F0
void AddFireballToModelScene()
{
    swrModel_Header* header;

    someRootNodeChildNodes[11] = NULL;
    header = swrModel_LoadFromId(MODELID_fireball_1_part);
    swrModel_LoadAllAnimationsOfModel(header);
    header = swrModel_LoadFromId(MODELID_fx_podasx_part);
    if (header == NULL)
        return;
    fx_podasx_anim = swrModel_LoadAllAnimationsOfModel(header);
    fireballNodePtr = header->entries[0].node;
    swrModel_AnimationsResetToZero(fx_podasx_anim);
    someRootNodeChildNodes[11] = fireballNodePtr;
    if (fireballNodePtr != NULL)
        swrModel_NodeModifyFlags(fireballNodePtr, 2, -4, 0x10, 3);
    rdMatrix_SetIdentity44(&swrRace_fireballTransform);
}

// 0x00465500
void* GetTrackModelRoot(void)
{
    return someRootNodeChildNodes[3];
}

// 0x00464b90
void swrObjJdge_SetupTrackEnvironment(swrObjJdge* judge, int* anims, int model)
{
    static const SPLINEID camSplines[8][4] = {
        { SPLINEID_tatooine_mini_track6came, SPLINEID_tatooine_track7camm, -1, -1 }, { SPLINEID_planeta_track6came, SPLINEID_planeta_track7camm, SPLINEID_planeta_track8camh, SPLINEID_planeth_track6came }, { SPLINEID_planetb1_track6came, SPLINEID_planetb2_track7camm, SPLINEID_planetb3_track8camh, -1 }, { SPLINEID_planetc_track6came, SPLINEID_planetc_track7camm, SPLINEID_planetc_track8camh, -1 }, { SPLINEID_planetd1_track6came, SPLINEID_planetd2_track7camm, SPLINEID_planetd3_track8camh, SPLINEID_planeti_track6came }, { SPLINEID_planete1_track6came, SPLINEID_planete2_track7camm, SPLINEID_planete3_track8camh, -1 }, { SPLINEID_planetf_track6came, SPLINEID_planetf_track7camm, SPLINEID_planetf_track8camh, -1 }, { SPLINEID_planetj1_track6came, SPLINEID_planetj2_track7camm, SPLINEID_planetj3_track8camh, -1 },
    };
    swrModel_Header* header = (swrModel_Header*)model;
    swrModel_Node* startNode = NULL;
    swrModel_Animation* camAnim;
    char* bufferBefore;
    int fogStartDist;
    int fogR = 0;
    int fogG = 0;
    int fogB = 0;

    judge->cam_splineId = -1;
    if (judge->planetId >= 0 && judge->planetId < 8 && judge->planet_track_number >= 0 && judge->planet_track_number < 4)
        judge->cam_splineId = camSplines[judge->planetId][judge->planet_track_number];
    judge->camSweepState = NULL;
    if ((int)judge->cam_splineId < 0)
        return;

    bufferBefore = swrAssetBuffer_GetBuffer();
    judge->cam_spline = swrSpline_LoadSplineById((char*)judge->cam_splineId);
    swrObjJdge_splineBufferBytes += swrAssetBuffer_GetBuffer() - bufferBefore;

    if (judge->planet_track_number == 0)
        startNode = header->entries[3].node;
    if (judge->planet_track_number == 1)
        startNode = header->entries[4].node;
    if (judge->planet_track_number == 2)
        startNode = header->entries[5].node;
    if (judge->planet_track_number == 3)
        startNode = header->entries[3].node;
    if (judge->cam_spline == NULL || startNode == NULL)
        return;

    judge->camSweepState = NULL;
    judge->camSweepCursor.spline = judge->cam_spline;
    judge->camSweepCursor.velocity = 0.0f;
    judge->camSweepCursor.segmentT = 0.0f;
    judge->camSweepCursor.tangentLength = 0.0f;
    judge->camSweepCursor.endFlag = 0;
    judge->camSweepCursor.startFlag = 0;
    judge->camSweepCursor.branchSelector = 0;
    judge->camSweepCursor.branchFlags = 0;
    if (judge->camSweepCursor.spline != NULL)
        swrSpline_CursorSeek(&judge->camSweepCursor, 0);
    swrSpline_EvaluateAtOffset(&judge->camSweepCursor, &judge->camSweepTransform, 0.0f);

    camAnim = NULL;
    if (anims != NULL) {
        for (; *anims != 0; anims++) {
            if (((swrModel_Animation*)*anims)->node_ptr == (swrModel_NodeTransformed*)startNode) {
                swrModel_AnimationClearFlags((swrModel_Animation*)*anims, 0x30);
                camAnim = (swrModel_Animation*)*anims;
            }
        }
    }
    // the sweep walks the whole camera spline over the start node's animation
    if (camAnim == NULL)
        judge->camSweepCursor.velocity = 1.0f;
    else
        judge->camSweepCursor.velocity = ((float)(int)((swrSpline*)judge->cam_spline)->num_control_points - 1.0f) / camAnim->duration4;
    swrCam_CamState_InitMainMat4(5, 2, &judge->camSweepTransform, 0);
    swrCam_CamState_SetOffsetSource(5, startNode, 2);
    judge->camSweepAnim = camAnim;

    nearClipDistance = 5.0f;
    drawDistance = 5000.0f;
    fogStartDist = 0;
    if (judge->planetId == 0) {
        drawDistance = 4500.0f;
        fogStartDist = 996;
        fogR = 0xdc;
        fogG = 0xea;
        fogB = 0xe5;
    }
    if (judge->planetId == 1) {
        drawDistance = 11000.0f;
        fogStartDist = 996;
        if (judge->planet_track_number == 3) {
            fogR = 0xad;
            fogG = 0xb9;
            fogB = 0xc6;
        } else {
            fogR = 0xd2;
            fogG = 0xd7;
            fogB = 0xe1;
        }
    }
    if (judge->planetId == 2) {
        if (judge->planet_track_number == 0) {
            drawDistance = 3500.0f;
        } else if (judge->planet_track_number == 1) {
            drawDistance = 3500.0f;
            fogStartDist = 996;
            fogR = 0x78;
            fogG = 0x64;
            fogB = 0x78;
        } else if (judge->planet_track_number == 2) {
            drawDistance = 11000.0f;
        }
    }
    if (judge->planetId == 3) {
        fogStartDist = 994;
        fogR = 0x9a;
        fogG = 0x81;
        fogB = 0x81;
        drawDistance = 11000.0f;
    }
    if (judge->planetId == 4) {
        if (judge->planet_track_number == 3) {
            drawDistance = 5000.0f;
        } else if (judge->planet_track_number == 0) {
            drawDistance = 5000.0f;
            fogStartDist = 996;
            fogR = 0xca;
            fogG = 0xb7;
            fogB = 0xc3;
        } else if (judge->planet_track_number == 1 || judge->planet_track_number == 2) {
            if (judge->planet_track_number == 1) {
                drawDistance = 1200.0f;
                fogStartDist = 992;
                fogR = 0x9b;
                fogG = 0x9a;
                fogB = 0xa7;
            } else {
                drawDistance = 1500.0f;
                fogStartDist = 990;
                fogR = 0x5a;
                fogG = 0x36;
                fogB = 0x28;
            }
            if (someRootNodeChildNodes[0] != NULL)
                swrModel_NodeModifyFlags(someRootNodeChildNodes[0], 2, -4, 0x10, 3);
        }
    }
    if (judge->planetId == 5) {
        fogR = 0xbe;
        fogG = 0x37;
        fogB = 0x0a;
        if (judge->planet_track_number == 0) {
            drawDistance = 8000.0f;
            fogStartDist = 990;
        } else if (judge->planet_track_number == 1) {
            drawDistance = 2500.0f;
            fogStartDist = 996;
        } else if (judge->planet_track_number == 2) {
            drawDistance = 4000.0f;
            fogStartDist = 996;
        }
    }
    if (judge->planetId == 6)
        drawDistance = 11000.0f;
    if (judge->planetId == 7) {
        if (judge->planet_track_number == 1)
            drawDistance = 2500.0f;
        else if (judge->planet_track_number == 0 || judge->planet_track_number == 2)
            drawDistance = 6000.0f;
    }

    if (fogStartDist == 0) {
        rdModel_SetFogEnabled_Maybe(0);
    } else {
        rdModel_SetFogEnabled_Maybe(1);
        SetFogParameters(fogStartDist, 1000, fogR, fogG, fogB, 0xff);
        SetClearColor(fogR, fogG, fogB);
    }
    swrRender_frameClearFlags |= swrRender_FRAME_CLEAR_COLOR;
}

// 0x004651a0
void swrModel_LoadBeamAndSparkModels(void)
{
    swrModel_Header* header;

    header = swrModel_LoadFromId(MODELID_beamanim_vlec);
    swrModel_LoadAllAnimationsOfModel(header);
    swrModel_beamTemplateNode = header->entries[0].node;
    header = swrModel_LoadFromId(MODELID_sparky_part);
    swrModel_LoadAllAnimationsOfModel(header);
    swrModel_sparkTemplateNode = header->entries[0].node->children.nodes[0];
}

// 0x00465510
void LoadTrackModels(swrObjJdge* judge)
{
    swrModel_Header* header;
    swrModel_Animation** anims;
    int i;
    int viewFlags6;
    int stackField;

    memset(someRootNodeChildNodes, 0, sizeof(someRootNodeChildNodes));
    swrModel_NodeInit(&someRootNode, NODE_BASIC);
    someRootNode.num_children = 15;
    someRootNode.children.nodes = someRootNodeChildNodes;

    swrObjJdge_trackModelBufferBytes = (int)swrAssetBuffer_GetBuffer();
    swr_noop4();
    header = swrModel_LoadFromId(judge->unk1b0_modelId);
    anims = swrModel_LoadAllAnimationsOfModel(header);
    someRootNodeChildNodes[0] = header->entries[2].node;
    someRootNodeChildNodes[3] = header->entries[0].node;
    if (swrObjJdge_splitscreenActive != 0)
        swrObjJdge_splitSkyboxNode = someRootNodeChildNodes[0];
    swrAssetBuffer_GetStats(&swrObjJdge_trackAssetStats1, &swrObjJdge_trackAssetStats2, &swrObjJdge_trackAssetStats4);
    swrObjJdge_trackModelBufferBytes = (int)swrAssetBuffer_GetBuffer() - swrObjJdge_trackModelBufferBytes;

    swrObjToss_AddDustKickModelsToScene();
    swrObjSmok_AddFireballModelsToScene();
    AddFireballToModelScene();
    swrObjJdge_SetupTrackEnvironment(judge, (int*)anims, (int)header);
    swrModel_LoadAllLightStreaks(header);

    if (judge->planetId == 4 && judge->planet_track_number == 0) {
        header = swrModel_LoadFromId(MODELID_beachanim_vlec);
        swrModel_LoadAllAnimationsOfModel(header);
        someRootNodeChildNodes[2] = header->entries[0].node;
        if (header->entries[0].node != NULL)
            swrModel_NodeModifyFlags(header->entries[0].node, 2, 3, 0x10, 2);
    } else {
        someRootNodeChildNodes[2] = NULL;
    }
    swrModel_LoadBeamAndSparkModels();

    header = swrModel_LoadFromId(MODELID_lightset_vlec);
    someRootNodeChildNodes[9] = header->entries[0].node;
    for (i = 0; i < 6; i++) {
        judge->splineMarkers[i] = header->entries[0].node->children.nodes[i];
        if (judge->splineMarkers[i] != NULL)
            swrModel_NodeModifyFlags(judge->splineMarkers[i], 2, -4, 0x10, 3);
    }

    header = swrModel_LoadFromId(MODELID_gate01_part);
    swrModel_LoadAllAnimationsOfModel(header);
    someRootNodeChildNodes[8] = header->entries[0].node;
    if (someRootNodeChildNodes[8] != NULL)
        swrModel_NodeModifyFlags(someRootNodeChildNodes[8], 2, -4, 0x10, 3);
    judge->unk28_model = header->entries[0].node;

    someRootNodeChildNodes[13] = swrModel_LoadFromId(MODELID_white_arrow_part)->entries[0].node;
    if (someRootNodeChildNodes[13] != NULL)
        swrModel_NodeModifyFlags(someRootNodeChildNodes[13], 2, -4, 0x10, 3);
    someRootNodeChildNodes[14] = swrModel_LoadFromId(MODELID_white_arrow_part)->entries[0].node;
    if (someRootNodeChildNodes[14] != NULL)
        swrModel_NodeModifyFlags(someRootNodeChildNodes[14], 2, -4, 0x10, 3);
    judge->unk30 = (int)someRootNodeChildNodes[3];

    swrModel_NodeInit(&swrObjJdge_podRootNode, NODE_BASIC);
    swrObjJdge_podRootNode.num_children = 0;
    swrObjJdge_podRootNode.children.nodes = swrObjJdge_podRootChildren;
    someRootNodeChildNodes[10] = &swrObjJdge_podRootNode;
    swrModel_NodeInit(&swrObjJdge_podReflectionRootNode, NODE_BASIC);
    swrObjJdge_podReflectionRootNode.num_children = 0;
    swrObjJdge_podReflectionRootNode.children.nodes = swrObjJdge_podReflectionRootChildren;
    someRootNodeChildNodes[1] = &swrObjJdge_podReflectionRootNode;

    swrObjJdge_AddTriggersToScene(judge);
    swrViewport_SetRootNodeForAllViewports(&someRootNode);

    viewFlags6 = 0x16;
    stackField = 0x10;
    if (judge->planet_track_number == 1) {
        viewFlags6 = 0x26;
        stackField = 0x20;
    }
    if (judge->planet_track_number == 2) {
        viewFlags6 = 0x46;
        stackField = 0x40;
    }
    if (judge->planet_track_number == 3) {
        viewFlags6 = 0x16;
        stackField = 0x10;
    }
    swrViewport_SetNodeFlagsForAllViewports(4, 0xffffff00);
    swrViewport_SetNodeFlagsForAllViewports(3, 0xffffff00);
    swrViewport_SetNodeFlagsForAllViewports(6, viewFlags6);
    rdMatrixStack_SetField_Maybe(5, stackField | 2);
    swr_noop2();
}

// 0x00465820
void RecordLoadedModel_Maybe(void* record, int value)
{
    swrModel_Node* node = (swrModel_Node*)record;

    if (node != NULL) {
        node->num_children++;
        node->children.nodes = (swrModel_Node**)value;
    }
}

// 0x00465840
void swrObjJdge_GetSpawnTransform(swrObjJdge* judge, rdMatrix44* out, int gridIndex)
{
    // starting grid: alternating rows of 4 and 3 pods
    int rowWidths[10] = { 4, 3, 4, 3, 4, 3, 4, 3, 4, 3 };
    int numPlayers = judge->num_players;

    swrSpline_EvaluateAtOffset(&judge->cursor, out, 0.0f);
    out->vD.x = out->vD.x - out->vB.x * 100.0f;
    out->vD.y = out->vD.y - out->vB.y * 100.0f;
    out->vD.z = out->vD.z - out->vB.z * 100.0f;
    int width = rowWidths[0];
    int unfilled = width - numPlayers;
    int row = 0;
    int col = gridIndex;
    if (col >= width) {
        int* next = &rowWidths[0];
        do {
            next++;
            col -= width;
            row++;
            width = *next;
            unfilled += width;
        } while (col >= width);
    }
    // the last row is centered on the racers actually in it
    if (unfilled > 0)
        width -= unfilled;
    float back = (float)row * -30.0f;
    float lateral = ((float)width - 1.0f) * 0.5f * -20.0f + (float)col * 20.0f;
    rdVector_Scale3Add3((rdVector3*)&out->vD, (rdVector3*)&out->vD, back, (rdVector3*)&out->vB);
    rdVector_Scale3Add3((rdVector3*)&out->vD, (rdVector3*)&out->vD, lateral, (rdVector3*)&out->vA);
}

// 0x00465cb0
void swrObjJdge_InitSplineCursor(swrObjJdge* judge)
{
    swrSplineCursor* cursor = &judge->cursor;
    cursor->spline = judge->unk2c_spline;
    cursor->velocity = 0.0f;
    cursor->segmentT = 0.0f;
    cursor->tangentLength = 0.0f;
    cursor->endFlag = 0;
    cursor->startFlag = 0;
    cursor->branchSelector = 0;
    cursor->branchFlags = 0;
    if (cursor->spline != NULL)
        swrSpline_CursorSeek(cursor, 0);
    swrSpline_EvaluateAtOffset(cursor, &judge->camBaseMat, 0.0f);
    cursor->velocity = 1.8f;
}

// 0x00465D00
void LoadTrackSpline(swrObjJdge* judge)
{
    int bufferBefore = (int)swrAssetBuffer_GetBuffer();
    // the spline id doubles as the loader's out-pointer slot
    judge->unk2c_spline = (swrSpline*)swrSpline_LoadSplineById((char*)judge->unk1b4_splineId);
    swrObjJdge_splineBufferBytes += (int)swrAssetBuffer_GetBuffer() - bufferBefore;
    swrSpline_Build(judge->unk2c_spline, (swrModel_Node*)judge->unk30);
    swrObjJdge_InitSplineCursor(judge);
}

// 0x00466370
void InitPrimaryLight()
{
    rdVector3 ambient = { 64.0f, 64.0f, 64.0f };
    rdVector3 color = { 255.0f, 255.0f, 255.0f };
    rdVector3 direction = { 0.0f, 0.0f, -100.0f };
    SetLightColorsAndDirection2(-1, &ambient, &color, &direction);
}

// Seeds the global AI tuning for the track that is about to start. Picks a base
// level and spread from a hard-coded per-(planet, track) table, scales the level by
// the AI Speed menu setting (+/-10%), and arms the scripted-AI / spline-variant
// selectors used on a handful of signature tracks. Consumed each frame by swrRace_AI.
// 0x004667E0
void InitAISettingsForTrack(swrObjJdge* judge)
{
    // 8 planets x 4 tracks, each a (base level, spread) pair. Built on the stack just
    // as the original does; empty track slots are 0,0. The base level is later * 0.1.
    float aiTable[64] = {
        8.64f,     20.0f, 11.2f,     38.0f, 0.0f,      0.0f,  0.0f,   0.0f, // planet 0
        8.784f,    35.0f, 9.700001f, 38.0f, 10.8f,     38.0f, 11.35f, 32.0f, // planet 1
        8.775f,    26.0f, 9.700001f, 35.0f, 9.991f,    40.0f, 0.0f,   0.0f, // planet 2
        9.9328f,   36.0f, 10.85f,    35.0f, 10.3f,     35.0f, 0.0f,   0.0f, // planet 3
        10.0395f,  37.0f, 10.0f,     34.0f, 10.05f,    35.0f, 10.45f, 27.0f, // planet 4
        8.459999f, 23.0f, 9.224999f, 40.0f, 9.700001f, 35.0f, 0.0f,   0.0f, // planet 5
        8.801999f, 25.0f, 10.4f,     30.0f, 10.6f,     33.0f, 0.0f,   0.0f, // planet 6
        8.865f,    32.0f, 9.9425f,   30.0f, 10.1f,     33.0f, 0.0f,   0.0f, // planet 7
    };
    int idx = (judge->planet_track_number + judge->planetId * 4) * 2;

    ai_track_script = -1;
    track_spline_variant = 0;

    swrRace_AILevel = aiTable[idx] * 0.1f;
    ai_spread = aiTable[idx + 1];

    // A few signature tracks run scripted AI behaviour (see swrRace_AutopilotSteer)
    // and use an alternate spline path variant.
    if (judge->planetId == 1 && judge->planet_track_number != 3) {
        ai_track_script = 1;
        track_spline_variant = (judge->planet_track_number == 0);
        if (judge->planet_track_number == 1) {
            track_spline_variant = 2;
        }
        if (judge->planet_track_number == 2) {
            track_spline_variant = 3;
        }
    }
    if (judge->planetId == 3) {
        if (judge->planet_track_number == 1) {
            ai_track_script = 6;
        }
        if (judge->planet_track_number == 2) {
            ai_track_script = 5;
        }
    }
    if (judge->planetId == 4 && judge->planet_track_number != 3) {
        if (judge->planet_track_number == 0) {
            ai_track_script = 2;
        }
        if (judge->planet_track_number == 1) {
            ai_track_script = 3;
        }
        if (judge->planet_track_number == 2) {
            ai_track_script = 4;
        }
    }

    // AI Speed menu setting (Slow / Average / Fast -> -1 / 0 / 1) scales the whole field.
    if (judge->aiSpeedSetting == -1) {
        swrRace_AILevel *= 0.9f;
    } else if (judge->aiSpeedSetting == 1) {
        swrRace_AILevel *= 1.1f;
    }

    // Reverse-track / special-event override: fixed spread.
    if ((judge->flag & 0x20) != 0) {
        ai_spread = 2.0f;
    }
}

static void swrObjJdge_PlaceGridMarkers(swrModel_Node** markers, int count, swrTranslationRotation* place, float stepX, float stepY)
{
    int i;

    for (i = 0; i < count; i++) {
        swrModel_NodeSetTransformFromTranslationRotation((swrModel_NodeTransformed*)markers[i], place);
        place->translation.x -= stepX;
        place->translation.y -= stepY;
    }
}

// 0x00465d50
void swrObjJdge_SetupStartingGrid(swrObjJdge* judge)
{
    swrTranslationRotation place;
    rdMatrix44 gate;
    rdMatrix44 finish;
    float gateZ;

    judge->unk80_mat = judge->camBaseMat;
    if (GetCustomStartTransform(&finish) != 0) {
        // open track: three markers at the start, three at the finish
        judge->unkbc_mat = judge->camBaseMat;
        judge->num_laps = 1;
        rdMatrix_ExtractTransform(&judge->camBaseMat, &place);
        place.yaw_roll_pitch.y = 0.0f;
        place.yaw_roll_pitch.z = 0.0f;
        place.translation.x = place.translation.x - judge->camBaseMat.vA.x * 10.0f;
        place.translation.y = place.translation.y - judge->camBaseMat.vA.y * 10.0f;
        swrObjJdge_PlaceGridMarkers(&judge->splineMarkers[0], 3, &place, judge->camBaseMat.vA.x * -10.0f, judge->camBaseMat.vA.y * -10.0f);

        rdMatrix_ExtractTransform(&finish, &place);
        place.translation.x = place.translation.x - finish.vA.x * 10.0f;
        place.translation.y = place.translation.y - finish.vA.y * 10.0f;
        place.yaw_roll_pitch.y = 0.0f;
        place.yaw_roll_pitch.z = 0.0f;
        swrObjJdge_PlaceGridMarkers(&judge->splineMarkers[3], 3, &place, finish.vA.x * -10.0f, finish.vA.y * -10.0f);
        gate = finish;
        gateZ = finish.vD.z;
    } else {
        rdMatrix_ExtractTransform(&judge->camBaseMat, &place);
        place.translation.x = place.translation.x - judge->camBaseMat.vA.x * 25.0f;
        place.translation.y = place.translation.y - judge->camBaseMat.vA.y * 25.0f;
        place.yaw_roll_pitch.y = 0.0f;
        place.yaw_roll_pitch.z = 0.0f;
        swrObjJdge_PlaceGridMarkers(&judge->splineMarkers[0], 6, &place, judge->camBaseMat.vA.x * -10.0f, judge->camBaseMat.vA.y * -10.0f);
        gate = judge->camBaseMat;
        judge->unkbc_mat = judge->unk80_mat;
        gateZ = judge->camBaseMat.vD.z;
    }

    gate.vD.z = gateZ - -22.0f;
    rdMatrix_AddRotationFromVectorAngle44Before(&gate, 180.0f, 0.0f, 0.0f, 1.0f, &gate);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)judge->unk28_model, &gate);
    swrModel_NodeSetColorsOnAllMaterials(judge->unk28_model, -1, -1, 0, 0xff, 0, 0);
    if (judge->unk28_model != NULL)
        swrModel_NodeModifyFlags(judge->unk28_model, 2, 3, 0x10, 2);
}

// 0x00465980
void swrObjJdge_SpawnRacer(swrObjJdge* judge, swrScore* score, int gridPos, void* podModel, int riderModel, int lodBody, int lodSelector, int duplicatePods)
{
    swrModel_Header* header = (swrModel_Header*)podModel;
    swrModel_Node* reflection = NULL; // faithful: uninitialized in the original when both podModel and lodBody are NULL
    swrModel_Node* node;
    swrRace* player;
    rdMatrix44 mirror;
    rdMatrix44 spawn;
    int i;
    static const int fullLodParts[6] = { 1, 2, 3, 4, 5, 0x47 };
    static const int fullLodParts2[4] = { 0x2a, 0x2b, 0x1c, 0x1d };

    score->unk58 = 0;
    score->unk5a = 0;
    score->results_P1_Lap = 0;
    *(short*)&score->results_P1_Position = -1;
    score->results_P1_total_time = 0.0f;
    score->results_P1_Lap1 = -1.0f;
    score->results_P1_Lap2 = -1.0f;
    score->results_P1_Lap3 = -1.0f;
    score->results_P1_Lap4 = -1.0f;
    score->results_P1_Lap5 = -1.0f;
    score->results_P1_Lap1 = 0.0f;
    score->unk7c = 0;
    score->flag &= ~3;
    player = (swrRace*)swrEvent_AllocObj('Test');
    score->obj_test_ptr = player;
    player->score_ptr = score;

    if (header != NULL) {
        swrObjJdge_podRootChildren[swrObjJdge_podRootNode.num_children++] = header->entries[0].node;
        node = &swrObjJdge_podReflectionNodes[swrObjJdge_podReflectionRootNode.num_children].node;
        swrModel_NodeInit(node, NODE_TRANSFORMED_WITH_PIVOT);
        swrObjJdge_podReflectionRootChildren[swrObjJdge_podReflectionRootNode.num_children] = node;
        // the reflection shares the pod root's children array and draws its first child Z-flipped
        node->num_children = 1;
        node->children.nodes = header->entries[0].node->children.nodes;
        rdMatrix_SetIdentity44(&mirror);
        mirror.vC.z = -1.0f;
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &mirror);
        node->flags_5 |= 1;
        swrObjJdge_podReflectionRootNode.num_children++;
        reflection = node;
        RecordLoadedModel_Maybe(header->entries[7].node, (int)&swrModel_beamTemplateNode);
        RecordLoadedModel_Maybe(header->entries[9].node, (int)&swrModel_beamTemplateNode);
        if (header->entries[0x48].node != NULL)
            swrModel_NodeModifyFlags(header->entries[0x48].node, 2, -4, 0x10, 3);
        if (header->entries[0x49].node != NULL)
            swrModel_NodeModifyFlags(header->entries[0x49].node, 2, -4, 0x10, 3);
        RecordLoadedModel_Maybe(header->entries[0x41].node, (int)&swrModel_sparkTemplateNode);
        RecordLoadedModel_Maybe(header->entries[0x42].node, (int)&swrModel_sparkTemplateNode);
    } else if (lodBody != 0) {
        swrObjJdge_podRootChildren[swrObjJdge_podRootNode.num_children++] = (swrModel_Node*)lodBody;
        swrModel_NodeModifyFlags((swrModel_Node*)lodBody, 2, 3, 0x10, 2);
    }

    swrObjJdge_GetSpawnTransform(judge, &spawn, player->score_ptr->unk14);
    swrRace_Init(player, judge->unk2c_spline, (swrModel_Node**)podModel, (swrModel_Node*)judge->unk30, player->obj.id, (float*)&spawn, gridPos, judge->num_players, NumLocalPlayers(), duplicatePods);
    player->reflectionNode = reflection;
    player->lodBodyNode = (swrModel_Node*)lodBody;
    player->lodSelectorNode = (swrModel_Node*)lodSelector;

    if (header != NULL && (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) {
        header->entries[0].node->flags_5 |= 0xc;
        header->entries[0].node->light_index = player->current_light_index;
        if (numLocalPlayers < 2) {
            for (i = 0; i < 6; i++) {
                if (header->entries[fullLodParts[i]].node != NULL)
                    header->entries[fullLodParts[i]].node->flags_5 |= 0x10;
            }
            for (i = 0; i < 4; i++) {
                if (header->entries[fullLodParts2[i]].node != NULL)
                    header->entries[fullLodParts2[i]].node->flags_5 |= 0x100;
            }
        }
    }
    SetLightColorsAndDirectionFromPrimaryLight3(player->current_light_index);
    if ((player->flags0 & swrObjTest_FLAG0_AI_SIMPLE) != 0)
        swrCam_CamState_InitMainMat4(1, 1, &player->transform, 0);
}

// 0x004663e0
void swrObjJdge_SpawnRacers(swrObjJdge* judge, swrScore* scores)
{
    int lodNode[SWR_MAX_RACERS];
    int spawnOrder[SWR_MAX_RACERS];
    int podHeader[SWR_MAX_RACERS];
    int lodNode2[SWR_MAX_RACERS];
    int riderHeader[SWR_MAX_RACERS]; // faithful: only written on the full-LOD path, garbage otherwise
    int aiSlot[SWR_MAX_RACERS];
    swrRacerData* racer;
    swrRacerData* other;
    swrModel_Header* header;
    swrModel_Header* rider;
    char* name;
    int duplicatePods;
    int lodClass;
    int i;
    int j;
    int pick;
    int slot;

    swrObjJdge_testObjBufferBytes = (int)swrAssetBuffer_GetBuffer();
    swrEvent_AllocateAndLoadObjs('Test', judge->num_players);
    swrEvent_FreeObjs('Test');
    swrObjJdge_testObjBufferBytes = (int)swrAssetBuffer_GetBuffer() - swrObjJdge_testObjBufferBytes;
    memset(swrObjJdge_racerBufferBytes, 0, sizeof(swrObjJdge_racerBufferBytes));
    for (i = 0; i < SWR_MAX_RACERS; i++)
        swrObjJdge_racerNameTags[i * 4] = 0;

    duplicatePods = 0;
    for (i = 0; i < judge->num_players; i++) {
        for (j = 0; j < judge->num_players; j++) {
            if (i != j && *scores[i].pilotId == *scores[j].pilotId)
                duplicatePods = 1;
        }
    }
    swrObjJdge_duplicatePods = duplicatePods;

    for (i = 0; i < judge->num_players; i++) {
        racer = (swrRacerData*)scores[i].pilotId;
        swrObjJdge_racerBufferBytes[i] = (int)swrAssetBuffer_GetBuffer();
        swrObjJdge_racerNameTags[i * 4] = swrText_Translate(racer->name)[2];
        swrObjJdge_racerNameTags[i * 4 + 1] = swrText_Translate(racer->name)[3];
        swrObjJdge_racerNameTags[i * 4 + 2] = swrText_Translate(racer->name)[4];
        swrObjJdge_racerNameTags[i * 4 + 3] = 0;

        // 1 = full pod + rider, 2 = full pod (split screen), 3 = low-detail pod
        lodClass = 3;
        if (scores[i].identifier == 'Locl')
            lodClass = (numLocalPlayers > 1) + 1;
        if ((judge->flag & swrObjJdge_FLAG_NON_PAUSABLE) != 0)
            lodClass = 1;
        else if (numLocalPlayers == 0)
            lodClass = 3;

        if (lodClass == 2 || lodClass == 1) {
            lodNode[i] = 0;
            lodNode2[i] = 0;
            header = swrModel_LoadFromId(racer->pod_modelID);
            podHeader[i] = (int)header;
            if (header == NULL) {
                judge->num_players = i;
                lowMemoryRacerCount = i;
            } else if (lodClass == 1 && (int)racer->pod_alt_modelID >= 0) {
                rider = swrModel_LoadFromId(racer->pod_alt_modelID);
                riderHeader[i] = (int)rider;
                if (rider == NULL) {
                    judge->num_players = i;
                    lowMemoryRacerCount = i;
                } else {
                    swrModel_FixupAltNodePointers((int*)header, (int*)rider);
                }
            }
        } else if (lodClass == 3) {
            podHeader[i] = 0;
            lodNode2[i] = 0;
            lodNode[i] = 0;
            header = swrModel_LoadFromId(racer->pod_lod_modelID);
            if (header != NULL) {
                lodNode[i] = header->entries[0].value;
                lodNode2[i] = header->entries[1].value;
            }
        } else if (lodClass == 4) {
            podHeader[i] = 0;
            lodNode2[i] = 0;
            lodNode[i] = 0;
            header = swrModel_LoadFromId(racer->unk10_modelID);
            if (header != NULL) {
                lodNode2[i] = 0;
                lodNode[i] = header->entries[0].value;
            }
        }
        swrObjJdge_racerBufferBytes[i] = (int)swrAssetBuffer_GetBuffer() - swrObjJdge_racerBufferBytes[i];
    }

    for (i = 0; i < judge->num_players; i++)
        spawnOrder[i] = -1;
    for (i = 0; i < judge->num_players; i++) {
        // pick the n-th still-free grid slot, n uniform in [0, remaining)
        pick = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * (judge->num_players - i));
        slot = -1;
        while (pick >= 0) {
            slot++;
            if (spawnOrder[slot] == -1)
                pick--;
        }
        spawnOrder[slot] = i;
    }

    slot = 1;
    for (i = 0; i < judge->num_players; i++) {
        if ((scores[i].flag & 0x20) == 0 && scores[i].identifier != 'Locl')
            aiSlot[i] = slot++;
        else
            aiSlot[i] = -1;
    }

    for (i = 0; i < judge->num_players; i++) {
        j = spawnOrder[i];
        swrObjJdge_SpawnRacer(judge, &scores[j], aiSlot[j], (void*)podHeader[j], riderHeader[j], lodNode[j], lodNode2[j], duplicatePods);
    }
}

// 0x00466BD0
unsigned int swrObjJdge_InitTrack(swrObjJdge* judge, swrScore* scores)
{
    swrScore* score;
    int i;

    rdroid_g_curRenderOptions2 = 0;
    for (i = 0; i < SWR_MAX_RACERS; i++)
        swrObjJdge_prevRacePositions[i] = i;
    swrAssetBuffer_ResetToIndex(1);
    swrObjJdge_raceBufferStart = swrAssetBuffer_GetBuffer();
    swrObjJdge_splineBufferBytes = 0;
    lowMemoryRacerCount = 0;
    swr_noop2();
    swrModel_ClearSceneAnimations();
    swrWeather_ResetParticles();
    ResetLightStreakSprites();
    ResetSunAndLensFlareSprites();
    ResetPlayerSpriteValues();

    judge->camSweepState = NULL;
    swrScoresPtr = scores;
    firstLocalPlayer = NULL;
    secondLocalPlayer = NULL;
    thirdLocalPlayer = NULL;
    fourthLocalPlayer = NULL;
    numLocalPlayers = 0;
    for (i = 0; i < judge->num_players; i++) {
        score = &scores[i];
        if (score->identifier != 'Locl')
            continue;
        numLocalPlayers++;
        if (firstLocalPlayer == NULL)
            firstLocalPlayer = score;
        else if (secondLocalPlayer == NULL)
            secondLocalPlayer = score;
        else if (thirdLocalPlayer == NULL)
            thirdLocalPlayer = score;
        else if (fourthLocalPlayer == NULL)
            fourthLocalPlayer = score;
    }

    swrModel_Node1 = NULL;
    swrModel_Node3 = NULL;
    swrModel_Node2 = NULL;
    swrModel_Node4 = NULL;
    swrObjJdge_splitscreenActive = 0;
    swrObjJdge_splitscreenWideFov = 0;
    if (numLocalPlayers > 1) {
        swrObjJdge_singleLocalViewport = 0;
        swrObjJdge_splitscreenActive = 1;
        if (judge->planetId == 6)
            swrObjJdge_splitscreenWideFov = 1;
    }
    if (judge->planetId == 3 && judge->planet_track_number == 2)
        swrObjTrig_regionGridLayout = 1;
    else if (judge->planetId == 1 && judge->planet_track_number == 0)
        swrObjTrig_regionGridLayout = 2;
    else
        swrObjTrig_regionGridLayout = 0;

    LoadTrackModels(judge);
    swrPlayerHUD_LoadRaceHUD(judge->planetId, judge->planet_track_number, (int)judge);
    LoadTrackSpline(judge);
    swrObjJdge_SetupStartingGrid(judge);
    InitPrimaryLight();
    InitAISettingsForTrack(judge);
    swrObjJdge_SpawnRacers(judge, scores);
    swrSound_ResetMusic();
    for (i = 0; i < SWR_MAX_RACERS; i++)
        swrSound_ClearSfxFlag(i, 0xff0000);

    swrObjJdge_raceBufferEnd = swrAssetBuffer_GetBuffer();
    swrObjJdge_raceBufferFree = swrAssetBuffer_RemainingSize();
    swrObjJdge_raceBufferOtherBytes = swrObjJdge_raceBufferEnd - swrObjJdge_raceBufferStart;
    swrObjJdge_raceBufferSlack = SWR_RACE_BUFFER_TALLY_SIZE - swrObjJdge_raceBufferOtherBytes - swrObjJdge_raceBufferFree;
    for (i = 0; i < SWR_MAX_RACERS; i++)
        swrObjJdge_raceBufferOtherBytes -= swrObjJdge_racerBufferBytes[i];
    swrObjJdge_raceBufferOtherBytes -= swrObjJdge_testObjBufferBytes + swrObjJdge_splineBufferBytes + swrObjJdge_trackModelBufferBytes;
    swrAssetBuffer_CheckOverflow();
    // faithful: the original returns CheckOverflow's leftover EAX; the only caller ignores it
    return 0;
}

// 0x00466e40
void swrObjJdge_ToggleSkyboxVisibility_Maybe(int unused, unsigned char mode)
{
    if ((mode & 4) == 0) {
        swrRender_frameClearFlags &= ~swrRender_FRAME_CLEAR_COLOR;
        if (someRootNodeChildNodes[0] != NULL)
            swrModel_NodeModifyFlags(someRootNodeChildNodes[0], 2, 3, 0x10, 2);
    } else {
        // no skybox: clear the frame instead
        swrRender_frameClearFlags |= swrRender_FRAME_CLEAR_COLOR;
        if (someRootNodeChildNodes[0] != NULL)
            swrModel_NodeModifyFlags(someRootNodeChildNodes[0], 2, -4, 0x10, 3);
    }
    if ((swrRace_DebugFlag & 0x200) != 0 && swrRace_DebugLevel > 0 && (inRaceLocalPlayerInputBitset3[0] & 0x1100) == 0x1100) {
        swrRender_frameClearFlags |= swrRender_FRAME_CLEAR_COLOR;
        SetClearColor(0, 0, 0);
    }
}

// 0x00466ec0
void swrObjElmo_SetAnimState(swrObjElmo* elmo, int animCmd)
{
    swrModel_Animation** anims;
    float speed = elmo->animSpeed;
    float animTime = 0.1f;
    float loopStart = 0.1f;
    float loopEnd = 0.2f;
    float transition = 0.2f;
    float loopTransition = 0.2f;
    bool setLoop = true;
    int apply = 1;
    int choiceCount = 5;
    int atWattoCounter = 0;
    int prevState;
    int choice;
    float angle;
    rdVector3 delta;
    swrObjElmo* other;

    if (elmo->unkc_index == -1)
        return;
    prevState = elmo->animCmd;
    elmo->animCmd = animCmd;
    elmo->unk18_ms = 0.0f;
    if (elmo->kind == swrObjElmo_KIND_UNUSED_6)
        return;

    if (speed < 0.0f)
        speed = -speed;
    swrObjElmo_CheckReachedTarget(elmo);
    anims = (swrModel_Animation**)elmo->unk34;
    for (int i = 0; anims[i] != NULL; i++)
        anims[i]->flags |= ANIMATION_ENABLED;

    switch (elmo->animCmd) {
    case 0:
        elmo->animSpeed = 0.0f;
        for (int i = 0; anims[i] != NULL; i++)
            anims[i]->flags &= ~ANIMATION_ENABLED;
        break;
    case 1:
        setLoop = false;
        switch ((int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 5.0f)) {
        case 0:
            elmo->unk88 = 0x1b;
            break;
        case 1:
            elmo->unk88 = 0x1c;
            break;
        case 2:
            elmo->unk88 = 0xf;
            break;
        case 3:
            elmo->unk88 = 0x19;
            break;
        default:
            elmo->unk88 = 0x1a;
            break;
        }
        break;
    case 2:
    case 0x21:
        elmo->unk88 = 0xf;
        setLoop = false;
        break;
    case 4:
    case 5:
        elmo->unk88 = 0x10;
        setLoop = false;
        break;
    case 6:
        setLoop = false;
        elmo->unk88 = 0xb;
        if (prevState == 6)
            transition = 0.0f;
        break;
    case 7:
        elmo->unk88 = 0x13;
        setLoop = false;
        break;
    case 8:
        playASound((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.3 ? 0x31 : 0x32, 6, 0.25f, 0.5f, 0);
        elmo->unk88 = 0x14;
        transition = 0.0f;
        break;
    case 9:
        elmo->unk88 = 0x15;
        transition = 0.0f;
        setLoop = false;
        break;
    case 0xa:
        elmo->unk88 = 8;
        setLoop = false;
        break;
    case 0xb:
        elmo->unk88 = 9;
        transition = 0.0f;
        loopTransition = 0.0f;
        break;
    case 0xc:
        elmo->unk88 = 10;
        transition = 0.0f;
        setLoop = false;
        break;
    case 0xd:
    case 0x36:
    case 0x3b:
    case 0x40:
        elmo->unk88 = 3;
        setLoop = false;
        break;
    case 0xe:
        transition = 0.0f;
        elmo->unk88 = 4;
        elmo->unk1c_ms = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 4.0f + 8.0f;
        break;
    case 0xf:
        setLoop = false;
        elmo->unk88 = 5;
        transition = 0.0f;
        break;
    case 0x10:
        setLoop = false;
        elmo->unk88 = 0;
        break;
    case 0x11:
        elmo->unk88 = 5;
        if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_NO_PIT_DROID_CHATTER) != 0)
            break;
        if (swrObjHang_lastMenuScreen == swrObjHang_STATE_JUNKYARD || swrObjHang_lastMenuScreen == swrObjHang_STATE_WATTO) {
            if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM >= 0.15f)
                break;
            if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM <= 0.998f) {
                swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 1, 5, 0x12, 0xe, 8, NULL);
            } else {
                swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 6, 9, 6, 9, 6, NULL);
            }
        } else if (swrObjHang_lastMenuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
            if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.05f) {
                if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5f) {
                    swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 0xc, 7, 5, 1, 0xb, NULL);
                } else {
                    swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 8, 7, 5, 3, 0xc, NULL);
                }
            } else if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.001f) {
                swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 6, 9, 6, 9, 6, NULL);
            }
        }
        break;
    case 0x12:
        if (elmo->moveTarget.x == maybeUICameraPlacements[1].position2.x && elmo->moveTarget.y == maybeUICameraPlacements[1].position2.y) {
            choiceCount = 2;
            atWattoCounter = 1;
        }
        choice = (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * choiceCount);
        if (choice == elmo->unka4)
            choice++;
        if (choice >= choiceCount)
            choice = 0;
        elmo->unka4 = choice;
        setLoop = false;
        switch (choice) {
        case 0:
            elmo->unk88 = atWattoCounter ? 4 : 3;
            break;
        case 1:
            elmo->unk88 = atWattoCounter ? 8 : 6;
            break;
        case 2:
            elmo->unk88 = 7;
            break;
        case 3:
            elmo->unk88 = 4;
            break;
        default:
            elmo->unk88 = 8;
            break;
        }
        break;
    case 0x13:
        loopTransition = 0.0f;
        if (elmo->unk88 == 1)
            apply = 0;
        elmo->unk88 = 1;
        break;
    case 0x14:
        rdVector_Sub3(&delta, &elmo->moveTarget, &elmo->position);
        delta.z = 0.0f;
        if (elmo->reachedTarget != 0) {
            angle = elmo->yawTarget;
        } else {
            angle = stdMath_ArcTan2(-delta.x, delta.y);
        }
        angle -= elmo->yaw;
        if (angle < -180.0f)
            angle += 360.0f;
        if (angle > 180.0f)
            angle -= 360.0f;
        elmo->unk88 = 1;
        if (angle > 5.0f || angle < -5.0f) {
            if (angle > 85.0f && angle < 175.0f) {
                elmo->unk88 = 0xb;
                setLoop = false;
            }
            if (angle < -85.0f && angle > -175.0f) {
                elmo->unk88 = 0xb;
                setLoop = false;
                speed = -1.0f;
            }
            if (angle > 175.0f || angle < -175.0f) {
                elmo->unk88 = 0xc;
                setLoop = false;
            }
        }
        loopTransition = 0.0f;
        if (prevState == 0x13 && elmo->unk88 == 1)
            apply = 0;
        break;
    case 0x18:
        elmo->unk88 = 9;
        break;
    case 0x19:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.75) {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(10, 0xb, 0xc, 0xd, 0x12);
        } else {
            swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 2, 2, 2, 2, 2, NULL);
        }
        elmo->unk88 = 9;
        setLoop = false;
        other = (swrObjElmo*)swrEvent_GetItem('Elmo', 0x15);
        if (other->animCmd == 0x20) {
            swrObjElmo_SetAnimState(other, 0x25);
        } else if (other->animCmd == 0x1d) {
            swrObjElmo_SetAnimState(other, 0x23);
        }
        break;
    case 0x1a:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.75) {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(2, 0x1f, 7, 8, 9);
        } else {
            swrSound_PlayRandomSfx(0, swrRace_UnlockDataBase[0], 3, 3, 3, 5, 5, NULL);
        }
        elmo->unk88 = 10;
        setLoop = false;
        other = (swrObjElmo*)swrEvent_GetItem('Elmo', 0x15);
        if (other->animCmd == 0x20) {
            swrObjElmo_SetAnimState(other, 0x26);
        } else if (other->animCmd == 0x1d) {
            swrObjElmo_SetAnimState(other, 0x24);
        }
        break;
    case 0x1b:
        // the EXE also walks the anim list here without touching it
        elmo->unk88 = 0xd;
        break;
    case 0x1c:
        elmo->unk88 = 0xd;
        break;
    case 0x1d:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5f) {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x30, 0x31, 0x32, 0x22, 0x2b);
        } else if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5f) {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x23, 0x24, 0x25, 0x26, 0x27);
        } else if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.8f || swrRace_UnlockDataBase[0] == 2) {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x18, 0x2e, 0x13, 0x29, 0x2b);
        } else {
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x19, 0x20, 0x2c, 0x19, 0x20);
        }
        loopTransition = 0.0f;
        transition = 0.0f;
        elmo->unk88 = 0;
        elmo->unk1c_ms = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 2.0f + 3.0f;
        break;
    case 0x1f:
        setLoop = false;
        elmo->unk88 = 0xb;
        transition = 0.0f;
        break;
    case 0x20:
        elmo->unk88 = 0xc;
        elmo->unk1c_ms = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 2.0f + 3.0f;
        break;
    case 0x22:
    case 0x1e:
        elmo->unk88 = 0;
        loopTransition = 0.0f;
        transition = 0.0f;
        break;
    case 0x23:
    case 0x25:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f)
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0xb, 0xc, 0xd, 0x2d, 0x14);
        elmo->unk88 = elmo->animCmd == 0x23 ? 3 : 0xd;
        setLoop = false;
        break;
    case 0x24:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f)
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x12, 0x28, 0x36, 0xe, 0x17);
        elmo->unk88 = 1;
        setLoop = false;
        break;
    case 0x26:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f)
            swrObjElmo_PlayRandomVoiceSfx_Maybe(0x12, 0x28, 0x36, 0xe, 0x17);
        // fallthrough
    case 3:
        elmo->unk88 = 0xe;
        setLoop = false;
        break;
    case 0x27:
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25f) {
            if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.8f || swrRace_UnlockDataBase[0] == 2) {
                swrObjElmo_PlayRandomVoiceSfx_Maybe(0x2a, 0x32, 0x31, 0x33, 0x13);
            } else {
                swrObjElmo_PlayRandomVoiceSfx_Maybe(0x2c, 0x19, 0x20, 0x2c, 0x19);
            }
        }
        // fallthrough
    case 0x2d:
    case 0x31:
        setLoop = false;
        elmo->unk88 = 2;
        loopTransition = 0.0f;
        transition = 0.0f;
        break;
    case 0x2b:
    case 0x2f:
    case 0x33:
    case 0x38:
    case 0x3d:
        setLoop = false;
        elmo->unk88 = 0;
        loopTransition = 0.0f;
        transition = 0.0f;
        break;
    case 0x2c:
    case 0x30:
    case 0x34:
    case 0x39:
    case 0x3e:
        elmo->unk88 = 1;
        loopTransition = 0.0f;
        transition = 0.0f;
        break;
    case 0x2e:
        elmo->unk88 = 3;
        loopTransition = 0.0f;
        speed = 0.5f;
        break;
    case 0x32:
        elmo->unk88 = 3;
        loopTransition = 0.0f;
        break;
    case 0x35:
    case 0x3a:
    case 0x3f:
        elmo->unk88 = 2;
        loopTransition = 0.0f;
        transition = 0.0f;
        break;
    case 0x37:
    case 0x3c:
    case 0x41:
        elmo->unk88 = 4;
        loopTransition = 0.0f;
        break;
    case 0x42:
        elmo->unk88 = 5;
        break;
    default:
        break;
    }

    if (elmo->kind == swrObjElmo_KIND_WATTO) {
        loopTransition = 0.0f;
        transition = 0.1f;
    }
    if (elmo->animCmd != 0) {
        swrObjElmo_GetAnimTiming(elmo, &loopStart, &loopEnd);
        animTime = loopStart;
    }
    if (elmo->animCmd == 0x1b && elmo->unk88 != 0xd)
        loopEnd = loopStart + 0.1f;
    if (speed < 0.0f)
        animTime = loopEnd - 0.1f;
    if (elmo->animCmd == 5) {
        loopStart = loopEnd - 0.1f;
        animTime = loopStart;
    }
    if (elmo->animCmd == 0x2a)
        loopTransition = 0.0f;
    if (apply != 0)
        swrModel_AnimationsSetSettings(anims, animTime, loopStart, loopEnd, setLoop, transition, loopTransition);
    if (elmo->animSpeed != speed) {
        elmo->animSpeed = speed;
        swrModel_SetAnimListSpeed(anims, speed);
    }
}

// 0x00467c80
void swrObjElmo_PlayRandomVoiceSfx_Maybe(int sfx1, int sfx2, int sfx3, int sfx4, int sfx5)
{
    if (swrSound_TestSfxFlag(0, 0x10) != 0 && swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING) == 0)
        swrSound_PlayRandomSfx(2, 0, sfx1, sfx2, sfx3, sfx4, sfx5, NULL);
}

// 0x00467cd0
void swrObjElmo_F0(swrObjElmo* elmo)
{
    swrModel_Animation** anims;
    float loopStart = 0.0f;
    float loopEnd = 0.0f;
    float angle;
    rdVector3 delta;

    elmo->unk18_ms = swrRace_fdeltaTimeSecs + elmo->unk18_ms;
    swrModel_CompensateRootMotion((swrModel_Node**)elmo->unk30_nodes, (swrModel_Animation**)elmo->unk34, &elmo->unk38, 30.0f);
    swrRace_GetEngineNodeOffsetPos((void**)elmo->unk30_nodes, &elmo->position);
    swrObjElmo_GetAnimTiming(elmo, &loopStart, &loopEnd);
    anims = (swrModel_Animation**)elmo->unk34;

    switch (elmo->animCmd) {
    case 0:
        return;
    case 1:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 6);
        break;
    case 3:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 2);
        break;
    case 6:
        if (elmo->unk88 == 0xc) {
            swrObjElmo_UpdateMovement(elmo);
            if (elmo->animCmd != 6)
                return;
        } else if (swrModel_GetAnimListTime(anims) >= loopEnd) {
            elmo->unkb4 = -78;
            elmo->unkb0 = 0;
            swrObjElmo_SetAnimState(elmo, 10);
        }
        break;
    case 7:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 8);
        break;
    case 8:
        playASound(0x33, 6, 0.25f, 0.5f, 1);
        if ((int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 3.0f) == 0 && loopEnd - 0.1 <= swrModel_GetAnimListTime(anims))
            swrObjElmo_SetAnimState(elmo, 9);
        break;
    case 9:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 7);
        break;
    case 0xa:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0xb);
        break;
    case 0xb:
        swrObjElmo_TurnToFaceTarget(elmo);
        swrObjElmo_CheckReachedTarget(elmo);
        if (elmo->reachedTarget != 0 && loopEnd - 0.1 <= swrModel_GetAnimListTime(anims) && swrObjElmo_TryTransition(elmo) == 0)
            return;
        break;
    case 0xc:
        if (swrModel_GetAnimListTime(anims) >= loopEnd && swrObjElmo_TryTransition(elmo) == 0)
            return;
        break;
    case 0xd:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0xe);
        break;
    case 0xe:
        if (loopEnd - 0.1 <= swrModel_GetAnimListTime(anims) && elmo->unk18_ms > elmo->unk1c_ms)
            swrObjElmo_SetAnimState(elmo, 0xf);
        break;
    case 0xf:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0xd);
        break;
    case 0x11:
        swrModel_SetAnimListSpeed(anims, swrObjHang_ambientAnimSpeed);
        elmo->unka8_ms = swrRace_fdeltaTimeSecs + elmo->unka8_ms;
        if (elmo->unka8_ms >= elmo->unkac_ms) {
            swrModel_SetAnimListSpeed((swrModel_Animation**)elmo->unk34, 1.0f);
            if (swrObjElmo_TryTransition(elmo) != 0)
                return;
            swrObjElmo_SetAnimState(elmo, 0x12);
            return;
        }
        // 1-in-101 chance per frame: the first pilot puppet drifts 5% toward its target
        if ((int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 101.0f) == 0 && elmo->unkc_index == SWR_SCENE_SLOT_PILOT_PUPPETS)
            rdVector_Scale3Add3_both(&elmo->position, 0.95f, &elmo->position, 0.05f, &elmo->moveTarget);
        swrRace_SetEngineNodeTranslation((void**)elmo->unk30_nodes, &elmo->position);
        break;
    case 0x12:
        if (swrModel_GetAnimListTime(anims) >= loopEnd) {
            int roll;

            elmo->unka8_ms = 0.0f;
            roll = swrUtils_Rand();
            elmo->unkac_ms = (float)roll * SWR_CTL_RAND_NORM + (float)roll * SWR_CTL_RAND_NORM - -3.0f;
            swrObjElmo_SetAnimState(elmo, 0x11);
            return;
        }
        break;
    case 0x13:
        rdVector_Sub3(&delta, &elmo->moveTarget, &elmo->position);
        delta.z = 0.0f;
        elmo->yaw = stdMath_ArcTan2(-delta.x, delta.y);
        if (swrObjElmo_CheckReachedTarget(elmo) != 0) {
            if (swrObjElmo_TryTransition(elmo) != 0)
                return;
            swrObjElmo_SetAnimState(elmo, 0x14);
            return;
        }
        if (swrObjHang_lastMenuScreen == swrObjHang_STATE_JUNKYARD)
            swrObjElmo_WalkIntoView(elmo);
        break;
    case 0x14:
        swrObjElmo_UpdateMovement(elmo);
        if (elmo->animCmd != 0x14)
            return;
        if (swrModel_GetAnimListTime(anims) < loopEnd || elmo->unk88 == 1)
            swrModel_GetAnimListTime(anims); // result unused
        break;
    case 0x19:
    case 0x1a:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0x11);
        break;
    case 0x1d:
        if (loopEnd - 0.1 <= swrModel_GetAnimListTime(anims) && elmo->unk18_ms > elmo->unk1c_ms) {
            if (swrObjElmo_GetWaypointIndex(elmo) == 4) {
                if ((int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 6.0f) == 0) {
                    rdVector_Copy3(&elmo->moveTarget, &swrObjElmo_waypoints[3]);
                    swrObjElmo_SetAnimState(elmo, 0x22);
                    break;
                }
            } else if (swrObjElmo_GetWaypointIndex(elmo) != 5) {
                break;
            }
            swrObjElmo_SetAnimState(elmo, 0x27);
        }
        break;
    case 0x1e:
        if (swrObjElmo_CheckReachedTarget(elmo) == 0) {
            // Watto glides toward his target at 130 units/s
            rdVector_Sub3(&delta, &elmo->moveTarget, &elmo->position);
            rdVector_Normalize3Acc(&delta);
            rdVector_Scale3Add3(&elmo->position, &elmo->position, swrRace_fdeltaTimeSecs * 130.0f, &delta);
            swrRace_SetEngineNodeTranslation((void**)elmo->unk30_nodes, &elmo->position);
        } else {
            // face the shop counter, or the camera when parked at waypoint 5
            elmo->yawTarget = stdMath_ArcTan2(elmo->position.x - 12.0f, -116.0f - elmo->position.y);
            if (rdVector_AreSame3(&elmo->moveTarget, &swrObjElmo_waypoints[5]))
                elmo->yawTarget = stdMath_ArcTan2(elmo->position.x - swrObjHang_cameraMatrix.vD.x, swrObjHang_cameraMatrix.vD.y - elmo->position.y);
            swrObjElmo_SetAnimState(elmo, 0x22);
        }
        break;
    case 0x1f:
    case 0x25:
    case 0x26:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0x20);
        break;
    case 0x20:
        if (loopEnd - 0.1 <= swrModel_GetAnimListTime(anims) && elmo->unk18_ms > elmo->unk1c_ms)
            swrObjElmo_SetAnimState(elmo, 0x21);
        break;
    case 0x21:
        if (swrModel_GetAnimListTime(anims) >= loopEnd) {
            rdVector_Copy3(&elmo->moveTarget, &swrObjElmo_waypoints[4]);
            swrObjElmo_SetAnimState(elmo, 0x22);
        }
        break;
    case 0x22:
        swrObjElmo_UpdateMovement(elmo);
        if (elmo->animCmd != 0x22)
            return;
        break;
    case 0x23:
    case 0x24:
    case 0x27:
        if (swrModel_GetAnimListTime(anims) >= loopEnd)
            swrObjElmo_SetAnimState(elmo, 0x1d);
        break;
    case 0x28:
    case 0x29:
    case 0x2a:
    case 0x32:
    case 0x37:
    case 0x3c:
    case 0x41:
        swrModel_SetAnimListSpeed(anims, swrObjHang_ambientAnimSpeed);
        break;
    case 0x2e:
        swrModel_SetAnimListSpeed(anims, swrObjHang_ambientAnimSpeed * 0.5f);
        break;
    case 0x43:
        swrModel_SetAnimListSpeed(anims, 0.0f);
        break;
    default:
        break;
    }

    if (elmo->animCmd == 0x1b)
        return;
    if (elmo->kind == swrObjElmo_KIND_PILOT)
        angle = elmo->yaw - swrModel_GetNodeYaw((swrModel_Node**)elmo->unk30_nodes, (swrModel_Animation**)elmo->unk34);
    else
        angle = elmo->yaw;
    swrRace_SetEngineNodeRotScale((void**)elmo->unk30_nodes, elmo->scale, angle);
}

// 0x00468570
void swrObjElmo_F3(swrObjElmo* elmo)
{
    swrModel_Node* node;
    int yawStep;

    if (elmo->kind == swrObjElmo_KIND_UNUSED_6)
        return;
    if (swrObjHang_screenTransitionActive != 0 && swrRace_Transition == 0.0f && elmo->animCmd == 0x1b)
        return;
    node = elmo->unk30_nodes[0];
    if (node == NULL)
        return;
    swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
    if (elmo->animCmd == 0)
        return;
    yawStep = elmo->unkb4;
    if (yawStep == 0 || elmo->kind == swrObjElmo_KIND_PIT_DROID) {
        if (yawStep != 0) {
            elmo->unkb4 = 0;
            elmo->yaw = (float)yawStep + elmo->yaw;
            elmo->turnStartYaw = elmo->yaw;
        }
        if (elmo->kind == swrObjElmo_KIND_PIT_DROID) {
            if (elmo->unk30_nodes[3] != NULL)
                swrModel_NodeModifyFlags(elmo->unk30_nodes[3], 2, -4, 0x10, 3);
            if (elmo->animCmd != 7 && elmo->animCmd != 8 && elmo->animCmd != 9 && elmo->unk30_nodes[4] != NULL)
                swrModel_NodeModifyFlags(elmo->unk30_nodes[4], 2, -4, 0x10, 3);
        }
    }
    swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
}

// 0x00468660
int swrObjElmo_F4(swrObjElmo* elmo, int* subEvents)
{
    switch (*subEvents) {
    case 'Aloc':
    case 'Modl':
    case 'Free':
        return 1;
    case 'Load':
    case 'RSet':
        swrObj_Free(&elmo->obj);
        return 1;
    default:
        return 0;
    }
}

// 0x004686b0
void swrObjElmo_Init_Maybe(swrObjElmo* elmo, swrModel_Node** nodes, void* anims, swrObjElmo_KIND kind)
{
    if (elmo == NULL)
        return;

    elmo->obj.flags &= ~swrObj_FLAG_FREED;
    elmo->unk30_nodes = (struct swrModel_Node**)nodes;
    elmo->unk34 = anims;
    rdVector_Set3(&elmo->position, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&elmo->moveTarget, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&elmo->moveStart, 0.0f, 0.0f, 0.0f);
    elmo->unk88 = -1;
    elmo->kind = kind;
    elmo->unk10 = 0;
    elmo->animCmd = 0;
    elmo->unk18_ms = 0.0f;
    elmo->unk1c_ms = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 5.0f + 3.0f;
    rdVector_Set3(&elmo->unk20, 0.0f, 0.0f, 0.0f);
    elmo->unk2c = 0;
    rdVector_Set3(&elmo->unk38, 0.0f, 0.0f, 0.0f);
    elmo->yaw = 90.0f;
    elmo->yawTarget = 90.0f;
    elmo->turnStartYaw = 90.0f;
    elmo->turnDelta = 0.0f;
    elmo->animSpeed = 1.0f;
    elmo->unk7c = 0.0f;
    elmo->unk80 = -1.0f;
    elmo->unk84 = -1.0f;
    elmo->unk8c = 0;
    elmo->unk90 = 0;
    elmo->scale = 1.0f;
    elmo->turnDuration = 0.0f;
    elmo->turnElapsed = 0.0f;
    elmo->reachedTarget = 0;
    elmo->unka4 = -1;
    elmo->unka8_ms = 0.0f;
    elmo->unkb0 = 0;
    elmo->unkb4 = 0;
    elmo->lastWaypoint = -1;
    elmo->unkac_ms = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 2.0f + 3.0f;
}

// 0x00468800
void swrObjElmo_SetTransformAndAnimById(int elmoId, int animCmd, rdVector3* position, rdVector3* moveTarget, float yaw, float yawTarget)
{
    swrObjElmo* elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', elmoId);
    swrModel_NodeTransformed* root;
    swrTranslationRotation xf;
    rdMatrix44 m;

    if (elmo == NULL)
        return;
    rdVector_Copy3(&elmo->position, position);
    rdVector_Copy3(&elmo->moveTarget, moveTarget);
    rdVector_Copy3(&elmo->moveStart, position);
    elmo->yaw = yaw;
    elmo->yawTarget = yawTarget;
    root = (swrModel_NodeTransformed*)elmo->unk30_nodes[0];
    if (root != NULL) {
        swrModel_NodeModifyFlags((swrModel_Node*)root, 2, -4, 0x10, 3);
        rdVector_Copy3(&xf.translation, &elmo->position);
        rdVector_Set3(&xf.yaw_roll_pitch, elmo->yaw, 0.0f, 0.0f);
        rdMatrix_SetTransform44(&m, &xf);
        swrModel_NodeSetTransform(root, &m);
    }

    // per-kind model scale; pit droids also get a random animation speed
    switch (elmo->kind) {
    case swrObjElmo_KIND_PIT_DROID:
        if (elmoId < SWR_ELMO_ID_PIT_DROID_BASE + SWR_MAX_PIT_DROIDS) {
            elmo->scale = 0.3f;
            elmo->animSpeed = (float)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * (double)0.4f - -0.8);
            break;
        }
        elmo->scale = 0.3f;
        break;
    case swrObjElmo_KIND_PILOT:
        elmo->scale = (animCmd == 0x1b || animCmd == 0x1c) ? 0.1f : 0.3f;
        break;
    case swrObjElmo_KIND_WATTO:
        elmo->scale = 0.24f;
        break;
    case swrObjElmo_KIND_DEWBACK:
        elmo->scale = 2.5f;
        break;
    case swrObjElmo_KIND_RONTO:
        elmo->scale = 0.4f;
        break;
    case swrObjElmo_KIND_UNUSED_6:
        elmo->scale = 0.2f;
        break;
    case swrObjElmo_KIND_BARTENDER:
        elmo->scale = 0.23f;
        break;
    case swrObjElmo_KIND_C3PO:
        elmo->scale = 1.8f;
        break;
    case swrObjElmo_KIND_JARJAR:
    case swrObjElmo_KIND_R2D2:
        elmo->scale = 1.7f;
        break;
    case swrObjElmo_KIND_JAWA:
        elmo->scale = 1.5f;
        break;
    case swrObjElmo_KIND_QUIGON:
        elmo->scale = 2.0f;
        break;
    }
    swrRace_SetEngineNodeTranslation((void**)elmo->unk30_nodes, &elmo->position);
    swrRace_SetEngineNodeRotScale((void**)elmo->unk30_nodes, elmo->scale, elmo->yaw);
    swrModel_SetAnimListSpeed((swrModel_Animation**)elmo->unk34, elmo->animSpeed);
    swrObjElmo_SetAnimState(elmo, animCmd);
}

// 0x00468fe0
void swrObjElmo_SetAnimStateById(int elmoId, int animCmd)
{
    swrObjElmo* elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', elmoId);

    if (elmo != NULL)
        swrObjElmo_SetAnimState(elmo, animCmd);
}

// 0x00468a30
void swrObjElmo_GetAnimTiming(swrObjElmo* elmo, float* outLoopStart, float* outLoopEnd)
{
    const swrObjElmo_AnimFrames* frames;
    float frameTime = 0.0333f;

    if (elmo->unk88 == -1 && (elmo->kind == swrObjElmo_KIND_PIT_DROID || elmo->kind == swrObjElmo_KIND_PILOT || elmo->kind == swrObjElmo_KIND_UNUSED_6 || elmo->kind == swrObjElmo_KIND_WATTO))
        return;

    switch (elmo->kind) {
    case swrObjElmo_KIND_PIT_DROID:
        frames = swrObjElmo_animFramesPitDroid;
        frameTime = 0.0666f;
        break;
    case swrObjElmo_KIND_PILOT:
        frames = swrObjElmo_animFramesPilot;
        break;
    case swrObjElmo_KIND_WATTO:
        frames = swrObjElmo_animFramesWatto;
        break;
    case swrObjElmo_KIND_DEWBACK:
        *outLoopStart = 0.03333f;
        *outLoopEnd = 14.3333f;
        return;
    case swrObjElmo_KIND_RONTO:
        *outLoopStart = 0.03333f;
        *outLoopEnd = 4.2f;
        return;
    case swrObjElmo_KIND_BARTENDER:
        *outLoopStart = 0.0666f;
        *outLoopEnd = 5.0616f;
        return;
    case swrObjElmo_KIND_C3PO:
        frames = swrObjElmo_animFramesC3po;
        break;
    case swrObjElmo_KIND_JARJAR:
        frames = swrObjElmo_animFramesJarJar;
        break;
    case swrObjElmo_KIND_JAWA:
        frames = swrObjElmo_animFramesJawa;
        break;
    case swrObjElmo_KIND_QUIGON:
        frames = swrObjElmo_animFramesQuiGon;
        break;
    case swrObjElmo_KIND_R2D2:
        frames = swrObjElmo_animFramesR2d2;
        break;
    default:
        *outLoopStart = 0.0f;
        *outLoopEnd = 0.0f;
        return;
    }
    *outLoopStart = (float)frames[elmo->unk88].start * frameTime;
    *outLoopEnd = (float)frames[elmo->unk88].end * frameTime;
}

// 0x00468d00
int swrObjElmo_CheckReachedTarget(swrObjElmo* elmo)
{
    if (elmo->kind == swrObjElmo_KIND_PILOT)
        elmo->moveTarget.z = elmo->position.z;
    elmo->reachedTarget = rdVector_Dist3(&elmo->moveTarget, &elmo->position) <= 10.0f ? 1 : 0;
    return elmo->reachedTarget;
}

// 0x00468d50
void swrObjElmo_UpdateMovement(swrObjElmo* elmo)
{
    rdVector3 delta;
    float targetYaw;
    float diff;
    float turnRate;

    if (swrObjElmo_moveHoldFrames > 0) {
        swrObjElmo_moveHoldFrames--;
        return;
    }
    rdVector_Sub3(&delta, &elmo->moveTarget, &elmo->position);
    if (elmo->kind == swrObjElmo_KIND_PILOT)
        delta.z = 0.0f;
    // the original compares position.z bit-exactly against -145.0f and -60.0f
    if (rdVector_Len3(&delta) <= 35.0f && elmo->position.z == -145.0f)
        elmo->reachedTarget = 1;
    if (elmo->reachedTarget != 0) {
        targetYaw = elmo->yawTarget;
    } else {
        targetYaw = stdMath_ArcTan2(-delta.x, delta.y);
        swrObjElmo_CheckReachedTarget(elmo);
    }
    diff = targetYaw - elmo->yaw;
    if (diff < -180.0f)
        diff -= -360.0f;
    if (diff > 180.0f)
        diff -= 360.0f;
    turnRate = elmo->position.z == -60.0f ? 2.0f : 1.0f;
    if (diff <= 5.0f && diff >= -5.0f) {
        elmo->yaw = targetYaw;
        switch (elmo->kind) {
        case swrObjElmo_KIND_PILOT:
            swrObjElmo_SetAnimState(elmo, elmo->reachedTarget != 0 ? 0x11 : 0x13);
            break;
        case swrObjElmo_KIND_WATTO:
            if (elmo->reachedTarget == 0)
                swrObjElmo_SetAnimState(elmo, 0x1e);
            else if (elmo->moveTarget.x == swrObjElmo_waypoints[3].x)
                swrObjElmo_SetAnimState(elmo, 0x1f);
            else
                swrObjElmo_SetAnimState(elmo, 0x1d);
            break;
        case swrObjElmo_KIND_PIT_DROID:
            swrObjElmo_SetAnimState(elmo, 10);
            break;
        default:
            break;
        }
        return;
    }
    // 90 degrees per second, doubled on the hangar floor (z == -60)
    elmo->turnDuration = turnRate * diff * (1.0f / 90.0f);
    if (elmo->turnDuration < 0.0f)
        elmo->turnDuration = -elmo->turnDuration;
    elmo->turnElapsed = 0.0f;
    elmo->turnStartYaw = elmo->yaw;
    elmo->turnDelta = diff;
    if (elmo->turnDuration > 0.0f) {
        elmo->turnElapsed = swrRace_fdeltaTimeSecs;
        if (swrRace_fdeltaTimeSecs > elmo->turnDuration)
            elmo->turnElapsed = elmo->turnDuration;
        elmo->yaw = elmo->turnElapsed / elmo->turnDuration * diff + elmo->yaw;
        if (elmo->yaw < -180.0f)
            elmo->yaw -= -360.0f;
        if (elmo->yaw > 180.0f)
            elmo->yaw -= 360.0f;
    }
}

// 0x00469010
void swrObjHang_TickHolotableSpin_Maybe(void)
{
    swrObjHang_ambientAnimPhase += swrRace_fdeltaTimeSecs;
    if (swrObjHang_ambientAnimPhase > 6.26666f)
        swrObjHang_ambientAnimPhase -= 6.26666f;
    swrObjHang_ambientAnimSpeed = swrObjHang_EaseSine_Maybe(swrObjHang_ambientAnimPhase, 3.13333f) * 0.15957463f + 0.5;
}

// 0x00469070
void swrObjElmo_WalkIntoView(swrObjElmo* elmo)
{
    rdVector3 lookDir;
    rdVector3 toElmo;
    rdVector3 walkDir;
    int steps = 0;

    rdVector_Sub3(&walkDir, &elmo->moveTarget, &elmo->position);
    rdVector_Sub3(&lookDir, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Sub3(&toElmo, &elmo->position, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Normalize3Acc(&walkDir);
    rdVector_Normalize3Acc(&lookDir);
    rdVector_Normalize3Acc(&toElmo);
    // step along the walk path (max 40 steps) until within 60 degrees of the camera's view axis
    while (rdVector_Dot3(&lookDir, &toElmo) < 0.5 && steps < 40) {
        rdVector_Scale3Add3(&elmo->position, &elmo->position, swrRace_fdeltaTimeSecs * 130.0f, &walkDir);
        rdVector_Sub3(&lookDir, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        rdVector_Sub3(&toElmo, &elmo->position, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        rdVector_Normalize3Acc(&lookDir);
        rdVector_Normalize3Acc(&toElmo);
        steps++;
    }
    if (steps > 0)
        swrRace_SetEngineNodeTranslation((void**)elmo->unk30_nodes, &elmo->position);
}

// 0x004691c0
int swrObjElmo_GetWaypointIndex(swrObjElmo* elmo)
{
    int i;

    for (i = 0; i < SWR_ELMO_NUM_WAYPOINTS; i++) {
        if (elmo->moveTarget.x == swrObjElmo_waypoints[i].x && elmo->moveTarget.y == swrObjElmo_waypoints[i].y)
            return i;
    }
    return -1;
}

// 0x00469200
void swrObjElmo_SetTargetWaypoint(swrObjElmo* elmo, int waypoint)
{
    rdVector_Copy3(&elmo->moveTarget, &swrObjElmo_waypoints[waypoint]);
    elmo->reachedTarget = 0;
}

// 0x00469230
int swrObjElmo_TryTransition(swrObjElmo* elmo)
{
    int waypoint = swrObjElmo_GetWaypointIndex(elmo);

    switch (waypoint) {
    case 0:
        swrObjElmo_SetTargetWaypoint(elmo, 1);
        break;
    case 1:
        swrObjElmo_SetTargetWaypoint(elmo, 2);
        break;
    case 2:
        swrObjElmo_SetAnimState(elmo, 0);
        elmo->lastWaypoint = 2;
        return 1;
    default:
        return 0;
    }
    elmo->lastWaypoint = waypoint;
    return 1;
}

// 0x004692a0
void swrObjElmo_TurnToFaceTarget(swrObjElmo* elmo)
{
    rdVector3 delta;
    float targetYaw;
    float diff;

    rdVector_Sub3(&delta, &elmo->moveTarget, &elmo->position);
    delta.z = 0.0f;
    rdVector_Len3(&delta); // result unused
    targetYaw = stdMath_ArcTan2(-delta.x, delta.y);
    diff = targetYaw - elmo->yaw;
    elmo->yawTarget = targetYaw;
    if (diff < -180.0f)
        diff -= -360.0f;
    if (diff > 180.0f)
        diff -= 360.0f;
    if (diff <= 5.0f && diff >= -5.0f) {
        elmo->yaw = targetYaw;
        return;
    }
    // 90 degrees per second toward the target
    if (diff < 0.0f)
        elmo->yaw -= swrRace_fdeltaTimeSecs * 90.0f;
    else
        elmo->yaw -= swrRace_fdeltaTimeSecs * -90.0f;
}

// Random hologram flicker: alpha 8..31 plus a fixed UV scroll.
static void swrObjHang_FlickerHoloNode(swrModel_Node* node)
{
    swrModel_MeshMaterial* material;

    swrModel_NodeSetColorsOnAllMaterials(node, 0, 0, 0, 0xff, 0, (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 24.0f - -8.0f));
    material = swrModel_NodeFindFirstMeshMaterial(node);
    if (material != NULL)
        swrModel_MeshMaterialSetTextureUVOffset(material, 0.11f, 0.11f);
}

// Spins, scales in and flickers one holotable hologram node.
static void swrObjHang_UpdateHoloNode(swrModel_Node* node, const rdVector3* anchor, float t)
{
    rdMatrix44 xf;

    rdMatrix_SetRotation44(&xf, swrObjHang_holoSpinAngle, 0.0f, 0.0f);
    rdMatrix_ScaleBasis44(&xf, 1.5f, 1.5f, 1.5f, &xf);
    // grows tall first, then wide
    if (t < 0.5f)
        rdMatrix_ScaleBasis44(&xf, 0.1f, 0.1f, t + t, &xf);
    else
        rdMatrix_ScaleBasis44(&xf, (t - 0.5f) + (t - 0.5f), (t - 0.5f) + (t - 0.5f), 1.0f, &xf);
    rdVector_Copy3((rdVector3*)&xf.vD, anchor);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &xf);
    swrObjHang_FlickerHoloNode(node);
    if (t > 0.0f)
        swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
    else
        swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
}

// 0x00469380
void swrObjHang_UpdateCantinaHolotable(int menuScreen)
{
    rdVector3 ambientFrom = { 80.0f, 75.0f, 50.0f };
    rdVector3 colorFrom = { 235.0f, 100.0f, 0.0f };
    rdVector3 directionFrom = { 0.0f, -100.0f, 400.0f };
    rdVector3 ambientTo = { 20.0f, 65.0f, 40.0f };
    rdVector3 colorTo = { 255.0f, 255.0f, 200.0f };
    rdVector3 directionTo;
    rdVector3 ambient;
    rdVector3 color;
    rdVector3 direction;
    rdMatrix44 xf;
    rdMatrix44 world;
    swrObjElmo* holo;
    swrObjElmo* droid;
    swrModel_Node* node;
    float t;
    float fade;
    float vehicleFade;

    t = swrObjHang_holotableActive != 0 ? swrRace_Transition : 0.0f;
    fade = 0.0f;
    rdVector_Sub3(&directionTo, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    directionTo.z = 400.0f;
    rdVector_Scale3Add3_both(&ambient, 1.0 - t, &ambientFrom, t, &ambientTo);
    rdVector_Scale3Add3_both(&color, 1.0 - t, &colorFrom, t, &colorTo);
    rdVector_Scale3Add3_both(&direction, 1.0 - t, &directionFrom, t, &directionTo);
    SetLightColorsAndDirection2(-1, &ambient, &color, &direction);

    t = swrRace_Transition;
    holo = (swrObjElmo*)swrEvent_GetItem('Elmo', 4);
    if (swrObjHang_holotableInitScreen == -1) {
        swrObjHang_holotableInitScreen = menuScreen;
        swrModel_GetNodeTranslation_Maybe(&swrObjHang_holoAnchor2, (int)holo, 2);
        swrModel_GetNodeTranslation_Maybe(&swrObjHang_holoAnchor8, (int)holo, 8);
        swrModel_GetNodeTranslation_Maybe(&swrObjHang_holoAnchor4, (int)holo, 4);
        swrModel_GetNodeTranslation_Maybe(&swrObjHang_holoAnchor5, (int)holo, 5);
    }
    swrObjHang_holoSpinAngle = swrObjHang_holoSpinAngle - swrRace_fdeltaTimeSecs * -9.0f;
    if (swrObjHang_holoSpinAngle > 360.0f)
        swrObjHang_holoSpinAngle = swrObjHang_holoSpinAngle - 360.0f;
    if (t == 0.0f)
        swrObjHang_holoSpinAngle = 0.0f;

    node = holo->unk30_nodes[2];
    if (node != NULL) {
        if (swrObjHang_holotableActive == 0)
            t = 0.0f;
        swrObjHang_UpdateHoloNode(node, &swrObjHang_holoAnchor2, t);
    }
    // faithful: t carries over, so node 8 stays hidden whenever node 2 was zeroed
    node = holo->unk30_nodes[8];
    if (node != NULL) {
        if (swrObjHang_screenTransitionActive == 0)
            t = 0.0f;
        swrObjHang_UpdateHoloNode(node, &swrObjHang_holoAnchor8, t);
    }

    if (swrObjHang_screenTransitionActive != 0)
        fade = swrRace_Transition;
    node = holo->unk30_nodes[5];
    if (node != NULL) {
        rdMatrix_SetIdentity44(&xf);
        rdVector_Copy3((rdVector3*)&xf.vD, &swrObjHang_holoAnchor5);
        xf.vD.z = xf.vD.z - (1.0f - fade) * 117.0f;
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &xf);
        node = holo->unk30_nodes[6];
        if (node != NULL) {
            if (fade > 0.0f) {
                swrObjHang_FlickerHoloNode(node);
                swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
            } else {
                swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
            }
        }

        droid = (swrObjElmo*)swrEvent_GetItem('Elmo', 0x1c);
        rdMatrix_SetIdentity44(&world);
        swrModel_ComputeNodeWorldMatrix_Maybe(holo->unk30_nodes[5], (float*)&world, holo->unk30_nodes[0], &world);
        world.vD.z = world.vD.z - -10.0f;
        if (fade == 1.0f) {
            rdVector_Scale3Add3_both((rdVector3*)&world.vD, 0.75f, &maybeUICameraPlacements[0x24].position1, 0.25f, (rdVector3*)&world.vD);
            fade = fade * 0.25f;
        }
        swrRace_SetEngineNodeTranslation((void**)droid->unk30_nodes, (rdVector3*)&world.vD);
        swrRace_SetEngineNodeRotScale((void**)droid->unk30_nodes, droid->scale * fade, swrObjHang_holoSpinAngle * 4.0f);
    }

    vehicleFade = swrObjHang_vehicleStatsFade;
    node = holo->unk30_nodes[4];
    if (node == NULL)
        return;
    rdMatrix_SetIdentity44(&xf);
    rdVector_Copy3((rdVector3*)&xf.vD, &swrObjHang_holoAnchor4);
    xf.vD.z = xf.vD.z - (1.0f - vehicleFade) * 117.0f;
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &xf);
    node = holo->unk30_nodes[7];
    if (node == NULL)
        return;
    if (vehicleFade > 0.0f) {
        swrObjHang_FlickerHoloNode(node);
        swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
    } else {
        swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
    }
}

// 0x00469b50
void swrModel_GetNodeTranslation_Maybe(rdVector3* out, int entity, int childIndex)
{
    rdMatrix44 xf;

    swrModel_NodeGetTransform((swrModel_NodeTransformed*)((swrObjElmo*)entity)->unk30_nodes[childIndex], &xf);
    rdVector_Copy3(out, (rdVector3*)&xf.vD);
}

// 0x00469b90
float swrObjHang_StepTransition(float rate)
{
    swrRace_Transition = rate * swrRace_fdeltaTimeSecs + swrRace_Transition;
    if (1.0f < swrRace_Transition)
        swrRace_Transition = 1.0f;
    if (swrRace_Transition < 0.0f)
        swrRace_Transition = 0.0f;
    return swrRace_Transition;
}

// 0x00469bf0
void swrObjHang_TickMenuRepeatDelay_Maybe(void)
{
    if (swrObjHang_menuRepeatTimer > 0.0f) {
        swrObjHang_menuRepeatTimer -= swrRace_fdeltaTimeSecs;
        if (swrObjHang_menuRepeatTimer < 0.0f)
            swrObjHang_menuRepeatTimer = 0.0f;
    }
}

// 0x00469c30
void swrObjHang_NavigateVehicleSelect(int player, float speed, int slideInWhenSettled)
{
    int stepped = 0;

    swrRace_MenuNavLeftActive = 0;
    swrRace_MenuNavRightActive = 0;
    swrRace_MenuCanScrollLeft = 0 < swrRace_MenuSelectedItem;
    swrRace_MenuCanScrollRight = swrRace_MenuSelectedItem < swrRace_MenuMaxSelection - 1;
    if ((swrUI_localPlayersInputDownBitset[player] & swrUI_INPUT_MENU_RIGHT) != 0) {
        if (swrRace_MenuSelectedItem < swrRace_MenuMaxSelection - 1) {
            swrRace_MenuNavRightActive = 1;
            if (swrObjHang_menuRepeatTimer == 0.0f || (swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_RIGHT) != 0) {
                stepped = 1;
                swrObjHang_menuRepeatDir = 1;
                swrObjHang_menuRepeatTimer = SWR_MENU_REPEAT_DELAY;
                if (0 < swrObjHang_menuRepeatCount)
                    swrObjHang_menuRepeatTimer = SWR_MENU_REPEAT_INTERVAL / speed;
            }
        } else if (swrRace_Transition == 1.0f) {
            playUISound(0x4b);
        }
    }
    if ((swrUI_localPlayersInputDownBitset[player] & swrUI_INPUT_MENU_LEFT) != 0) {
        if (swrRace_MenuSelectedItem < 1) {
            if (swrRace_Transition == 1.0f)
                playUISound(0x4b);
        } else {
            swrRace_MenuNavLeftActive = 1;
            if (swrObjHang_menuRepeatTimer == 0.0f || (swrUI_localPlayersInputPressedBitset[player] & swrUI_INPUT_MENU_LEFT) != 0) {
                stepped = 1;
                swrObjHang_menuRepeatDir = -1;
                swrObjHang_menuRepeatTimer = SWR_MENU_REPEAT_DELAY;
                if (swrObjHang_menuRepeatCount < 0)
                    swrObjHang_menuRepeatTimer = SWR_MENU_REPEAT_INTERVAL / speed;
            }
        }
    }
    // consume the low two pressed bits (meaning unidentified) while navigating
    if (swrRace_MenuNavLeftActive != 0 || swrRace_MenuNavRightActive != 0)
        swrUI_localPlayersInputPressedBitset[player] &= ~0x3;
    if (stepped) {
        if (swrObjHang_menuRepeatCount * swrObjHang_menuRepeatDir < 0)
            swrObjHang_menuRepeatCount = 0;
        swrRace_MenuSelectedItem += swrObjHang_menuRepeatDir;
        swrObjHang_menuRepeatCount += swrObjHang_menuRepeatDir;
        playUISound(0x58);
    }
    if (swrRace_MenuNavRightActive == 0 && swrRace_MenuNavLeftActive == 0)
        swrObjHang_menuRepeatCount = 0;

    if (swrObjHang_settledMenuItem == swrRace_MenuSelectedItem && swrRace_MenuNavLeftActive == 0 && swrRace_MenuNavRightActive == 0) {
        if (slideInWhenSettled != 0)
            swrObjHang_StepTransition(speed * SWR_MENU_SLIDE_RATE);
    } else {
        swrObjHang_StepTransition(speed * -SWR_MENU_SLIDE_RATE);
        if (swrRace_Transition == 0.0f)
            swrObjHang_settledMenuItem = swrRace_MenuSelectedItem;
    }
}

// 0x00469e70
void swrObjSmok_Free(swrObj* obj)
{
    swrObjSmok* smok = (swrObjSmok*)obj;

    for (int i = 0; i < smok->particleCount; i++) {
        if (smok->particleNodes[i] != NULL)
            swrModel_NodeModifyFlags(smok->particleNodes[i], 2, -4, 0x10, 3);
    }
    if (smok->ownerHandle != NULL)
        *(void**)smok->ownerHandle = NULL;
    swrObj_Free(obj);
}

// 0x00469ed0
void swrObjSmok_F0(swrObjSmok* smok)
{
    if (smok->lifetime <= 0.0f) {
        smok->lifetime = 0.0f;
        if ((smok->flags & swrObjSmok_FLAG_OWNER_MANAGED) == 0) {
            for (int i = 0; i < 5; i++) {
                if (smok->particleNodes[i] != NULL)
                    swrModel_NodeModifyFlags(smok->particleNodes[i], 2, -4, 0x10, 3);
            }
            swrObjSmok_Free(&smok->obj);
        }
        return;
    }

    int advanceFront = smok->alphaWindowFront < 1.0f;
    smok->lifetime = smok->lifetime - (float)swrRace_deltaTimeSecs;
    if (advanceFront)
        smok->alphaWindowFront = smok->alphaWindowFront - (swrRace_deltaTimeSecs * -4.0) / smok->totalLifetime;
    if (smok->lifetime < smok->totalLifetime)
        smok->alphaWindowTail = smok->alphaWindowTail - (swrRace_deltaTimeSecs * -4.0) / smok->totalLifetime;
}

// 0x00469fb0
void swrObjSmok_F3(swrObjSmok* smok)
{
    for (int i = 0; i < smok->particleCount; i++) {
        swrModel_Node* node = smok->particleNodes[i];
        if (node == NULL)
            continue;

        float phase = (float)i / (float)smok->particleCount + smok->lifetime / smok->totalLifetime;
        // Wrap into [0,1): subtracting almost-one biases the truncation below toward -inf.
        if (phase < 0.0f)
            phase -= 0.99999899f;
        float t = 1.0f - (phase - (float)(int)phase);
        if (t < 0.0f)
            t = 0.0f;
        if (t > 1.0f)
            t = 1.0f;

        // Billboard basis: Z runs along the drift velocity, X/Y span the quad.
        rdVector3 forward = smok->velocity;
        rdVector_Normalize3Acc(&forward);
        float absZ = forward.z < 0.0f ? -forward.z : forward.z;
        rdVector3 up;
        up.x = 0.0f;
        if (absZ <= 0.9) { // double compare, as in the original
            up.y = 0.0f;
            up.z = 1.0f;
        } else {
            up.y = 1.0f;
            up.z = 0.0f;
        }
        rdVector3 right;
        rdVector_Cross3(&right, &up, &forward);
        rdVector_Cross3(&up, &forward, &right);
        rdVector_Normalize3Acc(&up);
        rdVector_Normalize3Acc(&right);

        rdMatrix44 transform;
        rdMatrix_SetIdentity44(&transform);
        float width = (smok->widthStart + (smok->widthEnd - smok->widthStart) * t * t) * 0.01f;
        rdVector_Scale3((rdVector3*)&transform.vA, width, &right);
        rdVector_Scale3((rdVector3*)&transform.vB, width, &up);
        rdVector_Scale3((rdVector3*)&transform.vC, ((smok->lengthEnd - smok->lengthStart) * t * t + smok->lengthStart) * 0.01f, &forward);

        float spin = ((smok->spinRateEnd - smok->spinRateStart) * t + smok->spinRateStart) * (float)swrRace_deltaTimeSecs + smok->particleSpin[i];
        smok->particleSpin[i] = spin;
        rdMatrix_AddRotationFromVectorAngle44Before(&transform, spin, 0.0f, 0.0f, 1.0f, &transform);
        rdVector_Scale3Add3((rdVector3*)&transform.vD, (rdVector3*)&smok->transform.vD, t, &smok->velocity);

        int r = (int)(((smok->colorEnd.x - smok->colorStart.x) * t + smok->colorStart.x) * 255.0f);
        int g = (int)(((smok->colorEnd.y - smok->colorStart.y) * t + smok->colorStart.y) * 255.0f);
        int b = (int)(((smok->colorEnd.z - smok->colorStart.z) * t + smok->colorStart.z) * 255.0f);
        int a = (int)(((smok->colorEnd.w - smok->colorStart.w) * t + smok->colorStart.w) * 255.0f);

        if (t < smok->fadeInEnd && smok->fadeInEnd > 0.0f)
            a = (int)((float)a * (t / smok->fadeInEnd));
        if (t > smok->fadeOutStart && smok->fadeOutStart < 1.0f)
            a = (int)((float)a + (float)-a * ((t - smok->fadeOutStart) / (1.0 - smok->fadeOutStart)));
        if (t > smok->alphaWindowFront)
            a = (int)((float)a * (1.0f - (t - smok->alphaWindowFront) * 4.0f));
        if (t < smok->alphaWindowFront)
            a = (int)((float)a * (1.0f - (smok->alphaWindowTail - t) * 4.0f));

        if (r < 0)
            r = 0;
        if (r > 255)
            r = 255;
        if (g < 0)
            g = 0;
        if (g > 255)
            g = 255;
        if (b < 0)
            b = 0;
        if (b > 255)
            b = 255;
        if (a < 0)
            a = 0;
        if (a > 255)
            a = 255;

        swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &transform);
        swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
        if (a < 2)
            swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);

        swrModel_MeshMaterial* material = swrModel_NodeFindFirstMeshMaterial(node);
        if (material != NULL) {
            swrModel_MeshMaterialSetColors(material, 0, 0, r, g, b, a);
            swrModel_MeshMaterialSetTextureUVOffset(material, 0.0f, ((smok->uvScrollEnd - smok->uvScrollStart) * t + smok->uvScrollStart) * (float)swrRace_deltaTimeSecs);
        }
    }
}

// 0x0046a500
int swrObjSmok_F4(swrObjSmok* smok, int* subEvents)
{
    switch (*subEvents) {
    case 0x416c6f63: // 'Aloc'
        smok->type = 0;
        smok->flags = 0;
        smok->lifetime = 0.0f;
        smok->ownerHandle = NULL;
        for (int i = 0; i < 5; i++) {
            swrModel_Node* node = fireballChildNodesPtr[i + smok->obj.id * 5];
            smok->particleNodes[i] = node;
            if (node != NULL)
                swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
            smok->particleSpin[i] = 0.0f;
        }
        return 1;
    case 0x46726565: // 'Free'
        for (int i = 0; i < 5; i++)
            smok->particleNodes[i] = NULL;
        return 1;
    case 0x4c6f6164: // 'Load'
    case 0x52536574: // 'RSet'
        swrObj_Free(&smok->obj);
        smok->ownerHandle = NULL;
        return 1;
    default:
        return 0;
    }
}

// 0x0046A5E0
void swrObjSmok_SetFireballChildNodesPtr(swrModel_Node** nodes)
{
    fireballChildNodesPtr = nodes;
}

// 0x0046a5f0
swrObjSmok* swrObjSmok_Spawn(int type, int flags, float lifetime, rdVector3* pos, float scale)
{
    swrObjSmok* smok = (swrObjSmok*)swrEvent_AllocObj(0x536d6f6b); // 'Smok'
    if (smok == NULL)
        return NULL;

    smok->flags = flags;
    smok->type = type;
    smok->lifetime = lifetime;
    rdMatrix_SetDiagonal44(&smok->transform, scale, scale, scale);
    rdVector_Copy3((rdVector3*)&smok->transform.vD, pos);

    switch (type) {
    case swrObjSmok_TYPE_FIRE:
    case swrObjSmok_TYPE_EXPLOSION:
        smok->particleCount = 5;
        rdVector_Set3(&smok->velocity, 0.0f, 0.0f, scale * 10.0f);
        smok->widthEnd = scale * 5.0f;
        smok->widthStart = scale;
        smok->spinRateStart = 360.0f;
        smok->spinRateEnd = -9.0f;
        smok->lengthStart = scale * 10.0f;
        smok->uvScrollStart = 1.4f;
        smok->uvScrollEnd = 0.0f;
        smok->lengthEnd = scale * 5.0f;
        smok->totalLifetime = 3.0f;
        smok->unkac = 1.0f;
        smok->unkb0 = 0.5f;
        rdVector_Set4(&smok->colorStart, 1.0f, 1.0f, 1.0f, 1.0f);
        break;
    case swrObjSmok_TYPE_ENGINE_SMOKE:
        smok->particleCount = 5;
        rdVector_Set3(&smok->velocity, 0.0f, scale * -10.0f, 0.0f);
        smok->widthEnd = scale * 3.0f;
        smok->widthStart = scale;
        smok->spinRateStart = 360.0f;
        smok->spinRateEnd = -9.0f;
        smok->lengthStart = scale * 10.0f;
        smok->uvScrollStart = 1.4f;
        smok->uvScrollEnd = 0.0f;
        smok->totalLifetime = 3.0f;
        smok->unkac = 1.0f;
        smok->unkb0 = 0.5f;
        smok->lengthEnd = scale * 5.0f;
        rdVector_Set4(&smok->colorStart, 1.0f, 1.0f, 1.0f, 1.0f);
        break;
    case swrObjSmok_TYPE_FLAME_ATTACK:
        smok->particleCount = 5;
        rdVector_Set3(&smok->velocity, 0.0f, scale * -10.0f, 0.0f);
        smok->widthEnd = scale * 3.0f;
        smok->widthStart = scale;
        smok->spinRateStart = 360.0f;
        smok->spinRateEnd = -9.0f;
        smok->lengthStart = scale * 10.0f;
        smok->uvScrollStart = 2.4f;
        smok->uvScrollEnd = 0.5f;
        smok->totalLifetime = 3.0f;
        smok->unkac = 1.0f;
        smok->unkb0 = 0.5f;
        smok->lengthEnd = scale * 5.0f;
        rdVector_Set4(&smok->colorStart, 1.0f, 1.0f, 1.0f, 1.0f);
        break;
    default:
        return smok;
    }

    rdVector_Set4(&smok->colorEnd, 0.0f, 0.0f, 0.0f, 1.0f);
    smok->fadeInEnd = 0.1f;
    smok->fadeOutStart = 0.5f;
    smok->alphaWindowTail = 0.0f;
    smok->alphaWindowFront = 0.0f;
    return smok;
}

// 0x0046a920
void swrObjSmok_SetPosition(swrObjSmok* smok, rdVector3* pos)
{
    if (smok != NULL)
        rdVector_Copy3((rdVector3*)&smok->transform.vD, pos);
}

// 0x0046a940
void swrObjSmok_SetVelocity(swrObjSmok* smok, rdVector3* vel)
{
    if (smok != NULL)
        rdVector_Copy3(&smok->velocity, vel);
}

// 0x0046a960
void swrObjSmok_SetLifetime(swrObjSmok* smok, float lifetime)
{
    if (smok != NULL)
        smok->lifetime = lifetime;
}

// 0x0046a970
void swrObjSmok_SetOwnerHandle(swrObjSmok* smok, void* ownerHandle)
{
    if (smok != NULL)
        smok->ownerHandle = ownerHandle;
}

// 0x0046d040
void swrRace_HandleDeathSnap(swrRace* player)
{
    player->accelThrust = 0.0f;
    player->flags0 &= ~swrObjTest_FLAG0_THROTTLE_SETTLED;
    player->deathExplodeTimer -= swrRace_deltaTimeSecs;
    if (player->deathExplodeTimer > 0.0f)
        return;

    int subEvents[2] = { 'Snap', 0 };
    swrEvent_DispatchSubEvents(player, subEvents);
    for (int i = 0; i < 6; i++) {
        player->engineStatus[i] &= ~8;
        if (player->engineHealth[i] <= 0.1f)
            player->engineHealth[i] = 0.1f;
    }
    player->flags0 &= ~swrObjTest_FLAG0_RESET;
    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        swrControl_ClearDeviceState(1);
        swrControl_StopAllForceEffects(0);
        swrControl_SetForceFeedbackPlayer(player);
    }
}

// 0x0046d100
void swrRace_HandleRespawnFlag(swrRace* player)
{
    if ((player->flags0 & swrObjTest_FLAG0_RESPAWN) == 0)
        return;

    player->flags0 &= ~swrObjTest_FLAG0_RESPAWN;
    player->flags1 &= ~(swrObjTest_FLAG1_EXPLODING | swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT);
    if ((player->flags0 & swrObjTest_FLAG0_STATE_MASK) != swrObjTest_FLAG0_RACING)
        return;

    if ((player->flags0 & swrObjTest_FLAG0_DEAD) == 0)
        swrRace_HandleDeathExplosion(player);
    if (player->flags0 & swrObjTest_FLAG0_LOCAL)
        swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 0xe, 0xe, 0xe, 0xe, 0xe, (rdVector3*)&player->transform.vD);
}

// 0x0046d170
void swrObjTest_F0(swrRace* player)
{
    rdMatrix44 splinePoint;
    if (player->flags0 & swrObjTest_FLAG0_AI) {
        if ((player->flags0 & swrObjTest_FLAG0_STATE_MASK) == swrObjTest_FLAG0_RACING && (player->flags0 & (swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) == 0) {
            // an AI stuck for 5 s (2 s on the simple path) asks for a respawn
            if (player->idleTick > 5.0f || ((player->flags0 & swrObjTest_FLAG0_AI_SIMPLE) && player->idleTick > 2.0f))
                player->flags0 |= swrObjTest_FLAG0_RESPAWN;
        } else {
            player->idleTick = 0.0f;
        }
    }

    if (player->flags0 & swrObjTest_FLAG0_TP_TO_SPLINE) {
        swrRace_ResetToSpline(player, 0.5f);
        player->flags0 &= ~swrObjTest_FLAG0_TP_TO_SPLINE;
    }

    // AI Sebulba from lap 3 on: flame attack at anyone close in front
    if ((player->flags0 & swrObjTest_FLAG0_AI) && *player->score_ptr->pilotId == 2 && player->speedValue > 200.0f && player->score_ptr->results_P1_Lap + 1 >= 3) {
        rdVector3 pos = *(rdVector3*)&player->transform.vD;
        float distances[8];
        rdVector3 deltas[8];
        swrRace* nearby[8];
        int count = swrEvent_FindNearestObjects('Test', &pos, 10000.0f, NULL, 2, distances, deltas, (void**)nearby);
        for (int i = 0; i < count; i++) {
            if (nearby[i] == player)
                continue;
            rdVector3 toOther;
            rdVector_Sub3(&toOther, (rdVector3*)&nearby[i]->transform.vD, (rdVector3*)&player->transform.vD);
            if (player->transform.vA.x * toOther.x + player->transform.vA.y * toOther.y + player->transform.vA.z * toOther.z > 0.0f)
                swrRace_SpawnFlameAttack(player);
        }
    }

    if (player->score_ptr->results_P1_total_time < 10.0f)
        player->unk12_2 = 5.0f;
    if (player->flameSmokeHandle != NULL) {
        if (player->unk12_2 < 5.0f)
            player->unk12_2 = 5.0f;
    } else {
        player->unk12_2 -= swrRace_deltaTimeSecs;
    }

    player->lodDistance = (int)DistanceToNearestViewportCamera((rdVector3*)&player->transform.vD);
    if (((player->lodDistance - 400.0f) * 0.0016666667f < 1.0 || (player->flags0 & swrObjTest_FLAG0_LOCAL) || (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND)) && (player->flags1 & swrObjTest_FLAG1_SPLINE_SNAP)) {
        player->flags1 &= ~swrObjTest_FLAG1_SPLINE_SNAP;
        swrSpline_EvaluateAtOffset(&player->splineCursor, &splinePoint, 0.0f);
        player->transform.vD.x = splinePoint.vD.x;
        player->transform.vD.y = splinePoint.vD.y;
        player->transform.vD.z = splinePoint.vD.z;
        player->flags1 |= swrObjTest_FLAG1_IMMUNITY;
    }

    player->flags0 &= ~swrObjTest_FLAG0_POD_HIDDEN;
    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 && player->wallHitCooldown <= 0.0f)
        player->flags0 |= swrObjTest_FLAG0_THROTTLE_SETTLED;

    player->flags0 &= ~swrObjTest_FLAG0_CAN_CHARGE_BOOST;
    if (player->podStats.maxSpeed * 0.75 < player->speedValue && (player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) == 0 && (player->flags1 & swrObjTest_FLAG1_EXPLODING) == 0)
        player->flags0 |= swrObjTest_FLAG0_CAN_CHARGE_BOOST;

    if (player->podStats.maxSpeed < player->speedValue && (player->flags0 & swrObjTest_FLAG0_BOOSTING))
        player->flags0 |= swrObjTest_FLAG0_WAS_BOOSTING;
    else
        player->flags0 &= ~swrObjTest_FLAG0_WAS_BOOSTING;

    swrRace_CalcTargetTurnRate(player);
    if (player->wallHitCooldown > 0.0f)
        player->wallHitCooldown -= swrRace_deltaTimeSecs;
    swr_noop2();
    if (player->flags0 & swrObjTest_FLAG0_RESET)
        swrRace_HandleDeathSnap(player);
    swrRace_HandleRespawnFlag(player);
}

// 0x00470610
void swrObjTest_F3(swrRace* player)
{
    rdVector3 ambient;
    rdVector3 color;
    rdVector3 direction;
    swrScore* score;
    rdMatrix44* xf;
    float phase;
    float truncPhase;
    float level;
    int slot;
    int i;

    swrRace_ResetModelNodeFlags(player);
    if ((player->flags0 & swrObjTest_FLAG0_RESET) == 0) {
        if (swrMultiplayer_IsMultiplayerEnabled()) {
            if (player->score_ptr->identifier == 'Locl' || player->score_ptr->identifier == 'AAII')
                swrMultiplayer_PublishPodState(player);
            if (player->score_ptr->identifier == 'REMO') {
                unsigned int age = timeGetTime();
                score = player->score_ptr;
                slot = *(int*)&score->time_unk;
                age -= swrMultiplayer_aRemoteStateTime[slot];
                player->flags0 = swrMultiplayer_aRemoteFlags0[slot] | (player->flags0 & ~swrObjTest_FLAG0_REMOTE_SYNCED) | swrObjTest_FLAG0_REMOTE;
                player->flags1 = swrMultiplayer_aRemoteFlags1[slot] | (player->flags1 & ~swrObjTest_FLAG1_REMOTE_SYNCED) | swrObjTest_FLAG1_IMMUNITY;
                player->speedValue = swrMultiplayer_aRemoteSpeed[slot];
                swrRace_ExtrapolateTransform(player, &player->transform, (rdMatrix44*)((char*)&swrMultiplayer_remotePodTransform + slot * sizeof(swrRace)), (float)age * 0.001f);
            }
        }
        swrRace_PoddAnimateEngines(player);
        if (*player->score_ptr->pilotId == SWR_PILOT_NEVA_KEE) {
            rdMatrix_Copy44(&player->engineXfR, &player->cockpitXf);
            rdMatrix_Copy44(&player->engineXfL, &player->cockpitXf);
        }
        if (player->partNodes != NULL) {
            swrRace_PoddAnimateVariousThings(player);
            swrRace_PoddAnimateSteeringParts(player);
            swrRace_UpdateEngineExhaust(player, NULL, -1.0f, -1.0f);
            swrRace_UpdateScrapeSparks(player);
        }
        swrRace_UpdateEngineDamageFX(player);
        if (player->partNodes != NULL) {
            swrRace_ApplyPartSinkOffset(player);
            swrRace_UpdateEngineFireballNode((int)player);
        }
        swrRace_UpdateReflectionNode(player);
        swrRace_UpdateEngineSound(player);
        swrRace_UpdateSpinoutNodes(player);
    }

    if (player->partNodes == NULL) {
        if (player->lodBodyNode != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->lodBodyNode, &player->farLodPodXf);
        if (player->lodSelectorNode != NULL)
            swrModel_NodeSetSelectedChildNode((swrModel_NodeSelector*)player->lodSelectorNode, player->lodDistance > 100 ? 1 : 0);
    } else {
        if (player->partNodes[5] != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[5], &player->cockpitXf);
        if (player->partNodes[1] != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[1], &player->engineXfR);
        if (player->partNodes[2] != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[2], &player->engineXfL);
        if (player->partNodes[3] != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[3], &player->engineXfR2);
        if (player->partNodes[4] != NULL)
            swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[4], &player->engineXfL2);
        // shadow quads 1..3 only; partNodes[0x3d] / shadowXf0 is left alone
        xf = &player->shadowXf1;
        for (i = 0x3e; i <= 0x40; i++, xf++) {
            if (player->partNodes[i] != NULL)
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[i], xf);
        }
    }

    // respawn/death flicker: the pod's light pulses with the fractional part of timer * 4
    if ((player->flags0 & (swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 && player->current_light_index >= 0) {
        phase = player->respawnInvincibilityTimer * 4.0f;
        direction.x = 0.0f;
        direction.y = 0.0f;
        direction.z = -1.0f;
        truncPhase = phase;
        if (phase < 0.0f)
            truncPhase = phase - 0.999999f;
        level = (phase - (int)truncPhase) * 255.0f;
        ambient.x = level;
        ambient.y = level;
        ambient.z = 255.0f;
        color.x = level;
        color.y = level;
        color.z = 255.0f;
        SetLightColorsAndDirection2(player->current_light_index, &ambient, &color, &direction);
    }
}

// 0x00471760
void swrRace_PoddAnimateVariousThings(swrRace* arg0)
{
    HANG("TODO");
}

static void swrRace_SetPartTransform(swrRace* player, int part, const rdMatrix44* m)
{
    if (player->partNodes[part] != NULL)
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)player->partNodes[part], m);
}

// 0x00472A50
void swrRace_PoddAnimateSteeringParts(swrRace* a1)
{
    rdMatrix44 unusedTransform;
    rdMatrix44 m;
    float steer;
    float steerLeft;
    float steerRight;
    float steerDelta;
    float flapPitch;
    float vaneYaw;
    float yawL;
    float yawR;
    float pitchL;
    float pitchR;
    float speed;
    float spin;
    int pilot;

    if (a1->partNodes == NULL)
        return;
    pilot = *a1->score_ptr->pilotId;
    if (a1->partNodes[0x3b] != NULL)
        swrModel_NodeModifyFlags(a1->partNodes[0x3b], 2, 3, 0x10, 2);
    rdMatrix_Copy44(&unusedTransform, &a1->transform);

    // -0.05 is the double at 0x004adb58
    steer = a1->turnRateTarget * -0.05;
    if (steer < -1.0f)
        steer = -1.0f;
    else if (steer > 1.0f)
        steer = 1.0f;
    steerLeft = (steer - -1.0f) * -0.5f;
    steerRight = (1.0f - steer) * -0.5f;
    if (a1->lodDistance > 75 || a1->partNodes == NULL)
        return;

    steerDelta = steerRight - steerLeft;
    flapPitch = swrRace_SmoothEngineExhaustSize(a1, 0x2e, steerDelta * 40.0f, 0.0f, 75.0f, 75.0f, -40.0f, 40.0f);
    vaneYaw = swrRace_SmoothEngineExhaustSize(a1, 0x2f, 0.0f, 45.0f, 20.0f, 50.0f, 0.0f, 30.0f);
    yawR = swrRace_SmoothEngineExhaustSize(a1, 0x20, steerDelta * 30.0f, 45.0f, 20.0f, 50.0f, 0.0f, 30.0f);
    yawL = swrRace_SmoothEngineExhaustSize(a1, 0x12, (steerLeft - steerRight) * 30.0f, 45.0f, 20.0f, 50.0f, 0.0f, 30.0f);
    pitchR = swrRace_SmoothEngineExhaustSize(a1, 0x23, steerDelta * 30.0f, 45.0f, 80.0f, 80.0f, 0.0f, 30.0f);
    pitchL = swrRace_SmoothEngineExhaustSize(a1, 0x15, (steerLeft - steerRight) * 30.0f, 45.0f, 80.0f, 80.0f, 0.0f, 30.0f);

    // spinning parts: degrees per second, clamped to [100, 700]
    speed = a1->speedValue + a1->speedValue;
    if (speed < 100.0)
        speed = 100.0f;
    if (speed > 700.0)
        speed = 700.0f;
    spin = swrRace_deltaTimeSecs * speed + a1->partOffset[33].y;
    if (spin < -180.0)
        spin -= -360.0;
    if (spin > 180.0)
        spin -= 360.0;
    a1->partOffset[33].y = spin;

    switch (pilot) {
    case 0:
        rdMatrix_SetRotation44(&m, 0.0f, yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        rdMatrix_SetRotation44(&m, -pitchR, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x23, &m);
        rdMatrix_SetRotation44(&m, pitchR, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x16, &m);
        swrRace_SetPartTransform(a1, 0x2f, &m);
        rdMatrix_SetRotation44(&m, -pitchL, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x15, &m);
        swrRace_SetPartTransform(a1, 0x2e, &m);
        rdMatrix_SetRotation44(&m, pitchL, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x24, &m);
        break;
    case 1:
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, spin);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x12, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        rdMatrix_SetRotation44(&m, flapPitch, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x2e, &m);
        swrRace_SetPartTransform(a1, 0x2f, &m);
        break;
    case 2:
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x21, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x13, &m);
        break;
    case 3:
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, spin);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x12, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x2e, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x2f, &m);
        rdMatrix_SetRotation44(&m, flapPitch, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x30, &m);
        swrRace_SetPartTransform(a1, 0x31, &m);
        swrRace_SetPartTransform(a1, 0x32, &m);
        swrRace_SetPartTransform(a1, 0x33, &m);
        break;
    case 4:
        rdMatrix_SetRotation44(&m, -yawR, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x21, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x22, &m);
        swrRace_SetPartTransform(a1, 0x23, &m);
        rdMatrix_SetRotation44(&m, -yawL, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x13, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x14, &m);
        swrRace_SetPartTransform(a1, 0x15, &m);
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, -flapPitch);
        swrRace_SetPartTransform(a1, 0x2e, &m);
        swrRace_SetPartTransform(a1, 0x33, &m);
        break;
    case 5:
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, spin);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        swrRace_SetPartTransform(a1, 0x23, &m);
        swrRace_SetPartTransform(a1, 0x24, &m);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        swrRace_SetPartTransform(a1, 0x15, &m);
        swrRace_SetPartTransform(a1, 0x16, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x16, &m);
        swrRace_SetPartTransform(a1, 0x19, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x24, &m);
        swrRace_SetPartTransform(a1, 0x27, &m);
        break;
    case 6:
        rdMatrix_SetRotation44(&m, flapPitch, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x32, &m);
        swrRace_SetPartTransform(a1, 0x34, &m);
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, -flapPitch);
        swrRace_SetPartTransform(a1, 0x33, &m);
        swrRace_SetPartTransform(a1, 0x35, &m);
        break;
    case 7:
        rdMatrix_SetRotation44(&m, 0.0f, yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        break;
    case 8:
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, spin);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x12, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawL * -2.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        swrRace_SetPartTransform(a1, 0x15, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawR * -2.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        swrRace_SetPartTransform(a1, 0x23, &m);
        break;
    case 10:
        rdMatrix_SetRotation44(&m, -yawR, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        rdMatrix_SetRotation44(&m, yawR, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x13, &m);
        rdMatrix_SetRotation44(&m, -yawL, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        rdMatrix_SetRotation44(&m, yawL, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x21, &m);
        rdMatrix_SetRotation44(&m, vaneYaw, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x32, &m);
        swrRace_SetPartTransform(a1, 0x33, &m);
        break;
    case 12:
        rdMatrix_SetRotation44(&m, 0.0f, vaneYaw, 0.0f);
        swrRace_SetPartTransform(a1, 0x34, &m);
        swrRace_SetPartTransform(a1, 0x36, &m);
        // 0.5 is the double at 0x004ad9d8
        rdMatrix_SetRotation44(&m, 0.0f, flapPitch * 0.5, 0.0f);
        swrRace_SetPartTransform(a1, 0x32, &m);
        swrRace_SetPartTransform(a1, 0x35, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -flapPitch * 0.5, 0.0f);
        swrRace_SetPartTransform(a1, 0x33, &m);
        swrRace_SetPartTransform(a1, 0x37, &m);
        break;
    case 13:
        rdMatrix_SetRotation44(&m, 0.0f, 0.0f, spin);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x15, &m);
        rdMatrix_SetRotation44(&m, 0.0f, yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x23, &m);
        break;
    case 14:
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x24, &m);
        swrRace_SetPartTransform(a1, 0x25, &m);
        swrRace_SetPartTransform(a1, 0x26, &m);
        swrRace_SetPartTransform(a1, 0x27, &m);
        swrRace_SetPartTransform(a1, 0x28, &m);
        swrRace_SetPartTransform(a1, 0x29, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x16, &m);
        swrRace_SetPartTransform(a1, 0x17, &m);
        swrRace_SetPartTransform(a1, 0x18, &m);
        swrRace_SetPartTransform(a1, 0x19, &m);
        swrRace_SetPartTransform(a1, 0x1a, &m);
        swrRace_SetPartTransform(a1, 0x1b, &m);
        break;
    case 15:
        rdMatrix_SetRotation44(&m, 0.0f, -yawR, 0.0f);
        swrRace_SetPartTransform(a1, 0x20, &m);
        swrRace_SetPartTransform(a1, 0x21, &m);
        swrRace_SetPartTransform(a1, 0x22, &m);
        swrRace_SetPartTransform(a1, 0x23, &m);
        rdMatrix_SetRotation44(&m, 0.0f, -yawL, 0.0f);
        swrRace_SetPartTransform(a1, 0x12, &m);
        swrRace_SetPartTransform(a1, 0x13, &m);
        swrRace_SetPartTransform(a1, 0x14, &m);
        swrRace_SetPartTransform(a1, 0x15, &m);
        break;
    case 22:
        rdMatrix_SetRotation44(&m, flapPitch, 0.0f, 0.0f);
        swrRace_SetPartTransform(a1, 0x30, &m);
        swrRace_SetPartTransform(a1, 0x31, &m);
        break;
    default:
        break;
    }
}

// 0x00473e40
void swrRace_GetSplineLookahead(rdVector3* out, swrRace* racer)
{
    rdMatrix44 frame;
    rdVector3 ahead;
    rdVector3 hit;
    rdVector3 normal;
    float ray[7]; // origin xyz, direction xyz, max distance

    // drop a ray onto the track from high above a point 50 units ahead on the spline
    swrSpline_EvaluateAtOffset(&racer->splineCursor, &frame, 1.0f);
    rdVector_Scale3Add3(&ahead, (rdVector3*)&frame.vD, 50.0f, (rdVector3*)&frame.vA);
    ahead.z = ahead.z - -1000.0f;
    ray[0] = ahead.x;
    ray[1] = ahead.y;
    ray[2] = ahead.z;
    ray[3] = 0.0f;
    ray[4] = 0.0f;
    ray[5] = -1.0f;
    ray[6] = 1500.0f;
    if (swrRace_RaycastModel(racer->collisionModel, ray, &hit, &normal) < 0.0f) {
        out->x = frame.vD.x;
        out->y = frame.vD.y;
        out->z = frame.vD.z;
        return;
    }
    out->x = hit.x;
    out->y = hit.y;
    out->z = hit.z - -20.0f;
}

// 0x00473f40
void swrRace_ResetToSpline(swrRace* racer, float t)
{
    swrTranslationRotation splineRot;
    rdMatrix44 splineMat;

    swrSpline_EvaluateAtOffset(&racer->splineCursor, &splineMat, t);
    rdMatrix_ExtractTransform(&splineMat, &splineRot);
    racer->spawn_pos_rot.translation.x = splineRot.translation.x;
    racer->spawn_pos_rot.translation.y = splineRot.translation.y;
    racer->spawn_pos_rot.translation.z = splineRot.translation.z;
    racer->spawn_pos_rot.yaw_roll_pitch.x = splineRot.yaw_roll_pitch.x;
    racer->spawn_pos_rot.yaw_roll_pitch.y = splineRot.yaw_roll_pitch.y;
    racer->spawn_pos_rot.yaw_roll_pitch.z = splineRot.yaw_roll_pitch.z;
    rdMatrix_SetTransform44(&racer->transform, &racer->spawn_pos_rot);
    // clear per-race transient state bits
    racer->flags0 = racer->flags0 & ~(swrObjTest_FLAG0_THROTTLE_SETTLED | swrObjTest_FLAG0_BRAKING | swrObjTest_FLAG0_TP_TO_SPLINE | swrObjTest_FLAG0_POD_HIDDEN | swrObjTest_FLAG0_LOOK_BACK | swrObjTest_FLAG0_BOOSTING);
    racer->flags1 = racer->flags1 & ~(swrObjTest_FLAG1_FLAT_CACHE | swrObjTest_FLAG1_ON_FLAT);
    bool below = t < 0.0f;
    racer->flags0 = racer->flags0 & ~swrObjTest_FLAG0_ZOFF;
    racer->splineSampleSpacing = 0.0f;
    racer->splineTrackMesh = NULL;
    racer->splineProjResult1 = 0;
    racer->splineProjResult2 = 0;
    racer->trackOffset.w = 1.0f;
    racer->trackOffset.x = 0.0f;
    racer->trackOffset.y = 0.0f;
    racer->trackOffset.z = 1.0f;
    racer->checkpointCount = 0;
    racer->splineRebindResult = 0;
    racer->idleTick = 0.0f;
    racer->moveTick = 0;
    if (below)
        racer->lapCompMax = racer->lapComp;
    racer->throttle = 0.0f;
    racer->gravityScale = 32.0f;
    rdVector_Set3(&racer->world_gravity, 0.0f, 0.0f, -1.0f);
    racer->speedValue = 0.0f;
    racer->fallStep = 0.0f;
    racer->fallVelocity = 0.0f;
    racer->accelThrust = 0.0f;
    racer->boostValue = 0.0f;
    racer->engineTemp = 100.0f;
    rdVector_Set3(&racer->velocityDir, 0.0f, 0.0f, 0.0f);
    racer->unk1efc = 0.25f;
    racer->turnRate = 0.0f;
    racer->turnRateTarget = 0.0f;
    racer->unk10_3 = 0;
    racer->zeroGPitchRate = 0.0f;
    racer->zeroGPitchRateTarget = 0.0f;
    racer->turnModifier = 0.0f;
    racer->autoTilt = 0.0f;
    racer->contactSteerKick = 0.0f;
    racer->tiltAngleTarget = 0.0f;
    racer->tiltAngle = 0.0f;
    rdVector_Set3(&racer->velocitySlope, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&racer->velocityCollision, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&racer->velocityCollisionOpponent, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&racer->wallPushback, 0.0f, 0.0f, 0.0f);
    rdVector_Set3(&racer->bumpDirection, 0.0f, 0.0f, 1.0f);
    rdVector_Copy3(&racer->positionPrev, (rdVector3*)&racer->transform.vD);
    rdVector_Copy3(&racer->positionDeath, (rdVector3*)&racer->transform.vD);
    racer->speedLoss = 0.0f;
    racer->unk1f18 = 0;
    racer->unk11_1 = 0;
    racer->spinoutEngineAngle = 0.0f;
    racer->spinoutCockpitAngle = 0.0f;
    racer->spinoutSpinRamp = 0.0f;
    racer->unk1f14 = 0.0f;
    racer->tiltManualMult = 0.0f;
    racer->unk9 = 0;
    racer->wallHitCooldown = 0.0f;
    racer->unk19b0 = 0.0f;
    racer->groundToPodMeasure = 0.0f;
    racer->groundZ = 0.0f;
    racer->unk12_2 = 60.0f;
    racer->wobbleAmplitude = 1.0f;
    racer->unk19b4 = 1.0f;
}

// 0x004741D0
void swrRace_Explode(swrRace* player, char side)
{
    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 && (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0)
        return;
    if (player->flags1 & swrObjTest_FLAG1_EXPLODING)
        return;
    if (player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD))
        return;

    player->flags0 &= ~(swrObjTest_FLAG0_CAN_CHARGE_BOOST | swrObjTest_FLAG0_BOOSTING);
    player->flags1 |= swrObjTest_FLAG1_EXPLODING;
    player->deathExplodeTimer = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM + 2.0f;
    if (player->flags0 & swrObjTest_FLAG0_LOCAL)
        swrControl_StopAllForceEffects(0);

    int burst = 0;
    rdVector3 pos;
    rdVector3 fireballOffset = { 0.0f, 0.0f, 0.0f };
    if (side & swrRace_EXPLODE_SIDE_RIGHT) {
        pos = *(rdVector3*)&player->engineXfR.vD;
        player->flags1 |= swrObjTest_FLAG1_EXPLODING_LEFT;
        burst = 1;
        swrRace_SpawnEngineFireball(player, 1, &fireballOffset, 0.3f);
    } else if (side & swrRace_EXPLODE_SIDE_LEFT) {
        pos = *(rdVector3*)&player->engineXfL.vD;
        player->flags1 |= swrObjTest_FLAG1_EXPLODING_RIGHT;
        burst = 1;
        swrRace_SpawnEngineFireball(player, 2, &fireballOffset, 0.3f);
    }

    if (!burst) {
        swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 0xd, 0xe, 0xd, 0xe, 0xd, (rdVector3*)&player->transform.vD);
        return;
    }

    swrObjSmok_Spawn(swrObjSmok_TYPE_EXPLOSION, 0, 2.0f, &pos, 1.0f);
    swrObjSmok_Spawn(swrObjSmok_TYPE_EXPLOSION, 0, 2.2f, &pos, 3.0f);
    for (int i = 0; i < 2; i++) {
        float pick = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM;
        int sfx = pick < 0.33f ? 0x34 : (pick < 0.66f ? 0x35 : 0x36);
        float pitch = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.2 + 0.1;
        swrSound_PlaySpatialRange(sfx, 7, pitch, 1.0f, &pos, 0, 0, 10.0f, 500.0f);
    }
    swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 9, 9, 9, 9, 9, (rdVector3*)&player->transform.vD);
}

// Rounds a spline segment parameter up to the next multiple of 0.1 (inlined twice in UpdateSplineCursor).
static float swrRace_CeilSegmentT(float t)
{
    float scaled = t * -10.0f;
    if (scaled < 0.0f)
        scaled -= 0.99999994f;
    return (float)-(int)scaled * 0.1f;
}

// 0x004744b0
void swrRace_UpdateSplineCursor(swrRace* racer, rdMatrix44* out, int mode)
{
    swrSplineCursor* cursor = &racer->splineCursor;
    int requantize = mode;
    int useRaycast = mode;
    int valid;
    float ray[7];
    float nearDist;
    rdVector3 nearDelta;
    void* nearObj;

    if (mode == 0) {
        cursor->segmentT = swrRace_CeilSegmentT(cursor->segmentT);
        if (cursor->segmentT >= 1.0f) {
            cursor->segmentT = 0.0f;
            swrSpline_CursorStep(cursor->spline, 1, cursor);
        }
    }

    // ray = origin xyz, direction (0, 0, -1), length
    ray[3] = 0.0f;
    ray[4] = 0.0f;
    ray[5] = -1.0f;
    ray[6] = 5000.0f;
    do {
        void* mesh;
        valid = 1;
        if (useRaycast) {
            ray[0] = out->vD.x;
            ray[1] = out->vD.y;
            ray[2] = out->vD.z;
            mesh = (void*)swrModel_CollideRayWithModel((swrModel_NodeTransformed*)racer->collisionModel, ray);
        } else {
            mesh = swrRace_GetTrackMeshAtCursor(cursor);
        }
        if (mesh == NULL) {
            valid = 0;
        } else {
            swrModel_Behavior* behavior = swrModel_MeshGetBehavior((swrModel_Mesh*)mesh);
            if (behavior != NULL && (behavior->vehicle_reaction & (swrVehicleReaction_Lava | swrVehicleReaction_Fall | swrVehicleReaction_NRSp)) != 0)
                valid = 0;
        }

        if (valid) {
            if (swrEvent_FindNearestObjects('Test', (rdVector3*)&out->vD, 900.0f, racer, 1, &nearDist, &nearDelta, &nearObj) > 0)
                valid = 0;
        }

        if (!valid) {
            if (requantize) {
                cursor->segmentT = swrRace_CeilSegmentT(cursor->segmentT);
                requantize = 0;
                useRaycast = 0;
            } else {
                cursor->segmentT -= useRaycast ? -0.04f : -0.1f;
            }
            swrSpline_EvaluateToMatrix(cursor, out);
        } else if (!useRaycast && mode != 0) {
            cursor->segmentT -= 0.09f;
            useRaycast = 1;
            swrSpline_EvaluateToMatrix(cursor, out);
            valid = 0;
        }
    } while (!valid);
}

// Tail shared by PlaceOnTrack and HandleDeathExplosion (inlined twice in the EXE):
// engine fireball, two crash sounds, engine health floor.
static void swrRace_DeathFireballAndSounds(swrRace* player, rdVector3* pos)
{
    rdVector3* fireballPos;
    if (player->partNodes == NULL) {
        fireballPos = pos;
    } else if (player->flags1 & swrObjTest_FLAG1_EXPLODING_RIGHT) {
        fireballPos = (rdVector3*)&player->engineXfR.vD;
    } else if (player->flags1 & swrObjTest_FLAG1_EXPLODING_LEFT) {
        fireballPos = (rdVector3*)&player->engineXfL.vD;
    } else if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
        fireballPos = (rdVector3*)&player->engineXfR.vD;
    } else {
        fireballPos = (rdVector3*)&player->engineXfL.vD;
    }
    swrRace_SpawnEngineFireball(player, -1, fireballPos, 0.2f);

    for (int i = 0; i < 2; i++) {
        float pick = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM;
        int sfx = pick < 0.33f ? 0x34 : (pick < 0.66f ? 0x35 : 0x36);
        float pitch = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 0.2 + 0.1;
        swrSound_PlaySpatialRange(sfx, 7, pitch, 1.0f, pos, 0, 0, 10.0f, 500.0f);
    }

    for (int i = 0; i < 6; i++) {
        player->engineStatus[i] &= ~8;
        if (player->engineHealth[i] > 0.1f)
            player->engineHealth[i] = 0.1f;
    }
}

// 0x004746b0
void swrRace_PlaceOnTrack(swrRace* racer)
{
    rdVector3 pos;
    rdMatrix44 aheadMat;
    rdMatrix44 behindMat;

    if (racer->flags0 & swrObjTest_FLAG0_DEAD)
        return;

    pos = *(rdVector3*)&racer->transform.vD;
    racer->flags0 |= swrObjTest_FLAG0_DEAD;
    racer->flags1 &= ~(swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT);
    swrSpline_EvaluateAtOffset(&racer->splineCursor, &aheadMat, 0.005f);
    swrRace_UpdateSplineCursor(racer, &aheadMat, 0);
    swrRace_ResetToSpline(racer, 0.0f);
    // faithful: evaluated but never read
    swrSpline_EvaluateAtOffset(&racer->splineCursor, &behindMat, -0.01f);
    swrObjSmok_Spawn(swrObjSmok_TYPE_EXPLOSION, 0, 2.0f, &pos, 1.0f);
    swrObjSmok_Spawn(swrObjSmok_TYPE_EXPLOSION, 0, 2.2f, &pos, 3.0f);
    swrRace_DeathFireballAndSounds(racer, &pos);

    racer->respawnInvincibilityTimer = (racer->flags0 & swrObjTest_FLAG0_AI_SIMPLE) ? 1.0f : 5.0f;
}

// EXE: also forwards an unused 2nd stack arg to PlaceOnTrack, which never reads it.
// 0x00474970
void swrRace_HandleDeathExplosion(swrRace* player)
{
    rdVector3 pos;
    rdMatrix44 aheadMat;
    rdMatrix44 behindMat;
    struct
    {
        int event;
        swrRace* player;
        int unk;
        rdVector3* pos;
        rdVector4* aheadPos;
        rdVector4* behindPos;
    } deathEvent;

    if ((player->flags0 & swrObjTest_FLAG0_AI) && (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0) {
        swrRace_PlaceOnTrack(player);
        return;
    }
    if (player->flags0 & swrObjTest_FLAG0_DEAD)
        return;

    player->flags1 &= ~(swrObjTest_FLAG1_EXPLODING_LEFT | swrObjTest_FLAG1_EXPLODING_RIGHT);
    pos = *(rdVector3*)&player->transform.vD;
    player->flags0 = (player->flags0 & ~swrObjTest_FLAG0_BOOSTING) | swrObjTest_FLAG0_DEAD;
    player->respawnInvincibilityTimer = 10.0f;
    swrSpline_EvaluateAtOffset(&player->splineCursor, &aheadMat, 0.0f);
    swrRace_UpdateSplineCursor(player, &aheadMat, 1);
    swrRace_ResetToSpline(player, 0.0f);
    swrSpline_EvaluateAtOffset(&player->splineCursor, &behindMat, -0.01f);

    deathEvent.event = 'Deth';
    deathEvent.player = player;
    deathEvent.unk = 0;
    deathEvent.pos = &pos;
    deathEvent.aheadPos = &aheadMat.vD;
    deathEvent.behindPos = &behindMat.vD;
    swrEvent_CallF4('cMan', &deathEvent);

    swrObjSmok_Spawn(swrObjSmok_TYPE_EXPLOSION, 0, 3.2f, &pos, 3.0f);
    swrRace_DeathFireballAndSounds(player, &pos);

    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        swrControl_StopAllForceEffects(0);
        swrControl_PlayForceEffect(swrForceEffect_EXPLODING, -1, -1, -1);
        if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
            swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 0xe, 0xe, 0xe, 0xe, 0xe, (rdVector3*)&player->transform.vD);
            swrSound_ClearSfxFlag((char)player->score_ptr->sfxChannel, 0xf0000);
        }
    }
}

// Botm/KPow/T201 impact sound + rumble; nonzero when the pod is local (caller may add a grunt)
static int swrObjTest_PlayHitImpactSound(swrRace* player, swrForceEffect effect, int direction)
{
    int r;
    float gain;
    float pitch;
    unsigned int flags;

    if (!(player->lodDistance < SWR_POD_HIT_SOUND_MAX_LOD))
        return 0;

    r = swrUtils_Rand();
    gain = player->speedValue * 0.002f - 0.75f;
    pitch = (float)r * SWR_CTL_RAND_NORM * 0.3f - (-0.1f);
    if (gain > 1.0f)
        gain = 1.0f;
    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        swrControl_PlayForceEffect(effect, -1, direction, -1);
        flags = Main_sound_3dimpact;
    } else {
        flags = 0;
    }
    swrSound_PlaySpatialRange(0x37, 6, pitch, gain, (rdVector3*)&player->transform.vD, 0, flags, 10.0f, 200.0f);
    return (player->flags0 & swrObjTest_FLAG0_LOCAL) != 0;
}

// 0x00474d80
int swrObjTest_F4(swrRace* player, int* subEvent, int ghost)
{
    int kind;
    float amount;
    float share;
    int count;
    int engines[6];
    int forceDirection;
    int* query;
    float* lodTable;
    int i;

    forceDirection = -1;
    switch (*subEvent) {
    case 'Free':
    case 'Aloc':
        return 1;

    case 'Go!!':
        player->flags0 = (player->flags0 & ~swrObjTest_FLAG0_STATE_MASK) | swrObjTest_FLAG0_RACING;
        return 1;

    case 'Load':
    case 'RSet':
        swrObj_Free(&player->obj);
        return 1;

    case 'Qery':
        for (query = subEvent + 1; query[0] != 'Qery'; query += 2) {
            if (query[0] == '1st?' && (short)player->score_ptr->results_P1_Position == 1)
                *(swrRace**)query[1] = player;
            if (query[0] == '2nd?' && (short)player->score_ptr->results_P1_Position == 2)
                *(swrRace**)query[1] = player;
            if (query[0] == '3rd?' && (short)player->score_ptr->results_P1_Position == 3)
                *(swrRace**)query[1] = player;
            if (query[0] == 'CamP')
                swrRace_GetSplineLookahead((rdVector3*)query[1], player);
        }
        return 1;

    case 'RmCn':
        if ((player->flags0 & swrObjTest_FLAG0_REMOTE) && player->remoteId == subEvent[1]) {
            player->remoteControls[0] = *(int*)((char*)ghost + 8);
            player->remoteControls[1] = *(int*)((char*)ghost + 0xc);
            player->remoteControls[2] = subEvent[4];
        }
        return 1;

    case 'RmHi':
        if ((player->flags0 & swrObjTest_FLAG0_REMOTE) == 0 || player->remoteId >= 0)
            return 1;
        player->remoteId = subEvent[1];
        player->remoteControls[1] = 0;
        player->remoteControls[0] = 0;
        player->remoteControls[2] = 0;
        player->remotePose = player->spawn_pos_rot;
        return 2;

    case 'RmLc':
        if ((player->flags0 & swrObjTest_FLAG0_REMOTE) && player->remoteId == subEvent[1])
            memcpy(&player->remotePose, (char*)ghost + 8, sizeof(player->remotePose));
        return 1;

    case 'RmTh':
        if ((player->flags0 & swrObjTest_FLAG0_REMOTE) && player->remoteId == subEvent[1])
            memcpy(&player->remoteSteerTarget, (char*)ghost + 0xc, sizeof(player->remoteSteerTarget));
        return 1;

    case 'Snap':
        if (subEvent[1] < 0) {
            swrRace_ResetToSpline(player, -0.1f);
        } else if (subEvent[1] > 1) {
            swrRace_ResetToSpline(player, 0.01f);
        } else if (subEvent[1] == 1) {
            swrRace_ResetToSpline(player, 0.1f);
        } else {
            swrRace_ResetToSpline(player, 0.0f);
        }
        return 1;

    case 'sLOD':
        if (player->partNodes == NULL)
            return 1;
        if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
            lodTable = &swrObjTest_lodDistancesLocal[subEvent[1] * 8];
        } else {
            lodTable = &swrObjTest_lodDistancesAI[subEvent[1] * 8];
        }
        swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)player->partNodes[5], lodTable);
        for (i = 1; i <= 4; i++)
            swrModel_NodeSetLodDistances((swrModel_NodeLODSelector*)player->partNodes[i], lodTable + 1);
        return 1;

    case 'Hitt':
        break;

    default:
        return 0;
    }

    if (player->score_ptr == NULL)
        return 1;

    kind = subEvent[1];
    amount = *(float*)((char*)ghost + 8);
    if (player->flags0 & swrObjTest_FLAG0_WAS_BOOSTING)
        amount *= 4.0f;
    amount *= 0.0005f;
    if (player->flags0 & swrObjTest_FLAG0_LOCAL) {
        swrObjTest_hitKindLog[swrObjTest_hitLogIndex] = (char)kind;
        swrObjTest_hitAmountLog[swrObjTest_hitLogIndex] = amount;
        swrObjTest_hitLogIndex++;
        if (swrObjTest_hitLogIndex >= SWR_OBJTEST_HIT_LOG_SIZE)
            swrObjTest_hitLogIndex = 0;
    }

    switch (kind) {
    case 'Bits':
        player->fireballEngineSlot = -1;
        return 1;

    case 'Botm':
        count = (int)amount;
        if (count > 6)
            count = 6;
        if (count < 1)
            count = 1;
        player->vibrationMagnitude = 1.0f;
        share = amount / (float)count;
        for (i = 0; i < count; i++)
            swrRace_TakeDamage((int)player, (unsigned int)swrUtils_Rand() % 6, share);
        if (swrObjTest_PlayHitImpactSound(player, swrForceEffect_HARD_LANDING, -1) && (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.15f) {
            swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 7, 7, 7, 8, 8, (rdVector3*)&player->transform.vD);
        }
        return 1;

    case 'KPow':
        player->vibrationMagnitude = 1.0f;
        count = 1;
        engines[0] = 3;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
            count = 2;
            engines[1] = 0;
        }
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 4;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 1;
        share = amount / (float)count;
        for (i = 0; i < count; i++)
            swrRace_TakeDamage((int)player, engines[i], share);
        if (swrObjTest_PlayHitImpactSound(player, swrForceEffect_OBJ_COLLISION, 0) && (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.15f) {
            swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 5, 6, 5, 6, 7, (rdVector3*)&player->transform.vD);
        }
        return 1;

    case 'T201':
        share = amount * 0.33333334f;
        player->vibrationMagnitude = 1.0f;
        for (i = 0; i < 3; i++)
            swrRace_TakeDamage((int)player, (unsigned int)swrUtils_Rand() % 6, share);
        if (swrObjTest_PlayHitImpactSound(player, swrForceEffect_HARD_LANDING, -1) && (float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.15f) {
            swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 5, 6, 5, 6, 7, (rdVector3*)&player->transform.vD);
        }
        return 1;

    case 'RtFt':
    case 'LtFt':
    case 'RtSd':
    case 'LtSd':
    case 'VhLt':
        break;

    default:
        return 1;
    }

    player->vibrationMagnitude = 1.0f;
    if (kind == 'RtFt') {
        count = 1;
        engines[0] = 3;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
            count = 2;
            engines[1] = 0;
        }
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 4;
        forceDirection = 45;
    } else if (kind == 'LtFt') {
        count = 1;
        engines[0] = 0;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
            count = 2;
            engines[1] = 3;
        }
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 1;
        forceDirection = 315;
    } else if (kind == 'RtSd') {
        count = 1;
        engines[0] = 3;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
            count = 2;
            engines[1] = 4;
        }
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 5;
        forceDirection = 90;
    } else if (kind == 'LtSd') {
        count = 1;
        engines[0] = 0;
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.5) {
            engines[1] = 1;
            count = 2;
        }
        if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.25)
            engines[count++] = 2;
        forceDirection = 270;
    } else {
        count = 4;
        for (i = 0; i < 4; i++)
            engines[i] = (unsigned int)swrUtils_Rand() % 6;
        player->vehicleBumpTimer = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 6.0f - (-2.0f);
    }

    share = amount / (float)count;
    for (i = 0; i < count; i++)
        swrRace_TakeDamage((int)player, engines[i], share);

    if (!(player->lodDistance < SWR_POD_HIT_SOUND_MAX_LOD) || (player->flags0 & swrObjTest_FLAG0_LOCAL) == 0)
        return 1;
    swrControl_PlayForceEffect(swrForceEffect_OBJ_COLLISION, -1, forceDirection, -1);
    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 || !((float)swrUtils_Rand() * SWR_CTL_RAND_NORM < 0.15f))
        return 1;
    if (kind == 'VhLt') {
        swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 1, 6, 5, 6, 5, (rdVector3*)&player->transform.vD);
    } else {
        swrSound_PlayRandomSfx(1, *player->score_ptr->pilotId, 5, 6, 5, 6, 7, (rdVector3*)&player->transform.vD);
    }
    return 1;
}

// 0x0047ab40
void swrObjTest_UpdateControlAndMove(swrRace* player)
{
    rdVector3 newPos;
    int allMask = rdMatrixStack_GetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK);
    if (player->speedValue > 150.0f)
        rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK, allMask | 4);
    if (swrObjTrig_regionGridLayout != 0)
        swrRace_UpdateCollisionToggles(player);
    int anyMask = rdMatrixStack_GetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK);
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK, player->collisionToggles);
    swrObjTest_autoTiltSnapshot = player->autoTilt;

    int zeroG;
    if (player->flags0 & swrObjTest_FLAG0_ZON) {
        zeroG = 1;
        rdVector_Scale3(&player->world_gravity, -1.0f, (rdVector3*)&player->transform.vC);
        player->turnInput.y = 0.0f;
        player->turnInput.z = 0.0f;
        player->turnInput.x = 0.0f;
    } else {
        zeroG = 0;
        swrRace_ResetGravityDown(player);
        swrRace_ComputeTiltAngles((rdVector3*)&player->transform.vB, (rdVector3*)&player->transform.vA, &player->world_gravity, &player->turnInput);
    }
    player->positionPrev.x = player->transform.vD.x;
    player->positionPrev.y = player->transform.vD.y;
    player->positionPrev.z = player->transform.vD.z;
    player->nextRotation = player->turnInput;

    if (swrRace_GetDamagedEngineSides(player) != 0) {
        player->turnRateTarget = player->turnRateTarget * 0.8f;
    } else if (player->flags0 & swrObjTest_FLAG0_BOOSTING) {
        player->turnRateTarget = player->turnRateTarget * 0.5f;
    } else if (!zeroG) {
        float tilt = player->tiltManualMult;
        if (tilt < 0.0f)
            tilt = -tilt;
        player->turnRateTarget = (1.0f - tilt * 0.5f) * player->turnRateTarget;
    }

    if (player->flags1 & swrObjTest_FLAG1_MAGNET) {
        player->turnRateTarget = player->turnRateTarget * 0.5f;
        swrRace_UpdateTurn(&player->turnRate, &player->turnInput.x, player->turnRateTarget, player->podStats.turnResponse * player->paceMultiplier, player->turnModifier, player->contactSteerKick);
        // two ordered compares, not != 0: a NaN autoTilt is never added
        if (player->autoTilt > 0.0f || player->autoTilt < 0.0f)
            player->turnInput.x = player->autoTilt + player->turnInput.x;
    } else {
        swrRace_UpdateTurn(&player->turnRate, &player->turnInput.x, player->turnRateTarget, player->podStats.turnResponse * player->paceMultiplier, player->turnModifier, player->contactSteerKick + player->autoTilt);
    }

    player->turnModifier = stdMath_Decelerator(1.5f, (float)swrRace_deltaTimeSecs) * player->turnModifier;
    if (player->turnModifier < 0.5f && -player->turnModifier < 0.5f)
        player->turnModifier = 0.0f;

    if (zeroG) {
        double step = player->paceMultiplier * swrRace_deltaTimeSecs;
        if (player->zeroGPitchRate > player->zeroGPitchRateTarget) {
            player->zeroGPitchRate = player->zeroGPitchRate - step * player->podStats.turnResponse;
            if (player->zeroGPitchRate < player->zeroGPitchRateTarget)
                player->zeroGPitchRate = player->zeroGPitchRateTarget;
        } else {
            player->zeroGPitchRate = step * player->podStats.turnResponse + player->zeroGPitchRate;
            if (player->zeroGPitchRate > player->zeroGPitchRateTarget)
                player->zeroGPitchRate = player->zeroGPitchRateTarget;
        }
    }

    swrRace_IntegrateMotion(player, &player->positionPrev, &newPos, (rdVector3*)&player->transform.vB);
    if (zeroG) {
        player->terrainModel = player->splineTrackMesh;
        player->flags1 = player->flags1 | swrObjTest_FLAG1_GROUND_CACHED;
        player->surfaceSpeedFactor = 1.0f;
        player->surfaceGripFactor = 1.0f;
    }
    player->position = newPos;
    player->transform.vD.x = newPos.x;
    player->transform.vD.y = newPos.y;
    player->transform.vD.z = newPos.z;
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK, allMask);
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK, anyMask);
}

// 0x0047aee0
float swrRace_ClosestApproach2D(rdVector2* a0, float* a1, rdVector2* b0, float* b1, rdVector2* outA, rdVector2* outB, rdVector2* outDirA, rdVector2* outDirB)
{
    outDirA->x = a1[0] - a0->x;
    outDirA->y = a1[1] - a0->y;
    outDirB->x = b1[0] - b0->x;
    outDirB->y = b1[1] - b0->y;
    float relX = outDirA->x - outDirB->x;
    float relY = outDirA->y - outDirB->y;
    float relSq = relY * relY + relX * relX;
    if (relSq < 0.001f && -relSq < 0.001f)
        return -1.0f;
    float t = -(relY * (a0->y - b0->y) + relX * (a0->x - b0->x)) / relSq;
    if (t < 0.0f)
        t = 0.0f;
    if (t > 1.0f)
        t = 1.0f;
    rdVector_Scale2Add2(outA, a0, t, outDirA);
    rdVector_Scale2Add2(outB, b0, t, outDirB);
    return t;
}

// 0x0047b520
void swrObjTest_UpdatePhysicsContact(swrRace* player)
{
    rdVector3 pos;
    rdVector3 delta;
    rdVector3 up;
    float zMotion;
    int allMask = rdMatrixStack_GetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK);
    if (player->speedValue > 150.0f)
        rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK, allMask | 4);
    int anyMask = rdMatrixStack_GetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK);
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK, player->collisionToggles);

    pos = player->position;
    int zeroG = (player->flags0 & swrObjTest_FLAG0_ZON) != 0;
    player->flags1 = player->flags1 & ~swrObjTest_FLAG1_GROUND_CACHED;
    swrRace_ResolvePodCollision(player);
    if (zeroG) {
        rdVector_Scale3(&up, 1.0f, (rdVector3*)&player->transform.vC);
        zMotion = swrRace_UpdateWallContact(player, &pos.x, &player->positionPrev.x, &up);
    } else {
        zMotion = swrRace_UpdateGroundContact(player, &pos.x, (int)&player->positionPrev, &up, (int)&player->turnInput);
    }

    delta.x = pos.x - player->positionPrev.x;
    delta.y = pos.y - player->positionPrev.y;
    delta.z = pos.z - player->positionPrev.z;
    player->position = pos;
    float prevSpeed = player->speedValue;
    if (player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) {
        player->speedValue = 0.0f;
    } else {
        float dist;
        if (!zeroG && !(player->flags0 & swrObjTest_FLAG0_ZOFF))
            dist = rdVector_Len2((rdVector2*)&delta);
        else
            dist = rdVector_Len3(&delta);
        player->speedValue = dist / swrRace_deltaTimeSecs;
        if (player->transform.vB.z * delta.z + player->transform.vB.y * delta.y + player->transform.vB.x * delta.x < 0.0f)
            player->speedValue = -player->speedValue;
    }

    unsigned int flags1 = player->flags1;
    if (flags1 & swrObjTest_FLAG1_EXPLODING) {
        int slow = player->speedValue < 200.0f;
        player->deathExplodeTimer = player->deathExplodeTimer - swrRace_deltaTimeSecs;
        if (slow)
            player->flags0 = player->flags0 | swrObjTest_FLAG0_RESPAWN;
        if (player->deathExplodeTimer < 0.0f)
            player->flags0 = player->flags0 | swrObjTest_FLAG0_RESPAWN;
    }
    if ((player->flags0 & swrObjTest_FLAG0_AI) && !(flags1 & swrObjTest_FLAG1_FORCE_GROUND))
        player->flags1 = flags1 & ~swrObjTest_FLAG1_IMMUNITY;
    else
        swrRace_DeathSpeed(player, prevSpeed, prevSpeed - player->speedValue);

    if (player->flags0 & swrObjTest_FLAG0_WALL_IMPACT_CLAMP) {
        player->flags0 = player->flags0 & ~swrObjTest_FLAG0_WALL_IMPACT_CLAMP;
        if (player->accelThrust > 0.0f) {
            if (player->podStats.maxSpeed < player->speedValue) {
                player->accelThrust = 0.999f;
            } else {
                float thrust;
                if (player->speedValue < 0.0f)
                    thrust = 0.0f;
                else
                    thrust = (player->podStats.acceleration * player->speedValue) / (player->podStats.maxSpeed - player->speedValue);
                if (thrust < player->accelThrust)
                    player->accelThrust = thrust;
            }
        }
    }
    swrRace_UpdateHeat(player);

    if (!zeroG) {
        if (((float)player->lodDistance - 400.0f) * 0.0016666667f < 1.0 || (player->flags0 & swrObjTest_FLAG0_LOCAL) || (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND))
            swrRace_CalculateTiltFromTurn((int)player, (rdVector4*)&up, zMotion, &player->turnInput);
        player->turnInput.x = player->turnInput.x - player->nextRotation.x;
        player->turnInput.y = player->turnInput.y - player->nextRotation.y;
        player->turnInput.z = player->turnInput.z - player->nextRotation.z;
    }
    if (!(player->flags0 & swrObjTest_FLAG0_ZOFF) && !zeroG)
        swrRace_UpdateTurn2(player, &pos, &player->turnInput);
    else
        swrRace_UpdateSplineOrientation(player, &pos);
    swrRace_UpdateSurfaceTag(player);
    swrRace_ApplySmokProximityPush(player, &pos);

    if (player->vehicleBumpTimer > 0.0f)
        player->vehicleBumpTimer = player->vehicleBumpTimer - swrRace_deltaTimeSecs;
    if (player->respawnInvincibilityTimer > 0.0f)
        player->respawnInvincibilityTimer = player->respawnInvincibilityTimer - swrRace_deltaTimeSecs;

    unsigned int flags0 = player->flags0;
    if (flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) {
        if (player->respawnInvincibilityTimer <= 0.0f) {
            player->flags0 = flags0 & ~swrObjTest_FLAG0_RESPAWN_INVINC;
            player->flags1 = player->flags1 | swrObjTest_FLAG1_RESPAWN_RELIGHT;
        }
    } else if ((flags0 & swrObjTest_FLAG0_DEAD) && (flags0 & swrObjTest_FLAG0_AI) && player->respawnInvincibilityTimer <= 0.0f) {
        player->respawnInvincibilityTimer = 3.0f;
        player->flags0 = (flags0 & ~swrObjTest_FLAG0_DEAD) | swrObjTest_FLAG0_RESPAWN_INVINC;
    }
    if (!zeroG && (player->flags0 & swrObjTest_FLAG0_ZOFF) && zMotion < 12.0f)
        player->flags0 = player->flags0 & ~swrObjTest_FLAG0_ZOFF;

    player->unk1f18 = 0;
    if (player->flags0 & swrObjTest_FLAG0_LOCAL)
        swrControl_UpdateForceFeedback(); // EXE pushes two zero args the callee never reads
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ALL_MASK, allMask);
    rdMatrixStack_SetField_Maybe(rdMatrixStack_FIELD_COLLISION_ANY_MASK, anyMask);
}

// 0x0047b9e0
void swrObjToss_F2(swrObjToss* toss)
{
    if (toss->animTimer_ms > 0.0f) {
        toss->animTimer_ms = (float)(toss->animTimer_ms - swrRace_deltaTimeSecs);
        return;
    }
    if (toss->model != NULL)
        swrModel_NodeModifyFlags(toss->model, 2, -4, 0x10, 3);
    swrObj_Free(&toss->obj);
}

// Dust puff grows and fades over its lifetime; color channels are clamped to [1, 254].
// 0x0047ba30
void swrObjToss_F3(swrObjToss* toss)
{
    rdMatrix44 mat;
    float t;
    float scale;
    int r;
    int g;
    int b;
    int a;

    if (toss->model == NULL || toss->animDuration == 0.0f)
        return;
    t = toss->animTimer_ms / toss->animDuration;
    scale = (1.0f - t) * 6.0f + 0.5f;
    if (toss->meshMaterial != NULL) {
        r = (uint8_t)toss->r;
        g = (uint8_t)toss->g;
        b = (uint8_t)toss->b;
        a = (uint8_t)toss->a;
        if (t < 0.25f)
            a = (int)((float)a * t * 4.0f);
        if (r == 0) {
            r = 1;
        } else if (r > 254) {
            r = 254;
        }
        if (g == 0) {
            g = 1;
        } else if (g > 254) {
            g = 254;
        }
        if (b == 0) {
            b = 1;
        } else if (b > 254) {
            b = 254;
        }
        if (a < 1) {
            a = 1;
        } else if (a > 254) {
            a = 254;
        }
        swrModel_MeshMaterialSetColors((swrModel_MeshMaterial*)toss->meshMaterial, 0, 0, r, g, b, a);
        swrModel_MeshMaterialSetTextureUVOffset((swrModel_MeshMaterial*)toss->meshMaterial, 0.0f, (float)(swrRace_deltaTimeSecs * 7.5f));
    }
    rdMatrix_ScaleBasis44(&mat, 2.0f, scale, scale, &toss->transform);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)toss->model, &mat);
}

// 0x0047bba0
int swrObjToss_F4(swrObjToss* toss, int* subEvents)
{
    switch (*subEvents) {
    case 'Free':
        toss->model = NULL;
        return 1;
    case 'Aloc':
        toss->unk60 = 0;
        toss->unk64 = 0;
        toss->animTimer_ms = 0.0f;
        toss->model = dustWhirlChildNodesPtr[toss->obj.id];
        if (toss->model != NULL)
            swrModel_NodeModifyFlags(toss->model, 2, -4, 0x10, 3);
        return 1;
    case 'Load':
    case 'RSet':
        swrObj_Free(&toss->obj);
        return 1;
    default:
        return 0;
    }
}

// 0x0047BC40
int swrRace_SpawnDustKickObject(rdMatrix44* in, uint8_t r, uint8_t g, uint8_t b, int a, float life_time, int unk64)
{
    swrObjToss* toss;

    // nearly transparent puffs are not spawned; the original returns here without setting EAX
    if (a <= 15)
        return 0;
    toss = (swrObjToss*)swrEvent_AllocObj('Toss');
    if (toss == NULL)
        return 0;
    toss->animDuration = life_time;
    toss->animTimer_ms = life_time;
    toss->r = r;
    toss->unk64 = unk64;
    toss->g = g;
    toss->b = b;
    toss->a = (char)a;
    toss->meshMaterial = swrModel_NodeFindFirstMeshMaterial(toss->model);
    rdMatrix_Copy44(&toss->transform, in);
    if (toss->model != NULL)
        swrModel_NodeModifyFlags(toss->model, 2, 3, 0x10, 2);
    return 1;
}

// 0x0047BCD0
void swrObjToss_SetDustKickChildNodesPtr(swrModel_Node** nodes)
{
    dustWhirlChildNodesPtr = nodes;
}

// 0x0047bea0
void swrObjTrig_EnableFXAnimation(int index)
{
    swrModel_Animation* anim;
    swrModel_Animation** anim_ref;
    swrModel_Animation** tmp;

    anim_ref = swrObjTrig_AnimationArray[index];
    anim = *anim_ref;
    while (anim != NULL) {
        swrModel_AnimationSetFlags(anim, ANIMATION_ENABLED);
        swrModel_AnimationSetTime(*anim_ref, 0.0);
        tmp = anim_ref + 1;
        anim_ref = anim_ref + 1;
        anim = *tmp;
    }
}

// 0x0047bee0
void swrObjTrig_StopFXAnimation(int index)
{
    swrModel_Animation* anim;
    swrModel_Animation** anim_ref;
    swrModel_Animation** tmp;

    anim_ref = swrObjTrig_AnimationArray[index];
    anim = *anim_ref;
    while (anim != NULL) {
        swrModel_AnimationClearFlags(anim, ANIMATION_ENABLED);
        swrModel_AnimationSetTime(*anim_ref, 0.0);
        tmp = anim_ref + 1;
        anim_ref = anim_ref + 1;
        anim = *tmp;
    }
}

// 0x0047BF20
swrModel_Animation* swrObjTrig_AnimationActive(int index)
{
    swrModel_Animation* anim;
    swrModel_Animation** anim_ref;

    anim_ref = swrObjTrig_AnimationArray[index];
    anim = *anim_ref;
    if (anim == NULL) {
        return NULL;
    }
    while (((anim->flags & ANIMATION_ENABLED) != 0) && (anim->animation_time < anim->duration4)) {
        anim = anim_ref[1];
        anim_ref = anim_ref + 1;
        if (anim == NULL) {
            return anim;
        }
    }
    return (swrModel_Animation*)0x1;
}

// 0x0047BF70
void swrObjTrig_MaybeResetAnimation(swrObjTrig* trig)
{
    int index = -1;
    swrModel_TriggerType type = trig->trigger_type;
    switch (type) {
    case swrModel_TriggerType_BreakDestructable_100:
    case swrModel_TriggerType_BreakDestructable_102:
    case swrModel_TriggerType_BreakDestructable_201:
    case swrModel_TriggerType_BreakDestructable_212:
    case swrModel_TriggerType_MethaneVapor:
        index = 0;
        break;
    case swrModel_TriggerType_BreakDestructable_202:
        index = 1;
        break;
    case swrModel_TriggerType_LavaSplash:
        index = 5;
        break;
    default:
        break;
    }

    // methane / lava clear the trigger's enabled bit; the rest re-arm it
    if (type == swrModel_TriggerType_MethaneVapor || type == swrModel_TriggerType_LavaSplash)
        trig->trigger_description->flags &= ~1;
    else
        trig->trigger_description->flags |= 1;

    if (index != -1) {
        swrObjTrig_StopFXAnimation(index);
        if (swrObjTrig_ModelArray2[index] != NULL)
            swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[index], 2, -4, 0x10, 3);
        trig->flag &= ~swrObjTrig_FLAG_ACTIVE;
        swrObj_Free(&trig->obj);
    }

    if (trig->trigger_type == swrModel_TriggerType_SpawnFlag) {
        swrObjTrig_StopFXAnimation(2);
        if (swrObjTrig_ModelArray2[2] != NULL)
            swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[2], 2, -4, 0x10, 3);
        if (trig->unk48_node != NULL)
            swrModel_NodeModifyFlags(trig->unk48_node, 2, 3, 0x10, 2);
        trig->flag &= ~swrObjTrig_FLAG_ACTIVE;
        swrObj_Free(&trig->obj);
    }
}

// 0x0047C080
void swrObjTrig_MaybeResetAnimationByTriggerType(int type)
{
    int count = swrEvent_GetEventCount('Trig');
    for (int i = 0; i < count; i++) {
        swrObjTrig* trig = (swrObjTrig*)swrEvent_GetItem('Trig', i);
        if (trig != NULL && (trig->obj.flags & 0x100) == 0 && (trig->flag & swrObjTrig_FLAG_ACTIVE) != 0 && (short)trig->trigger_description->type == type) {
            swrObjTrig_MaybeResetAnimation(trig);
            return;
        }
    }
}

// 0x0047C0F0
swrModel_NodeTransformedWithPivot* swrObjTrig_FindNode(swrModel_TriggerDescription* desc)
{
    int i = 0;
    while (swrObjTrig_TriggerDescriptionArray2[i] != NULL && swrObjTrig_TriggerDescriptionArray2[i] != desc) {
        i++;
        if (i >= 50) // &TriggerDescriptionArray2[50] == 0xe270c8
            break;
    }
    if (swrObjTrig_TriggerDescriptionArray2[i] != NULL)
        return &swrObjTrig_NodePerTriggerArray[i];
    return NULL;
}

// 0x0047C130
swrModel_NodeTransformedWithPivot* swrObjTrig_InitNodeForTrigger(swrModel_TriggerDescription* desc)
{
    int i = 0;
    while (swrObjTrig_TriggerDescriptionArray2[i] != NULL && swrObjTrig_TriggerDescriptionArray2[i] != desc) {
        i++;
        if (i >= 50)
            break;
    }
    // only allocate a node for a not-yet-registered trigger
    if (swrObjTrig_TriggerDescriptionArray2[i] == NULL) {
        swrModel_NodeInit(&swrObjTrig_NodePerTriggerArray[i].node, NODE_TRANSFORMED_WITH_PIVOT);
        swrObjTrig_TriggerDescriptionArray2[i] = desc;
        return &swrObjTrig_NodePerTriggerArray[i];
    }
    return NULL;
}

// 0x0047C190
void swrObjTrig_SpawnEarthquakeShake(swrObjTrig* obj, int index)
{
    if ((obj->flag & swrObjTrig_FLAG_FX_SPAWNED) == 0) {
        if (1.5f < obj->unk10_ms) {
            obj->flag |= swrObjTrig_FLAG_FX_SPAWNED;

            float aabb[6];
            swrModel_NodeComputeFirstMeshAABB(obj->trigger_description->affected_node, aabb, 0);
            float x = (aabb[0] + aabb[3]) * 0.5f;
            float y = (aabb[1] + aabb[4]) * 0.5f;
            float z = (aabb[2] + aabb[5]) * 0.5f;

            swrModel_Node* node = obj->trigger_description->affected_node;
            if (node != NULL)
                swrModel_NodeModifyFlags(node, 2, -4, 0x10, 3);
            swrModel_NodeModifyFlags(obj->trigger_description->affected_node, 0, -3, 0x10, 3);
            swrModel_NodeSetTranslation((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[index], x, y, z);
            if (swrObjTrig_ModelArray2[index] != NULL)
                swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[index], 2, 3, 0x10, 2);
            swrObjTrig_EnableFXAnimation(index);
            obj->test_obj_transform_ptr = NULL;
            obj->model_material = swrModel_NodeFindFirstMaterial(swrObjTrig_ModelArray2[index]);
            obj->unk10_ms = 0.0f;
        }
    } else if (2.2f < obj->unk10_ms) {
        int subEvent[3] = { 'Shak', 0, 0 };
        swrEvent_CallF4('cMan', subEvent);
        swrObjTrig_StopFXAnimation(index);
        if (swrObjTrig_ModelArray2[index] != NULL)
            swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[index], 2, -4, 0x10, 3);
        obj->flag &= ~swrObjTrig_FLAG_ACTIVE;
        swrObj_Free(&obj->obj);
    }
}

// 0x0047C330
void swrObjTrig_MaybeResetCameraShake(swrObjTrig* obj)
{
    if (4.0f < obj->unk10_ms) {
        int subEvent[3] = { 'Shak', 0, 0 };
        swrEvent_CallF4('cMan', subEvent);
        obj->flag &= ~swrObjTrig_FLAG_ACTIVE;
        swrObj_Free(&obj->obj);
    }
}

// 0x0047c390
void swrObjTrig_F0(swrObjTrig* trig)
{
    if ((trig->flag & swrObjTrig_FLAG_ACTIVE) == 0)
        return;

    trig->unk10_ms += (float)swrRace_deltaTimeSecs;
    trig->unk14_ms += (float)swrRace_deltaTimeSecs;

    switch (trig->trigger_type) {
    case swrModel_TriggerType_BreakDestructable_100:
    case swrModel_TriggerType_BreakDestructable_102:
    case swrModel_TriggerType_BreakDestructable_201:
    case swrModel_TriggerType_BreakDestructable_212:
    case swrModel_TriggerType_MethaneVapor:
        if (swrObjTrig_AnimationActive(0) != NULL)
            swrObjTrig_MaybeResetAnimation(trig);
        break;
    case swrModel_TriggerType_SpawnFlag:
        if (swrObjTrig_AnimationActive(2) != NULL)
            swrObjTrig_MaybeResetAnimation(trig);
        break;
    case swrModel_TriggerType_BreakDestructable_202:
        if (swrObjTrig_AnimationActive(1) != NULL)
            swrObjTrig_MaybeResetAnimation(trig);
        break;
    case swrModel_TriggerType_LavaSplash:
        if (swrObjTrig_AnimationActive(5) != NULL)
            swrObjTrig_MaybeResetAnimation(trig);
        break;
    case swrModel_TriggerType_CollapsingGlacier:
    case swrModel_TriggerType_FallingPillar:
        swrObjTrig_MaybeResetCameraShake(trig);
        break;
    case swrModel_TriggerType_EarthquakeShortcut:
        swrObjTrig_SpawnEarthquakeShake(trig, 3);
        break;
    case swrModel_TriggerType_Earthquake:
        swrObjTrig_SpawnEarthquakeShake(trig, 1);
        break;
    default:
        break;
    }
}

// 0x0047c500
void swrObjTrig_F2(swrObjTrig* trig)
{
    if ((trig->flag & swrObjTrig_FLAG_ACTIVE) == 0)
        return;

    swrModel_TriggerType type = trig->trigger_type;

    // spawner types follow their affected node's transform
    if (type == swrModel_TriggerType_SpawnFish || type == swrModel_TriggerType_BalloonSpawner) {
        swrModel_NodeTransformed* affected = (swrModel_NodeTransformed*)trig->trigger_description->affected_node;
        if (affected != NULL) {
            rdMatrix44 transform;
            swrModel_NodeGetTransform(affected, &transform);
            if (trig->unk48_node != NULL) {
                swrModel_NodeModifyFlags(trig->unk48_node, 2, 3, 0x10, 2);
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)trig->unk48_node, &transform);
            }
        }
        return;
    }

    // FX-anim types: fade the FX material out and keep the FX model on the target
    int slot;
    float zOffset = 20.0f;
    switch (type) {
    case swrModel_TriggerType_BreakDestructable_100:
        slot = 0;
        break;
    case swrModel_TriggerType_BreakDestructable_102:
        slot = 0;
        zOffset = 0.0f;
        break;
    case swrModel_TriggerType_BreakDestructable_201:
        slot = 0;
        break;
    case swrModel_TriggerType_BreakDestructable_202:
        slot = 1;
        break;
    case swrModel_TriggerType_BreakDestructable_212:
        slot = 0;
        break;
    case swrModel_TriggerType_EarthquakeShortcut:
        slot = 3;
        break;
    case swrModel_TriggerType_Earthquake:
        slot = 1;
        break;
    case swrModel_TriggerType_MethaneVapor:
        slot = 0;
        break;
    case swrModel_TriggerType_LavaSplash:
        slot = 5;
        break;
    default:
        return;
    }

    if (trig->model_material != NULL) {
        float alpha = 0.0f;
        if (trig->unk10_ms <= 2.0f)
            alpha = (2.0f - trig->unk10_ms) * 0.5f; // fade over 2s
        trig->model_material->primitive_color[3] = (uint8_t)(long)(alpha * 255.0f);
    }

    rdMatrix44* src = trig->test_obj_transform_ptr;
    if (src != NULL) {
        trig->trigger_center.x = src->vD.x;
        trig->trigger_center.y = src->vD.y;
        trig->trigger_center.z = src->vD.z;
        if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_102)
            rdVector_Scale3Add3(&trig->trigger_center, &trig->trigger_center, 12.0f, (rdVector3*)&src->vB);
        swrModel_NodeSetTranslation((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[slot], trig->trigger_center.x, trig->trigger_center.y, zOffset + trig->trigger_center.z);
    }
}

// 0x0047c710
int swrObjTrig_F4(swrObjTrig* trig, int* subEvents)
{
    switch (*subEvents) {
    case 'Free':
        rdVector_Set3(&trig->unk30, 0.0f, 0.0f, 0.0f);
        trig->unk3c_node = NULL;
        trig->unk40_animation = NULL;
        trig->unk44_animation = NULL;
        trig->trigger_description = NULL;
        trig->flag = 0;
        return 1;
    case 'Aloc':
        trig->trigger_type = 0;
        trig->flag = 0;
        trig->unk10_ms = 0.0f;
        trig->unk14_ms = 0.0f;
        rdVector_Set3(&trig->unk30, 0.0f, 0.0f, 0.0f);
        trig->unk3c_node = NULL;
        trig->unk40_animation = NULL;
        trig->unk44_animation = NULL;
        trig->trigger_description = NULL;
        return 1;
    case 'Load':
    case 'RSet':
        swrObj_Free(&trig->obj);
        return 1;
    default:
        return 0;
    }
}

// 0x0047C7D0
swrObjTrig* swrObjTrig_FindOrCreate(swrModel_TriggerDescription* desc)
{
    int count = swrEvent_GetEventCount('Trig');
    for (int i = 0; i < count; i++) {
        swrObjTrig* existing = (swrObjTrig*)swrEvent_GetItem('Trig', i);
        if (existing != NULL && (existing->obj.flags & 0x100) == 0 && existing->trigger_description == desc) {
            // NULL if this trigger is being torn down, otherwise the live object
            return (existing->flag & swrObjTrig_FLAG_FIRED) ? NULL : existing;
        }
    }

    swrObjTrig* trig = (swrObjTrig*)swrEvent_AllocObj('Trig');
    if (trig == NULL)
        return NULL;

    trig->trigger_description = desc;
    trig->unk3c_node = desc->affected_node;
    trig->trigger_type = (swrModel_TriggerType)(short)desc->type;
    trig->unk40_animation = swrModel_FindLoadedAnimation(desc->affected_node, 8);
    trig->unk44_animation = swrModel_FindLoadedAnimation(trig->unk3c_node, 9);
    if (trig->unk3c_node != NULL) {
        rdMatrix44 parent;
        rdMatrix44 world;
        rdMatrix_SetIdentity44(&parent);
        swrModel_ComputeNodeWorldMatrix_Maybe(trig->unk3c_node, (float*)&world, (swrModel_Node*)GetTrackModelRoot(), &parent);
        rdVector_Copy3(&trig->unk30, (rdVector3*)&world.vD);
    }
    if (trig->unk40_animation != NULL) {
        swrModel_AnimationSetTime(trig->unk40_animation, 0.0f);
        swrModel_AnimationSetSpeed(trig->unk40_animation, 0.0f);
    }
    if (trig->unk44_animation != NULL) {
        swrModel_AnimationSetTime(trig->unk44_animation, 0.0f);
        swrModel_AnimationSetSpeed(trig->unk44_animation, 0.0f);
    }
    return trig;
}

// 0x0047C920
void swrObjTrig_HandleTrigger108(swrObjTrig* trig, swrRace* player)
{
    if (trig->unk3c_node != NULL)
        swrModel_NodeModifyFlags(trig->unk3c_node, 2, -4, 0x10, 3);
    trig->flag |= swrObjTrig_FLAG_FIRED;
    if (swrObjTrig_AnimationActive(2) == NULL)
        swrObjTrig_MaybeResetAnimationByTriggerType(swrModel_TriggerType_SpawnFlag);
    trig->flag |= swrObjTrig_FLAG_ACTIVE;

    rdMatrix44 transform;
    rdMatrix_SetIdentity44(&transform);
    swrModel_TriggerDescription* desc = trig->trigger_description;
    transform.vD.y = desc->center.y;
    transform.vD.x = desc->center.x + 8.0f; // center.x - (-8.0)
    transform.vD.z = desc->center.z - 24.0f;

    // orient the flag to the player's travel direction
    rdVector2 heading;
    heading.x = player->transform.vD.x - player->positionPrev.x;
    heading.y = player->transform.vD.y - player->positionPrev.y;
    if (0.001f < rdVector_Normalize2Acc(&heading)) {
        transform.vA.y = -heading.x;
        transform.vB.x = heading.x;
        transform.vB.y = heading.y;
        transform.vA.x = heading.y;
    }

    swrModel_NodeSetTransform((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[2], &transform);
    if (swrObjTrig_ModelArray2[2] != NULL)
        swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[2], 2, 3, 0x10, 2);

    swrModel_NodeTransformedWithPivot* node = swrObjTrig_FindNode(trig->trigger_description);
    trig->unk48_node = (swrModel_Node*)node; // &node->node (node is the first field)
    if (node != NULL) {
        swrModel_NodeModifyFlags(&node->node, 2, -4, 0x10, 3);
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &transform);
        node->node.children.nodes = swrObjTrig_ModelArray1 + 4;
    }
    swrObjTrig_EnableFXAnimation(2);
}

// 0x0047CA90
void swrObjTrig_HandleCrashHitTrigger(swrObjTrig* trig, swrRace* player)
{
    int subEvent[3];
    subEvent[0] = 'Hitt';
    subEvent[1] = 'T201';
    int slot = 0;

    // decelerate the pod and fire a damage sub-event, scaled per trigger type
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_201) {
        player->accelThrust *= stdMath_Decelerator(25.0f, (float)swrRace_deltaTimeSecs);
        *(float*)&subEvent[2] = 100.0f;
        swrEvent_DispatchSubEvents(player, subEvent);
        slot = 0;
    }
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_202) {
        player->accelThrust *= stdMath_Decelerator(2.5f, (float)swrRace_deltaTimeSecs);
        *(float*)&subEvent[2] = 600.0f;
        swrEvent_DispatchSubEvents(player, subEvent);
        slot = 1;
    }
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_100)
        slot = 0;
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_102) {
        player->accelThrust *= stdMath_Decelerator(2.5f, (float)swrRace_deltaTimeSecs);
        *(float*)&subEvent[2] = 300.0f;
        swrEvent_DispatchSubEvents(player, subEvent);
        slot = 0;
    }
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_212)
        slot = 0;

    if (trig->unk3c_node != NULL)
        swrModel_NodeModifyFlags(trig->unk3c_node, 2, -4, 0x10, 3);
    trig->flag |= swrObjTrig_FLAG_ACTIVE | swrObjTrig_FLAG_FIRED;
    swrModel_NodeModifyFlags(trig->unk3c_node, 0, -3, 0x10, 3);

    swrModel_TriggerDescription* desc = trig->trigger_description;
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_102 && (player->flags0 & swrObjTest_FLAG0_AI) != 0) {
        // AI hitting the asteroid gets a scaled-up FX placed at the trigger center
        rdMatrix44 transform;
        rdMatrix_SetDiagonal44(&transform, 8.0f, 8.0f, 8.0f);
        transform.vD.x = desc->center.x;
        transform.vD.y = desc->center.y;
        transform.vD.z = desc->center.z;
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[slot], &transform);
    } else {
        swrModel_NodeSetTranslation((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[slot], desc->center.x, desc->center.y, desc->center.z);
    }

    if (swrObjTrig_ModelArray2[slot] != NULL)
        swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[slot], 2, 3, 0x10, 2);
    swrObjTrig_EnableFXAnimation(slot);

    // randomized crash sound pitch: rand01 * 0.15 + 0.25
    int r = swrUtils_Rand();
    rdVector3* position = (rdVector3*)&player->transform.vD;
    swrSound_PlaySpatialRange(0x39, 6, (float)r * (1.0f / 2147483648.0f) * 0.15f + 0.25f, 1.0f, position, 0, 0, 10.0f, 500.0f);

    // capture the pod's velocity at the moment of impact (0.8 / dt)
    float invDt = (float)(0.8 / swrRace_deltaTimeSecs);
    trig->velocity.x = (player->transform.vD.x - player->positionPrev.x) * invDt;
    trig->velocity.y = (player->transform.vD.y - player->positionPrev.y) * invDt;
    trig->velocity.z = (player->transform.vD.z - player->positionPrev.z) * invDt;

    trig->trigger_center.x = desc->center.x;
    trig->trigger_center.y = desc->center.y;
    trig->trigger_center.z = desc->center.z;
    if (trig->trigger_type == swrModel_TriggerType_BreakDestructable_102 && (player->flags0 & swrObjTest_FLAG0_AI) != 0)
        trig->test_obj_transform_ptr = NULL;
    else
        trig->test_obj_transform_ptr = &player->transform;
    trig->model_material = swrModel_NodeFindFirstMaterial(swrObjTrig_ModelArray2[slot]);
    trig->unk10_ms = 0.0f;
}

// 0x0047CD90
void swrObjTrig_Handle314Or501Trigger(swrObjTrig* obj, int index)
{
    if (swrObjTrig_AnimationActive(index) == NULL) {
        swrObj_Free(&obj->obj);
        return;
    }
    obj->flag |= swrObjTrig_FLAG_ACTIVE;
    obj->trigger_description->flags |= 1;

    rdMatrix44 transform;
    swrModel_NodeGetTransform((swrModel_NodeTransformed*)obj->trigger_description->affected_node, &transform);
    swrModel_NodeSetTransform((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[index], &transform);
    if (swrObjTrig_ModelArray2[index] != NULL)
        swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[index], 2, 3, 0x10, 2);
    swrObjTrig_EnableFXAnimation(index);
    obj->test_obj_transform_ptr = NULL;
    if (index == 0)
        obj->model_material = swrModel_NodeFindFirstMaterial(swrObjTrig_ModelArray2[0]);
    else
        obj->model_material = NULL;
    obj->unk10_ms = 0.0f;
}

// 0x0047D310
swrModel_Node* swrObjTrig_AddNodeToScene(swrModel_TriggerDescription* trigger, int flags, int modelIndex)
{
    swrModel_NodeTransformedWithPivot* node = swrObjTrig_InitNodeForTrigger(trigger);
    if (node != NULL) {
        node->node.num_children = 1;
        node->node.children.nodes = &swrObjTrig_ModelArray1[modelIndex];
        swrObjTrig_SceneChildNodes[swrObjTrig_RootNode.num_children++] = &node->node;
        swrModel_NodeModifyFlags(&node->node, 2, 0xf, 0x10, 3);
        swrModel_NodeModifyFlags(&node->node, 2, flags & 0xfffffff0, 0x10, 2);
    }
    return &node->node;
}

// 0x0047d380
void swrObjTrig_AddTriggerDescriptions(swrModel_TriggerDescription* descriptions, int param2)
{
    rdMatrix44 transform;
    for (swrModel_TriggerDescription* desc = descriptions; desc != NULL; desc = desc->next) {
        swrObjTrig_AddTriggerDescription(desc);

        if (desc->type == swrModel_TriggerType_SpawnFlag) {
            swrModel_Node* node = swrObjTrig_AddNodeToScene(desc, param2, 3);
            if (node != NULL)
                swrModel_NodeSetTranslation((swrModel_NodeTransformed*)node, desc->center.x + 8.0f, desc->center.y, desc->center.z - 24.0f);
        }
        if (desc->type == swrModel_TriggerType_BreakDestructable_100)
            desc->flags |= swrModel_TriggerDescription_FLAG_NEEDS_SPEED;
        if (desc->type == swrModel_TriggerType_CollapsingGlacier) {
            desc->flags |= swrModel_TriggerDescription_FLAG_IGNORE_AI;
            swrModel_NodeSetAnimationFlagsAndSpeed(desc->affected_node, ANIMATION_ENABLED | ANIMATION_LOOP, 0, 0.6f);
        }
        if (desc->type == swrModel_TriggerType_KillPlayer)
            specialActiveTrigger = desc;
        if (desc->type == swrModel_TriggerType_BreakDestructable_201)
            swrModel_NodeModifyFlags(desc->affected_node, 0, -3, 0x10, 3);
        if (desc->type == swrModel_TriggerType_BreakDestructable_202) {
            swrModel_NodeModifyFlags(desc->affected_node, 0, -5, 0x10, 3);
            desc->flags |= swrModel_TriggerDescription_FLAG_NEEDS_SPEED;
            if (swrObjTrig_CurrentPlanetId == 1)
                specialActiveTrigger = desc;
        }
        if (desc->type == swrModel_TriggerType_TuskenRaiders)
            desc->flags |= swrModel_TriggerDescription_FLAG_IGNORE_AI;
        if (desc->type == swrModel_TriggerType_BalloonSpawner) {
            swrModel_Node* node = swrObjTrig_AddNodeToScene(desc, param2, 2);
            swrObjTrig* trig = swrObjTrig_FindOrCreate(desc);
            trig->unk48_node = node;
            trig->flag |= swrObjTrig_FLAG_ACTIVE;
            if (trig->unk44_animation != NULL)
                swrModel_AnimationSetSpeed(trig->unk44_animation, 1.0f);
            if (trig->unk40_animation != NULL)
                swrModel_AnimationSetSpeed(trig->unk40_animation, 1.0f);
            if (node != NULL && desc->affected_node != NULL) {
                swrModel_NodeGetTransform((swrModel_NodeTransformed*)trig->trigger_description->affected_node, &transform);
                if (trig->unk48_node != NULL) {
                    swrModel_NodeModifyFlags(trig->unk48_node, 2, 3, 0x10, 2);
                    swrModel_NodeSetTransform((swrModel_NodeTransformed*)trig->unk48_node, &transform);
                }
            }
        }
        if (desc->type == swrModel_TriggerType_BreakDestructable_212) {
            swrModel_NodeModifyFlags(desc->affected_node, 0, -5, 0x10, 3);
            desc->flags |= swrModel_TriggerDescription_FLAG_NEEDS_SPEED;
        }
        if (desc->type == swrModel_TriggerType_FlameSpawner) {
            swrModel_Node* node = swrObjTrig_AddNodeToScene(desc, param2, 2);
            if (node != NULL) {
                transform.vA = (rdVector4){ 1.0f, 0.0f, 0.0f, 0.0f };
                transform.vB = (rdVector4){ desc->direction.x, desc->direction.y, desc->direction.z, 0.0f };
                transform.vC = (rdVector4){ 0.0f, 0.0f, 1.0f, 0.0f };
                rdVector_Cross3((rdVector3*)&transform.vA, (rdVector3*)&transform.vB, (rdVector3*)&transform.vC);
                rdVector_Cross3((rdVector3*)&transform.vC, (rdVector3*)&transform.vA, (rdVector3*)&transform.vB);
                rdVector_Normalize3Acc((rdVector3*)&transform.vA);
                rdVector_Normalize3Acc((rdVector3*)&transform.vB);
                transform.vD = (rdVector4){ desc->center.x, desc->center.y, desc->center.z - desc->size_z * 0.5f, 1.0f };
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &transform);
                if (desc->affected_node != NULL)
                    swrModel_NodeModifyFlags(desc->affected_node, 2, -4, 0x10, 3);
            }
            desc->flags |= swrModel_TriggerDescription_FLAG_ENABLED;
        }
        if (desc->type == swrModel_TriggerType_EarthquakeShortcut)
            desc->flags |= swrModel_TriggerDescription_FLAG_SKIP_LAP1 | swrModel_TriggerDescription_FLAG_IGNORE_AI;
        if (desc->type == swrModel_TriggerType_Earthquake) {
            desc->flags |= swrModel_TriggerDescription_FLAG_SKIP_LAP1 | swrModel_TriggerDescription_FLAG_IGNORE_AI;
            if ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM > 0.5f)
                desc->flags |= swrModel_TriggerDescription_FLAG_SKIP_LAP2;
        }
        if (desc->type == swrModel_TriggerType_StartAnimDoor2)
            swrModel_NodeSetAnimationFlagsAndSpeed(desc->affected_node, ANIMATION_LOOP, 0, 1.0f);
        if (desc->type == swrModel_TriggerType_SpawnFish) {
            swrModel_Node* node = swrObjTrig_AddNodeToScene(desc, param2, 0);
            swrObjTrig* trig = swrObjTrig_FindOrCreate(desc);
            trig->unk48_node = node;
            trig->flag |= swrObjTrig_FLAG_ACTIVE;
            if (trig->unk44_animation != NULL)
                swrModel_AnimationSetSpeed(trig->unk44_animation, 1.0f);
            if (trig->unk40_animation != NULL)
                swrModel_AnimationSetSpeed(trig->unk40_animation, 1.0f);
            if (node != NULL && desc->affected_node != NULL) {
                swrModel_NodeGetTransform((swrModel_NodeTransformed*)trig->trigger_description->affected_node, &transform);
                if (trig->unk48_node != NULL) {
                    swrModel_NodeModifyFlags(trig->unk48_node, 2, 3, 0x10, 2);
                    swrModel_NodeSetTransform((swrModel_NodeTransformed*)trig->unk48_node, &transform);
                }
            }
        }
        if (desc->type == swrModel_TriggerType_DozerSpawner) {
            swrModel_Node* node = swrObjTrig_AddNodeToScene(desc, param2, 0);
            if (node != NULL && desc->affected_node != NULL) {
                swrModel_NodeGetTransform((swrModel_NodeTransformed*)desc->affected_node, &transform);
                swrModel_NodeModifyFlags(node, 2, 3, 0x10, 2);
                swrModel_NodeSetTransform((swrModel_NodeTransformed*)node, &transform);
            }
            desc->flags |= swrModel_TriggerDescription_FLAG_ENABLED;
        }
        if (desc->type == swrModel_TriggerType_FallingPillar) {
            desc->flags |= swrModel_TriggerDescription_FLAG_IGNORE_AI;
            swrModel_NodeSetAnimationFlagsAndSpeed(desc->affected_node, ANIMATION_ENABLED | ANIMATION_LOOP, 0, 1.0f);
        }
        if (desc->type == swrModel_TriggerType_MethaneVapor) {
            desc->flags |= swrModel_TriggerDescription_FLAG_IGNORE_AI;
            if (desc->affected_node != NULL)
                swrModel_NodeModifyFlags(desc->affected_node, 2, -4, 0x10, 3);
        }
        if (desc->type == swrModel_TriggerType_LavaSplash && desc->affected_node != NULL)
            swrModel_NodeModifyFlags(desc->affected_node, 2, -4, 0x10, 3);
    }
}

// 0x0047d890
void swrObjTrig_InitColorBands_Maybe(void)
{
    // the original leaves these uninitialized for other layouts; its only caller passes 1 or 2
    float minY = 0.0f;
    float maxY = 0.0f;
    float minX = 0.0f;
    float maxX = 0.0f;
    float rowHeight;
    float columnWidth;

    if (swrObjTrig_regionGridLayout == 1) {
        minY = -8500.0f;
        maxY = 3500.0f;
        maxX = 2500.0f;
        minX = -5500.0f;
    } else if (swrObjTrig_regionGridLayout == 2) {
        minY = -9300.0f;
        maxY = 9000.0f;
        maxX = 7500.0f;
        minX = -7500.0f;
    }
    rowHeight = (maxY - minY) * 0.125f;
    columnWidth = (maxX - minX) * 0.33333334f;
    swrObjTrig_regionBoundsX[0] = minX;
    swrObjTrig_regionBoundsX[1] = minX + columnWidth;
    swrObjTrig_regionBoundsX[2] = maxX - columnWidth;
    swrObjTrig_regionBoundsX[3] = maxX;
    swrObjTrig_regionBoundsY[0] = minY;
    swrObjTrig_regionBoundsY[1] = minY + rowHeight;
    swrObjTrig_regionBoundsY[2] = minY - rowHeight * -2.0f;
    swrObjTrig_regionBoundsY[3] = minY - rowHeight * -3.0f;
    swrObjTrig_regionBoundsY[4] = minY - rowHeight * -4.0f;
    swrObjTrig_regionBoundsY[5] = minY - rowHeight * -5.0f;
    swrObjTrig_regionBoundsY[6] = minY - rowHeight * -6.0f;
    swrObjTrig_regionBoundsY[7] = maxY - rowHeight;
    swrObjTrig_regionBoundsY[8] = maxY;
    swrObjTrig_regionMarginX = columnWidth * 0.25f;
    swrObjTrig_regionMarginY = rowHeight * 0.25f;
}

// 0x0047da10
unsigned int swrObjTrig_ApplyNodeRegionColor_Maybe(swrModel_Node* node)
{
    // mesh-group AABB (min xyz, max xyz) follows the node header
    const float* aabb = (const float*)(node + 1);
    const float minX = aabb[0];
    const float minY = aabb[1];
    const float maxX = aabb[3];
    const float maxY = aabb[4];

    // one bit per region row the AABB spans: rows 0..7 = bits 16..23
    unsigned int rows = 0;
    for (int row = 0; row < 8; row++) {
        if (minY < swrObjTrig_regionBoundsY[row + 1]) {
            rows = (0xff0000u << row) & 0xff0000u;
            break;
        }
    }
    if (rows != 0) {
        if (maxY < swrObjTrig_regionBoundsY[0]) {
            rows = 0;
        } else {
            for (int row = 1; row < 8; row++) {
                if (maxY < swrObjTrig_regionBoundsY[row]) {
                    rows &= (0x10000u << row) - 0x10000u;
                    break;
                }
            }
        }
    }

    // the same row bits per column: column 0 in bits 24..31, column 1 in 16..23, column 2 in 8..15
    unsigned int column0 = rows << 8;
    unsigned int column1 = rows;
    unsigned int column2 = (int)rows >> 8;
    if (column0 != 0) {
        if (maxX < swrObjTrig_regionBoundsX[0] || minX > swrObjTrig_regionBoundsX[1])
            column0 = 0;
        if (maxX < swrObjTrig_regionBoundsX[1] || minX > swrObjTrig_regionBoundsX[2])
            column1 = 0;
        if (maxX < swrObjTrig_regionBoundsX[2] || minX > swrObjTrig_regionBoundsX[3])
            column2 = 0;
    }

    unsigned int regions = column2 | column1 | column0;
    swrModel_NodeModifyFlags(node, 0, 0xff, 0x10, 3);
    swrModel_NodeModifyFlags(node, 0, regions, 0x10, 2);
    return regions;
}

// 0x0047DC40
unsigned int swrObjTrig_FindAndInitializeTriggersInNode(swrModel_Node* node)
{
    unsigned int result = 0;
    int nodeFlags = swrModel_NodeGetFlags(node);
    if (nodeFlags == NODE_MESH_GROUP) {
        if (swrObjTrig_regionGridLayout != 0 && swrObjTrig_regionGridSuppressed == 0)
            result = swrObjTrig_ApplyNodeRegionColor_Maybe(node);

        int numChildren = swrModel_NodeGetNumChildren(node);
        for (int i = 0; i < numChildren; i++) {
            swrModel_Mesh* mesh = swrModel_NodeGetMesh((swrModel_NodeMeshGroup*)node, i);
            if (mesh == NULL)
                continue;
            swrModel_Behavior* behavior = swrModel_MeshGetBehavior(mesh);
            if (behavior != NULL && behavior->triggers != NULL)
                swrObjTrig_AddTriggerDescriptions(behavior->triggers, swrModel_NodeGetFlags1Or2(node, 2));
        }
        return result;
    }

    if ((nodeFlags & NODE_HAS_CHILDREN) == 0)
        return result;

    int savedSuppressed = 0;
    if (nodeFlags & NODE_IS_TRANSFORMED) {
        savedSuppressed = swrObjTrig_regionGridSuppressed;
        swrObjTrig_regionGridSuppressed = 1;
    }

    int numChildren = swrModel_NodeGetNumChildren(node);
    for (int i = 0; i < numChildren; i++) {
        swrModel_Node* child = node->children.nodes[i];
        if (child != NULL)
            result |= swrObjTrig_FindAndInitializeTriggersInNode(child);
    }

    if (swrObjTrig_regionGridLayout != 0 && swrObjTrig_regionGridSuppressed == 0) {
        swrModel_NodeModifyFlags(node, 0, 0xff, 0x10, 3);
        swrModel_NodeModifyFlags(node, 0, result, 0x10, 2);
    }

    if (nodeFlags & NODE_IS_TRANSFORMED)
        swrObjTrig_regionGridSuppressed = savedSuppressed;

    return result;
}

// 0x0047DD90
swrModel_Node* swrObjTrig_CreateTriggerSceneNode()
{
    swrModel_NodeInit(&swrObjTrig_RootNode, NODE_BASIC);
    swrObjTrig_RootNode.num_children = 0;
    swrObjTrig_RootNode.children.nodes = swrObjTrig_SceneChildNodes;
    return &swrObjTrig_RootNode;
}

// Loads a one-shot trigger FX model: animation stopped, node hidden and parented under the trigger root.
static swrModel_Node* swrObjTrig_LoadFxModel(int slot, MODELID id)
{
    swrModel_Header* header = swrModel_LoadFromId(id);

    swrObjTrig_AnimationArray[slot] = swrModel_LoadAllAnimationsOfModel(header);
    swrObjTrig_StopFXAnimation(slot);
    swrObjTrig_ModelArray2[slot] = header->entries[0].node;
    if (swrObjTrig_ModelArray2[slot] != NULL)
        swrModel_NodeModifyFlags(swrObjTrig_ModelArray2[slot], 2, -4, 0x10, 3);
    swrObjTrig_SceneChildNodes[swrObjTrig_RootNode.num_children++] = header->entries[0].node;
    return header->entries[0].node;
}

// Loads an animated trigger prop that stays where the track places it.
static void swrObjTrig_LoadPropModel(int slot, MODELID id)
{
    swrModel_Header* header = swrModel_LoadFromId(id);

    swrObjTrig_AnimationArray[slot] = swrModel_LoadAllAnimationsOfModel(header);
    swrObjTrig_ModelArray1[slot] = header->entries[0].node;
    swrObjTrig_ModelArray2[slot] = swrObjTrig_ModelArray1[slot];
}

// 0x0047DDC0
swrModel_Node* swrObjTrig_LoadAndInitializeTriggerModels(int planetId, int trackNumber, swrModel_NodeTransformed* trackRoot)
{
    swrModel_Node* root = NULL;
    swrModel_Header* header;
    rdMatrix44 scale;

    specialActiveTrigger = NULL;
    memset(swrObjTrig_TriggerDescriptionArray2, 0, sizeof(swrObjTrig_TriggerDescriptionArray2));
    swrObjTrig_loadResetFlag = 0;
    swrObjTrig_CurrentPlanetId = planetId;
    if (swrObjTrig_regionGridLayout != 0)
        swrObjTrig_InitColorBands_Maybe();

    if (planetId == 1) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadFxModel(0, MODELID_fx_shards_part);
        swrObjTrig_LoadFxModel(1, MODELID_fx_rockbig_part);
        swrObjTrig_LoadFxModel(2, MODELID_flag_tip_part);
        header = swrModel_LoadFromId(MODELID_flag_wave_vlec);
        swrObjTrig_AnimationArray[3] = swrModel_LoadAllAnimationsOfModel(header);
        swrObjTrig_ModelArray1[3] = header->entries[0].node->children.nodes[1];
        swrObjTrig_ModelArray2[3] = swrObjTrig_ModelArray1[3];
        swrObjTrig_ModelArray1[4] = header->entries[0].node->children.nodes[0];
        swrObjTrig_ModelArray2[4] = swrObjTrig_ModelArray1[4];
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 2) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadPropModel(0, MODELID_char_big_fish_puppet);
        swrObjTrig_LoadFxModel(1, MODELID_fx_rockgiant_part);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 3) {
        root = swrObjTrig_CreateTriggerSceneNode();
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 4) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadFxModel(0, MODELID_fx_treesmash_part);
        swrObjTrig_LoadFxModel(1, MODELID_fx_rockash_part);
        swrObjTrig_LoadFxModel(3, MODELID_fx_rockgiant_part);
        swrObjTrig_LoadPropModel(2, MODELID_fx_flameanim_part);
        swrObjTrig_LoadFxModel(5, MODELID_fx_lavafoof_part);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 5) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadPropModel(0, MODELID_dozer_part);
        swrObjTrig_LoadPropModel(2, MODELID_fx_flameanim_part);
        rdMatrix_SetDiagonal44(&scale, 2.4f, 2.4f, 2.4f);
        swrModel_NodeSetTransform((swrModel_NodeTransformed*)swrObjTrig_ModelArray2[2], &scale);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 6) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadFxModel(0, MODELID_fx_rockzero_part);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 7) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadFxModel(0, MODELID_fx_methanefoof_part);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    if (planetId == 0) {
        root = swrObjTrig_CreateTriggerSceneNode();
        swrObjTrig_LoadFxModel(0, MODELID_fx_rocksmall_part);
        swrObjTrig_LoadFxModel(1, MODELID_fx_rockbig_part);
        swrObjTrig_LoadPropModel(2, MODELID_balloon01_part);
        if (trackRoot != NULL)
            swrObjTrig_FindAndInitializeTriggersInNode((swrModel_Node*)trackRoot);
    }
    return root;
}

// 0x0047E760
void swrObjTrig_AddTriggerDescription(swrModel_TriggerDescription* trigger)
{
    if ((trigger != NULL) && (swrObjTrig_NumTriggerDescriptions < 200))
        swrObjTrig_TriggerDescriptionArray[swrObjTrig_NumTriggerDescriptions++] = trigger;
}

// 0x0047E790
int swrObjTrig_FindTriggerDescriptionIndex(swrModel_TriggerDescription* trigger)
{
    for (int i = 0; i < swrObjTrig_NumTriggerDescriptions; i++)
        if (swrObjTrig_TriggerDescriptionArray[i] == trigger)
            return i;

    return -1;
}

// 0x0047E7C0
swrModel_TriggerDescription* swrObjTrig_GetTriggerDescription(int index)
{
    if (index < 0 || index >= swrObjTrig_NumTriggerDescriptions)
        return NULL;

    return swrObjTrig_TriggerDescriptionArray[index];
}

// 0x0047E7E0
void swrObjTrig_CreateAndActivateTriggerFromMultiplayerEvent(int trigger_index, int player_index)
{
    swrModel_TriggerDescription* description = swrObjTrig_GetTriggerDescription(trigger_index);
    swrRace* player = player_index < 0 ? NULL : swrScores[player_index].obj_test_ptr;
    if (description == NULL || player == NULL)
        return;

    swrObjTrig* trigger = swrObjTrig_FindOrCreate(description);
    if (trigger != NULL)
        swrRace_TriggerHandler((int)trigger, (int)player, 1);
}

// 0x0047E830
void swrObjTrig_SendMultiplayerTriggerEvent(swrModel_TriggerDescription* trigger_description, swrRace* player)
{
    if (trigger_description == NULL)
        return;

    int index = swrObjTrig_FindTriggerDescriptionIndex(trigger_description);
    if (index == -1)
        return;

    // only the first five args are pushed (add esp,0x14); the rest are stack garbage the receiver ignores
    swrMultiplayer_SendEvent(-1, 0, 'trig', index, player->score_ptr->time_unk, 0.0f, 0.0, NULL, NULL, 0);
}

// 0x00449260
void swrScene_ClearTextureAnim_Maybe(void)
{
    swrScene_textureScrollState[1] = 0;
}

// 0x004800c0
int GetCustomStartTransform(rdMatrix44* out)
{
    if (swrSpline_finishNodeIdx < 0)
        return 0;
    *out = swrSpline_finishMatrix;
    return 1;
}

// 0x004804a0
void swrScene_SetObjectsLoaded(void)
{
    swrScene_objectsLoaded = 1;
}

// 0x00428A60
void swrCam_CamState_InitMainMat4(uint16_t index, uint16_t val1, rdMatrix44* mat, uint16_t val2)
{
    int entry = (int16_t)index;
    unkCameraArray[entry].sourceType = val2;
    unkCameraArray[entry].behaviorType = val1;
    unkCameraArray[entry].matrixSource = mat;
}

// 0x00448d90
void swrScene_LoadPreviewModel(void)
{
    swrModel_Header* header;
    swrModel_Header* companion;

    if (swrScene_previewCompanionModelId < 0) {
        header = swrModel_LoadFromId((MODELID)swrScene_previewModelId);
        if (swrScene_previewAltModelId >= 0)
            swrModel_FixupAltNodePointers((int*)header, (int*)swrModel_LoadFromId((MODELID)swrScene_previewAltModelId));
        if (header->entries[0].node != NULL)
            swrModel_NodeModifyFlags(header->entries[0].node, 2, 3, 0x10, 2);
        swrViewport_SetViewport(0, 8, 8, 0x138, 0xe8);
        swrViewport_SetViewport(1, 8, 8, 0x138, 0xe8);
        swrViewport_Enable(1, 0);
        swrViewport_SetRootNodeForAllViewports(header->entries[0].node);
        swrModel_LoadAllAnimationsOfModel(header);
        return;
    }

    swrModel_NodeInit(&someRootNode, NODE_BASIC);
    someRootNode.num_children = 2;
    someRootNode.children.nodes = someRootNodeChildNodes;
    header = swrModel_LoadFromId((MODELID)swrScene_previewModelId);
    if (swrScene_previewAltModelId >= 0)
        swrModel_FixupAltNodePointers((int*)header, (int*)swrModel_LoadFromId((MODELID)swrScene_previewAltModelId));
    if (header->entries[0].node != NULL)
        swrModel_NodeModifyFlags(header->entries[0].node, 2, 3, 0x10, 2);
    swrModel_LoadAllAnimationsOfModel(header);
    someRootNodeChildNodes[0] = header->entries[0].node;
    companion = swrModel_LoadFromId((MODELID)swrScene_previewCompanionModelId);
    if (companion->entries[0].node != NULL)
        swrModel_NodeModifyFlags(companion->entries[0].node, 2, 3, 0x10, 2);
    swrModel_LoadAllAnimationsOfModel(companion);
    someRootNodeChildNodes[1] = companion->entries[0].node;
    swrViewport_SetViewport(0, 8, 8, 0x138, 0xe8);
    swrViewport_SetViewport(1, 8, 8, 0x138, 0xe8);
    swrViewport_Enable(1, 0);
    swrViewport_SetRootNodeForAllViewports(&someRootNode);
}

// 0x004292b0
void swrCam_GetActiveViewportCameraTransform(rdMatrix44* out)
{
    int count = swrViewport_GetNumViewports();
    for (int i = 0; i < count; i++) {
        swrViewport* viewport = swrViewport_Get(i);
        if (viewport != NULL && (swrModel_NodeGetFlags((swrModel_Node*)viewport) & swrViewport_FLAGS_CAMERA_VALID)) {
            // returns the viewport's camera index
            int cam = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)viewport);
            rdMatrix_Copy44(out, &unkCameraArray[cam].transform);
            return;
        }
    }
    rdMatrix_SetIdentity44(out);
}

// 0x00429330
void swrCam_PickNearestSplitCameraTransform_Maybe(rdMatrix44* out, float* pos)
{
    swrViewport* viewport1;
    swrViewport* viewport2;
    unsigned int flags1;
    unsigned int flags2;
    int cam1 = 0;
    int cam2 = 0;
    float dist1 = -1.0f;
    float dist2 = -1.0f;
    float dx;
    float dy;
    float dz;

    viewport1 = swrViewport_Get(1);
    viewport2 = swrViewport_Get(2);
    flags1 = swrModel_NodeGetFlags((swrModel_Node*)viewport1);
    flags2 = swrModel_NodeGetFlags((swrModel_Node*)viewport2);
    if (flags1 & swrViewport_FLAGS_CAMERA_VALID) {
        cam1 = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)viewport1);
        dx = pos[0] - unkCameraArray[cam1].transform.vD.x;
        dy = pos[1] - unkCameraArray[cam1].transform.vD.y;
        dz = pos[2] - unkCameraArray[cam1].transform.vD.z;
        dist1 = dz * dz + dy * dy + dx * dx;
    }
    if (flags2 & swrViewport_FLAGS_CAMERA_VALID) {
        cam2 = (int)swrModel_MeshGetBehavior((swrModel_Mesh*)viewport2);
        dx = pos[0] - unkCameraArray[cam2].transform.vD.x;
        dy = pos[1] - unkCameraArray[cam2].transform.vD.y;
        dz = pos[2] - unkCameraArray[cam2].transform.vD.z;
        dist2 = dz * dz + dy * dy + dx * dx;
    }
    // faithful: when only viewport 2 has a camera, dist2 <= -1 fails and the result is identity
    if (dist2 >= 0.0f && dist2 <= dist1) {
        rdMatrix_Copy44(out, &unkCameraArray[cam2].transform);
        return;
    }
    if (dist1 >= 0.0f) {
        rdMatrix_Copy44(out, &unkCameraArray[cam1].transform);
        return;
    }
    rdMatrix_SetIdentity44(out);
}

// 0x004294e0
int swrCam_IsBehaviorActiveViewportCamera_Maybe(swrModel_Behavior* behavior)
{
    int count = swrViewport_GetNumViewports();
    for (int i = 0; i < count; i++) {
        swrViewport* viewport = swrViewport_Get(i);
        if (viewport != NULL && (swrModel_NodeGetFlags((swrModel_Node*)viewport) & swrViewport_FLAGS_CAMERA_VALID) && swrModel_MeshGetBehavior((swrModel_Mesh*)viewport) == behavior)
            return 1;
    }
    return 0;
}

// 0x00428a40
void swrCam_CamState_SetFlags(int index, unsigned int flags)
{
    unkCameraArray[index].flags |= flags;
}

// 0x00428aa0
void swrCam_CamState_SetOffset(short index, float posX, float posY, float posZ, float yaw, float pitch, float roll)
{
    int entry = index;
    unkCameraArray[entry].posOffset.x = posX;
    unkCameraArray[entry].posOffset.y = posY;
    unkCameraArray[entry].posOffset.z = posZ;
    unkCameraArray[entry].rotationYPR.x = yaw;
    unkCameraArray[entry].rotationYPR.y = pitch;
    unkCameraArray[entry].rotationYPR.z = roll;
}

// 0x00428b10
void swrCam_CamState_SetOffsetSource(short index, void* source, short mode)
{
    unkCameraArray[index].offsetMode = mode;
    unkCameraArray[index].offsetSource = source;
}

// 0x00428c40
void swrCam_CamState_GetOffsetTransform(int mode, swrModel_NodeTransformed* node, rdMatrix44* out)
{
    if (mode == 3) {
        swrModel_NodeGetTransform(node, out);
        return;
    }
    if (mode == 2) {
        swrModel_NodeGetTransform(node, out);
        return;
    }
    if (swrModel_NodeGetFlags(&node->node) == NODE_TRANSFORMED_WITH_PIVOT) {
        swrModel_NodeGetTransform(node, out);
        return;
    }
    // faithful: the binary repeats the same type test
    if (swrModel_NodeGetFlags(&node->node) == NODE_TRANSFORMED_WITH_PIVOT) {
        swrModel_NodeGetTransform(node, out);
        return;
    }
    rdMatrix_SetIdentity44(out);
}

// Moves `angle` by a full turn when `delta` left +/-180 (x87 compare: NaN counts as below).
static void swrCam_UnwrapAngle(float* angle, float delta)
{
    if (delta > SWR_CAM_HALF_TURN) {
        *angle = *angle - SWR_CAM_FULL_TURN;
    }
    if (!(delta >= -SWR_CAM_HALF_TURN)) {
        *angle = *angle - -SWR_CAM_FULL_TURN;
    }
}

// 0x00428cd0
void swrCam_CamState_ApplyToViewport(swrViewport* viewport)
{
    swrTranslationRotation from;
    swrTranslationRotation to;
    swrTranslationRotation blended;
    rdMatrix44 target;
    rdMatrix44 view;
    rdVector3* lookAt;
    float t;
    float deltaX;
    float deltaZ;

    rdMatrix_ExtractTransform(&unkCameraArray[swrCam_blendFromIndex].transform, &from);
    rdMatrix_ExtractTransform(&unkCameraArray[swrCam_blendToIndex].transform, &to);
    t = swrCam_blendTime / swrCam_blendDuration;
    rdMatrix_ExtractTransform(&rdMatrix44_unk2, &blended);
    blended.translation.x = to.translation.x - from.translation.x;
    blended.translation.y = to.translation.y - from.translation.y;
    blended.translation.z = to.translation.z - from.translation.z;
    rdVector_Scale3Add3(&blended.translation, &from.translation, t, &blended.translation);

    if (swrCam_lookAtTarget == NULL) {
        if (t > 0.0f) {
            // mid-blend: unwrap each camera against its own last-frame angles
            deltaX = from.yaw_roll_pitch.x - swrCam_blendFromYPR.x;
            deltaZ = from.yaw_roll_pitch.z - swrCam_blendFromYPR.z;
            swrCam_UnwrapAngle(&from.yaw_roll_pitch.x, deltaX);
            swrCam_UnwrapAngle(&from.yaw_roll_pitch.z, deltaZ);
            deltaX = to.yaw_roll_pitch.x - swrCam_blendToYPR.x;
            deltaZ = to.yaw_roll_pitch.z - swrCam_blendToYPR.z;
            swrCam_UnwrapAngle(&to.yaw_roll_pitch.x, deltaX);
            swrCam_UnwrapAngle(&to.yaw_roll_pitch.z, deltaZ);
        } else {
            deltaX = to.yaw_roll_pitch.x - from.yaw_roll_pitch.x;
            deltaZ = to.yaw_roll_pitch.z - from.yaw_roll_pitch.z;
            swrCam_UnwrapAngle(&to.yaw_roll_pitch.x, deltaX);
            swrCam_UnwrapAngle(&to.yaw_roll_pitch.z, deltaZ);
        }
        blended.yaw_roll_pitch.x = to.yaw_roll_pitch.x - from.yaw_roll_pitch.x;
        blended.yaw_roll_pitch.y = to.yaw_roll_pitch.y - from.yaw_roll_pitch.y;
        blended.yaw_roll_pitch.z = to.yaw_roll_pitch.z - from.yaw_roll_pitch.z;
        swrCam_blendFromYPR = from.yaw_roll_pitch;
        swrCam_blendToYPR = to.yaw_roll_pitch;
        rdVector_Scale3Add3(&blended.yaw_roll_pitch, &from.yaw_roll_pitch, t, &blended.yaw_roll_pitch);
        rdMatrix_SetTransform44(&rdMatrix44_unk2, &blended);
    } else {
        if (swrCam_lookAtMode == 1) {
            lookAt = (rdVector3*)swrCam_lookAtTarget;
        } else {
            if (swrCam_lookAtMode == 0) {
                target = *(rdMatrix44*)swrCam_lookAtTarget;
            } else {
                swrCam_CamState_GetOffsetTransform(swrCam_lookAtMode, (swrModel_NodeTransformed*)swrCam_lookAtTarget, &target);
            }
            lookAt = (rdVector3*)&target.vD;
        }
        BuildLookAtTransform(&blended.translation, lookAt, &rdMatrix44_unk2, &blended, blended.yaw_roll_pitch.z);
    }

    view = rdMatrix44_unk2;
    swrViewport_SetMat3(viewport, &view);
    if (unkCameraArray[swrCam_blendFromIndex].blendNode != NULL) {
        swrModel_NodeModifyFlags(unkCameraArray[swrCam_blendFromIndex].blendNode, 2, 1, 0x10, 2);
    }
    if (unkCameraArray[swrCam_blendToIndex].blendNode != NULL) {
        swrModel_NodeModifyFlags(unkCameraArray[swrCam_blendToIndex].blendNode, 2, 1, 0x10, 2);
    }
    swrCam_blendTime = swrCam_blendTime + swrRace_deltaTimeSecs;
    if (swrCam_blendTime >= swrCam_blendDuration) {
        if (unkCameraArray[swrCam_blendToIndex].blendNode != NULL) {
            swrModel_NodeModifyFlags(unkCameraArray[swrCam_blendToIndex].blendNode, 2, -2, 0x10, 3);
        }
        swrViewport_SetActiveCamera(swrCam_blendToIndex);
        unkCameraArray[swrCam_blendFromIndex].flags &= ~swrCamera_FLAG_ACTIVE;
    }
}

// Cosine ease driving the front-end camera moves: 0 at t == 0, `period` at t == period.
// 0x0045a420
float swrObjHang_EaseSine_Maybe(float t, float period) {
    float sine;
    // The original passes its own `t` slot as the cosine out-param and reads it back.
    stdMath_SinCos((t / period) * 180.0f, &sine, &t);
    return (1.0f - t) * 0.5f * period;
}

// 0x00440b50
int swrObjHang_IsCameraMoving(swrObjHang* hang)
{
    const swrUICameraPlacement* place = &maybeUICameraPlacements[hang->cameraState];

    if (rdVector_AreSame3((rdVector3*)&place->position2, (rdVector3*)&swrObjHang_holoCameraMatrix.vD) && rdVector_AreSame3((rdVector3*)&place->position2, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD) && rdVector_AreSame3((rdVector3*)&place->position1, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD)) {
        return 0;
    }
    return 1;
}

// Point the camera-facing billboard rotation at the current look-at, keeping the eye position.
// 0x0043e210
void swrObjHang_UpdateHoloBillboardMatrix(void)
{
    float yaw;
    float pitch;
    rdVector3 dir;
    rdVector3 eye;

    rdVector_Copy3(&eye, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Sub3(&dir, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Normalize3Acc(&dir);
    yaw = stdMath_ArcTan2(-dir.x, dir.y);
    pitch = stdMath_ArcSin(dir.z);
    // Wrap yaw into [0, 360] and pitch into [-90, 90]; this family works in degrees.
    if (yaw < 0.0f)
        yaw = yaw + 360.0f;
    if (360.0f < yaw)
        yaw = yaw - 360.0f;
    if (pitch < -90.0f)
        pitch = pitch + 180.0f;
    if (90.0f < pitch)
        pitch = pitch - 180.0f;
    rdMatrix_SetRotation44(&swrObjHang_cameraMatrix, yaw, pitch, 0.0f);
    rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrix.vD, &eye);
}

// 0x0043e620
void swrObjHang_UpdatePitDroidAnims(swrObjHang* hang)
{
    rdVector3 origin;

    rdVector_Set3(&origin, 0.0f, 0.0f, 0.0f);
    swrObjElmo_SetTransformAndAnimById(SWR_SCENE_SLOT_PILOT_PUPPETS, 0x1b, &origin, &origin, 0.0f, 0.0f);
    swrObjElmo_SetAnimStateById(4, 0x43);
    swrObjElmo_SetAnimStateById(0x16, 0x2a);
    swrObjElmo_SetAnimStateById(0x17, 0x2e);
    hang->elmoEntityIndex = hang->isTournamentMode != 0 ? SWR_SCENE_SLOT_HANGAR_DROIDS + 1 : SWR_SCENE_SLOT_HANGAR_DROIDS;
    for (int index = SWR_SCENE_SLOT_HANGAR_DROIDS; index < SWR_SCENE_SLOT_HANGAR_DROIDS + SWR_HANGAR_DROID_COUNT; index++) {
        swrObjElmo* elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', index);
        if (elmo == NULL || swr_sceneModels[index] == NULL)
            continue;
        if (index == hang->elmoEntityIndex || elmo->kind == swrObjElmo_KIND_PIT_DROID)
            swrObjElmo_SetAnimStateById(index, 0);
        else
            swrObjElmo_SetAnimStateById(index, 0x11);
    }
    hang->elmoEntityIndex = -1;
}

// 0x0043e6f0
void ComputeModelViewBounds(void)
{
    swrModel_Node** pod = (swrModel_Node**)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS];

    if (swrModel_NodeComputeFirstMeshAABB(pod[0x40], swrObjHang_displayPodBoundsCockpit, 0) == 0) {
        rdVector_Set3((rdVector3*)&swrObjHang_displayPodBoundsCockpit[0], 0.0f, 0.0f, 0.0f);
        rdVector_Set3((rdVector3*)&swrObjHang_displayPodBoundsCockpit[3], -10.0f, -10.0f, -10.0f);
    } else {
        // look-at of the inspect-vehicle camera framing
        rdVector_Set3(&maybeUICameraPlacements[0x1e].position2, swrObjHang_displayPodBoundsCockpit[3] + 100.0f, (swrObjHang_displayPodBoundsCockpit[1] + swrObjHang_displayPodBoundsCockpit[4]) * 0.5, -157.0f);
    }
    if (swrModel_NodeComputeFirstMeshAABB(pod[0x3e], swrObjHang_displayPodBoundsEngineR, 0) == 0) {
        rdVector_Copy3((rdVector3*)&swrObjHang_displayPodBoundsEngineR[0], (rdVector3*)&swrObjHang_displayPodBoundsCockpit[0]);
        rdVector_Copy3((rdVector3*)&swrObjHang_displayPodBoundsEngineR[3], (rdVector3*)&swrObjHang_displayPodBoundsCockpit[3]);
    }
    if (swrModel_NodeComputeFirstMeshAABB(pod[0x3f], swrObjHang_displayPodBoundsEngineL, 0) == 0) {
        rdVector_Copy3((rdVector3*)&swrObjHang_displayPodBoundsEngineL[0], (rdVector3*)&swrObjHang_displayPodBoundsCockpit[0]);
        rdVector_Copy3((rdVector3*)&swrObjHang_displayPodBoundsEngineL[3], (rdVector3*)&swrObjHang_displayPodBoundsCockpit[3]);
        float midY = (swrObjHang_displayPodBoundsCockpit[1] + swrObjHang_displayPodBoundsCockpit[4]) * 0.5f;
        float cockpitMinY = (swrObjHang_displayPodBoundsCockpit[1] - swrObjHang_displayPodBoundsCockpit[4] * -5.0f) * 0.16666667f;
        swrObjHang_displayPodBoundsEngineL[4] = midY;
        // the right engine's max Y is overwritten even when its own AABB succeeded
        swrObjHang_displayPodBoundsEngineR[4] = midY;
        swrObjHang_displayPodBoundsCockpit[1] = cockpitMinY;
    }
}

// 0x00457350
void swrObjHang_AnimateTransitionNode(void)
{
    swrModel_NodeTransformed* node = (swrModel_NodeTransformed*)swr_sceneModels[INGAME_MODELID_flag2_part]->entries[0].node;
    rdMatrix44 m;
    rdVector3 pos;
    float scale;

    if (node == NULL)
        return;
    swrModel_NodeModifyFlags((swrModel_Node*)node, 2, -4, 0x10, 3);
    swrObjHang_UpdateHoloBillboardMatrix();
    rdMatrix_SetRotation44(&m, 10.080002f, 0.0f, 180.0f);
    rdVector_Copy3(&pos, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
    rdVector_Copy3((rdVector3*)&m.vD, &pos);
    scale = swrRace_Transition * 0.05f;
    rdMatrix_ScaleBasis44(&m, scale, scale, scale, &m);
    swrModel_NodeSetTransform(node, &m);
    swrModel_NodeModifyFlags((swrModel_Node*)node, 2, 3, 0x10, 2);
}

// 0x0045bf20
void swrObjHang_PositionPlayerPuppets(swrObjHang* hang)
{
    rdVector3 eye;
    rdVector3 lookAt;
    rdVector3 puppetPos;

    rdVector_Copy3(&eye, &maybeUICameraPlacements[hang->cameraState].position1); // unused, as in the original
    rdVector_Copy3(&lookAt, &maybeUICameraPlacements[hang->cameraState].position2);
    for (int player = 0; player < hang->num_local_players; player++) {
        swrObjElmo* elmo;
        swrObjHang_ComputeCameraEye(hang, player);
        elmo = (swrObjElmo*)swrEvent_GetItem('Elmo', SWR_SCENE_SLOT_PILOT_PUPPETS + player);
        if (elmo != NULL) {
            swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PILOT_PUPPETS + player], &puppetPos);
            swrObjElmo_SetTransformAndAnimById(SWR_SCENE_SLOT_PILOT_PUPPETS + player, 0x14, &puppetPos, &swrObjHang_sceneCameraEye, elmo->yaw, stdMath_ArcTan2(swrObjHang_sceneCameraEye.x - lookAt.x, lookAt.y - swrObjHang_sceneCameraEye.y));
        }
    }
}

// 0x00462cf0
void swrObjJdge_OnCycleHudButton(void)
{
    swrObjJdge* jdge = (swrObjJdge*)swrEvent_GetItem('Jdge', 0);

    playASound(0x8f, 6, 0.25f, 0.2f, 1);
    swrObjJdge_CycleHudMode(jdge);
    swrObjJdge_F3(jdge);
}

// 0x0045c010
void swrObjHang_SetHoloCameraTarget(rdVector3* pos, rdVector3* lookAt, short mode, int keepEyeOffset, int reset)
{
    rdVector3 eyeToLookAt;

    if (reset == 0) {
        rdMatrix_Copy44(&swrObjHang_holoCameraMatrixStart, &swrObjHang_holoCameraMatrix);
        rdMatrix_Copy44(&swrObjHang_cameraMatrixStart, &swrObjHang_cameraMatrix);
    }
    rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, pos);
    rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, lookAt);
    swrObjHang_cameraMoveMode = mode;
    if (mode == 3 && keepEyeOffset != 0) {
        // Put the target eye the same offset from the target look-at as it is from the current one.
        rdVector_Sub3(&eyeToLookAt, (rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        rdVector_Add3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, &eyeToLookAt);
    }
}

// 0x0045c9d0
void swrObjHang_BeginCameraMove(swrObjHang* hang, int mode)
{
    rdVector3 lookAtToEye;
    rdVector3 delta;
    float jitterScale;

    if (mode == 0) {
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&maybeUICameraPlacements[hang->cameraState].position2);
        rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&maybeUICameraPlacements[hang->cameraState].position1);
    } else {
        if (swrObjHang_state2 != (swrObjHang_STATE)~swrObjHang_STATE_LEGAL) {
            rdVector_Sub3(&lookAtToEye, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD);
            rdVector_Scale3Add3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, 10.0f, &lookAtToEye);
        }
        rdVector_Scale3Add3_both((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, 0.3333f, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD, 0.6667f, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD);
        if (hang->cameraState == HangCameraState_CounterBuyParts) {
            // The buy-parts counter is framed from a jittered eye so the shot differs each visit.
            // swrUtils_Rand returns a positive 31-bit value; 1/2^31 maps it to [0, 1).
            rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, &swrObjElmo_waypoints[6]);
            jitterScale = swrUtils_RandFloat();
            swrObjHang_cameraMatrixTarget.vD.x = ((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 10.0f + 180.0f) * jitterScale + swrObjHang_cameraMatrixTarget.vD.x;
            swrObjHang_cameraMatrixTarget.vD.y = ((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 125.0f - 375.0f) + swrObjHang_cameraMatrixTarget.vD.y;
            swrObjHang_cameraMatrixTarget.vD.z = (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 30.0f + 40.0f;
            rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, &swrObjElmo_waypoints[6]);
            rdVector_Sub3(&delta, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD);
            rdVector_Add3((rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, &delta);
        }
    }
    swrObjHang_cameraMoveMode = 1;
    swrObjHang_cameraMoveActive = 1;
}

// Resolve this frame's scene-camera eye, then override its height for the current room.
// 0x0045cb80
void swrObjHang_ComputeCameraEye(swrObjHang* hang, int mode)
{
    rdVector3 eye;
    rdVector3 up;
    rdVector3 side;
    rdVector3 forward;
    rdVector3 from;
    rdVector3 to;
    rdVector3* a;
    rdVector3* b;
    const rdVector3* eyeSrc;

    up.x = 0.0f;
    up.y = 0.0f;
    up.z = 1.0f;
    rdVector_Copy3(&from, (rdVector3*)&maybeUICameraPlacements[hang->cameraState].position1);
    rdVector_Copy3(&to, (rdVector3*)&maybeUICameraPlacements[hang->cameraState].position2);

    if (hang->cameraState == HangCameraState_CantinaHolotableFar) {
        eyeSrc = (rdVector3*)&maybeUICameraPlacements[HangCameraState_CantinaHolotableFar].position1;
    } else if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
        eyeSrc = (rdVector3*)&maybeUICameraPlacements[HangCameraState_InspectCharacter].position2;
    } else if (swrObjHang_cameraMoveParity == 0 || mode != 0 || hang->menuScreen != swrObjHang_STATE_WATTO || (swrObjHang_cameraMoveMode != 0 && swrObjHang_cameraMoveMode != 5)) {
        // Offset the eye off the from->to line: 3 parts along it to 1 part sideways, scaled x60.
        rdVector_Sub3(&forward, &to, &from);
        if (mode == 0) {
            b = &forward;
            a = &up;
        } else {
            b = &up;
            a = &forward;
        }
        rdVector_Cross3(&side, a, b);
        rdVector_Normalize3Acc(&side);
        rdVector_Normalize3Acc(&forward);
        rdVector_Scale3(&forward, 3.0f, &forward);
        rdVector_Add3(&eye, &forward, &side);
        rdVector_Scale3(&eye, 60.0f, &eye);
        rdVector_Add3(&eye, &from, &eye);
        eyeSrc = &eye;
    } else {
        eyeSrc = &to;
    }
    rdVector_Copy3(&swrObjHang_sceneCameraEye, eyeSrc);

    switch (hang->room) {
    case Shop:
    case Cantina:
        swrObjHang_sceneCameraEye.z = -60.0f;
        break;
    case Junkyard:
        swrObjHang_sceneCameraEye.z = -145.0f;
        break;
    case Hangar:
        swrObjHang_sceneCameraEye.z = -157.0f;
        break;
    default:
        break;
    }
}

// Duration-based camera move: eases the eye and look-at from their move-start snapshots to their
// targets over swrObjHang_cameraMoveDuration seconds.
// 0x0045c0b0
void swrObjHang_LerpHoloCamera(swrObjHang* hang)
{
    float t;
    rdVector3 lookAt;
    rdVector3 eye;

    rdVector_Copy3(&eye, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    rdVector_Copy3(&lookAt, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
    if (swrObjHang_cameraLerpNeedsInit != 0) {
        swrObjHang_cameraMoveLookAtDeltaX = swrObjHang_holoCameraMatrixTarget.vD.x - swrObjHang_holoCameraMatrixStart.vD.x;
        swrObjHang_cameraMoveLookAtDeltaY = swrObjHang_holoCameraMatrixTarget.vD.y - swrObjHang_holoCameraMatrixStart.vD.y;
        swrObjHang_cameraMoveLookAtDeltaZ = swrObjHang_holoCameraMatrixTarget.vD.z - swrObjHang_holoCameraMatrixStart.vD.z;
        swrObjHang_cameraMoveEyeDeltaX = swrObjHang_cameraMatrixTarget.vD.x - swrObjHang_cameraMatrixStart.vD.x;
        swrObjHang_cameraMoveEyeDeltaY = swrObjHang_cameraMatrixTarget.vD.y - swrObjHang_cameraMatrixStart.vD.y;
        swrObjHang_cameraMoveEyeDeltaZ = swrObjHang_cameraMatrixTarget.vD.z - swrObjHang_cameraMatrixStart.vD.z;
        swrObjHang_cameraMoveElapsed = 0.0f;
        swrObjHang_cameraMoveDuration = 0.5f;
        // A short hop across the junkyard counter gets a quicker move.
        if (swrObjHang_cameraMoveLookAtDeltaX < 500.0f && -500.0f < swrObjHang_cameraMoveLookAtDeltaX && swrObjHang_cameraMoveLookAtDeltaY < 500.0f && -500.0f < swrObjHang_cameraMoveLookAtDeltaY && hang->room == Junkyard) {
            swrObjHang_cameraMoveDuration = 0.3f;
        }
        swrObjHang_cameraLerpNeedsInit = 0;
    }
    if (swrObjHang_cameraMoveDuration <= swrObjHang_cameraMoveElapsed) {
        swrObjHang_cameraMoveMode = 5;
        if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
            swrObjHang_cameraMoveMode = 0;
        }
        swrObjHang_cameraLerpNeedsInit = 1;
        if (swrObjHang_cameraMoveActive != 0) {
            swrObjHang_cameraMoveActive = 0;
            swrObjHang_cameraMoveParity = swrObjHang_cameraMoveParity == 0;
            if (hang->room == Junkyard && hang->cameraState != HangCameraState__unk_3 && swrObjHang_cameraMoveParity != 0) {
                swrObjHang_screenTransitionDir = 1;
            }
        }
        rdMatrix_Copy44(&swrObjHang_holoCameraMatrixStart, &swrObjHang_holoCameraMatrix);
        rdMatrix_Copy44(&swrObjHang_cameraMatrixStart, &swrObjHang_cameraMatrix);
        if (swrObjHang_state2 != (swrObjHang_STATE)~swrObjHang_STATE_LEGAL && swrObjHang_screenTransitionDir == 0) {
            swrObjHang_cameraMoveParity = 0;
            return;
        }
    } else {
        swrObjHang_cameraMoveElapsed = swrObjHang_cameraMoveElapsed + swrRace_fdeltaTimeSecs;
        if (swrObjHang_cameraMoveDuration < swrObjHang_cameraMoveElapsed) {
            swrObjHang_cameraMoveElapsed = swrObjHang_cameraMoveDuration;
        }
        t = swrObjHang_cameraMoveElapsed / swrObjHang_cameraMoveDuration;
        swrObjHang_holoCameraMatrix.vD.x = (swrObjHang_holoCameraMatrixTarget.vD.x - swrObjHang_holoCameraMatrixStart.vD.x) * t + swrObjHang_holoCameraMatrixStart.vD.x;
        swrObjHang_holoCameraMatrix.vD.y = (swrObjHang_holoCameraMatrixTarget.vD.y - swrObjHang_holoCameraMatrixStart.vD.y) * t + swrObjHang_holoCameraMatrixStart.vD.y;
        swrObjHang_holoCameraMatrix.vD.z = (swrObjHang_holoCameraMatrixTarget.vD.z - swrObjHang_holoCameraMatrixStart.vD.z) * t + swrObjHang_holoCameraMatrixStart.vD.z;
        // Mode 3 moves the look-at only and leaves the eye where it is.
        if (swrObjHang_cameraMoveMode != 3) {
            swrObjHang_cameraMatrix.vD.x = (swrObjHang_cameraMatrixTarget.vD.x - swrObjHang_cameraMatrixStart.vD.x) * t + swrObjHang_cameraMatrixStart.vD.x;
            swrObjHang_cameraMatrix.vD.y = (swrObjHang_cameraMatrixTarget.vD.y - swrObjHang_cameraMatrixStart.vD.y) * t + swrObjHang_cameraMatrixStart.vD.y;
            swrObjHang_cameraMatrix.vD.z = (swrObjHang_cameraMatrixTarget.vD.z - swrObjHang_cameraMatrixStart.vD.z) * t + swrObjHang_cameraMatrixStart.vD.z;
        }
    }
}

// Speed-based camera move: steps the eye and look-at toward their targets, and applies the pending
// menu state once both arrive.
// 0x0045c3c0
void swrObjHang_UpdateHoloCamera(swrObjHang* hang)
{
    int lookAtArrived;
    int eyeArrived;
    float dist;
    rdVector3 toTarget;

    if (!rdVector_AreSame3(&swrObjHang_cameraLookAtTargetCached, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD)) {
        rdVector_Copy3(&swrObjHang_cameraLookAtTargetCached, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD);
        // On a retarget, pull a far-away look-at in to 500 units so the step does not crawl.
        rdVector_Sub3(&toTarget, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD);
        dist = rdVector_Len3(&toTarget);
        if (500.0f < dist) {
            rdVector_Normalize3Acc(&toTarget);
            rdVector_Scale3Add3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD, 500.0f, &toTarget);
        }
    }
    lookAtArrived = swrObjHang_StepCameraToward(hang, &swrObjHang_cameraStepLookAtSpeed, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrixStart.vD, 1.5f);
    eyeArrived = swrObjHang_StepCameraToward(hang, &swrObjHang_cameraStepEyeSpeed, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD, (rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_cameraMatrixStart.vD, 1.0f);
    if (eyeArrived != 0 && lookAtArrived != 0) {
        swrObjHang_cameraMoveMode = 5;
        swrObjHang_cameraMoveSettled = 1;
        if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
            swrObjHang_cameraMoveMode = 0;
        }
        if (swrObjHang_cameraMoveActive != 0) {
            swrObjHang_cameraMoveParity = swrObjHang_cameraMoveParity == 0;
            swrObjHang_cameraMoveActive = 0;
            if (hang->room == Junkyard && hang->cameraState != HangCameraState__unk_3 && swrObjHang_cameraMoveParity != 0) {
                swrObjHang_screenTransitionDir = 1;
            }
        }
        rdMatrix_Copy44(&swrObjHang_holoCameraMatrixStart, &swrObjHang_holoCameraMatrix);
        rdMatrix_Copy44(&swrObjHang_cameraMatrixStart, &swrObjHang_cameraMatrix);
        if (swrObjHang_state2 != (swrObjHang_STATE)~swrObjHang_STATE_LEGAL && swrObjHang_screenTransitionDir == 0) {
            swrObjHang_cameraMoveParity = 0;
            if (swrObjHang_fadeState == 0) {
                swrObjHang_SetMenuState(hang, swrObjHang_state2);
            }
        }
    }
}

// Advance `from` toward `target` this frame, ramping the carried speed down over the last stretch so
// the camera eases in. Returns nonzero once it has arrived.
// 0x0045c560
int swrObjHang_StepCameraToward(swrObjHang* hang, float* progress, rdVector3* target, rdVector3* from, rdVector3* to, float speed)
{
    swrObjHang_STATE screen;
    float dot;
    float step;
    float rate;
    float halfSpan;
    float arriveRadius;
    float distToTarget;
    float carriedSpeed;
    float decelSpan;
    rdVector3 targetToFrom;
    rdVector3 fromToTo;
    rdVector3 targetToTo;
    rdVector3 remaining;
    rdVector3 start;

    screen = hang->menuScreen;
    carriedSpeed = *progress;
    decelSpan = 1600.0f;
    if (screen == swrObjHang_STATE_RESULTS_INTRO || screen == swrObjHang_STATE_VEHICLE_SELECT_INTRO || (screen == swrObjHang_STATE_LOOK_AT_VEHICLE && 5.0f <= swrObjHang_inspectCameraTimer) || (screen == swrObjHang_STATE_MAIN_MENU && swrObjHang_fadeState == 0)) {
        decelSpan = 320.0f;
        rate = 0.2f;
    } else if (screen == swrObjHang_STATE_PLANET_SELECT_INTRO) {
        decelSpan = 80.0f;
        rate = 0.05f;
    } else {
        rate = 1.0f;
    }
    step = swrRace_fdeltaTimeSecs * 60000.0f * rate;

    rdVector_Copy3(&start, from);
    swrObjHang_cameraStepScratch = 0;
    step = step * speed;
    rdVector_Sub3(&targetToTo, target, to);
    halfSpan = rdVector_Len3(&targetToTo) * 0.5f;
    rdVector_Sub3(&fromToTo, to, from);
    rdVector_Len3(&fromToTo);
    rdVector_Sub3(&remaining, target, from);
    distToTarget = rdVector_Len3(&remaining);
    arriveRadius = step * 6.0f;
    if (halfSpan < arriveRadius) {
        arriveRadius = halfSpan;
    }
    if (distToTarget < arriveRadius || step <= carriedSpeed) {
        if ((distToTarget < arriveRadius || carriedSpeed < step) && distToTarget < arriveRadius && 1.0f < distToTarget) {
            if (swrObjHang_state2 != (swrObjHang_STATE)~swrObjHang_STATE_LEGAL && hang->menuScreen != swrObjHang_STATE_VEHICLE_SELECT_INTRO) {
                return 1;
            }
            carriedSpeed = stdMath_Sqrt(distToTarget / (decelSpan * speed)) * decelSpan * speed;
        }
    } else {
        carriedSpeed = carriedSpeed - speed * swrRace_fdeltaTimeSecs * -2000.0f;
        if (step < carriedSpeed) {
            carriedSpeed = step;
        }
    }
    if (1.0f < distToTarget) {
        rdVector_Normalize3Acc(&remaining);
        rdVector_Scale3Add3(from, from, carriedSpeed * swrRace_fdeltaTimeSecs, &remaining);
        rdVector_Sub3(&targetToFrom, target, from);
        dot = rdVector_Dot3(&remaining, &targetToFrom);
        // Overshot the target this frame if the direction flipped.
        if (0.0f <= dot) {
            *progress = carriedSpeed;
            return 0;
        }
    }
    rdVector_Copy3(from, target);
    *progress = 0.0f;
    return 1;
}

// Point the camera at a scene element: resolve the element position, then either retarget the camera
// or slide the whole rig so the eye keeps its offset.
// 0x0043e840
void LoadUpgradeModelsIntoScene_Maybe(swrObjHang* hang)
{
    char unlockedTracks = 0;
    int count = 0;

    swrRace_MenuMaxSelection = 0;
    for (int circuit = 0; circuit < SWR_CIRCUIT_COUNT; circuit++) {
        for (int track = 0; track < g_aTracksInCircuits[circuit]; track++) {
            if (((uint8_t)swrRace_UnlockDataBase[circuit + 1] & (1 << track)) != 0)
                unlockedTracks++;
        }
    }
    for (int type = 0; type < SWR_UPGRADE_CATEGORY_COUNT; type++) {
        uiUpgradeInfos[type].index = (char)type * SWR_UPGRADE_LEVEL_COUNT + (&swrRace_traction_upgrade_level)[type];
        uiUpgradeInfos[type].health = (&swrRace_traction_upgrade_health)[type];
    }

    if (hang->menuScreen == swrObjHang_STATE_WATTO) {
        for (int type = 0; type < SWR_UPGRADE_CATEGORY_COUNT; type++) {
            for (int level = 0; level < SWR_UPGRADE_LEVEL_COUNT; level++) {
                int part = type * SWR_UPGRADE_LEVEL_COUNT + level;
                if ((char)uiUpgradeInfos[type].index != part && (signed char)upgradeInfos[part].shopTracksRequired <= unlockedTracks - SWR_SHOP_STARTING_TRACKS) {
                    uiUpgradeInfos2[count].index = (char)part;
                    uiUpgradeInfos2[count].health = 0xff;
                    count++;
                }
            }
        }
        swrRace_MenuMaxSelection = count;
    } else if (hang->menuScreen == swrObjHang_STATE_JUNKYARD) {
        for (int slot = 0; slot < SWR_UPGRADE_CATEGORY_COUNT; slot++) {
            uiUpgradeInfos2[count].index = (char)slot * SWR_UPGRADE_LEVEL_COUNT + swrObjHang_junkyardStock[slot].level;
            uiUpgradeInfos2[count].health = swrObjHang_junkyardStock[slot].health;
            count++;
        }
        swrRace_MenuMaxSelection = count;
    }

    for (int i = 0; i < swrRace_MenuMaxSelection; i++)
        swrModel_LoadModelIntoScene(upgradeInfos[(char)uiUpgradeInfos2[i].index].model, -1, SWR_SCENE_SLOT_SHOP_PARTS + i, false);
    for (int i = 0; i < SWR_UPGRADE_CATEGORY_COUNT; i++)
        swrModel_LoadModelIntoScene(upgradeInfos[(char)uiUpgradeInfos[i].index].model, -1, SWR_SCENE_SLOT_INSTALLED_PARTS + i, false);
}

static void computeSelectedPartStats(swrObjHang* hang)
{
    swrUpgradeInfo* part = &upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index];

    swrObjHang_ComputeUpgradedStats((int)hang->vehiclePlayer, (int)(char)part->type, part->level, uiUpgradeInfos2[swrRace_MenuSelectedItem].health);
}

// 0x004376c0
void swrObjHang_UpdateWattoShop(swrObjHang* hang)
{
    char text[256];
    char* partName;
    char* format;
    int width;
    rdVector3 droidPos;
    rdVector3 droidLookAt;
    float yaw;

    swrObjHang_UpdateScreenTransition(hang, swrObjHang_menuJustEntered, 0x14);
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_screenSlideOffset = -300.0f;
        swrObjHang_screenTransitionDir = 0;
        if (hang->roomPrev != Shop)
            swrObjHang_LayoutVehicleSelectIcons(hang);
        swrObjHang_partLerpActive = 0;
        swrObjHang_pitDroidsForSale = SWR_MAX_PIT_DROIDS - (uint8_t)swrRace_nbPitDroids;
        swrObjHang_pitDroidPromptActive = 0;
        if (hang->activeMenu == 0) {
            swrObjHang_FocusMenuItem(hang, 1, ~swrObjHang_STATE_LEGAL, 0);
            swrObjHang_cameraMoveParity = 0;
            swrObjHang_BeginCameraMove(hang, 1);
            swrObjHang_partLayoutDirty = 1;
            computeSelectedPartStats(hang);
            swrObjHang_shopLastSelectedItem = swrRace_MenuSelectedItem;
        } else {
            swrRace_upgradeUnaffordable = swrRace_truguts < SWR_PIT_DROID_PRICE;
            swrObjHang_pitDroidPromptActive = swrObjHang_pitDroidsForSale != 0;
            if (swrObjHang_IsCameraMoving(hang) != 0)
                swrObjHang_FocusMenuItem(hang, 2, ~swrObjHang_STATE_LEGAL, 0);
        }
    }
    swrObjHang_PlayWattoVoiceLines_Maybe((int)hang);
    if (hang->activeMenu == 0) {
        if (swrObjHang_shopLastSelectedItem != swrRace_MenuSelectedItem) {
            swrObjHang_shopLastSelectedItem = swrRace_MenuSelectedItem;
            swrObjHang_partLayoutDirty = 1;
            computeSelectedPartStats(hang);
            swrRace_ComputeUpgradePrices();
        }
    } else if (0 < swrObjHang_pitDroidsForSale && swrObjHang_cameraMoveMode != 1 && swrObjHang_screenSlideOffset == -300.0f) {
        swrObjHang_screenTransitionDir = 1;
        swrObjHang_cameraMoveMode = 5;
        swrObjElmo_SetAnimStateById(swrObjHang_pitDroidsForSale + SWR_ELMO_ID_PIT_DROID_BASE, 3);
    }

    if (hang->cameraState == HangCameraState_CounterBuyParts) {
        swrRace_DrawPartShopScreen(hang);
        swrRace_VehicleStatisticsSubMenu(hang, 20.0f, 135.0f);
    } else {
        swrRace_BuyPitdroidsMenu(hang);
    }
    if (swrObjHang_partDetailActive == 0 && swrObjHang_screenTransitionDir == 0 && hang->cameraState == HangCameraState_CounterBuyParts && (swrObjHang_cameraMoveMode == 0 || swrObjHang_cameraMoveMode == 5)) {
        partName = swrText_Translate((char*)upgradeInfos[(char)uiUpgradeInfos2[swrRace_MenuSelectedItem].index].name);
        format = swrText_Translate(g_pTxtPartNameFormat);
        sprintf(text, format, partName);
        swrText_CreateTextEntry1(0xa0, 0x19, 0x32, -1, -1, -1, text);
        swrText_GetStringWidthByFont(text, 0);
        width = swrText_GetStringWidthByFont(text, 0);
        // the original also pushes width as a third argument, which the callee never reads
        swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - (double)width * 0.5), 0x1a);
    }
    swrRace_UpdatePartMenuLayout(hang);
    swrRace_UpdateStatPartModels(); // the original pushes hang; the callee takes no argument
    swrObjHang_partLayoutDirty = 0;
    if (hang->menuScreen == swrObjHang_STATE_MAIN_MENU)
        return;

    for (int player = 0; player < hang->num_local_players; player++) {
        if (swrObjHang_screenTransitionDir == 0 && swrMultiplayer_menuOverlayActive == 0) {
            if (swrControl_menuAcceptPressedEdge != 0) {
                playUISound(0x54);
                if (hang->activeMenu == 0) {
                    if (swrRace_MenuSelectedItem != -1) {
                        if (swrObjHang_partDetailActive == 0) {
                            if (swrObjHang_cameraMoveMode == 0 || swrObjHang_cameraMoveMode == 5) {
                                swrObjHang_partLayoutDirty = 1;
                                swrObjHang_partDetailActive = 1;
                                swrRace_upgradeUnaffordable = 0;
                                swrObjHang_screenTransitionDir = 1;
                                swrRace_ComputeUpgradePrices();
                            }
                        } else {
                            // buy (affordable) or decline; elmo 0x1c is player 1's pilot puppet
                            if (swrRace_upgradeUnaffordable == 0) {
                                swrObjElmo_SetAnimStateById(0x1c, 0x19);
                                swrObjHang_SwapSelectedPart(hang);
                            } else {
                                swrObjElmo_SetAnimStateById(0x1c, 0x1a);
                            }
                            swrObjHang_partLayoutDirty = 1;
                            swrRace_upgradeUnaffordable = 0;
                            swrObjHang_partDetailActive = 0;
                            swrObjHang_partDetailClosing = 1;
                            swrObjHang_screenTransitionDir = -1;
                        }
                    }
                } else if (hang->activeMenu == 1) {
                    if (swrObjHang_pitDroidPromptActive == 0) {
                        if (0 < swrObjHang_pitDroidsForSale) {
                            swrObjHang_pitDroidPromptActive = 1;
                            swrObjHang_screenTransitionDir = 1;
                            swrRace_upgradeUnaffordable = 0;
                            swrObjElmo_SetAnimStateById(swrObjHang_pitDroidsForSale + SWR_ELMO_ID_PIT_DROID_BASE, 3);
                        }
                    } else if (swrRace_upgradeUnaffordable == 1) {
                        swrRace_upgradeUnaffordable = 0;
                        swrObjHang_pitDroidPromptActive = 0;
                        swrObjHang_screenTransitionDir = -1;
                        swrObjElmo_SetAnimStateById(swrObjHang_pitDroidsForSale + SWR_ELMO_ID_PIT_DROID_BASE, 4);
                        if (swrObjHang_shopFocusTypePending != 2) {
                            swrObjHang_pitDroidPromptActive = 0;
                            swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
                            return;
                        }
                        swrObjHang_shopFocusTypePending = 0;
                        swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                        swrObjHang_fadeState = -1;
                    } else if (SWR_PIT_DROID_PRICE - 1 < swrRace_truguts) {
                        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PIT_DROIDS - 1 + swrObjHang_pitDroidsForSale], &droidPos);
                        rdVector_Copy3(&droidLookAt, &maybeUICameraPlacements[0].position2);
                        droidLookAt.z = -60.0f;
                        yaw = stdMath_ArcTan2(droidPos.x - 12.0f, -116.0f - droidPos.y);
                        swrObjElmo_SetTransformAndAnimById(swrObjHang_pitDroidsForSale + SWR_ELMO_ID_PIT_DROID_BASE, 10, &droidPos, &droidLookAt, yaw, yaw);
                        swrRace_truguts = swrRace_truguts - SWR_PIT_DROID_PRICE;
                        swrObjHang_pitDroidsForSale--;
                        swrRace_nbPitDroids++;
                        swrRace_SaveCurrentProfile();
                        if (swrObjHang_pitDroidsForSale < 1) {
                            swrObjHang_pitDroidPromptActive = 0;
                            swrObjHang_screenTransitionDir = -1;
                            if (swrObjHang_shopFocusTypePending == 2) {
                                swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                                swrObjHang_screenTransitionDir = -1;
                                swrObjHang_shopFocusTypePending = 0;
                                swrObjHang_pitDroidPromptActive = 0;
                                swrObjHang_fadeState = -1;
                                return;
                            }
                            hang->mainMenuSelection = 1;
                            swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
                            return;
                        }
                        swrObjElmo_SetAnimStateById(swrObjHang_pitDroidsForSale + SWR_ELMO_ID_PIT_DROID_BASE, 3);
                    }
                }
            }
            if (swrControl_cancelPressedEdge != 0) {
                playUISound(0x4d);
                if (swrObjHang_pitDroidPromptActive == 0) {
                    if (swrObjHang_partDetailActive == 0) {
                        swrObjHang_partLayoutDirty = 1;
                        if (swrObjHang_shopFocusTypePending == 1) {
                            swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                            swrObjHang_partLayoutDirty = 1;
                            swrObjHang_fadeState = -1;
                            return;
                        }
                        swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
                    } else {
                        swrObjElmo_SetAnimStateById(0x1c, 0x1a);
                        swrObjHang_partLayoutDirty = 1;
                        swrObjHang_partDetailActive = 0;
                        swrObjHang_partDetailClosing = 1;
                        swrRace_upgradeUnaffordable = 0;
                        swrObjHang_screenTransitionDir = -1;
                    }
                } else {
                    swrRace_upgradeUnaffordable = 0;
                    swrObjHang_screenTransitionDir = -1;
                    if (swrObjHang_shopFocusTypePending != 2) {
                        swrObjHang_pitDroidPromptActive = 0;
                        swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
                        return;
                    }
                    swrObjHang_shopFocusTypePending = 0;
                    swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                    swrObjHang_fadeState = -1;
                }
            }
        }
        if (hang->activeMenu == 0) {
            swrObjHang_NavigateVehicleSelect(0, 1.0f, 0);
            if (swrObjHang_partDetailActive == 0) {
                // swing the ring while scrolling
                if ((swrUI_localPlayersInputDownBitset[player] & swrUI_INPUT_MENU_RIGHT) != 0 && swrRace_MenuSelectedItem < swrRace_MenuMaxSelection - 1) {
                    swrObjHang_shopSwingPhase = swrRace_fdeltaTimeSecs * SWR_SHOP_SWING_PHASE_RATE + swrObjHang_shopSwingPhase;
                    if (SWR_SHOP_SWING_PHASE_MAX < swrObjHang_shopSwingPhase)
                        swrObjHang_shopSwingPhase = SWR_SHOP_SWING_PHASE_MAX;
                    swrObjHang_shopSwingLean = swrObjHang_shopSwingLean - swrRace_fdeltaTimeSecs * SWR_SHOP_SWING_LEAN_RATE;
                    if (swrObjHang_shopSwingLean < -1.0f)
                        swrObjHang_shopSwingLean = -1.0f;
                }
                if ((swrUI_localPlayersInputDownBitset[player] & swrUI_INPUT_MENU_LEFT) != 0 && 0 < swrRace_MenuSelectedItem) {
                    swrObjHang_shopSwingPhase = swrRace_fdeltaTimeSecs * SWR_SHOP_SWING_PHASE_RATE + swrObjHang_shopSwingPhase;
                    if (SWR_SHOP_SWING_PHASE_MAX < swrObjHang_shopSwingPhase)
                        swrObjHang_shopSwingPhase = SWR_SHOP_SWING_PHASE_MAX;
                    swrObjHang_shopSwingLean = swrRace_fdeltaTimeSecs * SWR_SHOP_SWING_LEAN_RATE + swrObjHang_shopSwingLean;
                    if (1.0f < swrObjHang_shopSwingLean)
                        swrObjHang_shopSwingLean = 1.0f;
                }
            }
        }
    }
}

// 0x00437ea0
void swrObjHang_PlayWattoVoiceLines_Maybe(int hang)
{
    // flag 0x10 (meaning unidentified) and the pending greeting gate every line
    if (swrSound_TestSfxFlag(0, 0x10) == 0 || swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING) == 0)
        return;
    swrSound_ClearSfxFlag(0, swrSound_HANGSFXFLAG_GREETING_PENDING);
    if (((swrObjHang*)hang)->activeMenu == 0) {
        if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_PARTS_INTRO_PLAYED) == 0) {
            swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_PARTS_INTRO_PLAYED);
            swrSound_PlaySfxThrottled(2, 0, 1, NULL);
            return;
        }
        swrSound_PlayRandomSfx(2, 0, 0x16, 0x17, 0x1e, 0x1f, 0x38, NULL);
        return;
    }
    if (swrSound_TestSfxFlag(0, swrSound_HANGSFXFLAG_PIT_DROID_INTRO_PLAYED) == 0) {
        swrSound_SetSfxFlag(0, swrSound_HANGSFXFLAG_PIT_DROID_INTRO_PLAYED);
        swrSound_PlaySfxThrottled(2, 0, 0xf, NULL);
        return;
    }
    swrSound_PlayRandomSfx(2, 0, 0x29, 0x2e, 0x2f, 0x30, 0xc, NULL);
}

// 0x00437f70
void swrObjHang_UpdateLookAtVehicle(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00440800
void swrObjHang_SwapSelectedPart(swrObjHang* hang)
{
    int selected = swrRace_MenuSelectedItem;
    swrUIUpgradeInfo* offered = &uiUpgradeInfos2[selected];
    int type = (char)upgradeInfos[(char)offered->index].type;
    swrUIUpgradeInfo* installed = &uiUpgradeInfos[type];
    swrUIUpgradeInfo swap;
    rdVector3 slotPos;

    swrRace_truguts = (swrRace_truguts - swrRace_upgradePrice) + swrRace_upgradeTradeInValue;
    if (hang->room == Junkyard)
        swrObjHang_junkyardStock[hang->cameraState - SWR_JUNKYARD_PLACEMENT_FIRST].health = (&swrRace_traction_upgrade_health)[type];

    // swap the two entries, then swap their positions back so each slot keeps its place
    swap = *offered;
    *offered = *installed;
    *installed = swap;
    rdVector_Copy3(&slotPos, &uiUpgradeInfos2[selected].vector1);
    rdVector_Copy3(&uiUpgradeInfos2[swrRace_MenuSelectedItem].vector1, &uiUpgradeInfos[type].vector1);
    rdVector_Copy3(&uiUpgradeInfos[type].vector1, &slotPos);

    (&swrRace_traction_upgrade_health)[type] = uiUpgradeInfos[type].health;
    (&swrRace_traction_upgrade_level)[type] = upgradeInfos[(char)installed->index].level;
    swrModel_SwapSceneModels(swrRace_MenuSelectedItem + SWR_SCENE_SLOT_SHOP_PARTS, type + SWR_SCENE_SLOT_INSTALLED_PARTS);
    swrObjHang_partLayoutDirty = 1;
    swrRace_SaveCurrentProfile();
    computeSelectedPartStats(hang);
    swrRace_ComputeUpgradePrices();
}

static void aimAtPodPart(int entry, rdVector3* out)
{
    rdMatrix44 xf;

    swrModel_NodeGetTransform((swrModel_NodeTransformed*)swr_sceneModels[SWR_SCENE_SLOT_POD_MODELS]->entries[entry].node, &xf);
    rdVector_Copy3(out, (rdVector3*)&xf.vD);
}

// 0x0043f770
void swrObjHang_CycleInspectCamera(swrObjHang* hang)
{
    int cameraState = hang->cameraState;
    if (swrObjHang_inspectIdleDelay == -1.0f)
        swrObjHang_inspectIdleDelay = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 4.0 + 3.0;

    swrObjHang_UpdateHoloCameraTarget(hang, cameraState);

    if (swrObjHang_cameraMoveMode != 1) {
        swrObjHang_inspectIdleTimer += swrRace_fdeltaTimeSecs;
        if (swrObjHang_inspectIdleTimer >= swrObjHang_inspectIdleDelay) {
            swrObjHang_inspectIdleTimer = 0.0f;
            swrObjHang_inspectIdleDelay = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 4.0 + 3.0;
            do {
                // InspectCockpit..InspectCharacter
                cameraState = HangCameraState_InspectCockpit - (int)((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * -10.0f);
                if (cameraState >= HangCameraState_InspectEngine1 && cameraState <= HangCameraState_InspectEngine4 && swrRacer_PodData[hang->vehiclePlayer].pod_modelID == MODELID_neva_kee_pod)
                    cameraState = hang->cameraState;
                if (cameraState >= HangCameraState_InspectEngine3 && cameraState <= HangCameraState_InspectEngine4 && swrRacer_PodData[hang->vehiclePlayer].pod_modelID != MODELID_ben_quadinaros_pod)
                    cameraState = hang->cameraState;
                if (cameraState <= HangCameraState_InspectPT04 && cameraState - HangCameraState_InspectEngine4 > (unsigned char)swrRace_nbPitDroids)
                    cameraState = hang->cameraState;
            } while (cameraState == hang->cameraState);
            swrObjHang_cameraMoveMode = 1;
        }
    }

    if (cameraState != hang->cameraState) {
        swrObjHang_AimHoloCamera(hang, cameraState, 0);
        hang->cameraState = cameraState;
    }
}

// Re-derive the inspect orbit (distance, yaw, pitch) from the current eye and look-at.
static void inspectOrbitFromCamera(void)
{
    rdVector3 dir;

    rdVector_Sub3(&dir, (rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
    swrObjHang_inspectOrbitDistance = rdVector_Len3(&dir);
    rdVector_Normalize3Acc(&dir);
    swrObjHang_inspectOrbitYaw = stdMath_ArcTan2(-dir.x, dir.y);
    swrObjHang_inspectOrbitPitch = stdMath_ArcSin(dir.z);
    if (swrObjHang_inspectOrbitYaw < 0.0f)
        swrObjHang_inspectOrbitYaw = swrObjHang_inspectOrbitYaw - -360.0f;
    if (swrObjHang_inspectOrbitYaw > 360.0f)
        swrObjHang_inspectOrbitYaw = swrObjHang_inspectOrbitYaw - 360.0f;
    if (swrObjHang_inspectOrbitPitch < -90.0f)
        swrObjHang_inspectOrbitPitch = swrObjHang_inspectOrbitPitch - -180.0f;
    if (swrObjHang_inspectOrbitPitch > 90.0f)
        swrObjHang_inspectOrbitPitch = swrObjHang_inspectOrbitPitch - 180.0f;
}

// 0x00438d20
void swrObjHang_UpdateInspectCamera(swrObjHang* hang)
{
    rdMatrix44 rot;
    int stepped = 0;
    int orbitMoved = 0;
    int snapToItem = 0;

    if (swrObjHang_inspectCameraReset != 0 || swrObjHang_menuJustEntered != 0 || swrObjHang_cameraMoveMode == 4) {
        if (swrObjHang_menuJustEntered != 0) {
            sprintf(swrObjHang_inspectCaption, wuRegistry_lpClass);
            if (swrObjHang_menuJustEntered != 0)
                rdVector_Set3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, 0.0f, 0.0f, 0.0f);
        }
        hang->cameraState = HangCameraState_InspectDefault;
        swrObjHang_AimHoloCamera(hang, HangCameraState_InspectDefault, 0);
        inspectOrbitFromCamera();
        swrObjHang_inspectCameraFresh = 1;
        swrObjHang_inspectCameraTimer = 0.0f;
        swrObjHang_inspectCameraReset = 0;
        swrObjHang_menuJustEntered = 0;
        swrObjHang_cameraMoveMode = 0;
    }
    if (swrObjHang_inspectCameraFresh != 0) {
        swrObjHang_inspectCameraTimer = swrObjHang_inspectCameraTimer + swrRace_fdeltaTimeSecs;
        if (!(swrObjHang_inspectCameraTimer < 5.0f))
            swrObjHang_inspectCameraTimer = 5.0f;
    }

    char* label = NULL;
    switch (hang->cameraState) {
    case HangCameraState_InspectDefault:
        sprintf(swrObjHang_inspectCaption, wuRegistry_lpClass);
        break;
    case HangCameraState_InspectCockpit:
        label = "/SCREENTEXT_152/~c~sCockpit";
        break;
    case HangCameraState_InspectEngine1:
        label = "/SCREENTEXT_153/~c~sEngine 1";
        break;
    case HangCameraState_InspectEngine2:
        label = "/SCREENTEXT_154/~c~sEngine 2";
        break;
    case HangCameraState_InspectEngine3:
        label = "/SCREENTEXT_155/~c~sEngine 3";
        break;
    case HangCameraState_InspectEngine4:
        label = "/SCREENTEXT_156/~c~sEngine 4";
        break;
    case HangCameraState_InspectPT01:
        label = "/SCREENTEXT_158/~c~sPT01";
        break;
    case HangCameraState_InspectPT02:
        label = "/SCREENTEXT_159/~c~sPT02";
        break;
    case HangCameraState_InspectPT03:
        label = "/SCREENTEXT_160/~c~sPT03";
        break;
    case HangCameraState_InspectPT04:
        label = "/SCREENTEXT_161/~c~sPT04";
        break;
    case HangCameraState_InspectCharacter: {
        char* lastname = swrText_Translate(swrRacer_PodData[(int)hang->vehiclePlayer].lastname);
        char* name = swrText_Translate(swrRacer_PodData[(int)hang->vehiclePlayer].name);
        char* format = swrText_Translate("~c~s%s %s");
        sprintf(swrObjHang_inspectCaption, format, name, lastname);
        break;
    }
    default:
        break;
    }
    if (label != NULL)
        sprintf(swrObjHang_inspectCaption, swrText_Translate(label));
    swrText_CreateTextEntry1(0xa0, 0xc3, 0, -1, 0, -1, swrObjHang_inspectCaption);

    for (int i = 0; i < hang->num_local_players; i++) {
        if (swrMultiplayer_menuOverlayActive == 0) {
            if (swrControl_menuAcceptPressedEdge != 0) {
                playUISound(0x54);
                swrObjHang_inspectCameraReset = 1;
                return;
            }
            if (swrControl_cancelPressedEdge != 0) {
                playUISound(0x4d);
                swrObjHang_inspectCameraReset = 1;
                swrObjHang_lookAtMenuFade = 0.0f;
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_MAIN_MENU);
                return;
            }
        }
        float prevDistance = swrObjHang_inspectOrbitDistance;
        // the first input after a reset only clears the fresh flag
        if (swrControl_aPlayerAxisX[i] > 0.1 || swrControl_aPlayerAxisX[i] < -0.1) {
            if (swrObjHang_inspectCameraFresh == 0) {
                swrObjHang_inspectOrbitYaw = swrObjHang_inspectOrbitYaw - swrControl_aPlayerAxisX[i] * swrRace_fdeltaTimeSecs * -70.0f * 1.5;
                orbitMoved = 1;
            }
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
        }
        if (swrControl_aPlayerAxisY[i] > 0.1 || swrControl_aPlayerAxisY[i] < -0.1) {
            if (swrObjHang_inspectCameraFresh == 0) {
                swrObjHang_inspectOrbitPitch = swrObjHang_inspectOrbitPitch - swrControl_aPlayerAxisY[i] * swrRace_fdeltaTimeSecs * -45.0f * 1.5;
                if (swrObjHang_inspectOrbitPitch > 89.0f)
                    swrObjHang_inspectOrbitPitch = 89.0f;
                if (swrObjHang_inspectOrbitPitch < -89.0f)
                    swrObjHang_inspectOrbitPitch = -89.0f;
                orbitMoved = 1;
            }
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
        }
        int input = swrUI_localPlayersInputDownBitset[i];
        if ((input & 4) != 0) {
            if (swrObjHang_inspectCameraFresh == 0) {
                swrObjHang_inspectOrbitDistance = swrObjHang_inspectOrbitDistance - swrRace_fdeltaTimeSecs * 800.0f;
                if (swrObjHang_inspectOrbitDistance < 100.0f)
                    swrObjHang_inspectOrbitDistance = 100.0f;
                orbitMoved = 1;
            }
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
        }
        if ((input & 8) != 0) {
            if (swrObjHang_inspectCameraFresh == 0) {
                swrObjHang_inspectOrbitDistance = swrObjHang_inspectOrbitDistance - swrRace_fdeltaTimeSecs * -800.0f;
                if (swrObjHang_inspectOrbitDistance > 1336.0f)
                    swrObjHang_inspectOrbitDistance = 1336.0f;
                orbitMoved = 1;
            }
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
        }
        // item stepping reads player 1's input for every local player
        int vehicle = (&hang->vehiclePlayer)[i];
        if ((swrUI_localPlayersInputDownBitset[0] & 0x10) != 0 && swrObjHang_cameraMoveMode != 3) {
            hang->cameraState++;
            if (hang->cameraState == HangCameraState_InspectEngine1 && swrRacer_PodData[vehicle].pod_modelID == MODELID_neva_kee_pod)
                hang->cameraState = HangCameraState_InspectPT01;
            if (hang->cameraState == HangCameraState_InspectEngine3 && swrRacer_PodData[vehicle].pod_modelID != MODELID_ben_quadinaros_pod)
                hang->cameraState = HangCameraState_InspectPT01;
            if (hang->cameraState <= HangCameraState_InspectPT04 && hang->cameraState - HangCameraState_InspectEngine4 > (swrRace_nbPitDroids & 0xff))
                hang->cameraState = HangCameraState_InspectCharacter;
            if (hang->cameraState > HangCameraState_InspectCharacter)
                hang->cameraState = HangCameraState_InspectDefault;
            stepped = 1;
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
            swrObjHang_inspectCameraTimer = 0.0f;
        }
        if ((swrUI_localPlayersInputDownBitset[0] & 0x20) != 0 && swrObjHang_cameraMoveMode != 3) {
            hang->cameraState--;
            if (hang->cameraState == HangCameraState_InspectEngine4) {
                if (swrRacer_PodData[vehicle].pod_modelID == MODELID_neva_kee_pod)
                    hang->cameraState = HangCameraState_InspectCockpit;
                if (hang->cameraState == HangCameraState_InspectEngine4 && swrRacer_PodData[vehicle].pod_modelID != MODELID_ben_quadinaros_pod)
                    hang->cameraState = HangCameraState_InspectEngine2;
            }
            if (hang->cameraState - HangCameraState_InspectEngine4 > (swrRace_nbPitDroids & 0xff))
                hang->cameraState = (swrRace_nbPitDroids & 0xff) + HangCameraState_InspectEngine4;
            if (hang->cameraState < HangCameraState_InspectDefault)
                hang->cameraState = HangCameraState_InspectCharacter;
            stepped = 1;
            if (swrObjHang_inspectCameraTimer == 5.0f)
                snapToItem = 1;
            swrObjHang_inspectCameraFresh = 0;
            swrObjHang_inspectCameraTimer = 0.0f;
        }
        if (stepped && !snapToItem) {
            swrObjHang_AimHoloCamera(hang, hang->cameraState, 1);
            stepped = 0;
        } else {
            swrObjHang_UpdateHoloCameraTarget(hang, hang->cameraState);
        }
        if (orbitMoved || swrObjHang_cameraMoveMode == 3) {
            rdMatrix_SetRotation44(&rot, swrObjHang_inspectOrbitYaw, swrObjHang_inspectOrbitPitch, 0.0f);
            rdVector_Scale3Add3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, swrObjHang_inspectOrbitDistance, (rdVector3*)&rot.vB);
            // keep the eye between the hangar floor and ceiling
            if (swrObjHang_cameraMatrix.vD.z < -147.0f) {
                rdVector_Scale3Add3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (swrObjHang_holoCameraMatrix.vD.z - -147.0f) / (swrObjHang_holoCameraMatrix.vD.z - swrObjHang_cameraMatrix.vD.z) * swrObjHang_inspectOrbitDistance, (rdVector3*)&rot.vB);
            }
            if (swrObjHang_cameraMatrix.vD.z > 1066.0f) {
                rdVector_Scale3Add3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, (swrObjHang_holoCameraMatrix.vD.z - 1066.0f) / (swrObjHang_holoCameraMatrix.vD.z - swrObjHang_cameraMatrix.vD.z) * swrObjHang_inspectOrbitDistance, (rdVector3*)&rot.vB);
            }
            if (swrObjHang_inspectOrbitDistance != prevDistance)
                swrObjHang_inspectOrbitDistance = rdVector_Dist3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
            if (orbitMoved)
                rdMatrix_Copy44(&swrObjHang_holoCameraMatrixStart, &swrObjHang_holoCameraMatrix);
            orbitMoved = 0;
        }
    }
    if (snapToItem) {
        // input after the 5 s idle snaps back to aiming at the selected item
        swrObjHang_inspectCameraFresh = 0;
        swrObjHang_inspectCameraTimer = 0.0f;
        swrObjHang_AimHoloCamera(hang, hang->cameraState, 1);
        inspectOrbitFromCamera();
    }
}

// 0x0043f8e0
void swrObjHang_AimHoloCamera(swrObjHang* hang, int cameraState, int fromCurrentEye)
{
    rdVector3 lookAt = { 0.0f, 0.0f, 0.0f }; // the original leaves this as stack garbage for camera states outside Inspect*
    rdVector3 eye;
    float spreadY;
    float spreadX;

    switch (cameraState) {
    case HangCameraState_InspectDefault:
        rdVector_Set3(&lookAt, 0.0f, 0.0f, 0.0f);
        break;
    case HangCameraState_InspectCockpit:
        aimAtPodPart(5, &lookAt);
        break;
    case HangCameraState_InspectEngine1:
        aimAtPodPart(1, &lookAt);
        break;
    case HangCameraState_InspectEngine2:
        aimAtPodPart(2, &lookAt);
        break;
    case HangCameraState_InspectEngine3:
        aimAtPodPart(3, &lookAt);
        break;
    case HangCameraState_InspectEngine4:
        aimAtPodPart(4, &lookAt);
        break;
    case HangCameraState_InspectPT01:
    case HangCameraState_InspectPT02:
    case HangCameraState_InspectPT03:
    case HangCameraState_InspectPT04:
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PIT_DROIDS + cameraState - HangCameraState_InspectPT01], &lookAt);
        if (lookAt.z == -157.0f)
            lookAt.z = lookAt.z - -60.0f;
        else
            lookAt.z = lookAt.z - -30.0f;
        break;
    case HangCameraState_InspectCharacter:
        swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[SWR_SCENE_SLOT_PILOT_PUPPETS], &lookAt);
        lookAt.z = (float)((double)swrRacer_PodData[(int)hang->vehiclePlayer].float20 * 0.6667 - 157.0);
        break;
    }

    if (fromCurrentEye != 0) {
        swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrix.vD, &lookAt, 3, 1, 0);
        return;
    }

    // jittered one-shot framing above the cameraState
    spreadY = (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 500.0f - 250.0f + lookAt.y;
    rdVector_Set3(&eye, (float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 500.0f - 250.0f + lookAt.x, spreadY, lookAt.z - -400.0f);
    if (cameraState >= HangCameraState_InspectPT01 && cameraState <= HangCameraState_InspectCharacter) {
        float scaleY = swrUtils_RandFloat();
        spreadY = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 150.0f - -200.0f) * scaleY + lookAt.y;
        float scaleX = swrUtils_RandFloat();
        spreadX = ((float)swrUtils_Rand() * SWR_CTL_RAND_NORM * 150.0f - -200.0f) * scaleX + lookAt.x;
        rdVector_Set3(&eye, spreadX, spreadY, lookAt.z);
        eye.z = eye.z - (lookAt.z == -97.0f ? 30.0f : -400.0f);
    }
    swrObjHang_SetHoloCameraTarget(&eye, &lookAt, 1, 0, 0);
}

// 0x0043fbc0
void swrObjHang_UpdateHoloCameraTarget(swrObjHang* hang, int itemIndex)
{
    rdVector3 eyeToLookAt;
    rdVector3 elementPos;

    if (0x19 < itemIndex) {
        if (itemIndex < 0x1e) {
            // Pod engine/part nodes live at swr_sceneModels[itemIndex + 26].
            swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[itemIndex + 26], &elementPos);
            if (elementPos.z == -157.0f) {
                elementPos.z = elementPos.z - -60.0f;
            } else {
                elementPos.z = elementPos.z - -30.0f;
            }
        } else {
            if (itemIndex != 0x1e) {
                return;
            }
            swrRace_GetEngineNodeOffsetPos((void**)swr_sceneModels[28], &elementPos);
            elementPos.z = swrRacer_PodData[hang->vehiclePlayer].float20 * 0.0331514f - 0.0f;
        }
        if (swrObjHang_cameraMoveMode == 1) {
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrixTarget.vD, &elementPos, 1, 0, 1);
            return;
        }
        if (swrObjHang_cameraMoveMode == 3) {
            swrObjHang_SetHoloCameraTarget((rdVector3*)&swrObjHang_cameraMatrix.vD, &elementPos, 3, 1, 1);
            return;
        }
        // No transition: move the look-at and carry the eye with it.
        rdVector_Sub3(&eyeToLookAt, (rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD);
        rdVector_Copy3((rdVector3*)&swrObjHang_holoCameraMatrix.vD, &elementPos);
        rdVector_Add3((rdVector3*)&swrObjHang_cameraMatrix.vD, (rdVector3*)&swrObjHang_holoCameraMatrix.vD, &eyeToLookAt);
    }
}

// Idle sway: once the camera has settled, drift the eye back and forth along the rig's right axis so
// the front end is never completely still.
// 0x0045c810
void swrObjHang_UpdateIdleCamera(swrObjHang* hang)
{
    int r;
    float cosine;
    float sine;
    rdVector3 eye;
    rdVector3 settledEye;

    if (swrObjHang_partDetailActive != 0) {
        swrObjHang_cameraMoveMode = 0;
        rdVector_Set3(&swrObjHang_idleCameraEyeBase, 0.0f, 0.0f, 0.0f);
        return;
    }
    if (hang->menuScreen == swrObjHang_STATE_LOOK_AT_VEHICLE) {
        swrObjHang_cameraMoveMode = 0;
        return;
    }
    rdVector_Copy3(&settledEye, (rdVector3*)&swrObjHang_cameraMatrix.vD);
    swrObjHang_idleCameraAngle = swrObjHang_idleCameraAngle - swrRace_fdeltaTimeSecs * -40.0f;
    if (360.0f < swrObjHang_idleCameraAngle) {
        swrObjHang_idleCameraAngle = swrObjHang_idleCameraAngle - 360.0f;
    }
    // Re-seed whenever the camera has just settled somewhere new.
    if (swrObjHang_cameraMoveSettled != 0 || swrObjHang_idleCameraSeeded != 5 || !rdVector_AreSame3(&swrObjHang_idleCameraEyeBase, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD) || !rdVector_AreSame3(&swrObjHang_idleCameraLookAtBase, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD)) {
        swrObjHang_cameraMoveSettled = 0;
        swrObjHang_UpdateHoloBillboardMatrix();
        rdMatrix_Copy44(&swrObjHang_cameraMatrixTarget, &swrObjHang_cameraMatrix);
        rdMatrix_Copy44(&swrObjHang_holoCameraMatrixTarget, &swrObjHang_holoCameraMatrix);
        rdVector_Copy3(&swrObjHang_idleCameraEyeBase, (rdVector3*)&swrObjHang_cameraMatrixTarget.vD);
        rdVector_Copy3(&swrObjHang_idleCameraLookAtBase, (rdVector3*)&swrObjHang_holoCameraMatrixTarget.vD);
        swrObjHang_idleCameraSeeded = 5;
        // Start half the time at the opposite end of the sway. The original draws ONE random
        // value and doubles it, so this truncates to 0 or 1 -> 0 or 180 degrees.
        r = swrUtils_Rand();
        swrObjHang_idleCameraAngle = (float)(int)((float)r * (1.0f / 2147483648.0f) + (float)r * (1.0f / 2147483648.0f)) * 180.0f;
    }
    stdMath_SinCos(swrObjHang_idleCameraAngle, &sine, &cosine);
    rdVector_Copy3(&eye, &swrObjHang_idleCameraEyeBase);
    rdVector_Scale3Add3(&eye, &eye, sine * 8.0f, (rdVector3*)&swrObjHang_cameraMatrixTarget.vA);
    rdVector_Copy3((rdVector3*)&swrObjHang_cameraMatrix.vD, &eye);
}
