#include "swrObj.h"

#include "globals.h"
#include "swrEvent.h"
#include "swrSprite.h"
#include "swrModel.h"
#include "swrSound.h"
#include "swrCam.h"

#include <macros.h>

// 0x004336d0
void swrObjHang_SetHangar2State(swrObjHang_STATE state)
{
    if (g_objHang2 != NULL)
    {
        HANG("TODO, easy");
    }
}

// 0x004336a0
void swrObjHang_SetHangar2Splash(void)
{
    HANG("TODO, easy");
}

// 0x004336f0
void swrObjHang_SetHangar2(swrObjHang* hang)
{
    g_objHang2 = hang;
}

// 0x00433700
void swrObjHang_SetUnused(void)
{
    if (g_objHang2 != NULL)
    {
        swrObjHang_unused_state = g_objHang2->menuScreen;
    }
    swrObjHang_unused_unk = -1;
}

// 0x004360e0
void DrawTracks(swrObjHang* hang, char param_2)
{
    HANG("TODO");
}

// 0x00440a00
char GetRequiredPlaceToProceed(char circuitIdx, char trackIdx)
{
    char res;

    if (('\x02' < circuitIdx) || (res = '\x04', '\x05' < trackIdx))
    {
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

    if ((reqPlace > 3 || beat != 0) && (circuitId > 2 || bNextTrackSelectable))
    {
        return 0;
    }
    return 1;
}

// 0x00440aa0
bool isTrackPlayable(swrObjHang* hang, char circuitIdx, char trackIdx)
{
    char tmp = swrRace_UnlockDataBase[circuitIdx + 1];
    if ((multiplayer_enabled != 0) && (circuitIdx < '\x03'))
    {
        return true;
    }
    if (hang->isTournamentMode == '\0')
    {
        tmp = g_aBeatTracksGlobal[circuitIdx];
    }
    return ((char)(1 << (trackIdx)) & tmp) != 0;
}

// 0x00440af0
int VerifySelectedTrack(swrObjHang* hang, int selectedTrackIdx)
{
    HANG("TODO");
}

// 0x00445680
void swrObjJudge_PollPause()
{
    HANG("TODO");
}

// 0x00445690
int GetPauseState()
{
    HANG("TODO");
}

// 0x004456B0
int requestPause()
{
    HANG("TODO");
}

// 0x00450e30
void swrObj_Free(swrObj* obj)
{
    HANG("TODO, easy");
}

// 0x00451cd0
void swrObjcMan_F0(swrObjcMan* cman)
{
    HANG("TODO");
}

// 0x00451d40
void swrObjcMan_F2(swrObjcMan* cman)
{
    HANG("TODO");
}

// 0x004542e0
void swrObjcMan_F3(swrObjcMan* cman)
{
    HANG("TODO");
}

// 0x004543f0
int swrObjcMan_F4(swrObjcMan* cman, int* subEvents, int p3)
{
    HANG("TODO");
    return 0;
}

// 0x00454a10
void swrObjScene_F0(swrObjScen* scene)
{
    HANG("TODO");
}

// 0x00454a30
int swrObjScene_F4(swrObjScen* scene, int* subEvents)
{
    HANG("TODO");
    return 0;
}

// 0x00454D10
void swrObjHang_InitSceneRootNode()
{
    HANG("TODO");
}

// 0x00454d40
void swrObjHang_SetMenuState(swrObjHang* hang, swrObjHang_STATE state)
{
    HANG("TODO");
}

// 0x00456800
void DrawHoloPlanet(swrObjHang* hang, int planetIdx, float scale)
{
    HANG("TODO");
}

// 0x00456c70
void DrawTrackPreview(void* unused, int TrackID, float param_3)
{
    HANG("TODO");
}

// 0x00457620
void swrObjHang_F0(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00457b00
void swrObjHang_F2(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00457b90
void swrObjHang_F3(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x00457bd0
void swrObjHang_LoadAllPilotSprites(void)
{
    swrSpriteTexture* tex;
    swrRacerData* data;
    short id;

    id = 0;
    data = (swrRacerData*)&swrRacer_PodData[0].pilot_spriteId;
    do
    {
        tex = swrSprite_LoadTexture_(data->id);
        swrSprite_NewSprite(id, tex);
        swrSprite_NewSprite(id + 0x17, tex);
        swrSprite_NewSprite(id + 0x2e, tex);
        id = id + 1;
        data = data + 1;
    } while (id < 0x17);
}

// 0x004584a0
void swrObjHang_InitTrackSprites(swrObjHang* hang, int initTracks)
{
    HANG("TODO");
}

// 0x0045a040
int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5)
{
    HANG("TODO");
    return 0;
}

// 0x0045d0b0
void swrObjJdge_Clear(swrObjJdge* jdge, int event)
{
    if (swrJdge_Cleared == 0)
    {
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

// 0x0045D350
int NumLocalPlayers()
{
    HANG("TODO");
}

// 0x0045D390
double swrRace_GetLapProgressIfAvailable()
{
    HANG("TODO");
}

// 0x0045D3D0
int GetLocalPlayerNumberFromScore(swrScore*)
{
    HANG("TODO");
}

// 0x0045E120
int KeyDownForPlayer1Or2(int)
{
    HANG("TODO");
}

// 0x0045e200
void swrObjJdge_F0(swrObjJdge* jdge)
{
    HANG("TODO");
}

// 0x0045ea30
void swrObjJdge_F2(swrObjJdge* jdge)
{
    HANG("TODO");
}

// 0x00462D40
int swrObjJdge_CheckIfPauseRequested()
{
    HANG("TODO");
}

// 0x00463580
void swrObjJdge_F3(swrObjJdge* jdge)
{
    HANG("TODO");
}

// 0x00463a50
int swrObjJdge_F4(swrObjJdge* jdge, int* subEvents, int p3)
{
    switch (*subEvents)
    {
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
        jdge->countdownTimer_ms = (float) subEvents[8];
        jdge->num_laps = subEvents[9];
        jdge->best_lap_time_ms = *(float*) (p3 + 0x28);
        jdge->recordLap3_ms = *(float*) (p3 + 0x2c);
        jdge->unk1c4 = subEvents[0xc];
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
        swrObjJdge_InitTrack(jdge, (swrScore*) subEvents[1]);
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
        if (swrRace_demoMode != 0)
        {
            swrObjJdge_demoHudCycleIndex++;
            if (swrObjJdge_demoHudCycleIndex == 6)
            {
                swrObjJdge_demoHudCycleIndex = 1;
                swrObjJdge_demoHudCycled = 1;
            }
            jdge->hud_mode = 4;
            swrObjJdge_creditsScrollState = 0;
        }
        return 1;

    case 'Load': // allocate-time reset of all per-race state
        swrCam_CamState_InitMainMat4(1, 1, &jdge->camBaseMat, 0);
        jdge->flag = 0;
        jdge->raceTimer_ms = 0.0f;
        jdge->unk30 = 0;
        jdge->unk2c_spline = NULL;
        jdge->camBaseMat.vA.x = 1.0f; jdge->camBaseMat.vA.y = 0.0f; jdge->camBaseMat.vA.z = 0.0f; jdge->camBaseMat.vA.w = 0.0f;
        jdge->camBaseMat.vB.x = 0.0f; jdge->camBaseMat.vB.y = 1.0f; jdge->camBaseMat.vB.z = 0.0f; jdge->camBaseMat.vB.w = 0.0f;
        jdge->camBaseMat.vC.x = 0.0f; jdge->camBaseMat.vC.y = 0.0f; jdge->camBaseMat.vC.z = 1.0f; jdge->camBaseMat.vC.w = 0.0f;
        jdge->camBaseMat.vD.x = 0.0f; jdge->camBaseMat.vD.y = 0.0f; jdge->camBaseMat.vD.z = 0.0f; jdge->camBaseMat.vD.w = 1.0f;
        for (int i = 0; i < 6; i++)
            jdge->splineMarkers[i] = NULL;
        jdge->unk28_model = NULL;
        jdge->unk1d8 = 0;
        jdge->unk1dc = 0;
        jdge->camSweepState = NULL;
        jdge->unk134_mat.vD.x = 1.0f;
        jdge->unk134_mat.vD.y = 0.0f;
        jdge->unk134_mat.vD.z = 0.0f;
        jdge->unk134_mat.vD.w = 0.0f;
        jdge->unk174[0] = 0.0f; jdge->unk174[1] = 1.0f; jdge->unk174[2] = 0.0f; jdge->unk174[3] = 0.0f;
        jdge->unk174[4] = 0.0f; jdge->unk174[5] = 0.0f; jdge->unk174[6] = 1.0f; jdge->unk174[7] = 0.0f;
        jdge->unk174[8] = 0.0f; jdge->unk174[9] = 0.0f; jdge->unk174[10] = 0.0f;
        jdge->unk1a0 = 1.0f;
        jdge->cam_spline = NULL;
        jdge->unk1a8 = 0;
        jdge->unk1e0 = 0;
        jdge->unk1e4 = 0.0f;
        jdge->hud_mode = 2;
        jdge->unk128[0] = 0; jdge->unk128[1] = 0; jdge->unk128[2] = 0; jdge->unk128[3] = 0;
        // fall through: 'Load' and 'RSet' both re-sleep every Jdge entity
    case 'RSet':
    {
        swr_noop2();
        int ev[16];
        ev[0] = 'Slep';
        swrEvent_CallF4('Jdge', ev);
        return 1;
    }

    case 'Join': // if we are the session host, broadcast the master-claim event
        if ((jdge->flag & 0x10) != 0)
        {
            int ev[16];
            ev[0] = 'Mstr';
            swrEvent_Broadcast('Jdge', ev);
        }
        return 1;

    case 'Mstr':
        jdge->flag &= ~0x10;
        return 1;

    case 'Paws': // pause-menu result: abort or restart the race
        if (subEvents[1] < 0)
        {
            if (subEvents[2] == 1)
                swrObjJdge_Clear(jdge, 'Abrt');
            else if (subEvents[2] == 2)
                swrObjJdge_Clear(jdge, 'RStr');
        }
        return 1;

    case 'Slep':
        *((unsigned char*) &jdge->obj.flags + 1) |= 0x10;
        return 1;

    case 'Wake':
        *((unsigned char*) &jdge->obj.flags + 1) &= ~0x10;
        return 1;

    case 'JAsn': // resolve a score's finish-time to its pod object, then forward the sub-event
        *subEvents = 'NAsn';
        for (int i = 0; i < jdge->num_players; i++)
        {
            if (swrScoresPtr[i].time_unk == (float) subEvents[2])
            {
                subEvents[2] = (int) swrScoresPtr[i].obj_test_ptr;
                swrEvent_DispatchSubEvents((void*) subEvents[3], subEvents);
                break;
            }
        }
        return 1;

    default:
        return 0;
    }
}

// 0x0045dad0
void swrObjJdge_UpdateViewportLayout(swrObjJdge* jdge, int mode)
{
    HANG("TODO");
}

// 0x00463FF0
int SetPlanetIdAndTrackNumber(int, int)
{
    HANG("TODO");
}

// 0x004651F0
void swrObjJdge_AddTriggersToScene(swrObjJdge* a1)
{
    HANG("TODO");
}

// 0x00465230
void swrObjToss_AddDustKickModelsToScene()
{
    HANG("TODO");
}

// 0x00465310
void swrObjSmok_AddFireballModelsToScene()
{
    HANG("TODO");
}

// 0x004653F0
void AddFireballToModelScene()
{
    HANG("TODO");
}

// 0x00465510
void LoadTrackModels(swrObjJdge* judge)
{
    HANG("TODO");
}

// 0x00465D00
void LoadTrackSpline(swrObjJdge*)
{
    HANG("TODO");
}

// 0x00466370
void InitPrimaryLight()
{
    HANG("TODO");
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
        8.64f,     20.0f, 11.2f,     38.0f, 0.0f,      0.0f,  0.0f,      0.0f,  // planet 0
        8.784f,    35.0f, 9.700001f, 38.0f, 10.8f,     38.0f, 11.35f,    32.0f, // planet 1
        8.775f,    26.0f, 9.700001f, 35.0f, 9.991f,    40.0f, 0.0f,      0.0f,  // planet 2
        9.9328f,   36.0f, 10.85f,    35.0f, 10.3f,     35.0f, 0.0f,      0.0f,  // planet 3
        10.0395f,  37.0f, 10.0f,     34.0f, 10.05f,    35.0f, 10.45f,    27.0f, // planet 4
        8.459999f, 23.0f, 9.224999f, 40.0f, 9.700001f, 35.0f, 0.0f,      0.0f,  // planet 5
        8.801999f, 25.0f, 10.4f,     30.0f, 10.6f,     33.0f, 0.0f,      0.0f,  // planet 6
        8.865f,    32.0f, 9.9425f,   30.0f, 10.1f,     33.0f, 0.0f,      0.0f,  // planet 7
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

// 0x00466BD0
unsigned int swrObjJdge_InitTrack(swrObjJdge* judge, swrScore* scores)
{
    HANG("TODO");
}

// 0x00467cd0
void swrObjElmo_F0(swrObjElmo* elmo)
{
    HANG("TODO");
}

// 0x00468570
void swrObjElmo_F3(swrObjElmo* elmo)
{
    HANG("TODO");
}

// 0x00468660
int swrObjElmo_F4(swrObjElmo* elmo, int* subEvents)
{
    HANG("TODO");
    return 0;
}

// 0x00469ed0
void swrObjSmok_F0(swrObjSmok* smok)
{
    HANG("TODO");
}

// 0x00469fb0
void swrObjSmok_F3(swrObjSmok* smok)
{
    HANG("TODO");
}

// 0x0046a500
int swrObjSmok_F4(swrObjSmok* smok, int* subEvents)
{
    HANG("TODO");
    return 0;
}

// 0x0046A5E0
void swrObjSmok_SetFireballChildNodesPtr(swrModel_Node** nodes)
{
    HANG("TODO");
}

// 0x0046d170
void swrObjTest_F0(swrRace* player)
{
    HANG("TODO");
}

// 0x00470610
void swrObjTest_F3(swrRace* player)
{
    HANG("TODO");
}

// 0x00471760
void swrRace_PoddAnimateVariousThings(swrRace* arg0)
{
    HANG("TODO");
}

// 0x00472A50
void swrRace_PoddAnimateSteeringParts(swrRace* a1)
{
    HANG("TODO");
}

// 0x004741D0
void swrRace_Explode(swrRace*, char)
{
    HANG("TODO");
}

// 0x00474d80
int swrObjTest_F4(swrRace* player, int* subEvent, int ghost)
{
    HANG("TODO");
    return 0;
}

// 0x0047ab40
void swrObjTest_TurnResponse(swrRace* player)
{
    HANG("TODO");
}

// 0x0047b520
void swrObjTest_SuperUnk(swrRace* player)
{
    HANG("TODO");
}

// 0x0047b9e0
void swrObjToss_F2(swrObjToss* toss)
{
    HANG("TODO");
}

//  0x0047ba30
void swrObjToss_F3(swrObjToss* toss)
{
    HANG("TODO");
}

// 0x0047bba0
int swrObjToss_F4(swrObjToss* toss)
{
    HANG("TODO");
    return 0;
}

// 0x0047BC40
void swrRace_SpawnDustKickObject(rdMatrix44* in, uint8_t r, uint8_t g, uint8_t b, int a, float life_time, int)
{
    HANG("TODO");
}

// 0x0047BCD0
void swrObjToss_SetDustKickChildNodesPtr(swrModel_Node**)
{
    HANG("TODO");
}

// 0x0047bea0
void swrObjTrig_EnableFXAnimation(int index)
{
    swrModel_Animation* anim;
    swrModel_Animation** anim_ref;
    swrModel_Animation** tmp;

    anim_ref = swrObjTrig_AnimationArray[index];
    anim = *anim_ref;
    while (anim != NULL)
    {
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
    while (anim != NULL)
    {
        swrModel_AnimationClearFlags(anim, ANIMATION_ENABLED);
        swrModel_AnimationSetTime(*anim_ref, 0.0);
        tmp = anim_ref + 1;
        anim_ref = anim_ref + 1;
        anim = *tmp;
    }
}

// 0x0047BF20
swrModel_Animation* swrObjTrig_AnimationActive(int)
{
    HANG("TODO");
}

// 0x0047BF70
void swrObjTrig_MaybeResetAnimation(swrObjTrig*)
{
    HANG("TODO");
}

// 0x0047C080
void swrObjTrig_MaybeResetAnimationByTriggerType(int)
{
    HANG("TODO");
}

// 0x0047C0F0
swrModel_NodeTransformedWithPivot* swrObjTrig_FindNode(swrModel_TriggerDescription* a1)
{
    HANG("TODO");
}

// 0x0047C130
swrModel_NodeTransformedWithPivot* swrObjTrig_InitNodeForTrigger(swrModel_TriggerDescription*)
{
    HANG("TODO");
}

// 0x0047C190
void swrObjTrig_Unk(swrObjTrig* obj, int index)
{
    HANG("TODO");
}

// 0x0047C330
void swrObjTrig_MaybeResetCameraShake(swrObjTrig* obj)
{
    HANG("TODO");
}

// 0x0047c390
void swrObjTrig_F0(swrObjTrig* trig)
{
    HANG("TODO");
}

// 0x0047c500
void swrObjTrig_F2(swrObjTrig* trig)
{
    HANG("TODO");
}

// 0x0047c710
int swrObjTrig_F4(swrObjTrig* trig, int* subEvents)
{
    HANG("TODO");
    return 0;
}

// 0x0047C7D0
swrObjTrig* swrObjTrig_FindOrCreate(swrModel_TriggerDescription*)
{
    HANG("TODO");
}

// 0x0047C920
void swrObjTrig_HandleTrigger108(swrObjTrig* a1, swrRace* a2)
{
    HANG("TODO");
}

// 0x0047CA90
void swrObjTrig_HandleCrashHitTrigger(swrObjTrig* a1, swrRace* a2)
{
    HANG("TODO");
}

// 0x0047CD90
void swrObjTrig_Handle314Or501Trigger(swrObjTrig* obj, int index)
{
    HANG("TODO");
}

// 0x0047D310
swrModel_Node* swrObjTrig_AddNodeToScene(swrModel_TriggerDescription*, int, int)
{
    HANG("TODO");
}

// 0x0047DC40
void swrObjTrig_FindAndInitializeTriggersInNode(swrModel_NodeTransformed* node)
{
    HANG("TODO");
}

// 0x0047DD90
swrModel_Node* swrObjTrig_CreateTriggerSceneNode()
{
    HANG("TODO");
}

// 0x0047DDC0
void swrObjTrig_LoadAndInitializeTriggerModels(int planet_id, int a2, swrModel_NodeTransformed* a3)
{
    HANG("TODO");
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
    HANG("TODO");
}

// 0x0047E830
void swrObjTrig_SendMultiplayerTriggerEvent(swrModel_TriggerDescription* trigger_description, swrRace* player)
{
    HANG("TODO");
}

// 0x004804a0
void swrScene_SetObjectsLoaded(void)
{
    HANG("TODO");
}

// 0x00428A60
void swrCam_CamState_InitMainMat4(uint16_t index, uint16_t val1, rdMatrix44* mat, uint16_t val2)
{
    HANG("TODO");
}
