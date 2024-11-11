#include "swrObj.h"

#include "globals.h"
#include "swrEvent.h"
#include "swrSprite.h"
#include "swrModel.h"

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

// 0x004336f0 HOOK
void swrObjHang_SetHangar2(swrObjHang* hang)
{
    g_objHang2 = hang;
}

// 0x00433700 HOOK
void swrObjHang_SetUnused(void)
{
    if (g_objHang2 != NULL)
    {
        swrObjHang_unused_state = g_objHang2->state;
    }
    swrObjHang_unused_unk = -1;
}

// 0x004360e0
void DrawTracks(swrObjHang* hang, char param_2)
{
    HANG("TODO");
}

// 0x00440a00 HOOK
char GetRequiredPlaceToProceed(char circuitIdx, char trackIdx)
{
    char res;

    if (('\x02' < circuitIdx) || (res = '\x04', '\x05' < trackIdx))
    {
        res = '\x03';
    }
    return res;
}

// 0x00440aa0
bool isTrackPlayable(swrObjHang* hang, char circuitIdx, char trackIdx)
{
    HANG("TODO");
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

// 0x00457bd0 HOOK
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

// 0x0045a040
int swrObjHang_F4(swrObjHang* hang, int* subEvents, int* p3, void* p4, int p5)
{
    HANG("TODO");
    return 0;
}

// 0x0045d0b0 HOOK
void swrObjJdge_Clear(swrObjJdge* jdge, int event)
{
    if (swrJdge_Cleared == 0)
    {
        swrJdge_Cleared = 1;
        swrModel_ClearSceneAnimations();
        jdge->unkc_ms = 0.5;
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
    HANG("TODO");
    return 0;
}

// 0x00463FF0
int SetPlanetIdAndTrackNumber(int, int)
{
    HANG("TODO");
}

// 0x00464010
void InitPlanetSpecificSprites(int planet_id, int planet_track_number)
{
    HANG("TODO");
}

// 0x00464630
int InitIngameSprites(int planet_id, int planet_track_number, swrObjJdge* a3)
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

// 0x004667E0
void InitAISettingsForTrack(swrObjJdge*)
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

// 0x0047bea0 HOOK
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

// 0x0047bee0 HOOK
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

// 0x0047E760 HOOK
void swrObjTrig_AddTriggerDescription(swrModel_TriggerDescription* trigger)
{
    if ((trigger != NULL) && (swrObjTrig_NumTriggerDescriptions < 200))
        swrObjTrig_TriggerDescriptionArray[swrObjTrig_NumTriggerDescriptions++] = trigger;
}

// 0x0047E790 HOOK
int swrObjTrig_FindTriggerDescriptionIndex(swrModel_TriggerDescription* trigger)
{
    for (int i = 0; i < swrObjTrig_NumTriggerDescriptions; i++)
        if (swrObjTrig_TriggerDescriptionArray[i] == trigger)
            return i;

    return -1;
}

// 0x0047E7C0 HOOK
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
