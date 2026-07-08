#include "swrObj.h"

#include "globals.h"
#include "swrEvent.h"
#include "swrSprite.h"
#include "swrModel.h"
#include "swrSound.h"
#include "swrCam.h"
#include "swrText.h"
#include "swrMultiplayer.h"
#include "swrUI.h"
#include "swrViewport.h"
#include "swrRace.h"
#include "swrSpline.h"
#include "Primitives/rdVector.h"

#include <macros.h>
#include <General/utils.h>

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
    HANG("TODO");
}

// 0x004457b0
void enablePause(void)
{
    pauseDisabled = 0;
    pauseEnabledFlag = 1;
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

// 0x0045d130
void swrObjJdge_ScrollCredits(swrObjJdge* jdge)
{
    HANG("TODO");
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
    HANG("TODO");
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
    float progress = ((float)(int)score->results_P1_Lap + lapCompMax) - wrap;
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

// Assigns finishing positions and per-pod HUD gap values. For each racer it stores the gap to the
// leader (unk128), the signed gap to the local player(s) (rivalGapAhead/rivalGapBehind), and the
// gap to the lead pod (aiLineOffset). It also tags the two nearest rivals ahead (flag 0x8000) and, in 2-player, behind
// (flag 0x10000) of the local players, for the on-screen rival arrows.
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
        score->obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_RIVAL_AHEAD;
        score->obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_RIVAL_BEHIND;
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
        pod->unk128 = (int)(firstPlaceRank - rankValues[maxIdx]);

        if (firstLocalPlayer == NULL) {
            pod->rivalGapAhead = -0x3d380000;
        } else if (secondLocalPlayer == NULL) {
            if (firstLocalIdx == maxIdx) {
                pod->rivalGapAhead = 0;
            } else {
                float gap = firstLocalRank - rankValues[maxIdx];
                bool neg = gap < 0.0f;
                pod->rivalGapAhead = (int)gap;
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
            pod->rivalGapAhead = 0;
            pod->rivalGapBehind = (int)(secondLocalRank - firstLocalRank);
        } else if (secondLocalIdx == maxIdx) {
            pod->rivalGapBehind = 0;
            pod->rivalGapAhead = (int)(firstLocalRank - secondLocalRank);
        } else {
            float gapAhead = firstLocalRank - rankValues[maxIdx];
            float gapBehind = secondLocalRank - rankValues[maxIdx];
            bool neg = gapAhead < 0.0f;
            pod->rivalGapAhead = (int)gapAhead;
            pod->rivalGapBehind = (int)gapBehind;
            if (neg)
                gapAhead = -gapAhead;
            if (aGapA <= gapAhead) {
                if (aGapB <= gapAhead) {
                    if (gapAhead < aGapC)
                        aGapC = gapAhead;
                } else {
                    aGapC = aGapB;
                    aGapB = gapAhead;
                    aheadIdx2 = maxIdx;
                }
            } else {
                aGapC = aGapB;
                aheadIdx2 = aheadIdx1;
                aGapB = aGapA;
                aGapA = gapAhead;
                aheadIdx1 = maxIdx;
            }
            if (gapBehind < 0.0f)
                gapBehind = -gapBehind;
            if (bGapA <= gapBehind) {
                if (bGapB > gapBehind) {
                    bGapC = bGapB;
                    bGapB = gapBehind;
                    behindIdx2 = maxIdx;
                }
            } else {
                bGapC = bGapB;
                behindIdx2 = behindIdx1;
                bGapB = bGapA;
                bGapA = gapBehind;
                behindIdx1 = maxIdx;
            }
        }

        pod->aiLineOffset = (int)(leaderProgress - rankValues[maxIdx]);
        rankValues[maxIdx] = 0.0f;
        *(short*)&swrScoresPtr[maxIdx].results_P1_Position = (short)pos;
        pos++;
    }

    // tag the two nearest rivals behind (2-player only) and ahead of the local player(s)
    if (secondLocalPlayer != NULL) {
        if (behindIdx1 != -1 && rankValues[behindIdx1] < (float)jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx1].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_RIVAL_BEHIND;
        if (behindIdx2 != -1 && rankValues[behindIdx2] < (float)jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx2].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_RIVAL_BEHIND;
    }
    if (aheadIdx1 != -1 && rankValues[aheadIdx1] < (float)jdge->num_laps - 0.1f) {
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_RIVAL_AHEAD;
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_RIVAL_BEHIND;
    }
    if (aheadIdx2 != -1 && rankValues[aheadIdx2] < (float)jdge->num_laps - 0.1f) {
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 |= swrObjTest_FLAG0_AI_RIVAL_AHEAD;
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 &= ~swrObjTest_FLAG0_AI_RIVAL_BEHIND;
    }
}

// 0x0045dd80
void swrObjJdge_TeardownRace(swrObjJdge* jdge, int event)
{
    HANG("TODO");
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
            // set the flags0 low-nibble race state to 1 (clears RACING == 2)
            racer->flags0 = (racer->flags0 & 0xfffffff1) | 1;
        }
    }
}

// 0x0045E120
int KeyDownForPlayer1Or2(int)
{
    HANG("TODO");
}

// Cycle the HUD layout when the toggle key is pressed (modes 0-4 single-screen, 4-7 splitscreen).
// 0x0045e1a0
void swrObjJdge_CycleHudMode(swrObjJdge* jdge)
{
    if (KeyDownForPlayer1Or2(0x40) != 0) {
        if (numLocalPlayers < 2) {
            jdge->hud_mode++;
            if (4 < jdge->hud_mode)
                jdge->hud_mode = 0;
        } else {
            jdge->hud_mode++;
            if (7 < jdge->hud_mode)
                jdge->hud_mode = 4;
        }
    }
}

// 0x0045e200
void swrObjJdge_F0(swrObjJdge* jdge)
{
    if (swrRace_demoMode == 0)
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
            if ((swrRace_demoMode == 0 || swrObjJdge_demoHudCycled != 0) && (jdge->countdownTimer_ms < 0.0f || inRaceLocalPlayerInputBitset1[0] != 0 || inRaceLocalPlayerInputBitset1[1] != 0)) {
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
            if (jdge->unk134_mat.vC.x == 0.0f)
                jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
            else if ((flags & 0x80) != 0)
                jdge->raceTimer_ms += (float)swrRace_deltaTimeSecs;
            else {
                jdge->raceTimer_ms = 0.0f;
                jdge->flag = flags | 0x80;
            }
            if (jdge->unk134_mat.vC.x != 0.0f && 0.5f < jdge->raceTimer_ms)
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
                swrUI_unk* page = swrUI_GetById(NULL, 0x30d41);
                swrUI_RunCallbacks2(page, 1);
            }
            swrObjJdge_TeardownRace(jdge, jdge->event);
            return;
        }
        jdge->raceTimer_ms -= (float)swrRace_deltaTimeSecs;
        break;
    }
}

// 0x0045ea30
void swrObjJdge_F2(swrObjJdge* jdge)
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
        if (4 < jdge->hud_mode)
            jdge->hud_mode = 2;
    } else if (jdge->hud_mode < 4) {
        jdge->hud_mode = 5;
    }

    int mode = jdge->hud_mode;
    if (mode == 0) {
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
                    if (*(int*)s->unk18 == -1 || gap > 164.0f || gap < 74.0f)
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
    } else if (mode == 1) {
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
            if (*(int*)s->unk18 == -1)
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
    } else if (mode == 2 || mode == 3) {
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
        if (mode == 2) {
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
                char type = (jdge->hud_mode == 2) ? 2 : 3;
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
    } else if (mode == 5 || mode == 7) {
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
            if (*(int*)s->unk18 != -1 && (s->obj_test_ptr->flags1 & (swrObjTest_FLAG1_FORCE_GROUND | swrObjTest_FLAG1_ON_LAVA)) == 0) {
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

    if ((racer->flags1 & swrObjTest_FLAG1_FINISHED) == 0 && (4 < racer->unk10c || racer->speedValue < swrObjJdge_notRacingSpeedThreshold)) {
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
        racer->flags0 &= 0xf7ffffff;
        if (someRootNodeChildNodes[nodeIdx] != NULL)
            swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, -4, 0x10, 3);
        swrObjJdge_HideEngineUI(score);
        return;
    }

    if ((jdge->flag & 0xf) == 1) {
        if (swrObjJdge_IsRacerRacing(jdge, racer) == 0) {
            racer->flags0 &= 0xf7ffffff;
            if (someRootNodeChildNodes[nodeIdx] != NULL)
                swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, -4, 0x10, 3);
        } else {
            if (someRootNodeChildNodes[nodeIdx] != NULL)
                swrModel_NodeModifyFlags(someRootNodeChildNodes[nodeIdx], 2, 3, 0x10, 2);
            racer->flags0 |= 0x8000000; // flags0 bit 0x8000000 not named in swrObjTest_FLAG0
            rdMatrix44 guideMat;
            swrSpline_EvaluateAtOffset(&racer->unk4_mat, &guideMat, 0.5f);
            rdVector_Copy3((rdVector3*)(racer->unk12 + 4), (rdVector3*)&guideMat.vD);
            *(swrModel_Node**)racer->unk12 = someRootNodeChildNodes[nodeIdx];
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
    HANG("TODO");
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

    if (swrRace_demoMode == 0) {
        if ((jdge->flag & 0xf) != 6) {
            uint32_t state = jdge->flag & 0xf;
            if (state == 1 || state == 2) {
                bool finalLap = false;
                if (1 < jdge->num_laps) {
                    if (firstLocalPlayer != NULL && jdge->num_laps <= (int)firstLocalPlayer->results_P1_Lap + 1)
                        finalLap = true;
                    if (secondLocalPlayer != NULL && jdge->num_laps <= (int)secondLocalPlayer->results_P1_Lap + 1)
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
        swrObjJdge_ScrollCredits(jdge);
        if (swrObjJdge_demoHudCycleIndex == 2)
            playASound(0x90, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_demoHudCycleIndex == 3)
            playASound(0x8e, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_demoHudCycleIndex == 4)
            playASound(0x91, 7, 0.25f, 1.0f, 1);
        else if (swrObjJdge_demoHudCycleIndex == 5)
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
    int entry = (int16_t) index;
    unkCameraArray[entry].sourceType = val2;
    unkCameraArray[entry].behaviorType = val1;
    unkCameraArray[entry].matrixSource = mat;
}
