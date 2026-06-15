#include "swrObj.h"

#include "globals.h"
#include "swrEvent.h"
#include "swrSprite.h"
#include "swrModel.h"
#include "swrSound.h"
#include "swrCam.h"
#include "swrText.h"

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

// 0x0045d410
// Placement metric: lap count + fraction of the current lap (spline progress, wrap-corrected).
float swrObjJdge_GetRacerProgress(swrScore* score)
{
    float lapCompMax = score->obj_test_ptr->lapCompMax;
    float wrap = lapCompMax - score->obj_test_ptr->lapComp;
    if (wrap < 0.0f)
        wrap = -wrap;
    if (0.5f < wrap)
        wrap = 1.0f - wrap;
    float progress = ((float) (int) score->results_P1_Lap + lapCompMax) - wrap;
    if (progress < 0.0f)
        progress = 0.0f;
    return progress;
}

// 0x0045d480
// Sort key for standings: finished racers rank by (10000 - total time); others by progress.
float swrObjJdge_GetRacerRankValue(swrScore* score)
{
    if ((score->flag & 2) == 0)
        return swrObjJdge_GetRacerProgress(score);
    return 10000.0f - score->results_P1_total_time;
}

// 0x0045d4a0
// Assigns finishing positions and per-car HUD gap values. For each racer it stores the gap to the
// leader (unk128), the signed gap to the local player(s) (unk130/unk134), and the gap to the lead
// car (unk12c). It also tags the two nearest rivals ahead (flag 0x8000) and, in 2-player, behind
// (flag 0x10000) of the local players, for the on-screen rival arrows.
void swrObjJdge_UpdateStandings(swrObjJdge* jdge)
{
    float rankValues[20];
    float leaderProgress = -1.0f;
    float firstLocalRank = 0.0f, secondLocalRank = 0.0f, firstPlaceRank = 0.0f;
    int firstLocalIdx = 0, secondLocalIdx = 0;

    // pass 1: reset each racer's position + rival-arrow flags, compute its rank value
    for (int i = 0; i < jdge->num_players; i++)
    {
        swrScore* score = &swrScoresPtr[i];
        *(short*) &score->results_P1_Position = -1;
        score->obj_test_ptr->flags0 &= 0xffff7fff; // clear rival-ahead arrow (0x8000)
        score->obj_test_ptr->flags0 &= 0xfffeffff; // clear rival-behind arrow (0x10000)
        float rank = swrObjJdge_GetRacerRankValue(score);
        rankValues[i] = rank;
        if (score == firstLocalPlayer)
        {
            firstLocalRank = rank;
            firstLocalIdx = i;
        }
        if (score == secondLocalPlayer)
        {
            secondLocalRank = rank;
            secondLocalIdx = i;
        }
        if ((score->obj_test_ptr->flags0 & 0x100) != 0)
        {
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
    if (secondLocalPlayer != NULL && firstLocalRank <= secondLocalRank)
    {
        int tmpIdx = secondLocalIdx;
        float tmpRank = secondLocalRank;
        secondLocalIdx = firstLocalIdx;
        secondLocalRank = firstLocalRank;
        firstLocalIdx = tmpIdx;
        firstLocalRank = tmpRank;
    }

    // pass 2: repeatedly take the highest remaining rank value -> assign place + gap displays
    for (int processed = 0; processed < jdge->num_players; processed++)
    {
        int maxIdx = -1;
        float best = 0.0f;
        for (int i = 0; i < jdge->num_players; i++)
        {
            if (best < rankValues[i])
            {
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

        swrRace* car = swrScoresPtr[maxIdx].obj_test_ptr;
        car->unk128 = (int) (firstPlaceRank - rankValues[maxIdx]);

        if (firstLocalPlayer == NULL)
        {
            car->unk130 = -0x3d380000;
        }
        else if (secondLocalPlayer == NULL)
        {
            if (firstLocalIdx == maxIdx)
            {
                car->unk130 = 0;
            }
            else
            {
                float gap = firstLocalRank - rankValues[maxIdx];
                bool neg = gap < 0.0f;
                car->unk130 = (int) gap;
                if (neg)
                    gap = -gap;
                if (aGapA <= gap)
                {
                    if (aGapB > gap)
                    {
                        aGapC = aGapB;
                        aGapB = gap;
                        aheadIdx2 = maxIdx;
                    }
                }
                else
                {
                    aGapC = aGapB;
                    aheadIdx2 = aheadIdx1;
                    aGapB = aGapA;
                    aGapA = gap;
                    aheadIdx1 = maxIdx;
                }
            }
        }
        else if (firstLocalIdx == maxIdx)
        {
            car->unk130 = 0;
            car->unk134 = (int) (secondLocalRank - firstLocalRank);
        }
        else if (secondLocalIdx == maxIdx)
        {
            car->unk134 = 0;
            car->unk130 = (int) (firstLocalRank - secondLocalRank);
        }
        else
        {
            float gapAhead = firstLocalRank - rankValues[maxIdx];
            float gapBehind = secondLocalRank - rankValues[maxIdx];
            bool neg = gapAhead < 0.0f;
            car->unk130 = (int) gapAhead;
            car->unk134 = (int) gapBehind;
            if (neg)
                gapAhead = -gapAhead;
            if (aGapA <= gapAhead)
            {
                if (aGapB <= gapAhead)
                {
                    if (gapAhead < aGapC)
                        aGapC = gapAhead;
                }
                else
                {
                    aGapC = aGapB;
                    aGapB = gapAhead;
                    aheadIdx2 = maxIdx;
                }
            }
            else
            {
                aGapC = aGapB;
                aheadIdx2 = aheadIdx1;
                aGapB = aGapA;
                aGapA = gapAhead;
                aheadIdx1 = maxIdx;
            }
            if (gapBehind < 0.0f)
                gapBehind = -gapBehind;
            if (bGapA <= gapBehind)
            {
                if (bGapB > gapBehind)
                {
                    bGapC = bGapB;
                    bGapB = gapBehind;
                    behindIdx2 = maxIdx;
                }
            }
            else
            {
                bGapC = bGapB;
                behindIdx2 = behindIdx1;
                bGapB = bGapA;
                bGapA = gapBehind;
                behindIdx1 = maxIdx;
            }
        }

        car->unk12c = (int) (leaderProgress - rankValues[maxIdx]);
        rankValues[maxIdx] = 0.0f;
        *(short*) &swrScoresPtr[maxIdx].results_P1_Position = (short) pos;
        pos++;
    }

    // tag the two nearest rivals behind (2-player only) and ahead of the local player(s)
    if (secondLocalPlayer != NULL)
    {
        if (behindIdx1 != -1 && rankValues[behindIdx1] < (float) jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx1].obj_test_ptr->flags0 |= 0x10000;
        if (behindIdx2 != -1 && rankValues[behindIdx2] < (float) jdge->num_laps - 0.1f)
            swrScoresPtr[behindIdx2].obj_test_ptr->flags0 |= 0x10000;
    }
    if (aheadIdx1 != -1 && rankValues[aheadIdx1] < (float) jdge->num_laps - 0.1f)
    {
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 |= 0x8000;
        swrScoresPtr[aheadIdx1].obj_test_ptr->flags0 &= 0xfffeffff;
    }
    if (aheadIdx2 != -1 && rankValues[aheadIdx2] < (float) jdge->num_laps - 0.1f)
    {
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 |= 0x8000;
        swrScoresPtr[aheadIdx2].obj_test_ptr->flags0 &= 0xfffeffff;
    }
}

// 0x0045E120
int KeyDownForPlayer1Or2(int)
{
    HANG("TODO");
}

// 0x0045e1a0
// Cycle the HUD layout when the toggle key is pressed (modes 0-4 single-screen, 4-7 splitscreen).
void swrObjJdge_CycleHudMode(swrObjJdge* jdge)
{
    if (KeyDownForPlayer1Or2(0x40) != 0)
    {
        if (numLocalPlayers < 2)
        {
            jdge->hud_mode++;
            if (4 < jdge->hud_mode)
                jdge->hud_mode = 0;
        }
        else
        {
            jdge->hud_mode++;
            if (7 < jdge->hud_mode)
                jdge->hud_mode = 4;
        }
    }
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
    rdVector3 mapPos = {0.0f, 0.0f, 0.0f};

    if (swrRace_demoMode == 0)
    {
        if ((jdge->flag & 0xf) != 6)
        {
            uint32_t state = jdge->flag & 0xf;
            if (state == 1 || state == 2)
            {
                bool finalLap = false;
                if (1 < jdge->num_laps)
                {
                    if (firstLocalPlayer != NULL && jdge->num_laps <= (int) firstLocalPlayer->results_P1_Lap + 1)
                        finalLap = true;
                    if (secondLocalPlayer != NULL && jdge->num_laps <= (int) secondLocalPlayer->results_P1_Lap + 1)
                        finalLap = true;
                }
                if (swrRace_music_enabled != 0)
                {
                    if (0.0f < GetPauseMenuScrollInOut() || (jdge->flag & 0xf) == 6)
                    {
                        swrSound_SetMusicFade(0); // NOTE: the call site passes a 2nd arg (planetId); swrSound.h proto is 1-arg
                        swrObjJdge_musicFadedForPause = 1;
                    }
                    else
                    {
                        if (swrObjJdge_musicFadedForPause != 0)
                        {
                            swrObjJdge_musicFadedForPause = 0;
                            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 0);
                        }
                        if (finalLap)
                        {
                            swrSound_SetMusicFade(1);
                        }
                        else if (NumLocalPlayers() < 1)
                        {
                            swrSound_SetMusicFade(1);
                        }
                        else if (swrObjJdge_postRaceHudState != 0)
                        {
                            swrSound_SelectTrackMusic(jdge->planetId, jdge->planet_track_number, 1);
                            swrSound_SetMusicFade(1);
                        }
                    }
                }
            }
            swrObjJdge_unkCa0c = 0;
        }
    }
    else
    {
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
    if (state == 4)
    {
        if (jdge->raceTimer_ms <= 0.0f)
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
        else
        {
            fadeValue = jdge->raceTimer_ms * 2.0f;
            fadeApplied = true;
        }
    }
    else if (state == 5)
    {
        if (jdge->raceTimer_ms <= 8.8f)
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
        else
        {
            fadeValue = 1.0f - (9.1f - jdge->raceTimer_ms) * 3.3333333f;
            fadeApplied = true;
        }
    }
    else if (state == 1 && (jdge->flag & 0x20) != 0)
    {
        if (0.3f <= jdge->raceTimer_ms)
            swrSprite_SetVisible(-0x67, 0);
        else
        {
            fadeValue = (0.3f - jdge->raceTimer_ms) * 3.3333333f;
            fadeApplied = true;
        }
    }
    else if (state == 6)
    {
        if (0.5f < jdge->raceTimer_ms)
        {
            swrSprite_SetColor(-0x67, 0, 0, 0, 0);
            return;
        }
        if (jdge->raceTimer_ms <= 0.25f)
        {
            swrSprite_SetColor(-0x67, 0, 0, 0, 0xff);
            return;
        }
        swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t) (int) ((0.5f - jdge->raceTimer_ms) * 4.0f * 255.0f));
        return;
    }
    if (fadeApplied)
        swrSprite_SetColor(-0x67, 0, 0, 0, (uint8_t) (int) (fadeValue * 255.0f));

    // blink the low-memory racer-count warning text
    swrObjJdge_lowMemTextBlink = (swrObjJdge_lowMemTextBlink == 0);
    if ((jdge->flag & 0xf) != 1 && lowMemoryRacerCount != 0 && swrObjJdge_lowMemTextBlink)
    {
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
    for (int i = 0; i < jdge->num_players; i++)
    {
        SetPlayerSpritePositionOnMap(i, &mapPos, -9999);
        short p = *(short*) &swrScoresPtr[i].results_P1_Position;
        if (0 < p)
            byPosition[p - 1] = &swrScoresPtr[i];
    }
    for (int i = 0; i < jdge->num_players; i++)
        swrSprite_SetVisible((short) (i + 0x2b), 0);
    swrSprite_SetVisible(0x19, 0);

    state = jdge->flag & 0xf;
    if (state != 4 && 1 < numLocalPlayers)
        swrObjJdge_DrawSplitDivider();
    if (state != 3 && state != 4 && state != 5)
    {
        if (firstLocalPlayer != NULL)
            swrObjJdge_UpdatePlayerHUD(jdge, firstLocalPlayer);
        if (secondLocalPlayer != NULL)
            swrObjJdge_UpdatePlayerHUD(jdge, secondLocalPlayer);
        if ((jdge->flag & 0xf) != 2)
        {
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
