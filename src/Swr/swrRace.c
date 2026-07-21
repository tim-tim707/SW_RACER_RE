#include "swrRace.h"

#include "swrObj.h"
#include "swrModel.h"
#include "swrSpline.h"
#include "swrEvent.h"
#include "swrText.h"
#include "swrSound.h"
#include "swrSprite.h"
#include "swrUI.h"
#include "swrMultiplayer.h"
#include "macros.h"
#include "engine_config.h"
#include "globals.h"

#include <General/stdMath.h>
#include <General/utils.h>
#include <General/stdFileUtil.h>
#include <General/stdFnames.h>
#include <Primitives/rdVector.h>
#include <Primitives/rdMatrix.h>
#include <Unknown/rdMatrixStack.h>

#include <stdio.h>
#include <string.h>

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

// 0x00421810
void swrRace_InitGameData(void)
{
    if (!swrRace_LoadGameData()) {
        swrRace_ResetGameData(1);
        if (!swrRace_SaveGameData())
            (*stdPlatform_hostServices_ptr->assert)("elfSaveLoad_SaveThisGameStruct()",
                                                    "D:\\devel.QA5\\pc_gnome\\SpecPlat\\rdroid_gnome\\Source\\elfSaveLoad.c", 0x4f);
    }
    swrRace_CopyProfileFromSave(0, 0);
}

// 0x00421850
bool swrRace_LoadProfile(char* playerName)
{
    FILE* stream;
    int failed;
    int version;
    swrSaveProfile profile;
    char path[256];

    version = 0;
    failed = 0;
    sprintf(path, "%s%s", ".\\data\\player\\", playerName);
    stdFnames_ChangeExt(path, "sav");
    stream = fopen(path, "rb");
    if (stream == NULL) {
        failed = 1;
    } else {
        if (fread(&version, 1, 4, stream) == 0 || version != ELFSAVE_VERSION_MAGIC ||
            fread(&profile, 1, sizeof(swrSaveProfile), stream) == 0)
            failed = 1;
        fclose(stream);
    }
    if (failed == 0) {
        swrRace_saveData.profiles[0] = profile;
        swrRace_profileLoaded = 0;
        swrRace_saveData.profiles[0].unk3c = 0;
        sprintf(swrRace_playerName, "%s", profile.name);
        swrRace_CopyProfileFromSave(0, 0);
    }
    return failed == 0;
}

// 0x004219d0
bool swrRace_SaveProfile(char* playerName)
{
    FILE* stream;
    size_t wroteMagic;
    size_t wroteProfile;
    int version;
    swrSaveProfile profile;
    char path[256];

    version = ELFSAVE_VERSION_MAGIC;
    profile = swrRace_saveData.profiles[0];
    if (swrRace_profileLoaded < 0)
        return false;
    sprintf(path, "%s%s", ".\\data\\player\\", playerName);
    stdFnames_ChangeExt(path, "sav");
    stream = fopen(path, "wb");
    if (stream == NULL)
        return false;
    wroteMagic = fwrite(&version, 1, 4, stream);
    wroteProfile = fwrite(&profile, 1, sizeof(swrSaveProfile), stream);
    fclose(stream);
    return wroteProfile != 0 && wroteMagic != 0;
}

// 0x00421b20
int swrRace_ResetGameData(int resetCurrentPlayer)
{
    swrSaveProfile profile;

    profile = swrRace_saveData.profiles[0];
    swrRace_InitDefaultGameData(&swrRace_saveData);
    if (resetCurrentPlayer == 0) {
        swrRace_saveData.profiles[0] = profile;
        return 1;
    }
    swrRace_playerName[0] = wuRegistry_lpClass[0];
    swrRace_profileLoaded = -1;
    return 1;
}

// 0x00421b90
bool swrRace_LoadGameData(void)
{
    FILE* stream;
    int failed;
    int version;
    char path[256];

    version = 0;
    failed = 0;
    sprintf(path, "%s%s", ".\\data\\player\\", "tgfd.dat");
    stream = fopen(path, "rb");
    if (stream == NULL) {
        failed = 1;
    } else {
        if (fread(&version, 1, 4, stream) == 0 || version != ELFSAVE_VERSION_MAGIC ||
            fread(&swrRace_saveData, 1, sizeof(swrSaveData), stream) == 0)
            failed = 1;
        fclose(stream);
    }
    if (failed == 0) {
        sprintf(swrRace_playerName, "%s", swrRace_saveData.profiles[0].name);
        swrRace_profileLoaded = (swrRace_playerName[0] != '\0') ? 0 : -1;
        swrRace_saveData.profiles[0].unk3c = 0;
        if (swrRace_IsGameDataUninitialized()) {
            swrRace_CopyProfileToSave(0, 0);
            swrRace_ResetGameData(0);
        }
    }
    return failed == 0;
}

// 0x00421c90
bool swrRace_SaveGameData(void)
{
    FILE* stream;
    size_t wroteMagic;
    size_t wroteImage;
    int version;
    char path[256];

    version = ELFSAVE_VERSION_MAGIC;
    if (swrRace_IsGameDataUninitialized()) {
        swrRace_CopyProfileToSave(0, 0);
        swrRace_ResetGameData(0);
    }
    stdFileUtil_MkDir(".\\data\\player\\");
    sprintf(path, "%s%s", ".\\data\\player\\", "tgfd.dat");
    stream = fopen(path, "wb");
    if (stream == NULL)
        return false;
    wroteMagic = fwrite(&version, 1, 4, stream);
    wroteImage = fwrite(&swrRace_saveData, 1, sizeof(swrSaveData), stream);
    fclose(stream);
    return wroteImage != 0 && wroteMagic != 0;
}

// 0x00421d80
bool swrRace_IsGameDataUninitialized(void)
{
    return swrRace_saveData.pilotsUnlockedGlobal == 0;
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

// Draws a track-record holder name below the record time (swrUI_Front_DrawRecord).
// The stored name field is 32 chars with no guaranteed NUL (a fresh save holds 32 'A's);
// the original sprintf's the raw copy and relies on whatever follows it on the stack,
// so we terminate explicitly instead.
// 0x00439c70
void swrRace_DrawRecordHolderName(float x, float y, float alpha, char* recordName)
{
    char name[33];
    char buffer[64];

    memcpy(name, recordName, 32);
    name[32] = '\0';
    sprintf(buffer, "~f4~c~s%s", name);
    swrText_CreateTextEntry1((int)x, (int)y, 0x32, -1, -1, (int)alpha, buffer);
}

// Post-race results screen. On entry (menuJustEntered) it sanitizes and sorts the race scores,
// routes record-setting guest players through name entry, commits new 3-lap / best-lap records
// into the save image (holder name + pilot from the live profile), and -- in tournament mode --
// applies the whole progression step: prize truguts, next-track/circuit unlocks, beat-place
// bits, the favorite-pilot unlock cutaway, and the podium hand-off; then autosaves. Every frame
// it renders the scrollable standings list and handles input.
// 0x00439ce0
void swrRace_ResultsMenu(swrObjHang* hang)
{
    swrScore* scores[20]; // race order: local players first
    float bestLap[2];
    swrScore* score;
    char* text;
    float rowYf;
    float alphaF;
    float lapTime;
    int rowY;
    int textY;
    int alpha;
    int spriteId;
    int pilot;
    int recordIdx;
    int lap;
    int i;
    int k;
    char effLaps;
    char newCircuitIdx;
    char minLocalPlace;
    char required;
    uint8_t favoritePilot;
    int storedPlaceBits;
    int gain;
    swrObjHang_STATE state2;
    char buffer[256];

    newCircuitIdx = hang->circuitIdx;
    bestLap[0] = ELFSAVE_RECORD_TIME_EMPTY;
    bestLap[1] = ELFSAVE_RECORD_TIME_EMPTY;
    g_CircuitIdxMax = (int)(150.0f - (float)hang->num_players * 30.0f); // scroll floor (see DrawScrollbar)
    effLaps = hang->numLaps;
    if (hang->isTournamentMode != 0)
        effLaps = 3;
    text = swrText_Translate("/SCREENTEXT_189/~c~sResults");
    swrText_CreateColorlessEntry1(0xa0, 0x14, text);
    for (i = 0; i < 20; i++)
        scores[i] = NULL;

    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrRace_resultsFanfareDelay = 2.0f;
        for (i = 0; i < g_aTracksInCircuits[(int)hang->circuitIdx]; i++) {
            if ((int)hang->track_index == g_aTrackIDs[hang->circuitIdx * 7 + i]) {
                swrObjHang_trackInCircuitIdx = (uint8_t)i;
                break;
            }
        }
        swrRace_resultsScrollY = 0.0f;
        swrRace_TournamentTrugutGain = 0;
        for (i = 0; i < 20; i++)
            swrRace_resultsSortedScores[i] = NULL;
        // collect + sanitize: out-of-range totals and lap times become the empty-record value
        for (i = 0; i < hang->num_players; i++) {
            score = &swrScores[i];
            scores[i] = score;
            if (score == NULL) {
                hang->num_players = (char)i;
                break;
            }
            if (ELFSAVE_RECORD_TIME_EMPTY < score->results_P1_total_time || score->results_P1_total_time < 0.0f)
                score->results_P1_total_time = ELFSAVE_RECORD_TIME_EMPTY;
            for (lap = 0; lap < effLaps; lap++) {
                if (ELFSAVE_RECORD_TIME_EMPTY < (&score->results_P1_Lap1)[lap] || (&score->results_P1_Lap1)[lap] < 0.0f)
                    (&score->results_P1_Lap1)[lap] = ELFSAVE_RECORD_TIME_EMPTY;
            }
            swrRace_resultsSortedScores[i] = score;
        }
        // sort by finishing position (bubble)
        for (i = 1; i < hang->num_players; i++) {
            for (k = 0; k < i; k++) {
                if ((short)swrRace_resultsSortedScores[i]->results_P1_Position <
                    (short)swrRace_resultsSortedScores[k]->results_P1_Position) {
                    score = swrRace_resultsSortedScores[i];
                    swrRace_resultsSortedScores[i] = swrRace_resultsSortedScores[k];
                    swrRace_resultsSortedScores[k] = score;
                }
            }
        }
        // best single lap per local player (a non-positive lap time ends the scan)
        for (k = 0; k < hang->num_local_players; k++) {
            bestLap[k] = (&scores[k]->results_P1_Lap1)[0];
            for (lap = 1; lap < effLaps; lap++) {
                lapTime = (&scores[k]->results_P1_Lap1)[lap];
                if (lapTime <= 0.0f)
                    break;
                if (lapTime < bestLap[k])
                    bestLap[k] = lapTime;
            }
        }
        // a record-setting guest profile (not linked to a save slot) gets sent to name entry
        recordIdx = hang->bMirror + hang->track_index * 2;
        if ((swrRace_resultsStateFlags & swrRace_RESULTSFLAG_NAME_ENTRY_P1) == 0 &&
            swrRace_aProfiles[0].linkedToSave == 0 &&
            ((effLaps == 3 && scores[0]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx] &&
              (hang->num_local_players == 1 || scores[0]->results_P1_total_time < scores[1]->results_P1_total_time)) ||
             (bestLap[0] < swrRace_saveData.recordLapTimes[recordIdx] &&
              (hang->num_local_players == 1 || bestLap[0] < bestLap[1])))) {
            swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_NAME_ENTRY_P1;
            hang->current_player_for_vehicle_selection = 0;
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_ENTER_NAME);
            return;
        }
        if (1 < hang->num_local_players && (swrRace_resultsStateFlags & swrRace_RESULTSFLAG_NAME_ENTRY_P2) == 0 &&
            swrRace_aProfiles[1].linkedToSave == 0 &&
            ((effLaps == 3 && scores[1]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx] &&
              scores[1]->results_P1_total_time < scores[0]->results_P1_total_time) ||
             (bestLap[1] < swrRace_saveData.recordLapTimes[recordIdx] && bestLap[1] < bestLap[0]))) {
            swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_NAME_ENTRY_P2;
            hang->current_player_for_vehicle_selection = 1;
            swrObjHang_SetMenuState(hang, swrObjHang_STATE_ENTER_NAME);
            return;
        }
        // commit new records: time + holder name + holder pilot from the live profile
        if ((swrRace_resultsStateFlags & swrRace_RESULTSFLAG_RECORDS_COMMITTED) == 0) {
            for (k = 0; k < hang->num_local_players; k++) {
                recordIdx = hang->bMirror + hang->track_index * 2;
                if (effLaps == 3 && scores[k]->results_P1_total_time < ELFSAVE_RECORD_TIME_EMPTY &&
                    scores[k]->results_P1_total_time < swrRace_saveData.record3LapTimes[recordIdx]) {
                    swrRace_saveData.record3LapTimes[recordIdx] = scores[k]->results_P1_total_time;
                    for (i = 0; i < 32; i++)
                        swrRace_saveData.record3LapNames[recordIdx][i] = swrRace_aProfiles[k].name[i];
                    swrRace_saveData.record3LapPilots[recordIdx] = swrRace_aProfiles[k].pilotId;
                }
                if (bestLap[k] < ELFSAVE_RECORD_TIME_EMPTY &&
                    bestLap[k] < swrRace_saveData.recordLapTimes[recordIdx]) {
                    swrRace_saveData.recordLapTimes[recordIdx] = bestLap[k];
                    for (i = 0; i < 32; i++)
                        swrRace_saveData.recordLapNames[recordIdx][i] = swrRace_aProfiles[k].name[i];
                    swrRace_saveData.recordLapPilots[recordIdx] = swrRace_aProfiles[k].pilotId;
                }
            }
        }
        swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_RECORDS_COMMITTED;

        swrRace_resultsPlaceP1 = *(char*)&scores[0]->results_P1_Position;
        swrRace_resultsPlaceP2 = -1;
        minLocalPlace = swrRace_resultsPlaceP1;
        if (1 < hang->num_local_players) {
            swrRace_resultsPlaceP2 = *(char*)&scores[1]->results_P1_Position;
            if (swrRace_resultsPlaceP2 < swrRace_resultsPlaceP1)
                minLocalPlace = swrRace_resultsPlaceP2;
        }
        if (3 < minLocalPlace) {
            // start the list scrolled so the local player's row is visible
            swrRace_resultsScrollY = (float)(minLocalPlace - 3) * -30.0f;
            if (swrRace_resultsScrollY < 150.0f - (float)hang->num_players * 30.0f)
                swrRace_resultsScrollY = 150.0f - (float)hang->num_players * 30.0f;
        }
        if (hang->num_local_players == 1 && hang->isTournamentMode != 0 && 3 < hang->num_players) {
            // equal totals share a finishing position
            for (i = 1; i < hang->num_players; i++) {
                if (swrRace_resultsSortedScores[i]->results_P1_total_time ==
                    swrRace_resultsSortedScores[i - 1]->results_P1_total_time)
                    *(short*)&swrRace_resultsSortedScores[i]->results_P1_Position =
                        *(short*)&swrRace_resultsSortedScores[i - 1]->results_P1_Position;
            }
            // winning a track can unlock its favorite pilot (cutaway state)
            if (swrRace_resultsPlaceP1 == 1 && hang->isTournamentMode != 0 &&
                (swrRace_resultsStateFlags & swrRace_RESULTSFLAG_PILOT_UNLOCK_SHOWN) == 0) {
                favoritePilot = g_aTrackInfos[(int)hang->track_index].FavoritePilot;
                if (favoritePilot == 2 && hang->track_index != 1)
                    favoritePilot = 0;
                if (0 < (char)favoritePilot &&
                    (swrRace_aProfiles[0].pilotsUnlocked & (1u << (favoritePilot & 0x1f))) == 0) {
                    swrRace_aProfiles[0].pilotsUnlocked |= 1u << (favoritePilot & 0x1f);
                    swrRace_saveData.pilotsUnlockedGlobal |= swrRace_aProfiles[0].pilotsUnlocked;
                    swrRace_SaveCurrentProfile();
                    swrRace_resultsStateFlags |= swrRace_RESULTSFLAG_PILOT_UNLOCK_SHOWN;
                    swrObjHang_SetMenuState(hang, swrObjHang_STATE_PILOT_UNLOCK);
                    return;
                }
            }
            required = GetRequiredPlaceToProceed(hang->circuitIdx, (char)swrObjHang_trackInCircuitIdx);
            if (swrRace_resultsPlaceP1 <= required) {
                storedPlaceBits = (swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] >>
                                   ((swrObjHang_trackInCircuitIdx & 0xf) * 2)) &
                                  3;
                if (isTrackUnlocked(hang->circuitIdx, (char)swrObjHang_trackInCircuitIdx) != 0) {
                    // prize scales with the circuit: x1.0 / x1.5 / x2.0 / x2.5
                    gain = (int)hang->winnings.truguts[hang->WinningsID - 1][swrRace_resultsPlaceP1 - 1];
                    gain = (int)((1.0 - (double)(int)hang->circuitIdx * -0.5) * (double)gain);
                    swrRace_TournamentTrugutGain = gain;
                    swrRace_truguts += gain;
                    if (hang->circuitIdx < 3) {
                        if ((int)swrObjHang_trackInCircuitIdx == g_aTracksInCircuits[(int)hang->circuitIdx] - 1 &&
                            (swrRace_aProfiles[0].circuitsCompleted & (1 << (hang->circuitIdx & 0x1f))) == 0) {
                            // circuit finished for the first time: jump to its invitational track
                            newCircuitIdx = 3;
                            swrRace_aProfiles[0].circuitsCompleted |= 1 << (hang->circuitIdx & 0x1f);
                            hang->track_index = (char)g_aTrackIDs[hang->circuitIdx + 0x15];
                        } else if ((int)swrObjHang_trackInCircuitIdx < g_aTracksInCircuits[(int)hang->circuitIdx] - 1 &&
                                   (swrRace_aProfiles[0].tracksUnlocked[(int)hang->circuitIdx] &
                                    (1 << ((swrObjHang_trackInCircuitIdx + 1) & 0x1f))) == 0) {
                            hang->track_index =
                                (char)g_aTrackIDs[hang->circuitIdx * 7 + swrObjHang_trackInCircuitIdx + 1];
                        }
                        swrRace_aProfiles[0].tracksUnlocked[(int)hang->circuitIdx] |=
                            1 << ((swrObjHang_trackInCircuitIdx + 1) & 0x1f);
                    }
                    swrRace_UpdatePartsHealth();
                }
                if ((int)swrObjHang_trackInCircuitIdx == g_aTracksInCircuits[(int)hang->circuitIdx] - 1 &&
                    hang->circuitIdx == 2)
                    swrObjHang_SelectDemoTracks_Maybe(hang);
                // best finishing place per track, 2 bits each (stored as 4 - place)
                if (storedPlaceBits < 4 - swrRace_resultsPlaceP1) {
                    swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] &=
                        (uint16_t)~(3 << (swrObjHang_trackInCircuitIdx * 2));
                    swrRace_aProfiles[0].beatTrackPlace[(int)hang->circuitIdx] |=
                        (uint16_t)((4 - swrRace_resultsPlaceP1) << (swrObjHang_trackInCircuitIdx * 2));
                    if (swrRace_aProfiles[0].beatTrackPlace[0] == 0x3fff &&
                        swrRace_aProfiles[0].beatTrackPlace[1] == 0x3fff &&
                        swrRace_aProfiles[0].beatTrackPlace[2] == 0x3fff) {
                        if ((swrRace_aProfiles[0].circuitsCompleted & 8) == 0) {
                            swrRace_aProfiles[0].circuitsCompleted |= 8;
                            newCircuitIdx = 3;
                            hang->track_index = (char)g_aTrackIDs[0x18];
                        } else if (swrRace_aProfiles[0].beatTrackPlace[3] == 0xff &&
                                   (swrRace_saveData.unlockFlags & swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST) == 0) {
                            swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST;
                        }
                    }
                }
            }
            // fold the profile's unlock progress into the machine-global unlocks
            // (UnlockDataBase[1..4] = tracksUnlocked[0..2] + circuitsCompleted)
            for (i = 0; i < 4; i++) {
                if (g_aBeatTracksGlobal[i] < (uint8_t)swrRace_UnlockDataBase[i + 1])
                    g_aBeatTracksGlobal[i] = (uint8_t)swrRace_UnlockDataBase[i + 1];
            }
        }
        hang->circuitIdx = newCircuitIdx;
        swrRace_SaveCurrentProfile();
    }

    if (0.0f < swrRace_resultsFanfareDelay) {
        swrRace_resultsFanfareDelay -= swrRace_fdeltaTimeSecs;
        if (swrRace_resultsFanfareDelay <= 0.0f)
            playASound(0xb6, 7, 0.25f, 1.0f, 0);
    }

    // standings rows (30px apart, faded near the top/bottom edges)
    rowY = 0x1e;
    for (i = 0; i < hang->num_players; i++) {
        score = swrRace_resultsSortedScores[i];
        rowYf = ((float)rowY + swrRace_resultsScrollY) + 15.0f;
        alphaF = 255.0f;
        if (rowYf < 45.0f)
            alphaF = (float)(255.0 - (45.0 - (double)rowYf) * 8.0);
        if (160.0f < rowYf)
            alphaF = (float)(255.0 - ((double)rowYf - 160.0) * 8.0);
        if (alphaF < 0.0f)
            alphaF = 0.0f;
        if (255.0f < alphaF)
            alphaF = 255.0f;
        alpha = (int)alphaF;
        // duplicate pods use the mirrored sprite bank (+0x17 per prior appearance)
        pilot = *(int*)score->unk18;
        spriteId = pilot;
        for (k = 0; k < i; k++) {
            if (pilot == *(int*)swrRace_resultsSortedScores[k]->unk18)
                spriteId += 0x17;
        }
        swrSprite_SetVisible((short)spriteId, 1);
        swrSprite_SetPos((short)spriteId, 0x1e, (short)(int)rowYf);
        swrSprite_SetDim((short)spriteId, 0.5f, 0.5f);
        swrSprite_SetColor((short)spriteId, 0xff, 0xff, 0xff, (uint8_t)alpha);
        rowYf += 10.0f;
        textY = (int)rowYf;
        if (i == swrRace_resultsPlaceP1 - 1 || i == swrRace_resultsPlaceP2 - 1) {
            // local player's row: highlighted, with the profile name underneath
            text = swrText_Translate("~r~s%d:");
            sprintf(buffer, text, (int)(short)score->results_P1_Position);
            swrText_CreateTextEntry1(0x58, textY, -0x5d, -0x42, 0x11, alpha, buffer);
            text = swrText_Translate("~f4~s%s %s");
            sprintf(buffer, text, swrText_Translate(swrRacer_PodData[pilot].name),
                    swrText_Translate(swrRacer_PodData[pilot].lastname));
            swrText_CreateTextEntry1(0x5c, (int)(rowYf + 1.0f), -0x5d, -0x42, 0x11, alpha, buffer);
            swrText_CreateTimeEntryFormat(0x109, textY, score->results_P1_total_time, -0x5d, -0x42, 0x11, alpha, 1);
            text = swrText_Translate("~f4~s%s");
            sprintf(buffer, text,
                    (i == swrRace_resultsPlaceP1 - 1) ? swrRace_aProfiles[0].name : swrRace_aProfiles[1].name);
            swrText_CreateTextEntry1(100, (int)(rowYf + 9.0f), -0x5d, -0x42, 0x11, alpha, buffer);
        } else {
            text = swrText_Translate("~r~s%d:");
            sprintf(buffer, text, (int)(short)score->results_P1_Position);
            swrText_CreateTextEntry1(0x58, textY, 0x32, -1, -1, alpha, buffer);
            text = swrText_Translate("~f4~s%s %s");
            sprintf(buffer, text, swrText_Translate(swrRacer_PodData[pilot].name),
                    swrText_Translate(swrRacer_PodData[pilot].lastname));
            swrText_CreateTextEntry1(0x5c, (int)(rowYf + 1.0f), 0x32, -1, -1, alpha, buffer);
            swrText_CreateTimeEntryFormat(0x109, textY, score->results_P1_total_time, 0x32, -1, -1, alpha, 1);
        }
        rowY += 0x1e;
    }
    if (4 < hang->num_players)
        swrRace_DrawScrollbar(0x122, 0x1e, 0x90);
    if (0 < swrRace_TournamentTrugutGain) {
        text = swrText_Translate("/SCREENTEXT_575/~c~sYou won %d Truguts!");
        sprintf(buffer, text, swrRace_TournamentTrugutGain);
        swrText_CreateColorlessEntry1(0x87, 0xcd, buffer);
        swrObjHang_PositionHoloNode(0, 7.0f, -7.0f, 1.0f);
    }

    state2 = swrObjHang_state2;
    for (k = 0; k < hang->num_local_players; k++) {
        if (swrControl_acceptPressedEdge != 0 || swrControl_cancelPressedEdge != 0) {
            swrUI_RunCallbacks2(swrUI_GetUI1(), 1);
            playUISound(0x54);
            if (hang->isTournamentMode == 0) {
                // multiplayer results return to the lobby flow (SELECT_PLANET - 11)
                state2 = swrMultiplayer_IsMultiplayerEnabled() != 0
                             ? (swrObjHang_STATE)(swrObjHang_STATE_SELECT_PLANET - 11)
                             : swrObjHang_STATE_SELECT_PLANET;
                swrObjHang_state2 = state2;
            } else if (swrRace_resultsPlaceP1 < 4 && swrObjHang_trackInCircuitIdx == 6) {
                // circuit final won: podium ceremony with the top three pilots
                for (i = 0; i < 3; i++)
                    hang->podiumCharacters[i] = *(char*)swrRace_resultsSortedScores[i]->unk18;
                state2 = swrObjHang_STATE_PODIUM;
                swrObjHang_state2 = state2;
            } else {
                state2 = swrObjHang_STATE_SELECT_PLANET;
                swrObjHang_state2 = state2;
            }
        }
        g_bCircuitIdxInRange = 0;
        swrUI_menuScrolled = 0;
        if (4 < hang->num_players) {
            // analog scroll through the standings
            if (swrControl_aPlayerAxisY[k] < -0.1f || 0.1f < swrControl_aPlayerAxisY[k]) {
                swrRace_resultsScrollY -= swrControl_aPlayerAxisY[k] * swrRace_fdeltaTimeSecs * -300.0f;
                if (0.0f < swrRace_resultsScrollY)
                    swrRace_resultsScrollY = 0.0f;
                if (swrRace_resultsScrollY < 150.0f - (float)hang->num_players * 30.0f)
                    swrRace_resultsScrollY = 150.0f - (float)hang->num_players * 30.0f;
            }
            swrUI_menuScrolled = (uint32_t)(swrRace_resultsScrollY < 0.0f);
            if ((float)g_CircuitIdxMax < swrRace_resultsScrollY)
                g_bCircuitIdxInRange = 1;
        }
    }
    if (state2 != ~swrObjHang_STATE_LEGAL) {
        // a state transition is pending: reset the one-shot latches for the next results screen
        swrRace_resultsStateFlags = 0;
        swrObjHang_camFocusIdx = -1;
    }
}

// 0x0043b240
void swrRace_CourseSelectionMenu(void)
{
    HANG("TODO");
}

// Course info screen (after track select): builds the option-row list on entry (mirror /
// winnings / laps / racers / AI speed / demo / cutscene, depending on mode), draws the rows,
// the planet hologram + track preview, the track name, both save-image records (3-lap + best
// lap, with holder name + pod sprite), the track's favorite pilot, and the tournament
// "must place N" hint; then handles option cycling and the start/back transitions.
// 0x0043b880
void swrRace_CourseInfoMenu(swrObjHang* hang)
{
    char* text;
    char* valueText;
    int rowY;
    int prizeY;
    int recordIdx;
    int trackInCircuit;
    int prize;
    int width;
    int colR;
    int colG;
    int colB;
    int i;
    char itemCount;
    char required;
    char pilot;
    uint8_t favoritePilot;
    char buffer[64];

    if ((uint8_t)nb_AI_racers == 0)
        nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
    if (swrObjHang_splitscreenRacerCount == 0)
        swrObjHang_splitscreenRacerCount = 2;

    itemCount = swrObjHang_courseInfoItemCount;
    if (swrObjHang_menuJustEntered != 0) {
        swrObjHang_menuJustEntered = 0;
        swrObjHang_FocusMenuItem(hang, 0x25, ~swrObjHang_STATE_LEGAL, 0);
        swrObjHang_courseInfoSelectedRow = 0;
        swrObjHang_courseInfoLeaving = 0;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_PLANET)
            swrRace_Transition = 1.0f;
        swrUI_Front_HandleCircuits(hang);
        if (hang->menuScreenPrev != swrObjHang_STATE_SELECT_PLANET)
            swrUI_Front_SeekToCurrentTrack_Maybe(hang);
        for (i = 0; i < 12; i++)
            swrObjHang_courseInfoItemKinds[i] = -1;
        swrObjHang_courseInfoItemCount = 0;
        if (swrUI_Front_BeatEverything1stPlace(hang)) {
            swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 0; // mirror toggle
            swrObjHang_courseInfoItemCount++;
        }
        if (hang->isTournamentMode == 0) {
            itemCount = swrObjHang_courseInfoItemCount + 1;
            swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 2; // laps
            if (hang->timeAttackMode == 0) {
                swrObjHang_courseInfoItemCount += 2;
                swrObjHang_courseInfoItemKinds[itemCount] = 3; // racers
                swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 4; // AI speed
                itemCount = swrObjHang_courseInfoItemCount + 1;
            }
        } else {
            trackInCircuit = VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
            if (isTrackUnlocked(hang->circuitIdx, (char)trackInCircuit) != 0) {
                swrObjHang_courseInfoItemKinds[(int)swrObjHang_courseInfoItemCount] = 1; // winnings
                itemCount = swrObjHang_courseInfoItemCount + 1;
            } else {
                itemCount = swrObjHang_courseInfoItemCount;
            }
        }
    }
    swrObjHang_courseInfoItemCount = itemCount;

    trackInCircuit = VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
    required = GetRequiredPlaceToProceed(hang->circuitIdx, (char)trackInCircuit);

    rowY = 0xa0;
    if (swrObjHang_courseInfoLeaving == 0 && 0 < swrObjHang_courseInfoItemCount) {
        for (i = 0; i < swrObjHang_courseInfoItemCount; i++) {
            valueText = NULL;
            switch (swrObjHang_courseInfoItemKinds[i]) {
            case 0: // mirror
                text = swrText_Translate(g_pTxtMirror);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = swrText_Translate(hang->bMirror == 0 ? g_pTxtOff : g_pTxtOn);
                break;
            case 1: // tournament winnings + prize table
                if (hang->WinningsID == 1)
                    text = swrText_Translate(g_pTxtFair);
                else if (hang->WinningsID == 2)
                    text = swrText_Translate(g_pTxtSkilled);
                else
                    text = swrText_Translate(g_pTxtWinnerTakesAll);
                sprintf(buffer, text);
                text = swrText_Translate(g_pTxtWinnings);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                swrUI_Front_TextMenu(hang, 0x55, rowY, 10, swrObjHang_courseInfoSelectedRow, i, buffer);
                prizeY = rowY + 10;
                text = swrText_Translate(g_pTxt1st);
                swrUI_Front_TextMenu(hang, 0x2d, prizeY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                text = swrText_Translate(g_pTxt2nd);
                swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x14, 10, swrObjHang_courseInfoSelectedRow, i, text);
                text = swrText_Translate(g_pTxt3rd);
                swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x1e, 10, swrObjHang_courseInfoSelectedRow, i, text);
                if (required == 4) {
                    text = swrText_Translate(g_pTxt4th);
                    swrUI_Front_TextMenu(hang, 0x2d, rowY + 0x28, 10, swrObjHang_courseInfoSelectedRow, i, text);
                }
                for (prize = 0; prize < required; prize++) {
                    // prize scales with the circuit: x1.0 / x1.5 / x2.0 / x2.5
                    int truguts = (int)((1.0 - (double)(int)hang->circuitIdx * -0.5) *
                                        (double)(int)hang->winnings.truguts[hang->WinningsID - 1][prize]);
                    text = swrText_Translate("~f0~r~s%d");
                    sprintf(buffer, text, truguts);
                    swrUI_Front_TextMenu(hang, 0x69, prizeY, 10, swrObjHang_courseInfoSelectedRow, i, buffer);
                    prizeY += 10;
                }
                continue;
            case 2: // laps
                text = swrText_Translate("~f0~s%d");
                sprintf(buffer, text, (int)hang->numLaps);
                text = swrText_Translate(g_pTxtLaps);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 3: // racer count
                text = swrText_Translate("~f0~s%d");
                sprintf(buffer, text, (int)(uint8_t)nb_AI_racers);
                if (1 < hang->num_local_players) {
                    text = swrText_Translate("~f0~s%d");
                    sprintf(buffer, text, (int)(uint8_t)swrObjHang_splitscreenRacerCount);
                }
                text = swrText_Translate(g_pTxtRacers);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 4: // AI speed
                if (hang->AISpeed == 1)
                    text = swrText_Translate(g_pTxtSlow);
                else if (hang->AISpeed == 2)
                    text = swrText_Translate(g_pTxtAverage);
                else
                    text = swrText_Translate(g_pTxtFast);
                sprintf(buffer, text);
                text = swrText_Translate(g_pTxtAISpeed);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            case 5: // demo mode
                rowY += 10;
                text = swrText_Translate(g_pTxtDemoMode);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = swrText_Translate(hang->demo_mode == 0 ? g_pTxtOff : g_pTxtOn);
                break;
            case 6: // cutscene selector
                if (hang->unk68_type < 0) {
                    text = swrText_Translate(g_pTxtOff2);
                    sprintf(buffer, text);
                } else {
                    text = swrText_Translate("~s%d");
                    sprintf(buffer, text, hang->unk68_type + 1);
                }
                text = swrText_Translate(g_pTxtCutscene);
                swrUI_Front_TextMenu(hang, 0x1e, rowY, 10, swrObjHang_courseInfoSelectedRow, i, text);
                valueText = buffer;
                break;
            default:
                continue;
            }
            swrUI_Front_TextMenu(hang, 0x55, rowY, 10, swrObjHang_courseInfoSelectedRow, i, valueText);
        }
    }

    swrObjHang_StepTransition(swrObjHang_courseInfoLeaving == 0 ? 3.3f : -3.3f);
    if (0.0f < swrRace_Transition)
        DrawHoloPlanet(hang, (int)(char)g_aTrackInfos[(int)hang->track_index].PlanetIdx,
                       swrRace_Transition * 0.5f);
    if (swrObjHang_courseInfoLeaving != 0)
        return;
    DrawTrackPreview(hang, (int)hang->track_index, 0.5f);
    if (swrObjHang_courseInfoLeaving != 0)
        return;

    if (g_aTrackInfos[(int)hang->track_index].trackID == (INGAME_MODELID)~INGAME_MODELID_loc_watto_part ||
        g_aTrackInfos[(int)hang->track_index].splineID == (SPLINEID)~SPLINEID_planetd_track) {
        // no model/spline assigned: flashing "planet not loaded" warning
        text = swrText_Translate(g_pTxtPlanetNotLoaded);
        sprintf(buffer, text);
        colB = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        colG = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 256.0f);
        swrText_CreateTextEntry1(0xa0, 0xcd, colR, colG, colB, -1, buffer);
    }
    text = swrUI_Front_GetTrackNameFromId((int)hang->track_index);
    valueText = swrText_Translate("~c~s%s");
    sprintf(buffer, valueText, text);
    swrText_CreateTextEntry1(0xa0, 0x25, 0, -1, 0, -1, buffer);
    swrText_GetStringWidthByFont(buffer, 0); // result unused in the original too
    width = swrText_GetStringWidthByFont(buffer, 0);
    swrUI_Front_MenuAxisHorizontal((void*)(int)(160.0 - (double)width * 0.5), 0x26);

    swrUI_Front_DrawRecord(hang, 100, 0x37, 255.0f, 0);
    swrUI_Front_DrawRecord(hang, 0xdc, 0x37, 255.0f, 3);
    // 3-lap record holder: pilot name + pod sprite
    recordIdx = hang->bMirror + hang->track_index * 2;
    if (swrRace_saveData.record3LapTimes[recordIdx] < ELFSAVE_RECORD_TIME_EMPTY) {
        pilot = swrRace_saveData.record3LapPilots[recordIdx];
        text = swrText_Translate("~f4~c~s%s %s");
        sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(int)pilot].name),
                swrText_Translate(swrRacer_PodData[(int)pilot].lastname));
        swrText_CreateTextEntry1(100, 0x4e, -0x5d, -0x42, 0x11, -1, buffer);
        swrSprite_SetVisible((short)(pilot + 0x17), 1);
        swrSprite_SetPos((short)(pilot + 0x17), 0x54, 0x55);
        swrSprite_SetDim((short)(pilot + 0x17), 0.5f, 0.5f);
        swrSprite_SetColor((short)(pilot + 0x17), 0xff, 0xff, 0xff, 0xff);
    }
    // best-lap record holder
    if (swrRace_saveData.recordLapTimes[recordIdx] < ELFSAVE_RECORD_TIME_EMPTY) {
        pilot = swrRace_saveData.recordLapPilots[recordIdx];
        text = swrText_Translate("~f4~c~s%s %s");
        sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(int)pilot].name),
                swrText_Translate(swrRacer_PodData[(int)pilot].lastname));
        swrText_CreateTextEntry1(0xdc, 0x4e, -0x5d, -0x42, 0x11, -1, buffer);
        swrSprite_SetVisible((short)(pilot + 0x2e), 1);
        swrSprite_SetPos((short)(pilot + 0x2e), 0xcc, 0x55);
        swrSprite_SetDim((short)(pilot + 0x2e), 0.5f, 0.5f);
        swrSprite_SetColor((short)(pilot + 0x2e), 0xff, 0xff, 0xff, 0xff);
    }
    // track favorite
    favoritePilot = g_aTrackInfos[(int)hang->track_index].FavoritePilot;
    text = swrText_Translate(g_pTxtTrackFavorite);
    swrText_CreateTextEntry1(0xf0, 0x82, 0x32, -1, -1, -1, text);
    text = swrText_Translate("~f4~c~s%s %s");
    sprintf(buffer, text, swrText_Translate(swrRacer_PodData[(char)favoritePilot].name),
            swrText_Translate(swrRacer_PodData[(char)favoritePilot].lastname));
    swrText_CreateTextEntry1(0xf0, 0x89, -0x5d, -0x42, 0x11, -1, buffer);
    swrSprite_SetVisible((short)(char)favoritePilot, 1);
    swrSprite_SetPos((short)(char)favoritePilot, 0xd0, 0x91);
    swrSprite_SetDim((short)(char)favoritePilot, 1.0f, 1.0f);
    swrSprite_SetColor((short)(char)favoritePilot, 0xff, 0xff, 0xff, 0xff);
    if (hang->isTournamentMode != 0) {
        trackInCircuit = VerifySelectedTrack(hang, swrRace_MenuSelectedItem);
        if (isTrackUnlocked(hang->circuitIdx, (char)trackInCircuit) != 0) {
            text = swrText_Translate(required == 3 ? g_pTxtMinPlace3rd : g_pTxtMinPlace4th);
            swrText_CreateTextEntry1(0xa0, 0x73, -0x5d, -0x42, 0x11, -1, text);
        }
    }

    if (swrObjHang_courseInfoLeaving == 0 && 1.0f <= swrRace_Transition) {
        // the original iterates a single element: only player 1's pressed bitset
        int* pressed = swrUI_localPlayersInputPressedBitset;
        if (swrMultiplayer_menuOverlayActive == 0) {
            if (swrControl_menuAcceptPressedEdge != 0 &&
                (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) &&
                swrObjHang_menuAcceptLock == 0) {
                playUISound(0x54);
                if (hang->isTournamentMode == 0) {
                    if (hang->timeAttackMode != 0) {
                        hang->num_players = 1;
                    } else if (hang->num_local_players < 2) {
                        if (hang->demo_mode != 0 && (uint8_t)nb_AI_racers == 2)
                            hang->num_players = 1;
                        else
                            hang->num_players = (uint8_t)nb_AI_racers;
                    } else {
                        hang->num_players = swrObjHang_splitscreenRacerCount;
                    }
                } else {
                    hang->num_players = 12;
                }
                swrObjHang_InitTrackSprites(hang, 0);
                swrObjHang_FocusMenuItem(hang, 0x24, swrObjHang_STATE_MAIN_MENU, 0);
                swrObjHang_courseInfoLeaving = 1;
                return;
            }
            if (swrControl_cancelPressedEdge != 0 && swrObjHang_menuAcceptLock == 0) {
                playUISound(0x4d);
                swrObjHang_InitTrackSprites(hang, 0);
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_PLANET);
                return;
            }
        }
        if (1 < swrObjHang_courseInfoItemCount) {
            if ((*pressed & swrUI_INPUT_MENU_UP) != 0) {
                swrObjHang_courseInfoSelectedRow--;
                playUISound(0x58);
            }
            if ((*pressed & swrUI_INPUT_MENU_DOWN) != 0) {
                swrObjHang_courseInfoSelectedRow++;
                playUISound(0x58);
            }
            if (swrObjHang_courseInfoSelectedRow < 0)
                swrObjHang_courseInfoSelectedRow = swrObjHang_courseInfoItemCount - 1;
            if (swrObjHang_courseInfoItemCount - 1 < swrObjHang_courseInfoSelectedRow)
                swrObjHang_courseInfoSelectedRow = 0;
        }
        if (0 < swrObjHang_courseInfoItemCount) {
            if ((*pressed & swrUI_INPUT_MENU_RIGHT) != 0) {
                switch (swrObjHang_courseInfoItemKinds[swrObjHang_courseInfoSelectedRow]) {
                case 0:
                    hang->bMirror = hang->bMirror == 0;
                    break;
                case 1:
                    hang->WinningsID++;
                    break;
                case 2:
                    hang->numLaps++;
                    break;
                case 3:
                    if (hang->num_local_players < 2) {
                        // 1 <-> 2 <-> 4 <-> 8 <-> 12 racers
                        if ((uint8_t)nb_AI_racers == 8)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
                        else if ((uint8_t)nb_AI_racers == 0xc)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 1;
                        else
                            nb_AI_racers = (nb_AI_racers & ~0xff) | (uint8_t)((uint8_t)nb_AI_racers << 1);
                    } else {
                        swrObjHang_splitscreenRacerCount += 2;
                        if (swrObjHang_splitscreenRacerCount == 8)
                            swrObjHang_splitscreenRacerCount = 2;
                    }
                    break;
                case 4:
                    hang->AISpeed++;
                    break;
                case 5:
                    hang->demo_mode = hang->demo_mode == 0;
                    break;
                case 6:
                    hang->unk68_type++;
                    break;
                }
                playUISound(0x58);
            }
            if ((*pressed & swrUI_INPUT_MENU_LEFT) != 0) {
                switch (swrObjHang_courseInfoItemKinds[swrObjHang_courseInfoSelectedRow]) {
                case 0:
                    hang->bMirror = hang->bMirror == 0;
                    break;
                case 1:
                    hang->WinningsID--;
                    break;
                case 2:
                    hang->numLaps--;
                    break;
                case 3:
                    if (hang->num_local_players < 2) {
                        if ((uint8_t)nb_AI_racers == 0xc)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 8;
                        else if ((uint8_t)nb_AI_racers == 1)
                            nb_AI_racers = (nb_AI_racers & ~0xff) | 0xc;
                        else
                            nb_AI_racers = (nb_AI_racers & ~0xff) | (uint8_t)((uint8_t)nb_AI_racers >> 1);
                    } else {
                        swrObjHang_splitscreenRacerCount -= 2;
                        if (swrObjHang_splitscreenRacerCount == 0)
                            swrObjHang_splitscreenRacerCount = 6;
                    }
                    break;
                case 4:
                    hang->AISpeed--;
                    break;
                case 5:
                    hang->demo_mode = hang->demo_mode == 0;
                    break;
                case 6:
                    hang->unk68_type--;
                    break;
                }
                playUISound(0x58);
            }
        }
        // wrap the cycling options
        if (hang->numLaps < 1)
            hang->numLaps = 5;
        if (5 < hang->numLaps)
            hang->numLaps = 1;
        if (hang->AISpeed < 1)
            hang->AISpeed = 3;
        if (3 < hang->AISpeed)
            hang->AISpeed = 1;
        if (hang->WinningsID < 1)
            hang->WinningsID = 3;
        if (3 < hang->WinningsID)
            hang->WinningsID = 1;
        if (hang->unk68_type < -1)
            hang->unk68_type = 0x14;
        if (0x14 < hang->unk68_type)
            hang->unk68_type = -1;

        if (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) {
            g_LoadTrackModel = g_aTrackInfos[(int)hang->track_index].trackID;
            swrMultiplayer_BroadcastPlayerState();
        }
    }
}

// 0x0043d720
void swrRace_UpdatePartsHealth(void)
{
    HANG("TODO");
}

// 0x0043d970
void swrRace_ResetAllProfiles(void)
{
    int i;

    for (i = 0; i < 20; i++)
        swrRace_GenerateDefaultDataSAV(0, i);
    for (i = 0; i < 4; i++)
        swrRace_GenerateDefaultDataSAV(1, i);
}

// 0x0043d9a0
void swrRace_CheatUnlockAll(void)
{
    if (swrRace_cheatUnlockAllDone == 0) {
        swrText_ShowTimedMessage("All Pods, tracks unlocked!!!", 3.0f);
        if (swrRace_cheatUnlockAllDone == 0) {
            swrRace_cheatUnlockAllDone = 1;
            swrRace_saveData.unlockFlags |= swrSaveData_UNLOCK_BEAT_ALL_TRACKS_FIRST;
            g_aBeatTracksGlobal[3] = 0xf;
            swrRace_saveData.pilotsUnlockedGlobal = 0xfffffff;
            swrRace_aProfiles[0].pilotsUnlocked = 0xfffffff;
            swrRace_saveData.profiles[0].pilotsUnlocked = 0xfffffff;
            g_aBeatTracksGlobal[0] = 0xff;
            g_aBeatTracksGlobal[1] = 0xff;
            g_aBeatTracksGlobal[2] = 0xff;
            swrRace_SaveCurrentProfile();
        }
    }
}

// 0x0043ea00
void swrRace_GenerateDefaultDataSAV(int user_tgfd, int slot)
{
    swrSaveProfile* profile;
    int i;

    if (user_tgfd == 0)
        profile = &swrRace_aProfiles[slot];
    else if (user_tgfd == 1)
        profile = &swrRace_saveData.profiles[slot];
    else
        return;

    profile->unk20 = 0;
    profile->truguts = ELFSAVE_DEFAULT_TRUGUTS;
    profile->nbPitDroids = 1;
    profile->unk23 = 0;
    profile->pilotsUnlocked = ELFSAVE_DEFAULT_PILOTS;
    profile->unk3c = 0;
    profile->linkedToSave = 1;
    profile->pilotId = 0;
    profile->saveSlot = (uint8_t)slot;
    profile->beatTrackPlace[0] = 0;
    profile->beatTrackPlace[1] = 0;
    profile->beatTrackPlace[2] = 0;
    profile->beatTrackPlace[3] = 0;
    profile->tracksUnlocked[0] = 1;
    profile->tracksUnlocked[1] = 1;
    profile->tracksUnlocked[2] = 1;
    profile->circuitsCompleted = 0;
    for (i = 0; i < 7; i++) {
        profile->upgradeLevels[i] = 0;
        profile->upgradeHealths[i] = -1;
    }
    memset(profile->name, 0, sizeof(profile->name));
    if (user_tgfd == 1)
        profile->unk4f = 0;
}

// 0x0043f380
void swrRace_BuyPitdroidsMenu(swrObjHang* hang)
{
    HANG("TODO");
}

// 0x0043fe90
void swrRace_DrawScrollbar(short x, short y, int height)
{
    HANG("TODO");
}

// Sets up the global ray-collision query state from `ray` (= {origin.xyz, dir.xyz, maxDist}),
// installs the per-face callbacks, resets the matrix stack, then recursively ray-tests the model's
// node tree (CollideNodeRecursiveRay, which latches the closest hit into the query globals). On a hit
// (closest <= maxDist) it fills outHit/outNormal and returns the hit distance; -1.0 on a miss. The hit
// node is published to swrRace_collisionHitNode.
// 0x00444d10
float swrRace_RaycastModel(swrModel_Node* model, float* ray, rdVector3* outHit, rdVector3* outNormal)
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

// 0x0044afb0
void swrRace_GetEngineNodeOffsetPos_Maybe(void** nodePair, rdVector3* outPos)
{
    if (nodePair == NULL) {
        rdVector_Set3(outPos, 0.0f, 0.0f, 0.0f);
        return;
    }
    swrModel_NodeTransformed* node = (swrModel_NodeTransformed*) nodePair[0];
    swrModel_NodeTransformed* offsetNode = (swrModel_NodeTransformed*) nodePair[1];
    if (node == NULL) {
        rdVector_Set3(outPos, 0.0f, 0.0f, 0.0f);
        return;
    }
    rdMatrix44 nodeMat;
    swrModel_NodeGetTransform(node, &nodeMat);
    outPos->x = nodeMat.vD.x;
    outPos->y = nodeMat.vD.y;
    outPos->z = nodeMat.vD.z;
    if (offsetNode != NULL) {
        rdMatrix44 offsetMat;
        swrModel_NodeGetTransform(offsetNode, &offsetMat);
        // offset the node position along the node's own second axis by the offset node's height
        rdVector_Scale3Add3(outPos, outPos, offsetMat.vD.y, (rdVector3*) &nodeMat.vB);
    }
}

// 0x0044b270
void swrRace_SetEngineNodeTranslation_Maybe(void** nodePair, rdVector3* pos)
{
    if (nodePair == NULL)
        return;
    swrModel_NodeTransformed* node = (swrModel_NodeTransformed*) nodePair[0];
    swrModel_NodeTransformed* offsetNode = (swrModel_NodeTransformed*) nodePair[1];
    if (node == NULL)
        return;

    rdMatrix44 nodeMat;
    swrModel_NodeGetTransform(node, &nodeMat);
    rdMatrix44 out;
    rdMatrix_Copy44(&out, &nodeMat);
    rdVector_Copy3((rdVector3*) &out.vD, pos);
    if (offsetNode == NULL) {
        swrModel_NodeSetTransform(node, &out);
        return;
    }
    rdMatrix44 offsetMat;
    swrModel_NodeGetTransform(offsetNode, &offsetMat);
    // remove the engine-height offset applied by swrRace_GetEngineNodeOffsetPos_Maybe
    rdVector_Scale3Add3((rdVector3*) &out.vD, (rdVector3*) &out.vD, -offsetMat.vD.y, (rdVector3*) &out.vB);
    swrModel_NodeSetTransform(node, &out);
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

// Rebuild the whole save image from scratch: header defaults, per-track record tables
// (3599.99s times, all-'A' holder names, each track's favorite pilot as holder), the 4 saved
// profile slots, and finally the checksum.
// 0x0044e320
void swrRace_InitDefaultGameData(void* saveImage)
{
    swrSaveData* save;
    int track;
    int mirror;
    int idx;
    int i;

    save = (swrSaveData*)saveImage;
    memset(save, 0, sizeof(swrSaveData));
    save->unk4 = 1;
    save->sfxVolume = 225;
    save->musicVolume = 200;
    save->unlockFlags = swrSaveData_UNLOCK_DEFAULT_Maybe;
    swrRace_saveDefaultsUnk = 0;
    swr_noop2();
    save->pilotsUnlockedGlobal = ELFSAVE_DEFAULT_PILOTS;
    save->beatTracksGlobal[0] = 7;
    save->beatTracksGlobal[1] = 3;
    save->beatTracksGlobal[2] = 1;
    save->beatTracksGlobal[3] = 0;
    for (track = 0; track < ELFSAVE_NB_TRACKS; track++) {
        for (mirror = 0; mirror < 2; mirror++) {
            idx = track * 2 + mirror;
            save->record3LapTimes[idx] = ELFSAVE_RECORD_TIME_EMPTY;
            save->recordLapTimes[idx] = ELFSAVE_RECORD_TIME_EMPTY;
            for (i = 0; i < 32; i++) {
                save->record3LapNames[idx][i] = 'A';
                save->recordLapNames[idx][i] = 'A';
            }
            save->record3LapPilots[idx] = g_aTrackInfos[track].FavoritePilot;
            save->recordLapPilots[idx] = g_aTrackInfos[track].FavoritePilot;
        }
    }
    for (i = 0; i < 4; i++)
        swrRace_GenerateDefaultDataSAV(1, i);
    // the original hardcodes the global image here, ignoring saveImage
    swrRace_saveData.checksum = swrRace_ComputeSaveChecksum(&swrRace_saveData);
}

// 0x0044e440
unsigned int swrRace_ComputeSaveChecksum(void* saveImage)
{
    return swrRace_Crc32((char*)saveImage + 4, sizeof(swrSaveData) - 4);
}

// 0x0044e460
unsigned int swrRace_Crc32(void* data, int length)
{
    unsigned char* bytes;
    unsigned int crc;

    if (swrRace_aCrc32Table[1] == 0)
        swrRace_InitCrc32Table();
    crc = 0xffffffff;
    bytes = (unsigned char*)data;
    for (; length > 0; length--) {
        crc = (crc << 8) ^ swrRace_aCrc32Table[(crc >> 24) ^ *bytes];
        bytes++;
    }
    return ~crc;
}

// 0x0044e4a0
void swrRace_InitCrc32Table(void)
{
    unsigned int value;
    int i;
    int bit;

    for (i = 0; i < 256; i++) {
        value = i << 24;
        for (bit = 8; bit != 0; bit--) {
            if ((value & 0x80000000) == 0)
                value = value << 1;
            else
                value = (value << 1) ^ 0x4c11db7;
        }
        swrRace_aCrc32Table[i] = value;
    }
}

// 0x0044e4e0
void swrRace_BackupGameData(void)
{
    swrRace_saveDataBackup = swrRace_saveData;
}

// 0x0044e500
void swrRace_CopyProfileFromSave(int workingSlot, int savedSlot)
{
    swrRace_aProfiles[workingSlot] = swrRace_saveData.profiles[savedSlot];
}

// 0x0044e530
void swrRace_CopyProfileToSave(int savedSlot, int workingSlot)
{
    swrRace_saveData.profiles[savedSlot] = swrRace_aProfiles[workingSlot];
}

// 0x0044e560
void swrRace_SaveCurrentProfile(void)
{
    if (swrRace_aProfiles[0].linkedToSave == 1)
        swrRace_CopyProfileToSave(swrRace_aProfiles[0].saveSlot, 0);
    swrRace_CopyProfileToSave(0, 0);
    swrRace_SaveGameData();
    swrRace_SaveProfile(swrRace_saveData.profiles[0].name);
}

// 0x0044e5a0
void swrRace_GetProfileRecordVec3_Maybe(int base, int index, float* out3)
{
    float* rec;

    rec = (float*)(*(int*)(base + 0xc) + index * 0x54 + 0x10);
    out3[0] = rec[0];
    out3[1] = rec[1];
    out3[2] = rec[2];
}

// 0x004550d0
void swrRace_VehicleStatisticsSubMenu(void* param_1, float param_2, float param_3)
{
    HANG("TODO");
}

// In-race HUD for one local racer: HUD frame sprites, speed readout, the lap-time popup shown
// for ~4s after each lap (with flickering color, "New Record" blink vs the session-best lap, the
// fanfare guard flag, and the FINAL LAP banner), the running TIME display when no lap popup is
// up, the LAP x/y and POS counters, and the speed dial.
// 0x00460950
void swrRace_InRaceTimer(swrScore* score, swrObjJdge* jdge)
{
    swrRace* pod;
    char* text;
    float x;
    float y;
    float speed;
    float lastLapTime;
    float fade;
    float flicker;
    int numLocal;
    int isPlayer2;
    int dialY;
    int lap;
    int lapShown;
    int colR;
    int colG;
    int colB;
    int alpha;
    int lapTimeShown;
    int blinkLapCounter;
    char buffer[256];

    dialY = 0xa4;
    numLocal = NumLocalPlayers();
    pod = score->obj_test_ptr;
    isPlayer2 = (score == secondLocalPlayer) ? 1 : 0;
    if (GetPauseState() == 0) {
        pod->unk2b8_timer -= (float)swrRace_deltaTimeSecs;
        if (pod->unk2b8_timer < 0.0f)
            pod->unk2b8_timer = 0.0f;
    }
    swrObjJdge_LayoutHudFrameSprites_Maybe(jdge->hud_mode == swrObjJdge_HUDMODE_PROGRESS_RING
                                               ? 5
                                               : (jdge->hud_mode == swrObjJdge_HUDMODE_GAP_ARROWS ? 2 : 0));

    // speed readout
    x = 254.0f;
    y = 190.0f;
    if (numLocal == 2) {
        x = 277.0f;
        y = (float)(isPlayer2 * 0x6e + 0x60);
    }
    speed = pod->speedValue;
    if (speed <= 0.0f)
        speed = 0.0f;
    text = swrText_Translate("~f2~c~s%.0f");
    sprintf(buffer, text, (double)speed);
    swrText_CreateTextEntry1((int)x, (int)y, 0, -0x3d, -2, -2, buffer);

    // lap-time popup panel position (the progress ring occupies the default spot)
    if (jdge->hud_mode == swrObjJdge_HUDMODE_PROGRESS_RING) {
        x = 240.0f;
        y = 30.0f;
    } else {
        x = 160.0f;
        y = 23.0f;
        if (numLocal == 2)
            y = (float)(isPlayer2 * 0x6e + 0x14);
    }
    lap = score->results_P1_Lap;
    lapTimeShown = 0;
    blinkLapCounter = 0;
    if (0 < lap) {
        lastLapTime = (&score->results_P1_Lap1)[lap - 1];
        // the popup fades out over the first 4 seconds of the new lap
        fade = 1.0f - (&score->results_P1_Lap1)[lap] * 0.25f;
        if (fade <= 0.0f || 1.0f <= fade) {
            // popup window over: release the fanfare guard once the sfx cooldown lapses
            if (swrSound_TestSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE) != 0 &&
                swrSound_IsSfxOnCooldown(6, 0) == 0)
                swrSound_ClearSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE);
        } else {
            flicker = 223.25f;
            if (pauseState == 0)
                flicker = (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f;
            colR = (int)flicker;
            colG = (int)((float)colR * 0.5f);
            alpha = (int)(fade * 255.0f) * 8;
            if (255 < alpha)
                alpha = 255;
            text = swrText_Translate("~f3~c~s");
            swrText_CreateTimeEntry((int)x, (int)y, lastLapTime, colR, colG, 0x40, alpha, text);
            text = swrText_Translate("/SCREENTEXT_420/~c~sLAP TIME");
            swrText_CreateTextEntry1((int)x, (int)y + 17, colR, colG, 0x40, alpha, text);
            if (lastLapTime <= jdge->best_lap_time_ms && ((int)(fade * 16.0f) & 1) != 0) {
                // this lap tied/beat the session best: blinking "New Record" + one fanfare
                text = swrText_Translate("/SCREENTEXT_538/~s~cNew Record");
                swrText_CreateTextEntry1((int)x, (int)y + 25, -0x38, -1, 0, alpha, text);
                if (swrSound_TestSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE) == 0) {
                    swrSound_PlaySfxThrottled(6, 0, 0x27, NULL);
                    swrSound_SetSfxFlag((char)score->sfxChannel, swrSound_SFXFLAG_LAP_FANFARE);
                }
            }
            lapTimeShown = 1;
            if (lap + 1 == jdge->num_laps) {
                if (numLocalPlayers < 2) {
                    // FINAL LAP banner, fading in over the second half of the popup window
                    fade = (fade - 0.5f) * 2.0f;
                    if (0.0f < fade) {
                        alpha = (int)(fade * 255.0f) * 4;
                        if (255 < alpha)
                            alpha = 255;
                        colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 255.0f : 191.25f);
                        text = swrText_Translate("/SCREENTEXT_526/~f6~s~cFINAL LAP");
                        swrText_CreateTextEntry1(0xa0, 0x46, colR, colG, colB, alpha, text);
                    }
                } else {
                    // splitscreen has no room for the banner: blink the LAP counter instead
                    blinkLapCounter = ((int)(fade * 36.0f) & 1) != 0;
                }
            }
        }
    }
    if (lapTimeShown == 0 && numLocal < 2) {
        // no lap popup: show the running total race time
        swrRace_hudTimeLabelShown = 0;
        text = swrText_Translate("~f3~c~s");
        swrText_CreateTimeEntry((int)x, (int)y, score->results_P1_total_time, -1, -1, -1, -0x42, text);
        text = swrText_Translate("/SCREENTEXT_422/~c~sTIME");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, -1, -1, -0x42, text);
    }
    if (jdge->hud_mode == swrObjJdge_HUDMODE_SPLIT_OFF || jdge->hud_mode == swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME)
        swrText_CreateTimeEntry(0x121, (int)y, score->results_P1_total_time, -1, -1, -1, -0x42, "~f3~r~s");

    // LAP x/y counter
    x = 62.0f;
    if (jdge->hud_mode != swrObjJdge_HUDMODE_PROGRESS_RING)
        x = 42.0f;
    lapShown = lap + 1;
    if (jdge->num_laps < lapShown)
        lapShown = jdge->num_laps;
    text = swrText_Translate("~f3~c~s%d/%d");
    sprintf(buffer, text, lapShown, jdge->num_laps);
    if (numLocalPlayers < 2 || blinkLapCounter == 0) {
        swrText_CreateTextEntry1((int)x, (int)y, -1, -1, -1, -0x42, buffer);
        text = swrText_Translate("/SCREENTEXT_424/~c~sLAP");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, -1, -1, -0x42, text);
    } else {
        swrText_CreateTextEntry1((int)x, (int)y, -1, 0x3f, 0x3f, -1, buffer);
        text = swrText_Translate("/SCREENTEXT_424/~c~sLAP");
        swrText_CreateTextEntry1((int)x, (int)y + 17, -1, 0x3f, 0x3f, -1, text);
    }

    // POS x/y counter (hidden in hud modes 1/6/7)
    if (jdge->hud_mode != swrObjJdge_HUDMODE_PROGRESS_RING && jdge->hud_mode != swrObjJdge_HUDMODE_SPLIT_OFF &&
        jdge->hud_mode != swrObjJdge_HUDMODE_SPLIT_COLUMN_TIME) {
        if (0 < (short)score->results_P1_Position) {
            text = swrText_Translate("~f3~c~s%d/%d");
            sprintf(buffer, text, (int)(short)score->results_P1_Position, jdge->num_players);
            swrText_CreateTextEntry1(0x116, (int)y, -1, -1, -1, -0x42, buffer);
        }
        text = swrText_Translate("/SCREENTEXT_426/~c~sPOS");
        swrText_CreateTextEntry1(0x116, (int)y + 17, -1, -1, -1, -0x42, text);
    }

    if (1 < numLocalPlayers && isPlayer2 == 0)
        dialY = 0x36;
    swrObjJdge_DrawSpeedDialHud_Maybe((int)jdge, (int)pod, 0xe1, (short)dialY, isPlayer2);
    if (swrRace_DebugLevel != 0 && assetBufferOverflow != 0)
        swrText_CreateTextEntry1(0xa0, 0x14, -1, 0, 0, -1, "~c~oZOT");
}

// 0x004611f0
void swrRace_InRaceEngineUI(void* param_1, int param_2)
{
    HANG("TODO");
}

// Post-race statistics panel for one local racer: per-lap time rows (the session-best lap
// flickers), the Total row, and the finishing-place text with the 1st/2nd/3rd medal sprite
// sliding in against jdge->raceTimer_ms. Also the only writer of jdge->recordLap3_ms: the
// session-best race total is latched here, in the draw pass, when the shown total beats it.
// 0x00462320
void swrRace_InRaceEndStatistics(swrObjJdge* jdge, swrScore* score)
{
    char* text;
    float total;
    float lapTime;
    int numLocal;
    int x;
    int rowY;
    int placeY;
    int textY;
    int colR;
    int colG;
    int colB;
    int i;
    short pos;
    short spriteX;
    char buf[32];

    numLocal = NumLocalPlayers();
    if (numLocal == 2) {
        if (score == firstLocalPlayer) {
            rowY = 0x69;
            placeY = 0x1e;
            for (i = 0xf; i < 0x13; i++)
                swrSprite_SetVisible((short)i, 0);
        } else {
            rowY = 0xd7;
            placeY = 0x8c;
            for (i = 0x13; i < 0x17; i++)
                swrSprite_SetVisible((short)i, 0);
        }
    } else {
        for (i = 0; i < 0x13; i++)
            swrSprite_SetVisible((short)i, 0);
        rowY = 0xd7;
        placeY = 0x37;
    }
    rowY -= jdge->num_laps * 0xe;

    // time-column x scales with the total's digit count
    total = score->results_P1_total_time;
    if (total < 60.0f)
        x = 0x5b;
    else if (total < 600.0f)
        x = 0x69;
    else if (total < 6000.0f)
        x = 0x73;
    else if (total < 60000.0f)
        x = 0x7d;
    else
        x = 0x87;

    for (i = 0; i < jdge->num_laps; i++) {
        lapTime = (&score->results_P1_Lap1)[i];
        text = swrText_Translate("/SCREENTEXT_211/~sLap");
        sprintf(buf, "~f4%s", text);
        swrText_CreateTextEntry1(0x19, rowY + 1, -1, -1, 0, -1, buf);
        sprintf(buf, "~s%d", i + 1);
        swrText_CreateTextEntry1(0x2d, rowY, -1, -1, 0, -1, buf);
        if (jdge->best_lap_time_ms < lapTime) {
            colR = 0xff;
            colG = 0x80;
        } else {
            // this row is the session-best lap: flicker it
            if (pauseState == 0)
                colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f);
            else
                colR = (int)223.25f;
            colG = colR - 0x14;
        }
        swrText_CreateTimeEntry(x, rowY - 3, lapTime, colR, colG, 0, -1, "~f1~r~s");
        rowY += 0xe;
    }

    if (jdge->recordLap3_ms < total) {
        colR = 0x32;
        colG = 0xff;
        colB = 5;
    } else {
        // new session-best race total: latch it and flicker the row
        jdge->recordLap3_ms = total;
        if (pauseState == 0)
            colR = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 26.0f + 24.0f);
        else
            colR = (int)43.5f;
        if (pauseState == 0)
            colG = (int)((float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f);
        else
            colG = (int)223.25f;
        colB = 0;
    }
    text = swrText_Translate("/SCREENTEXT_534/~sTotal: ");
    sprintf(buf, "~f4%s", text);
    swrText_CreateTextEntry1(0x19, rowY + 1, -0x10, -1, 0, -1, buf);
    swrText_CreateTimeEntry(x, rowY - 3, total, colR, colG, colB, -1, "~f1~r~s");

    if (numLocalPlayers < 2) {
        if (jdge->num_players < 2)
            return;
        if (8.0f < jdge->raceTimer_ms) {
            swrSprite_SetVisible(0xa4, 0);
            swrSprite_SetVisible(0xa5, 0);
            swrSprite_SetVisible(0xa6, 0);
            return;
        }
        // finishing-place banner slides in over the first half second and back out after 7.5s
        x = 0xa0;
        if (jdge->raceTimer_ms < 0.5f)
            x = (int)(160.0f - (0.5f - jdge->raceTimer_ms) * 380.0f);
        if (7.5f < jdge->raceTimer_ms)
            x = (int)((float)x + (jdge->raceTimer_ms - 7.5f) * 380.0f);
        textY = placeY;
        pos = (short)score->results_P1_Position;
        if (pos < 4) {
            x -= 0x14;
            textY = placeY + 0x14;
            swrSprite_AddDirtyRect(-x + 0x12f, placeY - 0xd, -x + 0x151, placeY + 0x35);
            spriteX = (short)(0x140 - x);
            if (pos == 1) {
                swrSprite_SetVisible(0xa4, 1);
                swrSprite_SetPos(0xa4, spriteX, (short)placeY);
            }
            if (pos == 2) {
                swrSprite_SetVisible(0xa5, 1);
                swrSprite_SetPos(0xa5, spriteX, (short)placeY);
            }
            if (pos == 3) {
                swrSprite_SetVisible(0xa6, 1);
                swrSprite_SetPos(0xa6, spriteX, (short)placeY);
            }
        }
        if (pos == 1)
            text = "/SCREENTEXT_427/~sst";
        else if (pos == 2)
            text = "/SCREENTEXT_428/~snd";
        else if (pos == 3)
            text = "/SCREENTEXT_429/~srd";
        else
            text = "/SCREENTEXT_430/~sth";
        text = swrText_Translate(text);
        colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
        sprintf(buf, "~f2~r~s%d", (int)pos);
        swrText_CreateTextEntry1(x, textY, colR, colG, colB, -2, buf);
        swrText_CreateTextEntry1(x + 1, textY, colR, colG, colB, -2, text);
        return;
    }

    // splitscreen: fixed-position place text, no medal sprite
    pos = (short)score->results_P1_Position;
    if (pos == 1)
        text = "/SCREENTEXT_427/~sst";
    else if (pos == 2)
        text = "/SCREENTEXT_428/~snd";
    else if (pos == 3)
        text = "/SCREENTEXT_429/~srd";
    else
        text = "/SCREENTEXT_430/~sth";
    text = swrText_Translate(text);
    colR = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    colG = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    colB = (int)(pauseState == 0 ? (float)swrUtils_Rand() * (1.0f / 2147483648.0f) * 127.0f + 128.0f : 223.25f);
    sprintf(buf, "~f2~r~s%d", (int)pos);
    swrText_CreateTextEntry1(0xa0, placeY, colR, colG, colB, -2, buf);
    swrText_CreateTextEntry1(0xa1, placeY, colR, colG, colB, -2, text);
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

// Per-frame "brain" for one AI racer. It never touches the flight model directly;
// it only computes a per-racer speed multiplier (aiSpeedTarget, smoothed into
// paceMultiplier) and a cross-track steer target (aiSteerTarget). The smoothed
// multiplier is copied into speedMultiplier by swrRace_UpdateCatchup and scales the
// pod in swrRace_UpdateSpeed. The two tuning inputs are the globals swrRace_AILevel
// (track base level * AI Speed setting) and ai_spread, both set in InitAISettingsForTrack.
// 0x0046b670
void swrRace_AI(int player)
{
    swrRace* p = (swrRace*) player;

    // Start from the track/difficulty-wide base level.
    p->aiSpeedTarget = swrRace_AILevel;

    if ((p->flags1 & swrObjTest_FLAG1_FINISHED) != 0) {
        // Finished / parked: coast at a fixed 0.65x and wind the AI look-ahead down to 75^2.
        p->aiSpeedTarget = 0.65f;
        p->podStats.turnResponse = 1500.0f;
        p->podStats.maxTurnRate = 400.0f;
        if (p->aiLookAheadDistSq <= 5625.0f) {
            p->aiLookAheadDistSq = 5625.0f;
        } else {
            p->aiLookAheadDistSq -= (float) (swrRace_deltaTimeSecs * 100.0);
        }
    } else {
        // Normalize the tuning by track length so the feel is consistent across courses.
        float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
        float spreadScaled = ai_spread * 0.0001f;
        float spreadBand = spreadScaled * invTrackLen;

        if ((p->flags0 & swrObjTest_FLAG0_AI_SIMPLE) != 0) {
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
                if (spreadBand * 0.25f < p->aiLineOffset && (p->flags0 & (swrObjTest_FLAG0_AI_RIVAL_AHEAD | swrObjTest_FLAG0_AI_RIVAL_BEHIND)) != 0) {
                    float gap = (p->flags0 & swrObjTest_FLAG0_AI_RIVAL_AHEAD) != 0 ? p->rivalGapAhead : p->rivalGapBehind;
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
    if (p->paceMultiplier < p->aiSpeedTarget) {
        p->paceMultiplier += (float) (swrRace_deltaTimeSecs * 0.2);
        if (p->aiSpeedTarget < p->paceMultiplier) {
            p->paceMultiplier = p->aiSpeedTarget;
        }
    } else if (p->aiSpeedTarget < p->paceMultiplier) {
        p->paceMultiplier -= (float) (swrRace_deltaTimeSecs * 0.2);
        if (p->aiSpeedTarget > p->paceMultiplier) {
            p->paceMultiplier = p->aiSpeedTarget;
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

    if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 || *(int*) &score->unkc == 0) {
        if ((player->flags0 & swrObjTest_FLAG0_AI) != 0) {
            swrRace_AI((int) player);
        } else {
            player->paceMultiplier = 1.0f;
        }
    } else {
        player->paceMultiplier = 1.0f;
        if (1 < NumLocalPlayers() && 0.0f < player->rivalGapAhead) {
            float invTrackLen = 500000.0f / swrSpline_GetTrackLength();
            float boost = (player->rivalGapAhead * 100.0f) / invTrackLen + 1.0f;
            player->paceMultiplier = boost;
            if (1.25f < boost) {
                player->paceMultiplier = 1.25f;
            }
        }
    }
    player->speedMultiplier = player->paceMultiplier;
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
    if ((p->flags0 & (swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 || (p->flags1 & swrObjTest_FLAG1_FINISHED) != 0) {
        return;
    }

    p->flags0 &= ~swrObjTest_FLAG0_BOOSTING; // taking damage cancels an active boost
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

    if (((test->flags0 & swrObjTest_FLAG0_ZON) != 0) && (test->speedValue < 75.0f))
        iceTarget = 75.0f - test->speedValue;

    test->flags1 = test->flags1 & ~(swrObjTest_FLAG1_ON_SWAMP | swrObjTest_FLAG1_ON_SIDE | swrObjTest_FLAG1_ON_MIRR | swrObjTest_FLAG1_FULL_RAYCAST | swrObjTest_FLAG1_MAGNET | swrObjTest_FLAG1_ON_LAVA | swrObjTest_FLAG1_ON_FALL | swrObjTest_FLAG1_ON_SOFT | swrObjTest_FLAG1_ON_FLAT);

    swrModel_Behavior* behavior = NULL;
    if (test->terrainModel != NULL)
        behavior = swrModel_MeshGetBehavior((swrModel_Mesh*) test->terrainModel);

    if (behavior != NULL) {
        uint32_t toggles = test->collisionToggles & ~behavior->unk20;
        test->collisionToggles = (((behavior->unk21 >> 8) | (toggles >> 8)) & 0xFFFFFF) << 8;

        if ((behavior->unk1 & 0x10) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_FULL_RAYCAST;
        if ((behavior->unk1 & 0x20) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_MAGNET;// surface-relative "magnet" gravity
        if ((behavior->vehicle_reaction & swrVehicleReaction_Lava) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_LAVA;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Fall) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_FALL;
        if (((behavior->vehicle_reaction & swrVehicleReaction_Flat) != 0) && ((test->flags0 & swrObjTest_FLAG0_AI) != 0) &&
            ((test->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0))
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_FLAT;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Soft) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SOFT;

        // debug hotkey: toggle the zero-g flag while held
        if (((swrRace_DebugFlag & 0x2000) != 0) && ((inRaceLocalPlayerInputBitset1[0] & 0x100) != 0) &&
            (((uint8_t) inRaceLocalPlayerInputBitset3[0] & 0x80) != 0))
            test->flags0 = test->flags0 ^ swrObjTest_FLAG0_ZON;

        if ((behavior->vehicle_reaction & swrVehicleReaction_ZOn) != 0)
            test->flags0 = test->flags0 | swrObjTest_FLAG0_ZON;
        if (((behavior->vehicle_reaction & swrVehicleReaction_ZOff) != 0) && ((test->flags0 & swrObjTest_FLAG0_ZON) != 0)) {
            // entering zero-g/orbit: seed velocityDir from the last move, clear the slide
            test->velocityDir.x = test->transform.vD.x - test->positionPrev.x;
            test->velocityDir.y = test->transform.vD.y - test->positionPrev.y;
            test->velocityDir.z = test->transform.vD.z - test->positionPrev.z;
            test->unk10_3 = 0x40400000;// 3.0f
            test->velocitySlope.x = 0.0;
            test->velocitySlope.y = 0.0;
            test->velocitySlope.z = 0.0;
            test->flags0 = (test->flags0 & ~swrObjTest_FLAG0_ZON) | swrObjTest_FLAG0_ZOFF;
        }

        if ((behavior->vehicle_reaction & swrVehicleReaction_Fast) != 0)
            iceTarget = 200.0f;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Slow) != 0) {
            terrainTractionTarget = 0.75f;
            if ((test->flags0 & swrObjTest_FLAG0_ZON) != 0)
                test->flags0 = test->flags0 & ~swrObjTest_FLAG0_BOOSTING;
        }
        if ((behavior->vehicle_reaction & swrVehicleReaction_Swst) != 0) {
            terrainTractionTarget = 0.1f;
            test->flags0 = test->flags0 & ~swrObjTest_FLAG0_BOOSTING;
        }
        if ((behavior->vehicle_reaction & swrVehicleReaction_Slip) != 0)
            terrainSkidTarget = 0.2f;
        if ((test->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
            terrainSkidTarget = 1.0f;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Swmp) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SWAMP;
        if (behavior->triggers != NULL)
            swrRace_ActivateTriggersInRange(test, behavior->triggers);
        if (((behavior->vehicle_reaction & swrVehicleReaction_Mirr) != 0) && (swrConfig_VIDEO_REFLECTIONS == 1))
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_MIRR;
        if ((behavior->vehicle_reaction & swrVehicleReaction_Side) != 0)
            test->flags1 = test->flags1 | swrObjTest_FLAG1_ON_SIDE;
    }

    if (specialActiveTrigger != NULL)
        swrRace_ActivateTriggersInRange(test, specialActiveTrigger);

    swrRace_easeTraction(&test->surfaceSpeedBonus, iceTarget, 25.0);
    swrRace_easeTraction(&test->surfaceSpeedFactor, terrainTractionTarget, 0.5);
    swrRace_easeTraction(&test->surfaceGripFactor, terrainSkidTarget, 0.5);

    test->unk11_1 = 0;
    if (((((float) test->lodDistance - 400.0f) * 0.0016666667f < 1.0f) || ((test->flags0 & swrObjTest_FLAG0_LOCAL) != 0) ||
         ((test->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) &&
        (((test->flags1 & swrObjTest_FLAG1_ON_FALL) != 0) && ((test->flags1 & swrObjTest_FLAG1_AIRBORNE) == 0)))
        test->flags0 = test->flags0 | swrObjTest_FLAG0_RESPAWN;
}

// 0x004774f0
void swrRace_ApplyGravity(swrRace* player, float* a, float b)
{
    // Down direction: surface-relative on walls/tubes (flags1 0x400), else the world vector.
    float gx, gy, gz;
    uint32_t flags1 = player->flags1;
    if ((flags1 & swrObjTest_FLAG1_MAGNET) == 0)
    {
        gx = player->world_gravity.x;
        gy = player->world_gravity.y;
        gz = player->world_gravity.z;
    }
    else
    {
        gx = -player->up.x;
        gy = -player->up.y;
        gz = -player->up.z;
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
            player->flags0 |= swrObjTest_FLAG0_RESPAWN;
    }

    // Airborne flag once high enough off the ground.
    if (b <= 30.0f)
        flags1 &= ~swrObjTest_FLAG1_AIRBORNE;
    else
        flags1 |= swrObjTest_FLAG1_AIRBORNE;
    player->flags1 = flags1;

    // Integrate the vertical-velocity accumulator (fallVelocity).
    if (groundDist <= 12.0f)
    {
        player->fallVelocity += (1.0f - (12.0f - groundDist) / (12.0f - hoverDelta)) * swrRace_deltaTimeSecs;
        if (hoverDelta < groundDist && player->fallVelocity < 0.0f)
            player->fallVelocity *= stdMath_Decelerator(4.0f, swrRace_deltaTimeSecs);
    }
    else if (player->speedValue < 0.0f)
    {
        player->fallVelocity += swrRace_deltaTimeSecs * 2.0;   // stored constant is the double -2.0, applied as a subtract
    }
    else
    {
        player->fallVelocity += swrRace_deltaTimeSecs;
    }

    // fallStep = dt * gravityScale * fallVelocity * 30. Negative pitch scales the fall step DOWN by
    // (1 + 0.9*pitch), i.e. reduces the descent (glide) -- this is a reduction, not a boost.
    float fallStep = swrRace_deltaTimeSecs * player->gravityScale * player->fallVelocity * 30.0f;
    player->fallStep = fallStep;
    if (player->pitch < 0.0f && 0.0f <= player->speedValue && 0.0f < fallStep)
        player->fallStep = (player->pitch * 0.9f + 1.0f) * fallStep;

    // Clamp the fall to the ground; on a hard landing dispatch the "HitBotm" event.
    if (player->fallStep <= groundDist)
    {
        player->flags0 &= ~swrObjTest_FLAG0_HIT_BOTTOM;
    }
    else
    {
        float impactRate = player->fallStep;
        float bounceMag = player->fallVelocity * 8.0f;
        player->fallStep = groundDist;
        if (0.0f < player->fallVelocity)
            player->fallVelocity = -(player->fallVelocity * 0.2f);
        if (4.0f < bounceMag && (player->flags0 & swrObjTest_FLAG0_HIT_BOTTOM) == 0)
        {
            int subEvents[3];
            subEvents[0] = 0x48697474; // 'Hitt'
            subEvents[1] = 0x426f746d; // 'Botm'
            *(float*)&subEvents[2] = (impactRate / swrRace_deltaTimeSecs) * 0.5f;
            swrEvent_DispatchSubEvents(player, subEvents);
        }
        player->flags0 |= swrObjTest_FLAG0_HIT_BOTTOM;
    }

    // Apply the fall along the down direction.
    a[0] += player->fallStep * gx;
    a[1] += player->fallStep * gy;
    a[2] += player->fallStep * gz;
}

// Normal-mode slope steering (no magnet). Projects world gravity (world_gravity) onto the surface plane
// to accumulate the downhill slide into velocitySlope (force quadratic in the steer term), and drives
// autoTilt (auto-tilt) from the downhill/facing alignment. Also publishes the slope angle to
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

    float dotND = normal->x * player->world_gravity.x + normal->y * player->world_gravity.y +
                  normal->z * player->world_gravity.z;
    if ((dotND < -0.995) || (0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, 0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->autoTilt = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->world_gravity);
    rdVector_Cross3(out1, normal, &downhillAxis);
    rdVector_Normalize3Acc(out1);// out1 = normalized downhill gradient on the surface
    float slopeSin = out1->x * player->world_gravity.x + out1->y * player->world_gravity.y +
                     out1->z * player->world_gravity.z;
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
        player->autoTilt = t * t * tiltScale * 600.0f;
        return;
    }
    player->autoTilt = 0.0;
}

// Magnet-mode slope steering (flags1 0x400): keeps the pod glued to a tagged surface. Same gravity-on-
// surface velocitySlope build as the normal version but with a much stronger, speed-tiered steer term,
// and the auto-tilt (autoTilt) aligns the pod's facing to the downhill direction. Same near-flat /
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

    float dotND = normal->x * player->world_gravity.x + normal->y * player->world_gravity.y +
                  normal->z * player->world_gravity.z;
    if ((dotND < -0.995) || (0.995 < dotND)) {
        rdVector_Set3(out1, 0.0, 0.0, 0.0);
        rdVector_Scale3(&player->velocitySlope, 0.9f, &player->velocitySlope);
        rdVector_Copy3(out2, &player->velocitySlope);
        player->autoTilt = 0.0;
        return;
    }

    rdVector_Cross3(&downhillAxis, normal, &player->world_gravity);
    rdVector_Normalize3Acc(&downhillAxis);
    rdVector_Cross3(out1, normal, &downhillAxis);// out1 = downhill gradient on the surface
    float slopeSin = out1->x * player->world_gravity.x + out1->y * player->world_gravity.y +
                     out1->z * player->world_gravity.z;
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
            player->autoTilt = -(a * slopeSin);
        else
            player->autoTilt = -(-a * slopeSin);
    } else {
        player->autoTilt = 0.0;
    }
}

// Casts a ray "down" (world world_gravity, or -up in magnet mode, started 2 units up) to find the
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

    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0) {
        down = player->world_gravity;
    } else {
        down.x = -player->up.x;
        down.y = -player->up.y;
        down.z = -player->up.z;
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
    if ((player->flags1 & swrObjTest_FLAG1_FULL_RAYCAST) == 0)
        hitDist = swrModel_CollideRayWithMesh((swrModel_Mesh*) player->unkec_node, ray,
                                              (float*) &outPoint, (float*) &outNormal);
    else
        hitDist = -1.0f;

    if (hitDist < 0.0)
        hitDist = swrRace_RaycastModel(player->model_unk, ray, &outPoint, &outNormal);

    if (((player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) && (hitDist < 0.0)) {
        // surface-relative cast missed: retry straight down (world gravity)
        ray[3] = player->world_gravity.x;
        ray[4] = player->world_gravity.y;
        ray[5] = player->world_gravity.z;
        hitDist = swrRace_RaycastModel(player->model_unk, ray, &outPoint, &outNormal);
    }

    player->terrainModel = swrRace_GetCollisionHit();

    if (hitDist < 0.0) {
        ((float*) outSurfaceNormal)[0] = 0.0;
        ((float*) outSurfaceNormal)[1] = 0.0;
        ((float*) outSurfaceNormal)[2] = 1.0;
        player->groundZ = -10000.0f;
        return 100000.0f;
    }

    ((float*) outSurfaceNormal)[0] = outNormal.x;
    ((float*) outSurfaceNormal)[1] = outNormal.y;
    ((float*) outSurfaceNormal)[2] = outNormal.z;
    player->groundZ = outPoint.z;
    return hitDist - 2.0f;
}

// Per-frame ground-contact orchestrator. Raycasts the ground (RaycastGround) to get the surface
// normal, stores it as the pod's "up" in up, runs slope steering (magnet variant when flags1
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

    const float progress = ((float) player->lodDistance - 400.0f) * 0.0016666667f;
    if ((progress < 1.0f) || ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) || ((player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) {
        uint32_t flags1;
        if (((player->flags1 & swrObjTest_FLAG1_FLAT_CACHE) == 0) || ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) == 0)) {
            groundDist = swrRace_RaycastGround(player, (rdVector3*) velocity, (int*) up);
            flags1 = player->flags1;
            if ((flags1 & swrObjTest_FLAG1_ON_FLAT) == 0)
                flags1 = flags1 & ~swrObjTest_FLAG1_FLAT_CACHE;
            else
                flags1 = flags1 | swrObjTest_FLAG1_FLAT_CACHE;
        } else {
            groundDist = velocity[2] - player->groundZ;
            up->x = player->up.x;
            up->y = player->up.y;
            up->z = player->up.z;
            player->terrainModel = player->unkec_node;
            flags1 = player->flags1 | swrObjTest_FLAG1_GROUND_CACHED;
        }
        player->flags1 = flags1;

        // surface-relative magnet mode: keep the "up" normal from tipping past ~horizontal/inverted
        if (((flags1 & swrObjTest_FLAG1_MAGNET) != 0) && (up->z < 0.05f)) {
            up->z = 0.05f;
            rdVector_Normalize3Acc(up);
        }
        player->up.x = up->x;
        player->up.y = up->y;
        player->up.z = up->z;

        if (((player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0) &&
            ((0.1f < player->throttle) || (0.1f < -player->throttle) ||
             ((player->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) == 0))) {
            if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0)
                swrRace_ApplySlopeSteering(player, (int) velocity, scrapeData, groundDist, up, &slopeOut1,
                                           &slopeOut2);
            else
                swrRace_ApplySlopeSteeringMagnet(player, (int) velocity, scrapeData, groundDist, up,
                                                 &slopeOut1, &slopeOut2);
        }

        if ((player->flags0 & swrObjTest_FLAG0_ZOFF) == 0)
            swrRace_ApplyGravity(player, velocity, groundDist);

        if (groundDist < 0.0)
            groundDist = 2.0f;

        if ((((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) && ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0) &&
            (0.0f <= progress && progress <= 1.0f)) {
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
            velocity[2] = progress * (splineMat.vD.z - velocity[2]) + velocity[2];
        }

        if ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) == 0) {
            if ((player->flags0 & swrObjTest_FLAG0_LOCAL) == 0) {
                swrRace_CollideBlockMove((rdVector3*) velocity, &prevPos, player->model_unk, &collideNormal);
            } else {
                rdVector3 before;
                before.x = velocity[0];
                before.y = velocity[1];
                before.z = velocity[2];
                swrRace_DetectWallScrape(player, velocity, (float*) scrapeData);
                wallDelta.x = player->wallPushback.x + (velocity[0] - before.x);
                wallDelta.y = player->wallPushback.y + (velocity[1] - before.y);
                wallDelta.z = player->wallPushback.z + (velocity[2] - before.z);
                swrRace_ApplyWallCollision(player, &wallDelta, up);
            }
        }

        if (1.0f <= ((float) player->lodDistance - 40.0f) * 0.016666668f) {
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
        player->flags1 = player->flags1 | swrObjTest_FLAG1_GROUND_CACHED;
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING) {
            swrSpline_EvaluateAtOffset(&player->splineCursor, &splineMat, 0.0);
            velocity[2] = splineMat.vD.z;
        }
        groundDist = 2.0f;
        up->x = 0.0;
        up->y = 0.0;
        up->z = 1.0;
        if (((uint8_t) player->flags0 & 0xf) == swrObjTest_FLAG0_RACING)
            player->flags1 = player->flags1 | swrObjTest_FLAG1_SPLINE_SNAP;
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
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) != 0) {
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

    if ((player->flags0 & swrObjTest_FLAG0_ZOFF) == 0) {
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
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0)
        pRDot->z = pRDot->z - player->tiltAngleTarget;

    swrRace_AlignToSurface(player, (rdVector3*) pXformZ, (rdVector3*) &player->transform.vB,
                           (rdVector3*) &player->transform.vA, &player->world_gravity, ZMotion, hoverHi,
                           hoverLo, pRDot);

    // Magnet mode (flags1 0x400) suppresses ALL of the player banking + manual tilt below; only the
    // surface alignment from swrRace_AlignToSurface reaches the tilt axis.
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0) {
        pRDot->z = player->tiltAngleTarget + pRDot->z;

        // Bank-into-turn: ease tiltAngleTarget toward the turn-rate-driven lean (capped at 300 deg
        // on the ground / 70 deg airborne), then blend the change into pRDot->z.
        float prevTilt = player->tiltAngleTarget;
        float maxAngle = ((player->flags0 & swrObjTest_FLAG0_AI) == 0) ? 70.0f : 300.0f;
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

    if ((((float) player->lodDistance - 400.0f) * 0.0016666667f < 1.0f) || ((player->flags0 & swrObjTest_FLAG0_LOCAL) != 0) ||
        ((player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) != 0)) {
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
    // Acceleration scale: 4.0 while boosting or in the boost-start window, otherwise 1.5.
    float accel = ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0 || (player->flags1 & swrObjTest_FLAG1_BOOST_START) != 0) ? 4.0f : 1.5f;

    // swrScore.flag bit 3 (e.g. AI/replay) skips the fast idle-decay path below.
    bool scoreFlag = (player->score_ptr->flag & 8) != 0;

    if (player->throttle <= 0.1f)
    {
        if (-0.1f <= player->throttle)
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
            float v = swrRace_deltaTimeSecs * accel * player->throttle + player->accelThrust;
            bool braking = -0.6f < player->throttle;
            player->accelThrust = v;
            if (braking && v < player->throttle * 0.5f)
                player->accelThrust *= stdMath_Decelerator(20.0f, swrRace_deltaTimeSecs);
        }
    }
    else
    {
        // Forward throttle above 0.1: integrate, then clamp via a throttle-dependent ceiling.
        float v = swrRace_deltaTimeSecs * accel * player->throttle + player->accelThrust;
        bool below = player->throttle < 0.99f;
        player->accelThrust = v;
        float ceiling = below ? player->throttle / (1.0f - player->throttle) : 10000.0f;
        if (ceiling < v)
            player->accelThrust *= stdMath_Decelerator(player->podStats.deceleration_interval, swrRace_deltaTimeSecs);
    }

    // Air brake.
    if ((player->flags0 & swrObjTest_FLAG0_BRAKING) != 0)
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
        player->flags1 &= ~swrObjTest_FLAG1_GROUNDED;
    }
    else
    {
        uint32_t f = player->flags1;
        if ((f & swrObjTest_FLAG1_GROUNDED) == 0)
        {
            bool slow = player->surfaceSpeedFactor < 1.0f;
            player->flags1 = f | swrObjTest_FLAG1_GROUNDED;
            if (slow)
                player->flags1 = f | (swrObjTest_FLAG1_GROUNDED | swrObjTest_FLAG1_IMMUNITY);
        }
        speed *= player->surfaceSpeedFactor;
    }
    speed += player->surfaceSpeedBonus;

    // Minimum-speed floor on certain surfaces.
    if ((player->flags0 & swrObjTest_FLAG0_ZOFF) != 0 && speed < 75.0f)
        speed = 75.0f;

    // AI glide-assist speed bonus. This is not a player nose-down input: for AI, `pitch` is
    // driven to -1.0 (else 0.0) by swrRace_UpdateAIGlidePitch when the pod is gliding above
    // its spline target, so this branch only fires in that glide state -- 1.3x (1.9x if finished).
    if ((player->flags0 & swrObjTest_FLAG0_AI) != 0 && player->pitch < -0.5f)
    {
        if ((player->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
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

    if ((player->flags1 & swrObjTest_FLAG1_ON_LAVA) != 0) {
        // On lava terrain: drain fast regardless of throttle; tilt direction biases the failure.
        player->engineTemp -= (float) (swrRace_deltaTimeSecs * 20.0);
        if (player->tiltManualMult < -0.5f) {
            spinDir = -1;
        } else if (0.5f < player->tiltManualMult) {
            spinDir = 1;
        }
    } else if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) != 0) {
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
    player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;
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
    float grip = player->podStats.antiSkid * player->surfaceGripFactor * player->slide2;
    float traction = (1.0f - grip * grip) * 0.99666601f;
    if (1.0f < player->paceMultiplier)
    {
        if (player->paceMultiplier <= 2.0f)
            traction = (2.0f - player->paceMultiplier) * traction;
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
    if ((player->flags1 & swrObjTest_FLAG1_SLIDE_LOCK) == 0)
    {
        float target = 1.0f;
        if ((player->flags1 & swrObjTest_FLAG1_NOT_ACCEL) != 0)
            target = 0.8f;
        if ((player->flags1 & swrObjTest_FLAG1_SLIDING) != 0)
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
    rdVector3 seg;
    seg.x = curPos->x - prevPos->x;
    seg.y = curPos->y - prevPos->y;
    seg.z = curPos->z - prevPos->z;

    float len = rdVector_Len3(&seg);
    if (0.001f < len) {
        // Cast a ray from prevPos along the unit movement direction, over the segment length.
        float inv = 1.0f / len;
        float ray[7];
        ray[0] = prevPos->x;
        ray[1] = prevPos->y;
        ray[2] = prevPos->z;
        ray[3] = seg.x * inv;
        ray[4] = seg.y * inv;
        ray[5] = seg.z * inv;
        ray[6] = len;

        rdVector3 hitPoint, normal;
        float dist = swrRace_RaycastModel(model, ray, &hitPoint, &normal);
        if (0.0f <= dist) {
            // Push curPos back out past the contact plane along the normal (+2.0 of clearance,
            // i.e. the stored -2.0 skin subtracted).
            float push = (normal.x * hitPoint.x + normal.y * hitPoint.y + normal.z * hitPoint.z) -
                         (normal.x * curPos->x + normal.y * curPos->y + normal.z * curPos->z) + 2.0f;
            curPos->x += normal.x * push;
            curPos->y += normal.y * push;
            curPos->z += normal.z * push;
            *outNormal = normal;
            return 1;
        }
    }
    return 0;
}

// 0x00478d80
void swrRace_IntegrateMotion(swrRace* player, rdVector3* b, rdVector3* c, rdVector3* d)
{
    rdVector3 vel;

    // Longitudinal speed + boost, run through traction into the frame velocity.
    float speed = swrRace_UpdateSpeed(player);
    speed += swrRace_ApplyBoost(player);
    swrRace_ApplyTraction(player, speed, d, &vel);

    // Flatten a too-steep climb (unless on a wall/repulsor surface).
    if ((player->flags1 & swrObjTest_FLAG1_MAGNET) == 0 && (player->flags0 & swrObjTest_FLAG0_ZON) == 0 && 0.0f < vel.z)
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
    if ((player->flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_DEAD)) == 0 &&
        (0.1f < player->throttle || 0.1f < -player->throttle || (player->flags0 & swrObjTest_FLAG0_RESPAWN_INVINC) == 0))
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

    // Once the pod is beyond the LOD distance, freeze the move delta and bail. lodDistance is the
    // distance to the nearest active viewport camera (set in swrObjTest_F0); (lodDistance - 400)/600 >= 1
    // means >= ~1000 units away. Skipped for local players and FORCE_GROUND pods.
    if (1.0 <= ((float)player->lodDistance - 400.0f) * 0.0016666667f &&
        (player->flags0 & swrObjTest_FLAG0_LOCAL) == 0 && (player->flags1 & swrObjTest_FLAG1_FORCE_GROUND) == 0)
    {
        player->wallPushback.x = 0.0f;
        player->wallPushback.y = 0.0f;
        player->wallPushback.z = 0.0f;
        return;
    }
    if ((player->flags1 & swrObjTest_FLAG1_ON_FLAT) != 0)
    {
        player->wallPushback.x = 0.0f;
        player->wallPushback.y = 0.0f;
        player->wallPushback.z = 0.0f;
        return;
    }

    // Resolve track collisions (up to 6 passes), then record the resulting move delta.
    rdVector3 outNormal;
    float savedX = c->x, savedY = c->y, savedZ = c->z;
    int iter;
    int hit = swrRace_CollideTrack(c, b, player->model_unk, &outNormal);
    for (iter = 0; hit != 0 && iter < 6; iter++)
        hit = swrRace_CollideTrack(c, b, player->model_unk, &outNormal);
    if (0 < iter && (player->flags0 & swrObjTest_FLAG0_AI) != 0)
        player->accelThrust *= stdMath_Decelerator(5.0f, swrRace_deltaTimeSecs);
    player->wallPushback.x = c->x - savedX;
    player->wallPushback.y = c->y - savedY;
    player->wallPushback.z = c->z - savedZ;
}

// 0x004787f0
float swrRace_ApplyBoost(swrRace* player)
{
    if ((player->flags0 & swrObjTest_FLAG0_BOOSTING) == 0)
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

    // Air-brake cancels an active boost.
    if ((player->flags0 & swrObjTest_FLAG0_BRAKING) != 0)
        player->flags0 &= ~swrObjTest_FLAG0_BOOSTING;

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
    if ((flags0 & (swrObjTest_FLAG0_RESPAWN | swrObjTest_FLAG0_RESPAWN_INVINC | swrObjTest_FLAG0_DEAD)) != 0 || (player->flags1 & swrObjTest_FLAG1_FINISHED) != 0)
        return;
    if ((player->flags1 & swrObjTest_FLAG1_IMMUNITY) != 0)
    {
        player->flags1 &= ~swrObjTest_FLAG1_IMMUNITY;
        return;
    }

    // Both impact components must clear their thresholds, and the pod must not be invincible.
    if (swrRace_DeathSpeedDrop < b && swrRace_DeathSpeedMin < a && swrRace_IsInvincible == 0)
    {
        if (200.0f <= player->speedValue && (flags0 & swrObjTest_FLAG0_AI) == 0)
        {
            // Fast enough and not on a no-death surface: explode, spinning toward the turn direction.
            swrRace_Explode(player, (0.0f <= player->turnModifier) ? 2 : 1);
            player->throttle = 5.0f;
            player->flags0 |= swrObjTest_FLAG0_BOOSTING;
        }
        else
        {
            // Otherwise just flag for a respawn instead of exploding.
            player->flags0 |= swrObjTest_FLAG0_RESPAWN;
        }
    }
}

// 0x0047ce60
void swrRace_TriggerHandler(int player, int a, char b)
{
    // TODO
}

// 0x0047e580
void swrRace_InitFireEffects(int racer, float reset)
{
    HANG("TODO");
}

// Overall lap progress in [0..1) for a pod's spline cursor: the current control point's baked
// progress base plus segmentT scaled by the segment's progress span (spline_progress_values).
// Closed tracks clamp to just under 1.0 (the wrap is what swrRace_LapCompletion detects);
// open tracks (swrSpline_finishNodeIdx >= 0) clamp to exactly 1.0 = finished.
// 0x0047f810
float swrRace_LapProgress(swrSplineCursor* cursor)
{
    int cp;
    float progress;

    cp = swrSpline_getControlPoint(cursor, 0);
    progress = cursor->segmentT * spline_progress_values[cp].y + spline_progress_values[cp].x;
    if (swrSpline_finishNodeIdx < 0) {
        if (1.0f <= progress)
            progress = 0.9999f;
    } else if (1.0f < progress) {
        progress = 1.0f;
    }
    return progress;
}

// Per-frame lap-progress bookkeeping for one pod; returns true when it crossed the start/finish
// line this frame. lapCompMax tracks the furthest progress reached; near the line (lapComp < 0.1)
// it is unwrapped by -1.0 so a crossing shows up as progress overtaking a negative lapCompMax.
// Remote ('REMO') pods take their progress from the swrMultiplayer_aRemote* arrays instead of
// the local spline cursor. checkCrossing gates the crossing test (forced on for dead pods).
// 0x0047fdd0
bool swrRace_LapCompletion(swrRace* player, int checkCrossing)
{
    swrScore* score;
    int netSlot;
    float maxComp;
    bool crossed;

    if ((player->flags0 & swrObjTest_FLAG0_DEAD) != 0)
        checkCrossing = 1;
    player->lapCompPrev = player->lapComp;
    if (multiplayer_enabled != 0 && (player->flags0 & swrObjTest_FLAG0_REMOTE) != 0) {
        score = player->score_ptr;
        netSlot = *(int*)&score->time_unk;
        player->lapCompMax = swrMultiplayer_aRemoteLapCompMax[netSlot];
        score->results_P1_Lap = swrMultiplayer_aRemoteLap[netSlot];
    }
    if (multiplayer_enabled == 0 || (player->flags0 & swrObjTest_FLAG0_REMOTE) == 0)
        player->lapComp = swrRace_LapProgress(&player->splineCursor);
    else
        player->lapComp = swrMultiplayer_aRemoteLapComp[*(int*)&player->score_ptr->time_unk];

    if (player->moveTick < 9)
        player->idleTick += (float)swrRace_deltaTimeSecs;
    else
        player->idleTick = 0.0f;

    // skip the crossing test when the pod just jumped backward over the line
    // (progress snapped high while the previous frame was just past it)
    if (checkCrossing != 0 && (player->lapComp <= 0.8f || 0.1f <= player->lapCompPrev)) {
        maxComp = player->lapCompMax;
        if (player->lapComp < 0.1f) {
            if (0.8f < maxComp)
                maxComp -= 1.0f;
            if (0.8f < player->lapCompPrev)
                player->lapCompPrev -= 1.0f;
        }
        if (swrSpline_finishNodeIdx >= 0) {
            // open (point-to-point) track: done once progress reaches 1.0
            crossed = 1.0f <= player->lapComp;
            player->idleTick = 0.0f;
            player->lapCompMax = player->lapComp;
            return crossed;
        }
        if (maxComp < player->lapComp && player->lapCompPrev - 0.01f <= maxComp) {
            // a negative (unwrapped) high-water mark being overtaken == line crossed
            crossed = maxComp < 0.0f;
            player->idleTick = 0.0f;
            player->lapCompMax = player->lapComp;
            return crossed;
        }
    }
    return false;
}

// 0x0047f890
swrModel_Node* swrRace_GetTrackMeshAtCursor(swrSplineCursor* cursor)
{
    HANG("TODO");
}

// Steps the cursor forward over each node plane the pod passed (segmentT += 0.01 per step);
// on entering node 0 computes *outCrossTime = frame time at the lap-boundary plane crossing
// (line-plane interpolation of positionPrev -> position, x raw delta). Steps backward and sets
// *outBackward when the pod fell behind the current plane.
// 0x0047f8e0
void swrRace_AdvanceSplineCursor(swrRace* player, float* outCrossTime, int* outForward, int* outBackward)
{
    HANG("TODO");
}

// 0x0047fbb0
int swrRace_UpdateSplineBinding(swrRace* player)
{
    HANG("TODO");
}

// 0x0047fca0
void swrRace_ComputeTrackOffset(swrRace* player)
{
    HANG("TODO");
}

// Per-racer race-progress update (called per racer from swrObjJdge_F2): advances the spline
// cursor, refreshes the cursor-derived state (track mesh, sample spacing, projections), runs
// swrRace_LapCompletion, and ticks the forward/backward movement counters. Returns nonzero when
// the pod completed a lap this frame; *outCrossTime then holds the portion of the frame delta
// spent before the line crossing (F2 uses it to time laps with sub-frame precision).
// 0x0047ffb0
int swrRace_UpdateRaceProgress(swrRace* player, float* outCrossTime)
{
    int movedForward;
    int wentBackward;
    int binding;
    int completedLap;

    swrRace_AdvanceSplineCursor(player, outCrossTime, &movedForward, &wentBackward);
    player->unkf0 = (int)player->unkec_node;
    player->unkec_node = swrRace_GetTrackMeshAtCursor(&player->splineCursor);
    // the original passes the cursor, but the retail GetSampleSpacing stub ignores it
    player->splineSampleSpacing = swrSpline_GetSampleSpacing_Maybe();
    player->unkf8 = swrSpline_ProjectPointStub_Maybe(&player->splineCursor, &player->unkf4);
    player->unk100 = swrSpline_ProjectPointStub_Maybe(&player->splineCursor, &player->unkfc);
    if (player->unkf0 != (int)player->unkec_node)
        player->unk1f24 = 0;
    binding = swrRace_UpdateSplineBinding(player);
    swrRace_ComputeTrackOffset(player);
    completedLap = swrRace_LapCompletion(player, (movedForward != 0 || binding == 1) ? 1 : 0);
    if (wentBackward != 0) {
        player->unk10c++;
        player->moveTick = 0;
    }
    if (movedForward != 0) {
        player->unk10c = 0;
        if (wentBackward == 0 && player->moveTick < 200)
            player->moveTick++;
    }
    player->unk10e = (short)binding;
    return completedLap;
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
