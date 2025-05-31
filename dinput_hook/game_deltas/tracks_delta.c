#include "tracks_delta.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "types.h"
#include "types_enums.h"
#include "globals.h"
#include "FUN.h"

#include "General/stdMath.h"
#include "General/utils.h"
#include "Platform/stdControl.h"
#include "Primitives/rdMatrix.h"
#include "Primitives/rdVector.h"
#include "Swr/swrMultiplayer.h"
#include "Swr/swrObj.h"
#include "Swr/swrSprite.h"
#include "Swr/swrText.h"
#include "Swr/swrUI.h"

extern FILE *hook_log;

TrackInfo g_aNewTrackInfos[MAX_NB_TRACKS] = {0};
static char g_aCustomTrackNames[MAX_NB_TRACKS][32] = {0};
static uint16_t trackCount = DEFAULT_NB_TRACKS;

static uint16_t GetCircuitCount(bool includeCustomTracks) {
    assert(trackCount > 0);
    if (!includeCustomTracks) {
        return DEFAULT_NB_CIRCUIT_PER_TRACK;
    }
    const uint16_t NumCustomTracks = trackCount - DEFAULT_NB_TRACKS;
    return DEFAULT_NB_CIRCUIT_PER_TRACK + (NumCustomTracks / DEFAULT_NB_CIRCUIT + 1);
}

static uint16_t GetTrackCount(int circuitId) {
    if (circuitId < 4) {
        return g_aTracksInCircuits[circuitId];
    }
    if (circuitId >= GetCircuitCount(true)) {
        return 0;
    }

    const uint16_t customCircuitId = circuitId - DEFAULT_NB_CIRCUIT_PER_TRACK;
    const uint16_t NumCustomTracks = trackCount - DEFAULT_NB_TRACKS;
    uint16_t numTracks = NumCustomTracks - (customCircuitId * DEFAULT_NB_CIRCUIT);
    if (numTracks > DEFAULT_NB_CIRCUIT) {
        numTracks = DEFAULT_NB_CIRCUIT;
    }
    return numTracks;
}

static TrackInfo GetTrackInfo(uint16_t TrackID) {
    if (TrackID >= trackCount) {
        fprintf(hook_log, "GetTrackInfo: trackId %d is greater than the trackCount %d\n", TrackID,
                trackCount);
        fflush(hook_log);
        assert(false);
        return (TrackInfo) {};
    }
    return g_aNewTrackInfos[TrackID];
}


void init_customTracks() {
    fprintf(hook_log, "[init_customTracks]\n");
    fflush(hook_log);

    // Copy stock Infos
    for (uint8_t i = 0; i < 25; i++) {
        g_aNewTrackInfos[i] = g_aTrackInfos[i];
    }

    const uint16_t numCustomTracks = 2;// TODO

    trackCount = DEFAULT_NB_TRACKS + numCustomTracks;
    for (uint16_t i = DEFAULT_NB_TRACKS; i < trackCount; i++) {
        g_aNewTrackInfos[i] = (TrackInfo) {
            .trackID = MODELID_planete1_track,
            .splineID = SPLINEID_planete1_track,
            .planetTrackNumber = 0,
            .PlanetIdx = 0,
            .FavoritePilot = 0,
            .unused = 0,
        };

        const uint8_t CustomID = i - DEFAULT_NB_TRACKS;
        snprintf(g_aCustomTrackNames[CustomID], sizeof(g_aCustomTrackNames[CustomID]),
                 "Custom Track %u", CustomID + 1);
    }
}

// 0x004368a0
void swrRace_MainMenu_delta(swrObjHang *hang) {
    bool bVar1;
    float fVar2;
    char cVar3;
    int32_t uVar4;
    int iVar5;
    int iVar6;
    char cVar7;
    HangRoom iVar8;
    float fVar9;
    char *pcVar10;
    char local_71;
    rdVector3 local_6c;
    char local_60[32];
    rdMatrix44 local_40;

    const char *pTrackName = swrUI_GetTrackNameFromId_delta(hang->track_index);
    sprintf(local_60, "~f5~s~c%s", pTrackName);
    swrText_CreateTextEntry1(160, 40, 255, 255, 255, 255, local_60);

    iVar8 = -1;
    DAT_0050c480 = 0;
    if (DAT_004c4000 != 0) {
        DAT_004c4000 = 0;
        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_TRACK) {
            hang->mainMenuSelection = 0;
        }

        rdVector_Sub3(&local_6c, (rdVector3 *) &rdMatrix44_unk4.vD, &DAT_00e2af90);
        fVar9 = rdVector_Len3(&local_6c);
        DAT_0050c11c = (float) fVar9;
        rdVector_Normalize3Acc(&local_6c);
        fVar9 = stdMath_ArcTan2(-local_6c.x, local_6c.y);
        gamma_unk = fVar9;
        fVar9 = stdMath_ArcSin(local_6c.z);
        alpha_unk = fVar9;

        if (gamma_unk < 0.0) {
            gamma_unk += 360.0;
        }
        if (gamma_unk > 360.0) {
            gamma_unk -= 360.0;
        }
        if (alpha_unk < -90.0) {
            alpha_unk += 180.0;
        }
        if (alpha_unk > 90.0) {
            alpha_unk -= 180.0;
        }

        cVar7 = 1;
        DAT_0050c308[0] = 0;
        DAT_0050c308[1] = 0xff;
        DAT_0050c308[2] = 0xff;
        DAT_0050c308[3] = 0xff;
        DAT_0050c308[4] = 0xff;
        DAT_0050c308[5] = 0xff;
        DAT_0050c308[6] = 0xff;
        DAT_0050c308[7] = 0xff;
        DAT_0050c308[8] = 0xff;
        DAT_0050c308[9] = 0xff;
        DAT_0050c308[10] = 0xff;
        DAT_0050c308[11] = 0xff;

        if (hang->num_local_players == 1) {
            DAT_0050c308[0] = 0;
            DAT_0050c308[1] = 1;
            DAT_0050c308[2] = 0xff;
            DAT_0050c308[3] = 0xff;
            cVar7 = 2;
        }

        cVar3 = cVar7;
        if (hang->isTournamentMode) {
            DAT_0050c308[cVar7] = 2;
            DAT_0050c308[(char) (cVar7 + 1)] = 3;
            cVar3 = cVar7 + 3;
            DAT_0050c308[(char) (cVar7 + 2)] = 4;
            if (swrRace_nbPitDroids < 4) {
                iVar6 = (int) cVar3;
                cVar3 = cVar7 + 4;
                DAT_0050c308[iVar6] = 5;
            }
        }

        DAT_0050c524 = cVar3 + 1;
        DAT_0050c308[cVar3] = 6;
    }

    swrText_CreateColorlessEntry1(160, 25, swrText_Translate(g_pTxtMainMenu));

    uint16_t PosY = 80;
    for (uint8_t i = 0; i < DAT_0050c524; i++) {
        const char *pMenuEntry = NULL;
        switch (DAT_0050c308[i]) {
            case 0: {
                pMenuEntry = "~f4~sLos Geht's";//swrText_Translate(g_pTxtStartRace);
                break;
            }
            case 1: {
                pMenuEntry = swrText_Translate(g_pTxtInspectVehicle);
                break;
            }
            case 2: {
                pMenuEntry = swrText_Translate(g_pTxtVehicleUpgrades);
                break;
            }
            case 3: {
                pMenuEntry = swrText_Translate(g_pTxtBuyParts);
                break;
            }
            case 4: {
                pMenuEntry = swrText_Translate(g_pTxtJunkyard);
                break;
            }
            case 5: {
                pMenuEntry = swrText_Translate(g_pTxtBuyPitDroids);
                break;
            }
            case 6: {
                pMenuEntry = swrText_Translate(g_pTxtChangeVehicle);
                break;
            }
            case 7: {
                pMenuEntry = swrText_Translate(g_pTxtOptions);
                break;
            }
        }

        sprintf(local_60, pMenuEntry);
        swrUI_TextMenu(hang, 60, PosY, 10, hang->mainMenuSelection, i, local_60);
        PosY += 10;
    }

    for (uint8_t i = 0; i < hang->num_local_players; i++) {
        if ((swrUI_localPlayersInputPressedBitset[i] & 0x8000) != 0) {
            cVar7 = hang->mainMenuSelection + 1;
            hang->mainMenuSelection = cVar7;
            if ((DAT_0050c524 - 1) < cVar7) {
                hang->mainMenuSelection = 0;
            }
            FUN_00440550(0x58);
        }
        if ((swrUI_localPlayersInputPressedBitset[i] & 0x4000) != 0) {
            cVar7 = hang->mainMenuSelection + -1;
            hang->mainMenuSelection = cVar7;
            if (cVar7 < 0) {
                hang->mainMenuSelection = DAT_0050c524 + -1;
            }
            FUN_00440550(88);
        }
        if (stdControl_ReadKey(56, 0) != 0 || stdControl_ReadKey(184, 0) != 0 ||
            stdControl_ReadKey(42, 0) != 0 || stdControl_ReadKey(54, 0) != 0) {
            fVar2 = DAT_0050c11c;
            bVar1 = false;
            DAT_0050c930 = 0;
            if (DAT_00e98ea0[i] > 0.1f || DAT_00e98ea0[i] < -0.1) {
                bVar1 = true;
                gamma_unk = gamma_unk - DAT_00e98ea0[iVar6] * swrRace_fdeltaTimeSecs * 105.0;
            }
            if (DAT_00e98e80[i] > 0.1 || DAT_00e98e80[i] < -0.1) {
                alpha_unk = alpha_unk - DAT_00e98e80[i] * swrRace_fdeltaTimeSecs * -67.5;
                if (alpha_unk > 45.0) {
                    alpha_unk = 45.0;
                }
                if (alpha_unk < -45.0) {
                    alpha_unk = -45.0;
                }
                bVar1 = true;
            }
            if (bVar1) {
                rdMatrix_SetRotation44(&local_40, gamma_unk, alpha_unk, 0);
                rdVector_Scale3Add3((rdVector3 *) &DAT_00e2af90, (rdVector3 *) &rdMatrix44_unk4.vD,
                                    -DAT_0050c11c, (rdVector3 *) &local_40.vB);
                if (DAT_0050c11c != fVar2) {
                    fVar9 = rdVector_Dist3((rdVector3 *) &rdMatrix44_unk4.vD,
                                           (rdVector3 *) &DAT_00e2af90);
                    DAT_0050c11c = (float) fVar9;
                }
                rdMatrix_Copy44(&rdMatrix44_unk3, &rdMatrix44_unk4);
            }
        }
        if (DAT_004d6b44 != 0) {
            FUN_00440550(77);
            iVar8 = 3;
            swrObjHang_state2 = swrObjHang_STATE_SELECT_TRACK;
        }
        if (DAT_004d6b48 != 0) {
            FUN_00440550(84);

            // Start Race
            if (hang->mainMenuSelection == 0) {
                iVar8 = -1;
                FUN_0040a120(0);
                FUN_00409d70(0xffffffff);
                FUN_00409d70(0);

                TrackInfo Info = GetTrackInfo((uint16_t) hang->track_index);
                FUN_00427d90(Info.PlanetIdx, Info.planetTrackNumber);

                if (!swrMultiplayer_IsMultiplayerEnabled() || swrMultiplayer_IsHost() != 0) {
                    if (hang->isTournamentMode && swrRace_UnlockDataBase[0] != Info.FavoritePilot &&
                        DAT_00ec8854 != 0.0f && DAT_0050c458 == 0) {
                        swrObjHang_state2 = 15;
                    }

                    DAT_0050c944 = 0xffffffff;
                    iVar8 = FUN_004409d0(DAT_00e35a60, DAT_004c0948);
                    if ((iVar8 != 0) && ((swrUI_localPlayersInputDownBitset[0] & 4) != 0)) {
                        FUN_00440c10(hang);
                    }

                    FUN_0041e660();
                    return;
                }
            } else {
                switch (DAT_0050c308[hang->mainMenuSelection]) {
                    case 1: {
                        swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                        iVar8 = Hangar;
                        hang->activeMenu = 0;
                        FUN_0045a3e0();
                        break;
                    }
                    case 2: {
                        swrObjHang_state2 = swrObjHang_STATE_LOOK_AT_VEHICLE;
                        iVar8 = Hangar;
                        hang->activeMenu = 1;
                        FUN_0045a3e0();
                        break;
                    }
                    case 3: {
                        swrObjHang_state2 = swrObjHang_STATE_WATTO;
                        iVar8 = Shop;
                        hang->activeMenu = 0;
                        break;
                    }
                    case 4: {
                        iVar8 = Junkyard;
                        swrObjHang_state2 = swrObjHang_STATE_JUNKYARD;
                        break;
                    }
                    case 5: {
                        swrObjHang_state2 = swrObjHang_STATE_WATTO;
                        iVar8 = Shop;
                        hang->activeMenu = 1;
                        break;
                    }
                    case 6: {
                        swrObjHang_state2 = swrObjHang_STATE_SELECT_VEHICLE;
                        hang->current_player_for_vehicle_selection = i;
                        iVar8 = Cantina;
                        DAT_0050c480 = 1;
                        break;
                    }
                    case 7: {
                        hang->activeMenu = 1;
                        return;
                    }
                }
            }
        }
    }

    if (iVar8 != -1) {
        if (hang->room == iVar8) {
            swrObjHang_SetMenuState(hang, swrObjHang_state2);
            return;
        }
        DAT_0050c944 = 0xffffffff;
    }
}

// 0x0043b0b0
void HandleCircuits_delta(swrObjHang *hang) {

    int circuitId = hang->circuitIdx;

    int selectionId = 0;
    g_CircuitIdxMax = 3;
    swrRace_MenuMaxSelection = 0;
    if (hang->isTournamentMode == '\0') {
        if (g_aBeatTracksGlobal[3] == '\0') {
            g_CircuitIdxMax = 2;
        }
        for (uint8_t i = 0; i < g_aTracksInCircuits[circuitId]; i++) {
            if ((g_aBeatTracksGlobal[circuitId] & (1 << i)) != 0) {
                swrRace_MenuMaxSelection += 1;
            }
        }
    } else {
        // DELTA
        // if (swrRace_UnlockDataBase[4] == '\0') {
        //     g_CircuitIdxMax = 2;
        // }
        g_CircuitIdxMax = GetCircuitCount(true) - 1;
        // END DELTA
        // DELTA if (cond) { original_game } else { body }
        if (circuitId < 4) {
            for (uint8_t i = 0; i < g_aTracksInCircuits[circuitId]; i++) {
                if ((swrRace_UnlockDataBase[circuitId + 1] & (char) (1 << ((char) i))) != 0) {
                    swrRace_MenuMaxSelection += 1;
                }
            }
        } else {
            swrRace_MenuMaxSelection = GetTrackCount(circuitId);
        }
    }
    if (multiplayer_enabled && (circuitId < '\x03')) {
        swrRace_MenuMaxSelection = g_aTracksInCircuits[circuitId];
    }
    if (swrRace_MenuSelectedItem >= swrRace_MenuMaxSelection) {
        swrRace_MenuSelectedItem = swrRace_MenuMaxSelection - 1;
    }
    // DELTA
    if (swrRace_MenuMaxSelection > 0 && swrRace_MenuSelectedItem < 0) {
        swrRace_MenuSelectedItem = 0;
    }
    //END DELTA
    DAT_00e295c0 = (uint32_t) (circuitId > 0);
    g_bCircuitIdxInRange = (int) (circuitId < g_CircuitIdxMax);
    return;
}

static void DrawTextBox(uint16_t PosX, uint16_t PosY, uint8_t R, uint8_t G, uint8_t B, uint8_t A,
                        const char *pFormatting, const char *pText, uint16_t LineLengthMax,
                        uint16_t LinesMax, uint16_t LineSpacing) {

    // Since 'swrText_CreateTextEntry1' expects a null terminated string
    // I have to make a copy for each line, unfortunately...
    const uint16_t LINES_MAX = 64;
    const uint16_t LINE_LENGTH_MAX = 128;

    const uint16_t FormattingLen = (uint16_t) strnlen(pFormatting, LINE_LENGTH_MAX);

    if (LinesMax > LINES_MAX) {
        LinesMax = LINES_MAX;
    }
    if (LineLengthMax > LINE_LENGTH_MAX - FormattingLen - 1) {
        LineLengthMax = LINE_LENGTH_MAX - FormattingLen - 1;
    }

    char Lines[LINES_MAX][LINE_LENGTH_MAX];

    uint16_t LineCount = 0;
    const char *pLastSpace = pText;
    const char *pLastNewLine = pText;
    for (; LineCount < LinesMax; pText++) {
        if (*pText == ' ') {
            pLastSpace = pText + 1;
        }

        uint16_t LineLen = pText - pLastNewLine;
        if (LineLen >= LineLengthMax) {
            LineLen = LineLengthMax;
        }

        if (*pText == 0) {
            strncpy(Lines[LineCount], pFormatting, FormattingLen);
            strncpy(Lines[LineCount] + FormattingLen, pLastNewLine, LineLen);
            Lines[LineCount++][FormattingLen + LineLen] = 0;
            break;
        }

        if (*pText == '\n' || (LineLen >= LineLengthMax && pLastSpace != pLastNewLine)) {
            strncpy(Lines[LineCount], pFormatting, FormattingLen);
            strncpy(Lines[LineCount] + FormattingLen, pLastNewLine, LineLen);
            Lines[LineCount++][FormattingLen + LineLen] = 0;

            for (; *pText == ' '; pText++)
                ;
            pLastSpace = pText;
            pLastNewLine = pText;
        }
    }

    for (uint16_t i = 0; i < LineCount; i++) {
        swrText_CreateTextEntry1(PosX, PosY + (LineSpacing * i), R, G, B, A, Lines[i]);
    }
}

// 0x0043b240
void swrRace_CourseSelectionMenu_delta(void) {
    char *pcVar2;
    float uVar6;
    char buffer[256];

    swrObjHang *hang = g_objHang2;// == g_pMenuState
    const TrackInfo Track = GetTrackInfo(hang->track_index);
    if (DAT_004c4000 != 0) {
        DAT_004c4000 = 0;
        FUN_0045bee0(hang, 0x25, 0xffffffff, 0);
        DAT_0050c54c = 0;

        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_PLANET) {
            swrRace_Transition = 1.0;
        }
        if ((hang->menuScreenPrev == swrObjHang_STATE_SELECT_VEHICLE) ||
            (hang->menuScreenPrev == swrObjHang_STATE_SPLASH)) {
            hang->circuitIdx = 0;
        }

        HandleCircuits_delta(hang);
        if ((hang->menuScreenPrev == swrObjHang_STATE_SELECT_VEHICLE) ||
            (hang->menuScreenPrev == swrObjHang_STATE_SPLASH)) {
            swrRace_MenuSelectedItem = 0;
            if (hang->isTournamentMode) {
                if (!isTrackUnlocked(hang->circuitIdx, swrRace_MenuMaxSelection - 1)) {
                    swrRace_MenuSelectedItem = swrRace_MenuMaxSelection - 1;
                }
            }
        } else {
            FUN_0043b1d0(hang);
        }

        swrObjHang_InitTrackSprites_delta(hang, true);
        DAT_0050c134 = Track.PlanetIdx;
        DAT_0050c17c = hang->circuitIdx;
    }

    if (DAT_0050c54c == 0) {
        if (DAT_00e295d4 == swrRace_MenuSelectedItem) {
            uVar6 = 3.3f;
            DAT_0050c134 = Track.PlanetIdx;
            DAT_0050c17c = hang->circuitIdx;
            goto LAB_0043b357;
        }
    } else {
        uVar6 = -3.3f;
    LAB_0043b357:
        FUN_00469b90(uVar6);
    }

    if (swrRace_Transition > 0.0f && hang->track_index >= 0) {
        DrawHoloPlanet(hang, (int) DAT_0050c134, swrRace_Transition * 0.5f);
    }
    if (DAT_0050c54c != 0) {
        return;
    }

    const int32_t SelectedTrackIdx = VerifySelectedTrack_delta(hang, swrRace_MenuSelectedItem);
    if (SelectedTrackIdx >= 0) {
        if (hang->circuitIdx < 4) {
            hang->track_index =
                g_aTrackIDs[hang->circuitIdx * DEFAULT_NB_CIRCUIT + SelectedTrackIdx];
        } else {
            hang->track_index = hang->circuitIdx * DEFAULT_NB_CIRCUIT + SelectedTrackIdx;
        }

        // Draw "Planet not loaded!!!" warning
        if ((Track.trackID == -1) || (Track.splineID == -1)) {
            const char *pText = swrText_Translate(g_pTxtPlanetNotLoaded);
            sprintf(buffer, pText);

            // The following I decompiled by hand, Ghidra returned just trash
            int32_t a = swrUtils_Rand();
            float b = (float) a * DAT_004ac86c * DAT_004ac93c;
            int32_t B = (int32_t) b;

            a = swrUtils_Rand();
            b = (float) a * DAT_004ac86c * DAT_004ac93c;
            int32_t G = (int32_t) b;

            a = swrUtils_Rand();
            b = (float) a * DAT_004ac86c * DAT_004ac93c;
            int32_t R = (int32_t) b;

            swrText_CreateTextEntry1(160, 205, R, G, B, 255, buffer);
        }

        const char *pTrackName = swrUI_GetTrackNameFromId_delta(hang->track_index);
        sprintf(buffer, "~c~s%s", pTrackName);
        swrText_CreateTextEntry1(160, 54, 0, 255, 0, 255, buffer);
        pcVar2 = buffer;
        FUN_0042de10(pcVar2, 0);
        FUN_0042de10(buffer, 0);
    } else {
        hang->track_index = -1;
    }

    MenuAxisHorizontal(NULL, 55);

    uint8_t R, G, B;
    char *pTxtCircuit = NULL;
    switch (hang->circuitIdx) {
        case 0: {
            pTxtCircuit = swrText_Translate(g_pTxtCircuitAmateur);
            B = 255;
            G = 255;
            R = 50;
            break;
        }
        case 1: {
            pTxtCircuit = swrText_Translate(g_pTxtCircuitSemiPro);
            B = 62;
            G = 255;
            R = 68;
            break;
        }
        case 2: {
            pTxtCircuit = swrText_Translate(g_pTxtCircuitGalactic);
            B = 17;
            G = 190;
            R = 163;
            break;
        }
        case 3: {
            pTxtCircuit = swrText_Translate(g_pTxtCircuitInvitational);
            B = 32;
            G = 89;
            R = 157;
            break;
        }
        default: {
            if (hang->track_index < DEFAULT_NB_TRACKS) {
                fprintf(
                    hook_log,
                    "track index is %d, but should be greater than the default number of tracks",
                    hang->track_index);
                assert(false);
            }

            char BufferPage[128];
            sprintf(BufferPage, "~c~sCustom Tracks Page %u/%u", hang->circuitIdx - 3,
                    GetCircuitCount(true) - 4);
            pTxtCircuit = swrText_Translate(BufferPage);
            B = TRACK_COLOR_B;
            G = TRACK_COLOR_G;
            R = TRACK_COLOR_R;

            swrText_CreateTextEntry1(55, 80, 50, 255, 255, 255, buffer);
            const char *pDescription = "Brief description of the track";
            DrawTextBox(55, 150, 50, 255, 255, 255, "~f4~s", pDescription, 17, 7, 8);
            break;
        }
    }
    swrText_CreateTextEntry1(160, 34, R, G, B, 255, pTxtCircuit);

    char *pTextMode = NULL;
    if (!hang->isTournamentMode) {
        if (hang->timeAttackMode != 0) {
            pTextMode = swrText_Translate(g_pTxtTimeAttack);
            goto LAB_0043b5c4;
        }
        if (hang->num_local_players == 2) {
            pTextMode = swrText_Translate(g_pTxt2Player);
            goto LAB_0043b5c4;
        }
        pTextMode = g_pTxtFreePlay;
    } else {
        pTextMode = g_pTxtTournament;
    }
    pTextMode = swrText_Translate(pTextMode);

LAB_0043b5c4:
    sprintf(buffer, pTextMode);
    swrText_CreateTextEntry1(160, 24, 50, 255, 255, 255, buffer);

    DrawTracks(hang, DAT_0050c17c);
    if (hang->track_index >= 0) {
        // TODO: Custom Planets?
        if (Track.PlanetIdx < 8) {
            // Draw planet preview image
            const uint16_t ImgIdx = Track.PlanetIdx + 69;
            swrSprite_SetVisible(ImgIdx, true);
            swrSprite_SetPos(ImgIdx, 160, 150);
            swrSprite_SetDim(ImgIdx, 1.0f, 1.0f);
            swrSprite_SetColor(ImgIdx, 255, 255, 255, 255);

            // Tatooine_textbuffer is in fact an array of strings
            char *pPlanetName = Tatooine_textbuffer[Track.PlanetIdx];
            swrText_CreateTextEntry1(224, 143, 0, 255, 0, 255, pPlanetName);
        }
    }

    FUN_0043fe90(0x2d, 0x54, 0x1e);
    if (DAT_0050c54c == 0) {
        FUN_00469c30(0, 1.0f, 1);
        uint32_t puVar2 = *swrUI_localPlayersInputPressedBitset;
        if (DAT_004eb39c == 0) {
            if (DAT_004d6b48 != 0 &&
                (swrMultiplayer_IsMultiplayerEnabled() == 0 || swrMultiplayer_IsHost() != 0) &&
                hang->track_index >= 0) {
                if (multiplayer_enabled != 0) {
                    FUN_004118b0();
                    return;
                }
                if (DAT_00e2a698 != 0) {
                    return;
                }

                FUN_00440550(0x54);
                swrObjHang_InitTrackSprites_delta(hang, false);
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_TRACK);
                DAT_0050c54c = 1;
                return;
            }
            if ((DAT_004d6b44 != 0) && (DAT_00e2a698 == 0)) {
                if (multiplayer_enabled) {
                    FUN_004118b0();
                    return;
                }

                FUN_00440550(0x4d);
                if (swrMultiplayer_IsMultiplayerEnabled() && swrMultiplayer_IsHost() != 0) {
                    return;
                }
                swrObjHang_InitTrackSprites_delta(hang, false);
                swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_VEHICLE);
                return;
            }
        }
        uint8_t circuitIdx = hang->circuitIdx;
        if (DAT_0050c17c == circuitIdx) {
            // Move down
            if ((puVar2 & 0x8000) != 0) {
                if (circuitIdx < g_CircuitIdxMax) {
                    hang->circuitIdx++;
                    DAT_00e295d4 = -1;
                    FUN_00440550(0x58);
                    HandleCircuits_delta(hang);
                } else {
                    FUN_00440550(0x4b);
                }
            }

            // Move up
            if ((puVar2 & 0x4000) != 0) {
                if (hang->circuitIdx < 1) {
                    FUN_00440550(0x4b);
                } else {
                    hang->circuitIdx--;
                    DAT_00e295d4 = -1;
                    FUN_00440550(88);
                    HandleCircuits_delta(hang);
                }
            }
        }

        if (hang->track_index >= 0) {
            multiplayer_track_select = (int) hang->track_index;
            if (!swrMultiplayer_IsMultiplayerEnabled() || swrMultiplayer_IsHost() != 0) {
                g_LoadTrackModel = Track.trackID;
                FUN_0041e5a0();
            }
        }
    }
}

// 0x0043b880
void swrRace_CourseInfoMenu_delta(swrObjHang *hang) {
    int8_t iVar3;
    char cVar4;
    int iVar6;
    int8_t uVar13;
    int32_t uVar18;
    char local_40[64];

    if (nb_AI_racers == 0) {
        nb_AI_racers = 12;
    }
    if (DAT_0050c55c == 0) {
        DAT_0050c55c = 2;
    }

    iVar3 = DAT_0050c560;
    if (DAT_004c4000 != 0) {
        DAT_004c4000 = 0;
        FUN_0045bee0(hang, 0x25, -1, 0);
        DAT_0050c550 = 0;
        DAT_0050c554 = 0;

        if (hang->menuScreenPrev == swrObjHang_STATE_SELECT_PLANET) {
            swrRace_Transition = 1.0;
        }

        HandleCircuits_delta(hang);
        if (hang->menuScreenPrev != swrObjHang_STATE_SELECT_PLANET) {
            FUN_0043b1d0(hang);
        }

        DAT_0050c430[0] = 0xff;
        DAT_0050c430[1] = 0xff;
        DAT_0050c430[2] = 0xff;
        DAT_0050c430[3] = 0xff;
        DAT_0050c430[4] = 0xff;
        DAT_0050c430[5] = 0xff;
        DAT_0050c430[6] = 0xff;
        DAT_0050c430[7] = 0xff;
        DAT_0050c430[8] = 0xff;
        DAT_0050c430[9] = 0xff;
        DAT_0050c430[10] = 0xff;
        DAT_0050c430[11] = 0xff;
        DAT_0050c560 = 0;

        if (BeatEverything1stPlace(hang)) {
            iVar6 = DAT_0050c560;
            DAT_0050c560 = DAT_0050c560 + 1;
            DAT_0050c430[iVar6] = 0;
        }
        if (!hang->isTournamentMode) {
            iVar3 = DAT_0050c560 + 1;
            DAT_0050c430[DAT_0050c560] = 2;
            if (hang->timeAttackMode != 0) {
                goto LAB_0043b9b4;
            }
            DAT_0050c560 = DAT_0050c560 + 2;
            DAT_0050c430[iVar3] = 3;
            DAT_0050c430[DAT_0050c560] = 4;
        } else {
            int32_t NumUnlockedTracks = VerifySelectedTrack_delta(hang, swrRace_MenuSelectedItem);
            iVar6 = isTrackUnlocked(hang->circuitIdx, NumUnlockedTracks);
            iVar3 = DAT_0050c560;
            if (iVar6 == 0) {
                goto LAB_0043b9b4;
            }
            DAT_0050c430[DAT_0050c560] = 1;
        }
        iVar3 = DAT_0050c560 + 1;
    }

LAB_0043b9b4:
    DAT_0050c560 = iVar3;
    const int32_t NumUnlockedTracks = VerifySelectedTrack_delta(hang, swrRace_MenuSelectedItem);
    const uint8_t ReqPlaceToProcceed =
        GetRequiredPlaceToProceed(hang->circuitIdx, NumUnlockedTracks);

    int32_t PosY = 160;
    if (DAT_0050c554 == 0 && DAT_0050c560 > 0) {
        for (int8_t i = 0; i < DAT_0050c560; i++) {
            if (DAT_0050c430[i] > 6) {
                assert(false);
                continue;
            }

            char *pText = NULL;
            switch (DAT_0050c430[i]) {
                case 0: {
                    pText = swrText_Translate(g_pTxtMirror);
                    swrUI_TextMenu(hang, 30, PosY, 10, DAT_0050c550, i, pText);
                    if (hang->bMirror != 0) {
                        pText = swrText_Translate(g_pTxtOn);
                        uVar13 = (int8_t) DAT_0050c550;
                        goto LAB_0043be29;
                    }
                    pText = swrText_Translate(g_pTxtOff);
                    goto LAB_0043be20;
                }

                // Tournament track winnings
                case 1: {
                    if (hang->WinningsID == 1) {
                        pText = swrText_Translate(g_pTxtFair);
                    } else if (hang->WinningsID == 2) {
                        pText = swrText_Translate(g_pTxtSkilled);
                    } else// == 3
                    {
                        assert(hang->WinningsID == 3);
                        pText = swrText_Translate(g_pTxtWinnerTakesAll);
                    }

                    swrUI_TextMenu(hang, 30, PosY, 10, DAT_0050c550, i,
                                   swrText_Translate(g_pTxtWinnings));
                    swrUI_TextMenu(hang, 85, PosY, 10, DAT_0050c550, i, pText);

                    swrUI_TextMenu(hang, 45, PosY + 10, 10, DAT_0050c550, i,
                                   swrText_Translate(g_pTxt1st));
                    swrUI_TextMenu(hang, 45, PosY + 20, 10, DAT_0050c550, i,
                                   swrText_Translate(g_pTxt2nd));
                    swrUI_TextMenu(hang, 45, PosY + 30, 10, DAT_0050c550, i,
                                   swrText_Translate(g_pTxt3rd));
                    if (ReqPlaceToProcceed == 4) {
                        swrUI_TextMenu(hang, 45, PosY + 40, 10, DAT_0050c550, i,
                                       swrText_Translate(g_pTxt4th));
                    }

                    uint16_t PosYIt = PosY + 10;
                    for (int8_t j = 0; j < ReqPlaceToProcceed; j++) {
                        float fTruguts = 1.0 + hang->circuitIdx * 0.5;
                        fTruguts *= hang->winnings.truguts[hang->WinningsID - 1][j];
                        pText = swrText_Translate("~f0~r~s%d");
                        sprintf(local_40, pText, (int) fTruguts);
                        swrUI_TextMenu(hang, 105, PosYIt, 10, DAT_0050c550, i, local_40);
                        PosYIt = PosYIt + 10;
                    }

                    continue;
                }
                case 2: {
                    pText = swrText_Translate("~f0~s%d");
                    sprintf(local_40, pText, hang->numLaps);
                    pText = g_pTxtLaps;
                    break;
                }
                case 3: {
                    pText = swrText_Translate("~f0~s%d");
                    sprintf(local_40, pText, nb_AI_racers);
                    if (hang->num_local_players > 1) {
                        pText = swrText_Translate("~f0~s%d");
                        sprintf(local_40, pText, DAT_0050c55c);
                    }
                    pText = g_pTxtRacers;
                    goto LAB_0043bd30;
                }
                case 4: {
                    if (hang->AISpeed == 1) {
                        pText = swrText_Translate(g_pTxtSlow);
                    } else if (hang->AISpeed == 2) {
                        pText = swrText_Translate(g_pTxtAverage);
                    } else {
                        pText = swrText_Translate(g_pTxtFast);
                    }
                    sprintf(local_40, pText);
                    pText = g_pTxtAISpeed;

                LAB_0043bd30:
                    pText = swrText_Translate(pText);
                    swrUI_TextMenu(hang, 30, PosY, 10, DAT_0050c550, i, pText);
                    pText = local_40;
                    uVar13 = DAT_0050c550;
                    goto LAB_0043be29;
                }
                case 5: {
                    pText = swrText_Translate(g_pTxtDemoMode);
                    swrUI_TextMenu(hang, 30, PosY, 10, DAT_0050c550, i, pText);
                    if (hang->demo_mode != 0) {
                        pText = swrText_Translate(g_pTxtOn);
                        goto LAB_0043be20;
                    }
                    pText = swrText_Translate(g_pTxtOff);
                    uVar13 = DAT_0050c550;
                    goto LAB_0043be29;
                }
                case 6: {
                    if (hang->unk68_type < 0) {
                        pText = swrText_Translate(g_pTxtOff2);
                        sprintf(local_40, pText);
                    } else {
                        pText = swrText_Translate("~s%d");
                        sprintf(local_40, pText, hang->unk68_type + 1);
                    }
                    pText = g_pTxtCutscene;
                }
            }
            pText = swrText_Translate(pText);
            swrUI_TextMenu(hang, 30, PosY, 10, (char) DAT_0050c550, i, pText);

        LAB_0043be20:
            uVar13 = DAT_0050c550;

        LAB_0043be29:
            swrUI_TextMenu(hang, 85, PosY, 10, uVar13, i, local_40);

            PosY = PosY + 10;
        }
    }

    if (DAT_0050c554 == 0) {
        uVar18 = 0x40533333;
    } else {
        uVar18 = 0xc0533333;
    }

    FUN_00469b90(uVar18);

    TrackInfo trackInfo = GetTrackInfo(hang->track_index);
    if (swrRace_Transition > 0.0) {
        DrawHoloPlanet(hang, trackInfo.PlanetIdx, swrRace_Transition * 0.5);
    }

    if (DAT_0050c554 == 0 && DAT_0050c554 == 0) {
        if (hang->track_index < 28) {
            DrawTrackPreview(hang, hang->track_index, 0.5);
        }

        // Track Name
        char *pTrackName = swrUI_GetTrackNameFromId_delta(hang->track_index);
        pTrackName = swrText_Translate(pTrackName);
        sprintf(local_40, "~c~s%s", pTrackName);
        swrText_CreateTextEntry1(0xa0, 0x25, 0, 0xff, 0, 0xff, local_40);
        FUN_0042de10(local_40, 0);
        FUN_0042de10(local_40, 0);
        MenuAxisHorizontal(NULL, 38);

        if (hang->track_index < 28) {
            swrUI_DrawRecord(hang, 100, 55, 255.0, 0);
            swrUI_DrawRecord(hang, 220, 55, 255.0, 3);

            // Record 3 Laps
            iVar6 = hang->bMirror + hang->track_index * 2;
            if (hang->track_index < 28 && DAT_00e365f4[iVar6] < 3599.0f) {
                uint8_t PilotIdx = DAT_00e37404[iVar6];
                char *pNameFirst = swrText_Translate(swrRacer_PodData[PilotIdx].lastname);
                char *pNameLast = swrText_Translate(swrRacer_PodData[PilotIdx].name);
                sprintf(local_40, "~f4~c~s%s %s", pNameFirst, pNameLast);
                swrText_CreateTextEntry1(100, 78, 163, 190, 17, 255, local_40);
                swrSprite_SetVisible(23 + PilotIdx, true);
                swrSprite_SetPos(23 + PilotIdx, 84, 85);
                swrSprite_SetDim(23 + PilotIdx, 0.5, 0.5);
                swrSprite_SetColor(23 + PilotIdx, 255, 255, 255, 255);
            }

            // Record Best Lap
            iVar6 = hang->bMirror + hang->track_index * 2;
            if (hang->track_index < 28 && DAT_00e366bc[iVar6] < 3599.0f) {
                uint8_t PilotIdx = DAT_00e37436[iVar6];
                char *pNameFirst = swrText_Translate(swrRacer_PodData[PilotIdx].name);
                char *pNameLast = swrText_Translate(swrRacer_PodData[PilotIdx].lastname);
                sprintf(local_40, "~f4~c~s%s %s", pNameFirst, pNameLast);

                swrText_CreateTextEntry1(220, 78, 163, 190, 17, 255, local_40);
                swrSprite_SetVisible(46 + PilotIdx, true);
                swrSprite_SetPos(46 + PilotIdx, 204, 85);
                swrSprite_SetDim(46 + PilotIdx, 0.5, 0.5);
                swrSprite_SetColor(46 + PilotIdx, 255, 255, 255, 255);
            }
        } else {
            swrText_CreateTextEntry1(160, 75, 50, 255, 255, 255, "~f5~s~cRecords not available");
            swrText_CreateTextEntry1(160, 90, 50, 255, 255, 255, "~f5~s~cfor custom tracks");
        }

        // Track Favorite
        uint8_t FavPilotIdx = trackInfo.FavoritePilot;
        char *pNameFirst = swrText_Translate(swrRacer_PodData[FavPilotIdx].name);
        char *pNameLast = swrText_Translate(swrRacer_PodData[FavPilotIdx].lastname);

        swrText_CreateTextEntry1(240, 130, 50, 255, 255, 255,
                                 swrText_Translate(g_pTxtTrackFavorite));
        sprintf(local_40, "~f4~c~s%s %s", pNameFirst, pNameLast);
        swrText_CreateTextEntry1(240, 137, 163, 190, 17, 255, local_40);
        swrSprite_SetVisible(FavPilotIdx, true);
        swrSprite_SetPos(FavPilotIdx, 208, 145);
        swrSprite_SetDim(FavPilotIdx, 1.0, 1.0);
        swrSprite_SetColor(FavPilotIdx, 255, 255, 255, 255);

        // "Must place xxx or better to progress"
        if (hang->isTournamentMode) {
            iVar6 = VerifySelectedTrack_delta(hang, swrRace_MenuSelectedItem);
            iVar6 = isTrackUnlocked(hang->circuitIdx, iVar6);
            if (iVar6 != 0) {
                char *pMinPlace = ReqPlaceToProcceed == 3 ? g_pTxtMinPlace3rd : g_pTxtMinPlace4th;
                pMinPlace = swrText_Translate(pMinPlace);
                swrText_CreateTextEntry1(160, 115, 163, 190, 17, 255, pMinPlace);
            }
        }

        if (DAT_0050c554 == 0 && swrRace_Transition >= 1.0) {
            if (DAT_004eb39c == 0) {
                if (DAT_004d6b48 != 0 && DAT_00e2a698 == 0) {
                    FUN_00440550(84);
                    if (!hang->isTournamentMode) {
                        if (hang->timeAttackMode == 0) {
                            if (hang->num_local_players < 2) {
                                if (hang->demo_mode == 0 || nb_AI_racers != 2) {
                                    hang->num_players = nb_AI_racers;
                                } else {
                                    hang->num_players = 1;
                                }
                            } else {
                                hang->num_players = DAT_0050c55c;
                            }
                        } else {
                            hang->num_players = 1;
                        }
                    } else {
                        hang->num_players = 12;
                    }
                    swrObjHang_InitTrackSprites(hang, false);
                    FUN_0045bee0(hang, 0x24, 3, 0);
                    DAT_0050c554 = 1;
                    return;
                }
                if (DAT_004d6b44 != 0 && DAT_00e2a698 == 0) {
                    FUN_00440550(36);
                    swrObjHang_InitTrackSprites(hang, false);
                    swrObjHang_SetMenuState(hang, swrObjHang_STATE_SELECT_PLANET);
                    return;
                }
            }
            if (DAT_0050c560 > 1) {
                if ((swrUI_localPlayersInputPressedBitset[0] & 0x4000) != 0) {
                    DAT_0050c550--;
                    FUN_00440550(88);
                }
                if ((swrUI_localPlayersInputPressedBitset[0] & 0x8000) != 0) {
                    DAT_0050c550++;
                    FUN_00440550(88);
                }
                if (DAT_0050c550 < 0) {
                    DAT_0050c550 = DAT_0050c560 - 1;
                }
                if ((DAT_0050c560 - 1) < DAT_0050c550) {
                    DAT_0050c550 = 0;
                }
            }
            if (DAT_0050c560 > 0) {
                if ((swrUI_localPlayersInputPressedBitset[0] & 0x20000) != 0) {
                    switch (DAT_0050c430[DAT_0050c550]) {
                        case 0: {
                            hang->bMirror = hang->bMirror == 0;
                            break;
                        }
                        case 1: {
                            hang->WinningsID++;
                            break;
                        }
                        case 2: {
                            hang->numLaps++;
                            break;
                        }
                        case 3: {
                            if (hang->num_local_players < 2) {
                                if (nb_AI_racers == 1) {
                                    nb_AI_racers = 2;
                                } else if (nb_AI_racers < 20) {
                                    nb_AI_racers += 2;
                                }
                            } else {
                                cVar4 = DAT_0050c55c + 2;
                                DAT_0050c55c = cVar4;
                                if (cVar4 == 8) {
                                    DAT_0050c55c = 2;
                                }
                            }
                            break;
                        }
                        case 4: {
                            hang->AISpeed++;
                            break;
                        }
                        case 5: {
                            hang->demo_mode = hang->demo_mode == 0;
                            break;
                        }
                        case 6: {
                            hang->unk68_type++;
                        }
                    }
                    FUN_00440550(88);
                }
                if ((swrUI_localPlayersInputPressedBitset[0] & 0x10000) != 0) {
                    switch (DAT_0050c430[DAT_0050c550]) {
                        case 0: {
                            hang->bMirror = hang->bMirror == 0;
                            break;
                        }
                        case 1: {
                            hang->WinningsID--;
                            break;
                        }
                        case 2: {
                            hang->numLaps--;
                            break;
                        }
                        case 3: {
                            if (hang->num_local_players < 2) {
                                if (nb_AI_racers == 2) {
                                    nb_AI_racers = 1;
                                } else if (nb_AI_racers > 2) {
                                    nb_AI_racers -= 2;
                                }
                            } else {
                                cVar4 = DAT_0050c55c - 2;
                                DAT_0050c55c = cVar4;
                                if (cVar4 == 0) {
                                    DAT_0050c55c = 6;
                                }
                            }
                            break;
                        }
                        case 4: {
                            hang->AISpeed--;
                            break;
                        }
                        case 5: {
                            hang->demo_mode = hang->demo_mode == 0;
                            break;
                        }
                        case 6: {
                            hang->unk68_type--;
                            break;
                        }
                    }
                    FUN_00440550(88);
                }
            }
            if (hang->numLaps < 1) {
                hang->numLaps = 5;
            }
            if (hang->numLaps > 5) {
                hang->numLaps = 1;
            }
            if (hang->AISpeed < 1) {
                hang->AISpeed = 3;
            }
            if (hang->AISpeed > 3) {
                hang->AISpeed = 1;
            }
            if (hang->WinningsID < 1) {
                hang->WinningsID = 3;
            }
            if (hang->WinningsID > 3) {
                hang->WinningsID = 1;
            }
            if (hang->unk68_type < -1) {
                hang->unk68_type = 20;
            }
            if (hang->unk68_type > 20) {
                hang->unk68_type = -1;
            }

            if (swrMultiplayer_IsMultiplayerEnabled() || swrMultiplayer_IsHost() != 0) {
                g_LoadTrackModel = trackInfo.trackID;
                FUN_0041e5a0();
            }
        }
    }
}

// 0x00440620
char *swrUI_GetTrackNameFromId_delta(int trackId) {

    if (trackId >= trackCount) {
        fprintf(hook_log, "trackId %d is bigger than the number of tracks %d\n", trackId,
                trackCount);
        fflush(hook_log);
        assert(false);
        return "Invalid Track!";
    }

    switch (trackId) {
        case 0:
            return swrText_Translate(g_pTxtTrackID_00);
        case 1:
            return swrText_Translate(g_pTxtTrackID_01);
        case 2:
            return swrText_Translate(g_pTxtTrackID_02);
        case 3:
            return swrText_Translate(g_pTxtTrackID_03);
        case 4:
            return swrText_Translate(g_pTxtTrackID_04);
        case 5:
            return swrText_Translate(g_pTxtTrackID_05);
        case 6:
            return swrText_Translate(g_pTxtTrackID_06);
        case 7:
            return swrText_Translate(g_pTxtTrackID_07);
        case 8:
            return swrText_Translate(g_pTxtTrackID_08);
        case 9:
            return swrText_Translate(g_pTxtTrackID_09);
        case 10:
            return swrText_Translate(g_pTxtTrackID_10);
        case 11:
            return swrText_Translate(g_pTxtTrackID_11);
        case 12:
            return swrText_Translate(g_pTxtTrackID_12);
        case 13:
            return swrText_Translate(g_pTxtTrackID_13);
        case 14:
            return swrText_Translate(g_pTxtTrackID_14);
        case 15:
            return swrText_Translate(g_pTxtTrackID_15);
        case 16:
            return swrText_Translate(g_pTxtTrackID_16);
        case 17:
            return swrText_Translate(g_pTxtTrackID_17);
        case 18:
            return swrText_Translate(g_pTxtTrackID_18);
        case 19:
            return swrText_Translate(g_pTxtTrackID_19);
        case 20:
            return swrText_Translate(g_pTxtTrackID_20);
        case 21:
            return swrText_Translate(g_pTxtTrackID_21);
        case 22:
            return swrText_Translate(g_pTxtTrackID_22);
        case 23:
            return swrText_Translate(g_pTxtTrackID_23);
        case 24:
            return swrText_Translate(g_pTxtTrackID_24);
    }

    // DELTA
    return g_aCustomTrackNames[trackId - DEFAULT_NB_TRACKS];
}

// 0x00440aa0
bool isTrackPlayable_delta(swrObjHang *hang, char circuitIdx, char trackIdx) {
    // DELTA custom circuits
    if (circuitIdx >= 4)
        return true;

    uint8_t tracksBitMask = swrRace_UnlockDataBase[circuitIdx + 1];
    if ((multiplayer_enabled != 0) && (circuitIdx < '\x03')) {
        return true;
    }
    if (!hang->isTournamentMode) {
        tracksBitMask = g_aBeatTracksGlobal[circuitIdx];
    }
    return ((uint8_t) (1 << (trackIdx)) & tracksBitMask) != 0;
}

// 0x00440af0
int VerifySelectedTrack_delta(swrObjHang *hang, int selectedTrackIdx) {
    bool bIsPlayable;
    uint8_t trackCount = 0;
    // DELTA
    const uint8_t numTracks = GetTrackCount(hang->circuitIdx);
    if (numTracks == 0) {
        fprintf(hook_log, "Error: Number of tracks for circuit %d is zero !\n", hang->circuitIdx);
        fflush(hook_log);
        return -1;
    }
    while ((bIsPlayable = isTrackPlayable_delta(hang, hang->circuitIdx, trackCount),
            !bIsPlayable || (trackCount != selectedTrackIdx))) {

        trackCount++;
        if (trackCount >= numTracks) {
            fprintf(
                hook_log,
                "Error: Track count %d exceeds the number of tracks %d, with selected track %d\n",
                trackCount, numTracks, selectedTrackIdx);
            fflush(hook_log);
            return -1;
        }
    }
    return trackCount;
}

static uint16_t GetImgStartBackground(uint16_t TrackID) {
    if (TrackID < 25) {
        return 99 + TrackID;
    }
    TrackID -= 25;

    // Slots 256 - 399 seem to be free...
    // 144 slots / 2 = 72 possible custom tracks
    assert(TrackID < MAX_CUSTOM_TRACKS);
    return 256 + TrackID;
}

static uint16_t GetImgStartBorder(uint16_t TrackID) {
    if (TrackID < 25) {
        return 99 + 25 + TrackID;
    }
    TrackID -= 25;

    // Slots 256 - 399 seem to be free...
    // 144 slots / 2 = 72 possible custom tracks max, but Ben1138 only uses 70. ?
    assert(TrackID < MAX_CUSTOM_TRACKS);
    return 256 + MAX_CUSTOM_TRACKS + TrackID;
}


// 0x004584a0
void swrObjHang_InitTrackSprites_delta(swrObjHang *hang, int initTracks) {
    // Taking sprite slots [130, 162[
    for (uint16_t imgId = 130; imgId < 162; imgId++) {
        swrSprite_NewSprite(imgId, hang->sprite_whitesquare_rgb);
    }

    // DELTA
    // Reset custom track images
    for (uint16_t imgId = 256; imgId < 400; imgId++) {
        swrSprite_NewSprite(imgId, NULL);
    }

    if (initTracks) {
        const int32_t NumCircuits = GetCircuitCount(!hang->isTournamentMode);

        for (int32_t circuitId = 0; circuitId < NumCircuits; circuitId++) {
            for (int32_t trackId = 0; trackId < DEFAULT_NB_CIRCUIT; trackId++) {
                const uint16_t totalTrackId = circuitId * DEFAULT_NB_CIRCUIT + trackId;

                // Init track background
                const uint16_t imgIdxBack = GetImgStartBackground(totalTrackId);
                swrSprite_NewSprite(imgIdxBack, hang->award_wdw_blue_rgb);
                swrSprite_SetFlag(imgIdxBack, 0x8000);

                // Init track border
                const uint16_t imgIdxBorder = GetImgStartBorder(totalTrackId);
                swrSprite_NewSprite(imgIdxBorder, hang->award_wdw_select_blue_rgb);
                swrSprite_SetFlag(imgIdxBorder, 0x8000);

                if (hang->isTournamentMode) {
                    assert(circuitId < DEFAULT_NB_CIRCUIT_PER_TRACK);
                    const uint8_t Bits = trackId * 2;
                    const uint16_t Beat = (g_aBeatTrackPlace[circuitId] >> Bits) & 3;

                    switch (Beat) {
                        // 3rd place
                        case 1: {
                            swrSprite_NewSprite(imgIdxBack, hang->award_third_rgb);
                            break;
                        }

                        // 2nd place
                        case 2: {
                            swrSprite_NewSprite(imgIdxBack, hang->award_second_rgb);
                            break;
                        }

                        // 1st place
                        case 3: {
                            swrSprite_NewSprite(imgIdxBack, hang->award_first_rgb);
                            break;
                        }
                    }
                }
            }
        }
    }
}
