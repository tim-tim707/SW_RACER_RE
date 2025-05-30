#include "tracks_delta.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "types.h"
#include "types_enums.h"
#include "globals.h"

#include "General/utils.h"
#include "Swr/swrMultiplayer.h"
#include "Swr/swrObj.h"
#include "Swr/swrSprite.h"
#include "Swr/swrText.h"
#include "Swr/swrUI.h"

extern void FUN_004118b0(void);
extern void FUN_0041e5a0(void);
extern void FUN_0042de10(char *str, int index);
extern void FUN_0043b1d0(swrObjHang *hang);
extern void FUN_0043fe90(short x, short y, int scale);
extern void FUN_00440550(int soundId);
extern void FUN_0045b290(swrObjHang *hang, int *param_2, int param_3);
extern void FUN_0045bee0(swrObjHang *hang, int index, swrObjHang_STATE param_3, int param_4);
extern float FUN_00469b90(float f);
extern void FUN_00469c30(int index, float param_2, int param_3);

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

// 0x004368a0
void swrRace_MainMenu_delta(swrObjHang *hang) {
    // TODO
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

static TrackInfo GetTrackInfo(uint16_t TrackID) {
    if (TrackID >= trackCount) {
        assert(false);
        return (TrackInfo) {};
    }
    return g_aNewTrackInfos[TrackID];
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
            assert(hang->track_index >= DEFAULT_NB_TRACKS);

            char BufferPage[128];
            sprintf(BufferPage, "~c~sCustom Tracks - Page %u/%u", hang->circuitIdx - 3,
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
    // TODO
}

// 0x00440620
char *swrUI_GetTrackNameFromId_delta(int trackId) {
    if (trackId >= trackCount) {
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
    return g_aCustomTrackNames[trackId - 28];
}

// 0x00440aa0
bool isTrackPlayable_delta(swrObjHang *hang, char circuitIdx, char trackIdx) {
    uint8_t tracksBitMask = swrRace_UnlockDataBase[circuitIdx + 1];
    if ((multiplayer_enabled != 0) && (circuitIdx < '\x03')) {
        return true;
    }
    if (hang->isTournamentMode == '\0') {
        if (circuitIdx < 4) {// DELTA
            tracksBitMask = g_aBeatTracksGlobal[circuitIdx];
        } else {// DELTA
            return true;
        }
    }
    return ((uint8_t) (1 << (trackIdx)) & tracksBitMask) != 0;
}

// 0x00440af0
int VerifySelectedTrack_delta(swrObjHang *hang, int selectedTrackIdx) {
    bool bIsPlayable;
    uint8_t TrackCount = 0;
    // DELTA
    const uint8_t NumTracks = GetTrackCount(pState->CircuitIdx);
    if (NumTracks == 0) {
        return -1;
    }
    while ((bIsPlayable = IsTrackPlayable(pState, pState->CircuitIdx, TrackCount),
            !bIsPlayable || (TrackCount != SelectedTrackIdx))) {
        TrackCount++;
        if (TrackCount >= NumTracks) {
            return -1;
        }
    }
    return TrackCount;
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
