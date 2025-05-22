#include "tracks_delta.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "types.h"
#include "FUN.h"
#include "globals.h"

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

// 0x0043b240
void swrRace_CourseSelectionMenu_delta(void) {
    // TODO
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
    // TODO
}


// 0x004584a0
void swrObjHang_InitTrackSprites_delta(swrObjHang *hang_, int initTracks) {
    // TODO
}
