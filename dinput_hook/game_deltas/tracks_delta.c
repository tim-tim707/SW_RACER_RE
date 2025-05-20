#include "tracks_delta.h"

#include <stdbool.h>
#include <stdint.h>

#include "types.h"
#include "FUN.h"
#include "globals.h"

TrackInfo g_aNewTrackInfos[MAX_NB_TRACKS] = {0};
static char g_aCustomTrackNames[MAX_NB_TRACKS][32] = {0};
static uint16_t trackCount = 0;

const char *getTrackName(int trackId) {
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

    return g_aCustomTrackNames[trackId - 28];
}
