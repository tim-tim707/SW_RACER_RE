#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Total number of vanilla tracks
#define DEFAULT_NB_TRACKS 28
// Variations of tracks per planet/circuit
#define DEFAULT_NB_CIRCUIT_PER_TRACK 4
/// == Number of unique planets 7
#define DEFAULT_NB_CIRCUIT (DEFAULT_NB_TRACKS / DEFAULT_NB_CIRCUIT_PER_TRACK)
#define MAX_CUSTOM_TRACKS 70
#define MAX_NB_TRACKS (DEFAULT_NB_TRACKS + MAX_CUSTOM_TRACKS)
#define TRACK_COLOR_B 150
#define TRACK_COLOR_G 80
#define TRACK_COLOR_R 240

extern TrackInfo g_aNewTrackInfos[MAX_NB_TRACKS];

extern int uiX;
extern int uiY;

extern int ui2X;
extern int ui2Y;

void init_customTracks();

void swrRace_MainMenu_delta(swrObjHang *hang);

void HandleCircuits_delta(swrObjHang *hang);

void swrRace_CourseSelectionMenu_delta(void);

void swrRace_CourseInfoMenu_delta(swrObjHang *hang);

char *swrUI_GetTrackNameFromId_delta(int trackId);

bool isTrackPlayable_delta(swrObjHang *hang, char circuitIdx, char trackIdx);

int VerifySelectedTrack_delta(swrObjHang *hang, int selectedTrackIdx);

void swrObjHang_InitTrackSprites_delta(swrObjHang *hang_, int initTracks);

void DrawTracks_delta(swrObjHang *hang, uint8_t circuitIdx);

#ifdef __cplusplus
}
#endif
