#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "types.h"

#define DEFAULT_NB_TRACKS 28
#define MAX_CUSTOM_TRACKS 70
#define MAX_NB_TRACKS (DEFAULT_NB_TRACKS + MAX_CUSTOM_TRACKS)

void swrRace_MainMenu_delta(swrObjHang *hang);

void HandleCircuits_delta(swrObjHang *hang);

void swrRace_CourseSelectionMenu_delta(void);

void swrRace_CourseInfoMenu_delta(swrObjHang *hang);

char *swrUI_GetTrackNameFromId_delta(int trackId);

bool isTrackPlayable_delta(swrObjHang *hang, char circuitIdx, char trackIdx);

int VerifySelectedTrack_delta(swrObjHang *hang, int selectedTrackIdx);

void swrObjHang_InitTrackSprites_delta(swrObjHang *hang_, int initTracks);
