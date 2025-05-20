#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "types.h"

#define DEFAULT_NB_TRACKS 28
#define MAX_CUSTOM_TRACKS 70
#define MAX_NB_TRACKS (DEFAULT_NB_TRACKS + MAX_CUSTOM_TRACKS)

const char *getTrackName(int trackId);
