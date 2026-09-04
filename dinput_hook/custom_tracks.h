#pragma once

#include <filesystem>
#include <optional>
#include <cstdint>

#include "types.h"

struct CustomTrack {
    std::filesystem::path folder;
    int model_id;
    int spline_id;
};

struct TrackModelInfo {
    int model_id;
    uint32_t hash;
};

struct TrackSplineInfo {
    int spline_id;
    uint32_t hash;
    uint32_t num_control_points;
    // false when the on-disk entry is not a well-formed spline (no control points, or a size that
    // disagrees with the count). Pairing a track with one crashes on the first frame of the race.
    bool bUsable;
};

// The loader's three block file paths, as pointers into the game's own string globals.
// Redirecting them is how a custom track's blocks load in place of data/lev01.
#define SWR_SPLINEBLOCK_PATH_PTR ((const char **) 0x004B9590)
#define SWR_TEXTUREBLOCK_PATH_PTR ((const char **) 0x004B9594)
#define SWR_MODELBLOCK_PATH_PTR ((const char **) 0x004B9598)

extern int currentCustomID;
extern std::optional<CustomTrack> currentCustomTrack;

void init_customTracks();

bool prepare_loading_custom_track_model(MODELID *model_id);
void finalize_loading_custom_track_model(swrModel_Header *header);
void fixup_custom_model(swrModel_Header *header);

bool prepare_loading_custom_track_spline(SPLINEID *spline_id);
void finalize_loading_custom_track_spline(swrSpline *spline);
