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
};

extern int currentCustomID;
extern std::optional<CustomTrack> currentCustomTrack;

void init_customTracks();

bool prepare_loading_custom_track_model(MODELID *model_id);
void finalize_loading_custom_track_model(swrModel_Header *header);

bool prepare_loading_custom_track_spline(SPLINEID *spline_id);
void finalize_loading_custom_track_spline(swrSpline *spline);
