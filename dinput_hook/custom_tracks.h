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
    // doesn't match the control point count). Pairing a track with one of these is what produces a
    // garbage swrSpline::control_points and a crash on the first frame of the race.
    bool bUsable;
};

extern int currentCustomID;
extern std::optional<CustomTrack> currentCustomTrack;

void init_customTracks();

bool prepare_loading_custom_track_model(MODELID *model_id);
void finalize_loading_custom_track_model(swrModel_Header *header);
void fixup_custom_model(swrModel_Header *header);

bool prepare_loading_custom_track_spline(SPLINEID *spline_id);
void finalize_loading_custom_track_spline(swrSpline *spline);
