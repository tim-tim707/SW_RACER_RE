#pragma once

// Parsers for the big-endian block files a custom track ships (out_splineblock.bin /
// out_modelblock.bin). Pure -- no game memory, no file I/O -- so fuzz/ links them standalone.

#include <cstddef>
#include <cstdint>
#include <vector>

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

std::vector<TrackSplineInfo> parse_spline_block(const char *data, size_t size);
std::vector<TrackModelInfo> parse_model_block(const char *data, size_t size);
