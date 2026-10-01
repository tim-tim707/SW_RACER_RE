#include "custom_track_blocks.h"

#include <string_view>

#include "types.h"
#include "imgui_internal.h"

// Every count and offset below comes from the file, so each is checked against the buffer before
// use: a truncated or hand-edited block must load as "no entries", not read out of bounds.

static uint32_t read_be32(const char *data, size_t offset) {
    return __builtin_bswap32(*(const uint32_t *) &data[offset]);
}

// [begin, end) lies inside the buffer.
static bool entry_in_bounds(uint32_t begin, uint32_t end, size_t size) {
    return begin <= end && end <= size;
}

// Layout: be32 count, then count + 1 be32 offsets (entry i spans offsets[i] .. offsets[i + 1]).
std::vector<TrackSplineInfo> parse_spline_block(const char *data, size_t size) {
    if (size < sizeof(uint32_t))
        return {};

    const uint32_t num_entries = read_be32(data, 0);
    if (size < 2 * sizeof(uint32_t) || num_entries > size / sizeof(uint32_t) - 2)
        return {};

    std::vector<TrackSplineInfo> hashes(num_entries);
    for (uint32_t i = 0; i < num_entries; i++) {
        const uint32_t entry_begin = read_be32(data, 4 * (i + 1));
        const uint32_t entry_end = read_be32(data, 4 * (i + 2));
        hashes[i] = {
            .spline_id = (int) i,
            .hash = 0,
            .num_control_points = 0,
            .bUsable = false,
        };
        if (!entry_in_bounds(entry_begin, entry_end, size))
            continue;
        hashes[i].hash = ImHashData(&data[entry_begin], entry_end - entry_begin);

        // An entry is a big-endian swrSpline header followed by its control points, so its size
        // is determined by the control point count -- exact for all 91 stock entries. Pairing a
        // track with an entry that fails this hands swrSpline_Interpolate a garbage array.
        if (entry_end - entry_begin < sizeof(swrSpline))
            continue;

        const uint32_t num_control_points =
            read_be32(data, entry_begin + offsetof(swrSpline, num_control_points));
        hashes[i].num_control_points = num_control_points;
        hashes[i].bUsable = num_control_points > 0 &&
                            (uint64_t) (entry_end - entry_begin) ==
                                sizeof(swrSpline) + (uint64_t) num_control_points * sizeof(swrSplineControlPoint);
    }

    return hashes;
}

// Layout: be32 count, then count (begin, end) be32 offset pairs starting at byte 8.
std::vector<TrackModelInfo> parse_model_block(const char *data, size_t size) {
    if (size < sizeof(uint32_t))
        return {};

    const uint32_t num_entries = read_be32(data, 0);
    if (size < 2 * sizeof(uint32_t) || num_entries > (size / sizeof(uint32_t) - 2) / 2)
        return {};

    std::vector<TrackModelInfo> track_infos;
    for (uint32_t i = 0; i < num_entries; i++) {
        const uint32_t entry_begin = read_be32(data, 4 * (2 * i + 2));
        const uint32_t entry_end = read_be32(data, 4 * (2 * i + 3));
        if (!entry_in_bounds(entry_begin, entry_end, size) || entry_end - entry_begin < 4)
            continue;
        if (std::string_view(&data[entry_begin], 4) == "Trak") {
            track_infos.emplace_back() = {
                .model_id = (int) i,
                .hash = ImHashData(&data[entry_begin], entry_end - entry_begin),
            };
        }
    }

    return track_infos;
}

// The on-disk spline entry layout the size check in parse_spline_block relies on.
static_assert(sizeof(swrSpline) == 0x10);
static_assert(sizeof(swrSplineControlPoint) == 0x54);
