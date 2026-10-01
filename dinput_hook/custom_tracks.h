#pragma once

#include <filesystem>
#include <optional>
#include <cstdint>

#include "types.h"
#include "custom_track_blocks.h"

struct CustomTrack {
    std::filesystem::path folder;
    int model_id;
    int spline_id;
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
