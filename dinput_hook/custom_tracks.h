#pragma once

#include <filesystem>
#include <optional>
#include <cstdint>

#include "types.h"
extern "C" {
#include <globals.h>
}
#include "custom_track_blocks.h"

struct CustomTrack {
    std::filesystem::path folder;
    int model_id;
    int spline_id;
};


// The loader's three block file paths, as pointers into the game's own string globals.
// Redirecting them is how a custom track's blocks load in place of data/lev01.
#define SWR_SPLINEBLOCK_PATH_PTR ((const char **) &swrLoader_spline_path)
#define SWR_TEXTUREBLOCK_PATH_PTR ((const char **) &swrLoader_texture_path)
#define SWR_MODELBLOCK_PATH_PTR ((const char **) &swrLoader_model_path)

extern int currentCustomID;
extern std::optional<CustomTrack> currentCustomTrack;

void init_customTracks();

bool prepare_loading_custom_track_model(MODELID *model_id);
void finalize_loading_custom_track_model(swrModel_Header *header);
void fixup_custom_model(swrModel_Header *header);

bool prepare_loading_custom_track_spline(SPLINEID *spline_id);
void finalize_loading_custom_track_spline(swrSpline *spline);
