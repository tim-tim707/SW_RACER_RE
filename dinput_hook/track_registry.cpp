#include "track_registry.h"

#include <cstdio>
#include <vector>

#include "virtual_block.h"

extern "C" {
#include <globals.h>// g_objHang2
#include "game_deltas/tracks_delta.h"

extern FILE *hook_log;
}

namespace {
    struct RegisteredTrack {
        TrackManifest manifest;
        int track_index;
    };

    std::vector<RegisteredTrack> registry;
    int installed_track_index = -1;

    void remove_views() {
        virtual_block_Remove(swrLoader_TYPE_MODEL_BLOCK);
        virtual_block_Remove(swrLoader_TYPE_SPLINE_BLOCK);
        virtual_block_Remove(swrLoader_TYPE_TEXTURE_BLOCK);
        installed_track_index = -1;
    }
}

void track_registry_Init() {
    for (TrackManifest &manifest: track_manifest_ScanAll()) {
        if (trackCount >= MAX_NB_TRACKS) {
            fprintf(hook_log, "[track_registry] no slot left for '%s': the %d track slots are full\n",
                    manifest.slug.c_str(), MAX_NB_TRACKS);
            fflush(hook_log);
            break;
        }

        const int track_index = trackCount++;

        // A track that ships no spline of its own races the line of the stock track it stands in
        // for, so take that slot's spline rather than inventing one.
        SPLINEID spline_id = (SPLINEID) manifest.model.block_index;
        if (manifest.has_spline) {
            spline_id = (SPLINEID) manifest.spline.block_index;
        } else if (manifest.placement.overrides_stock_slot >= 0 &&
                   manifest.placement.overrides_stock_slot < DEFAULT_NB_TRACKS) {
            spline_id = g_aNewTrackInfos[manifest.placement.overrides_stock_slot].splineID;
        }

        // A manifest track loads the stock block entries it declares -- the views substitute their
        // contents -- so its table entry names those entries rather than a custom id range.
        g_aNewTrackInfos[track_index] = (TrackInfo){
            .trackID = (INGAME_MODELID) manifest.model.block_index,
            .splineID = spline_id,
            .planetTrackNumber = (uint8_t) manifest.placement.planet_track_number,
            .PlanetIdx = (uint8_t) manifest.placement.planet,
            .FavoritePilot = (uint8_t) manifest.placement.favorite_pilot,
            .unused = 0,
        };
        // Names are looked up as g_aCustomTrackNames[trackId - DEFAULT_NB_TRACKS]
        // (swrUI_GetTrackNameFromId_delta), i.e. by custom ordinal rather than by track index.
        const int name_index = track_index - DEFAULT_NB_TRACKS;
        snprintf(g_aCustomTrackNames[name_index], sizeof(g_aCustomTrackNames[name_index]), "%s",
                 manifest.name.empty() ? manifest.slug.c_str() : manifest.name.c_str());

        fprintf(hook_log,
                "[track_registry] track %d '%s' (%s): model %u, spline %u, planet %d, pilot %d\n",
                track_index, g_aCustomTrackNames[name_index], manifest.slug.c_str(),
                manifest.model.block_index, g_aNewTrackInfos[track_index].splineID,
                manifest.placement.planet, manifest.placement.favorite_pilot);
        fflush(hook_log);

        registry.push_back({std::move(manifest), track_index});
    }

    if (registry.empty()) {
        // Nothing declared: the loose-chunk folder stays available for testing a single entry.
        virtual_block_LoadFolderOverrides();
    } else {
        fprintf(hook_log, "[track_registry] %d manifest track(s), %d track slots used\n",
                (int) registry.size(), (int) trackCount);
        fflush(hook_log);
    }
}

int track_registry_Count() {
    return (int) registry.size();
}

const TrackManifest *track_registry_FindByTrackIndex(int track_index) {
    for (const RegisteredTrack &track: registry) {
        if (track.track_index == track_index)
            return &track.manifest;
    }
    return nullptr;
}

extern "C" void track_registry_ApplyForCurrentTrack() {
    if (registry.empty())
        return;

    const swrObjHang *hang = g_objHang2;
    const int track_index = hang != nullptr ? (int) hang->track_index : -1;
    if (track_index == installed_track_index)
        return;

    const TrackManifest *manifest = track_registry_FindByTrackIndex(track_index);
    if (manifest == nullptr) {
        // A stock or legacy track: it must see the player's own archives, not the last manifest
        // track's entries.
        remove_views();
        return;
    }

    remove_views();
    if (track_manifest_InstallViews(*manifest))
        installed_track_index = track_index;
    else
        fprintf(hook_log, "[track_registry] '%s' could not be mapped; loading stock assets\n",
                manifest->slug.c_str());
    fflush(hook_log);
}
