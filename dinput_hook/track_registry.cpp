#include "track_registry.h"

#include <cstdio>
#include <vector>

#include "config.h"
#include "track_catalog.h"
#include "track_env.h"
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
        bool installed;// false = a ghost: listed from the catalog, nothing on disk yet
    };

    std::string install_requested_slug;

    std::vector<RegisteredTrack> registry;
    int installed_track_index = -1;
    // A track whose assets would not bind. Remembered so the course-info screen, which applies
    // every frame, does not re-hash a broken blob per frame, and so it can refuse to start.
    int failed_track_index = -1;
    std::string failed_slug;

    void remove_views() {
        virtual_block_Remove(swrLoader_TYPE_MODEL_BLOCK);
        virtual_block_Remove(swrLoader_TYPE_SPLINE_BLOCK);
        virtual_block_Remove(swrLoader_TYPE_TEXTURE_BLOCK);
        installed_track_index = -1;
    }
}

namespace {
    // Appending a track is safe at any time: the table has headroom, existing entries keep their
    // index, and the menus read trackCount. Renumbering would not be -- a save or a menu could
    // already be holding an index.
    bool register_manifest(TrackManifest &manifest, bool installed) {
        if (trackCount >= MAX_NB_TRACKS) {
            fprintf(hook_log, "[track_registry] no slot left for '%s': the %d track slots are full\n",
                    manifest.slug.c_str(), MAX_NB_TRACKS);
            fflush(hook_log);
            return false;
        }

        const int track_index = trackCount++;

        // Everything the table row carries beyond the geometry comes from the descriptor: the
        // preset the manifest inherits (a track without its own spline races that one's line),
        // then whatever it overrides.
        const TrackEnv env = track_env_FromManifest(manifest);

        // A manifest track loads the stock block entries it declares -- the views substitute their
        // contents -- so its table entry names those entries rather than a custom id range.
        g_aNewTrackInfos[track_index] = (TrackInfo){
            .trackID = (INGAME_MODELID) manifest.model.block_index,
            .splineID = (SPLINEID) env.spline_id,
            .planetTrackNumber = (uint8_t) env.subtrack,
            .PlanetIdx = (uint8_t) env.planet,
            .FavoritePilot = (uint8_t) env.favorite_pilot,
            .unused = 0,
        };
        // Names are looked up as g_aCustomTrackNames[trackId - DEFAULT_NB_TRACKS]
        // (swrUI_GetTrackNameFromId_delta), i.e. by custom ordinal rather than by track index.
        const int name_index = track_index - DEFAULT_NB_TRACKS;
        snprintf(g_aCustomTrackNames[name_index], sizeof(g_aCustomTrackNames[name_index]), "%s",
                 manifest.name.empty() ? manifest.slug.c_str() : manifest.name.c_str());

        fprintf(hook_log,
                "[track_registry] track %d '%s' (%s)%s: model %u, spline %u, planet %d.%d, "
                "pilot %d%s%s\n",
                track_index, g_aCustomTrackNames[name_index], manifest.slug.c_str(),
                installed ? "" : " [not downloaded]", manifest.model.block_index,
                g_aNewTrackInfos[track_index].splineID, env.planet, env.subtrack,
                env.favorite_pilot, env.inherited_from.empty() ? "" : ", inherits ",
                env.inherited_from.c_str());
        fflush(hook_log);

        registry.push_back({std::move(manifest), track_index, installed});
        return true;
    }

    RegisteredTrack *find_by_slug(const std::string &slug) {
        for (RegisteredTrack &track: registry) {
            if (track.manifest.slug == slug)
                return &track;
        }
        return nullptr;
    }

    RegisteredTrack *find_by_index(int track_index) {
        for (RegisteredTrack &track: registry) {
            if (track.track_index == track_index)
                return &track;
        }
        return nullptr;
    }

    // Catalog entries the table does not have yet become ghosts; the menus can show them and the
    // course-info screen downloads one when it is chosen.
    void register_catalog_ghosts() {
        int added = 0;
        for (const CatalogTrack &entry: track_catalog_Tracks()) {
            if (find_by_slug(entry.slug) != nullptr)
                continue;
            TrackManifest manifest;
            if (!track_manifest_Parse(entry.manifest_json, entry.slug.c_str(), &manifest))
                continue;
            manifest.directory = std::filesystem::path("./assets/tracks") / entry.slug;
            if (register_manifest(manifest, entry.installed))
                added++;
        }
        if (added != 0) {
            fprintf(hook_log, "[track_registry] %d catalog track(s) listed for download\n", added);
            fflush(hook_log);
        }
    }
}

void track_registry_Init() {
    for (TrackManifest &manifest: track_manifest_ScanAll())
        register_manifest(manifest, true);

    if (registry.empty()) {
        // Nothing declared: the loose-chunk folder stays available for testing a single entry.
        virtual_block_LoadFolderOverrides();
    } else {
        fprintf(hook_log, "[track_registry] %d manifest track(s), %d track slots used\n",
                (int) registry.size(), (int) trackCount);
        fflush(hook_log);
    }

    // The catalog is what puts tracks the player does not have into track select; fetched on the
    // worker, folded in by track_registry_Tick from the menus.
    if (config::get_int("tracks", "browse_catalog", 1) != 0)
        track_catalog_Refresh();
}

int track_registry_Rescan() {
    int added = 0;
    for (TrackManifest &manifest: track_manifest_ScanAll()) {
        if (RegisteredTrack *known = find_by_slug(manifest.slug)) {
            if (!known->installed) {
                // The download landed: the ghost becomes a track with files behind it.
                known->manifest = std::move(manifest);
                known->installed = true;
                fprintf(hook_log, "[track_registry] track %d '%s' downloaded\n", known->track_index,
                        known->manifest.slug.c_str());
                fflush(hook_log);
            }
            continue;
        }
        if (register_manifest(manifest, true))
            added++;
    }
    if (added != 0) {
        fprintf(hook_log, "[track_registry] %d track(s) added, %d slots used\n", added,
                (int) trackCount);
        fflush(hook_log);
    }
    // A rescan follows a download, which may have replaced the very blob that failed.
    failed_track_index = -1;
    failed_slug.clear();
    return added;
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

extern "C" bool track_registry_IsPointToPoint(int track_index) {
    const TrackManifest *manifest = track_registry_FindByTrackIndex(track_index);
    return manifest != nullptr && manifest->point_to_point;
}

extern "C" void track_registry_ApplyForCurrentTrack() {
    if (registry.empty())
        return;

    const swrObjHang *hang = g_objHang2;
    const int track_index = hang != nullptr ? (int) hang->track_index : -1;
    if (track_index == installed_track_index || track_index == failed_track_index)
        return;

    const RegisteredTrack *track = find_by_index(track_index);

    // The descriptor every consumer of "what track is this" reads from now on, stock or not.
    TrackEnv env;
    if (track != nullptr)
        env = track_env_FromManifest(track->manifest);
    else if (!track_env_FromTableRow(track_index, &env))
        env = {};
    track_env_SetCurrent(env);

    if (track == nullptr || !track->installed) {
        // A stock or legacy track must see the player's own archives, not the last manifest
        // track's entries; a ghost has nothing to map yet.
        remove_views();
        return;
    }
    const TrackManifest *manifest = &track->manifest;

    remove_views();
    if (track_manifest_InstallViews(*manifest)) {
        installed_track_index = track_index;
        return;
    }
    failed_track_index = track_index;
    failed_slug = manifest->slug;
    fprintf(hook_log, "[track_registry] '%s' could not be mapped; the course-info screen will "
                      "refuse to start it\n",
            manifest->slug.c_str());
    fflush(hook_log);
}

extern "C" void track_registry_Tick() {
    if (track_catalog_TakePendingCatalog())
        register_catalog_ghosts();
    if (track_catalog_TakePendingRescan())
        track_registry_Rescan();
}

extern "C" bool track_registry_IsInstalled(int track_index) {
    const RegisteredTrack *track = find_by_index(track_index);
    return track == nullptr || track->installed;
}

extern "C" void track_registry_RequestInstall(int track_index) {
    const RegisteredTrack *track = find_by_index(track_index);
    if (track == nullptr || track->installed)
        return;
    install_requested_slug = track->manifest.slug;
    track_catalog_Install(track->manifest.slug);
}

extern "C" int track_registry_InstallState(int track_index, char *text, int size,
                                           float *fraction) {
    text[0] = '\0';
    *fraction = 0.0f;
    const RegisteredTrack *track = find_by_index(track_index);
    if (track == nullptr || install_requested_slug != track->manifest.slug)
        return 0;

    const CatalogStatus status = track_catalog_Status();
    if (status.state == CatalogState::Downloading && status.active_slug == track->manifest.slug) {
        if (status.bytes_total != 0)
            *fraction = (float) ((double) status.bytes_done / (double) status.bytes_total);
        snprintf(text, size, "%.1f of %.1f MB", status.bytes_done / (1024.0 * 1024.0),
                 status.bytes_total / (1024.0 * 1024.0));
        return 1;
    }
    if (status.state == CatalogState::Fetching) {
        snprintf(text, size, "%s", status.message.c_str());
        return 1;
    }
    if (status.state == CatalogState::Failed) {
        snprintf(text, size, "%s", status.message.c_str());
        return 2;
    }
    return 0;
}

extern "C" bool track_registry_BindFailed(int track_index) {
    return track_index >= 0 && track_index == failed_track_index;
}

bool track_registry_BindFailedSlug(const std::string &slug) {
    return failed_track_index >= 0 && failed_slug == slug;
}
