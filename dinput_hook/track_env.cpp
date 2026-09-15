#include "track_env.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "track_manifest.h"

extern "C" {
#include <globals.h>
#include "game_deltas/tracks_delta.h"// DEFAULT_NB_TRACKS, g_aNewTrackInfos, trackCount

extern FILE *hook_log;
}

namespace {
    const char *STOCK_PREFIX = "vanilla:track:";
    TrackEnv current = {0, 0, 0, 0, false, ""};
}

int track_env_ParseStockSlug(const std::string &slug) {
    const size_t prefix = strlen(STOCK_PREFIX);
    if (slug.compare(0, prefix, STOCK_PREFIX) != 0 || slug.size() == prefix)
        return -1;
    char *end = nullptr;
    const long index = strtol(slug.c_str() + prefix, &end, 10);
    if (*end != '\0' || index < 0 || index >= DEFAULT_NB_TRACKS)
        return -1;
    return (int) index;
}

bool track_env_FromTableRow(int track_index, TrackEnv *out) {
    if (track_index < 0 || track_index >= (int) trackCount)
        return false;
    const TrackInfo &info = g_aNewTrackInfos[track_index];
    *out = {};
    out->planet = info.PlanetIdx;
    out->subtrack = info.planetTrackNumber;
    out->favorite_pilot = info.FavoritePilot;
    out->spline_id = (int) info.splineID;
    out->point_to_point = false;// no stock track is
    return true;
}

TrackEnv track_env_FromManifest(const TrackManifest &manifest) {
    TrackEnv env = {};
    const TrackEnvSpec &spec = manifest.environment;

    const int preset = track_env_ParseStockSlug(spec.inherit);
    if (preset >= 0 && track_env_FromTableRow(preset, &env)) {
        env.inherited_from = spec.inherit;
    } else if (!spec.inherit.empty()) {
        fprintf(hook_log, "[track_env] %s inherits '%s', which is not a stock track; ignored\n",
                manifest.slug.c_str(), spec.inherit.c_str());
        fflush(hook_log);
    }

    if (spec.planet >= 0)
        env.planet = spec.planet;
    if (spec.planet_track_number >= 0)
        env.subtrack = spec.planet_track_number;
    if (spec.favorite_pilot >= 0)
        env.favorite_pilot = spec.favorite_pilot;
    if (manifest.has_spline)
        env.spline_id = (int) manifest.spline.block_index;
    else if (env.inherited_from.empty())
        env.spline_id = (int) manifest.model.block_index;// the entry it replaces, as before
    env.point_to_point = manifest.point_to_point;
    return env;
}

void track_env_SetCurrent(const TrackEnv &env) {
    current = env;
}

const TrackEnv &track_env_Current() {
    return current;
}
