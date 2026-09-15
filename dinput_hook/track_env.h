// What a track is beyond its geometry: everything the EXE keys on (planet, subtrack) today.
//
// A stock track's descriptor is filled from the game's own track table by those two numbers, so
// nothing changes for it. A manifest track's is filled from the manifest, which may name a stock
// preset to copy ("inherit": "vanilla:track:NN") and override fields on their own. Consumers read
// this, never the two numbers -- that is what lets a track stop standing in for a stock slot one
// field at a time.
#pragma once

#include <string>

struct TrackManifest;

struct TrackEnv {
    int planet;        // hologram, name, sun and moon, intro cinematic (PlanetIdx)
    int subtrack;      // which of the planet's tracks: node visibility and half of every table index
    int favorite_pilot;// the pilot the course-info screen names
    int spline_id;     // the stock spline a track without one of its own races on
    bool point_to_point;
    std::string inherited_from;// the preset copied, "vanilla:track:NN", or empty
};

// "vanilla:track:NN" -> NN, or -1 for anything else.
int track_env_ParseStockSlug(const std::string &slug);

// The descriptor a row of the track table implies: a stock track, or a legacy custom-track entry.
bool track_env_FromTableRow(int track_index, TrackEnv *out);

// Inherit, then override. A manifest naming no preset and no fields gets planet 0, subtrack 0.
TrackEnv track_env_FromManifest(const TrackManifest &manifest);

// The descriptor of the track the game is loading. Set by the registry at every track load.
void track_env_SetCurrent(const TrackEnv &env);
const TrackEnv &track_env_Current();
