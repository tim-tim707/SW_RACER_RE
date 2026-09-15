// What a track is beyond its geometry: everything the EXE keys on (planet, subtrack) today.
//
// A stock track's descriptor is filled from the game's own track table by those two numbers, so
// nothing changes for it. A manifest track's is filled from the manifest, which may name a stock
// preset to copy ("inherit": "vanilla:track:NN") and override fields on their own. Consumers read
// this, never the two numbers -- that is what lets a track stop standing in for a stock slot one
// field at a time.
#pragma once

#include <string>
#include <vector>

struct TrackManifest;

// One ambient sound cue: plays while the racer's lap progress is inside [start, end] (start > end
// wraps across the finish line), looping or retriggered at random.
struct TrackAmbientCue {
    float start;
    float end;
    int sound;// bank index
    bool random;
};

struct TrackEnv {
    int planet;        // hologram, name, sun and moon, intro cinematic (PlanetIdx)
    int subtrack;      // which of the planet's tracks: node visibility and half of every table index
    int favorite_pilot;// the pilot the course-info screen names
    int spline_id;     // the stock spline a track without one of its own races on
    bool point_to_point;
    std::string inherited_from;// the preset copied, "vanilla:track:NN", or empty

    // The EXE's per-(planet, subtrack) tables, as this track wants them. -1 / empty = whatever
    // the tables say for its planet and subtrack, i.e. what the inherited preset plays.
    int music;         // in-race music, bank index
    int intro_music;   // the planet's preload theme, bank index
    std::string cutscene;// pre-race .znm in data/, "none" to play nothing, "" to inherit
    bool has_ambient;
    std::vector<TrackAmbientCue> ambient;
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

// Make the EXE's tables say what the descriptor says, for its (planet, subtrack), until the next
// call: music, intro theme, ambient cue list, pre-race cinematic. The readers are untouched --
// they index the same tables they always did. Entries are restored before a new set is written,
// so a stock track sees the original values.
void track_env_ApplyTables(const TrackEnv &env);
void track_env_RevertTables();

// Whether the cinematic about to play is one the current track asked to skip.
bool track_env_SkipCinematic(const char *znm_name);
