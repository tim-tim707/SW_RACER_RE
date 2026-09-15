// What a track is beyond its geometry: everything the EXE keys on (planet, subtrack) today.
//
// A stock track's descriptor is filled from the game's own track table by those two numbers, so
// nothing changes for it. A manifest track's is filled from the manifest, which may name a stock
// preset to copy ("inherit": "vanilla:track:NN") and override fields on their own. Consumers read
// this, never the two numbers -- that is what lets a track stop standing in for a stock slot one
// field at a time.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TrackManifest;

// A wav the track ships in the content store, named so the environment can refer to it.
struct TrackSoundAsset {
    std::string name;
    std::string sha256;
    uint32_t size;
};

// Weather from a completed lap onward: how many particles, which way the wind blows, and
// optionally how stretched the particles are and how dim the sun goes.
struct TrackWeatherStage {
    int lap;// 0 = from the start, 1 = after the first lap, ...
    int cap;
    float velocity_x;
    float velocity_y;
    float stretch;// <= 0 keeps the current value
    int sun_alpha;// < 0 keeps the current value
};

// One ambient sound cue: plays while the racer's lap progress is inside [start, end] (start > end
// wraps across the finish line), looping or retriggered at random.
struct TrackAmbientCue {
    float start;
    float end;
    std::string sound;// a name (the track's own, or Sounds.map's) or a bank index as digits
    bool random;
};

struct TrackEnv {
    int planet;        // hologram, name, sun and moon, intro cinematic (PlanetIdx)
    int subtrack;      // which of the planet's tracks: node visibility and half of every table index
    int favorite_pilot;// the pilot the course-info screen names
    int spline_id;     // the stock spline a track without one of its own races on
    bool point_to_point;
    std::string inherited_from;// the preset copied, "vanilla:track:NN", or empty

    // The EXE's per-(planet, subtrack) tables, as this track wants them. Empty = whatever the
    // tables say for its planet and subtrack, i.e. what the inherited preset plays. Sounds are
    // names, resolved when the tables are applied: the track's own wavs first (registered into the
    // bank on first use), then data/Sounds.map, or a bank index written as digits.
    std::vector<TrackSoundAsset> sounds;
    std::string music;      // in-race music
    std::string intro_music;// the planet's preload theme
    std::string cutscene;// pre-race .znm in data/, "none" to play nothing, "" to inherit
    bool has_ambient;
    std::vector<TrackAmbientCue> ambient;

    // What swrObjJdge_SetupTrackEnvironment decides from the two numbers: <= 0 / !has_fog =
    // inherit. Fog end is fixed at 1000 in the game; only the start moves (990..996 in stock).
    float draw_distance;
    bool has_fog;
    bool fog_enabled;
    int fog_near;
    int fog_rgb[3];

    // What InitAISettingsForTrack decides: < 0 = inherit. level is the table value the game
    // scales by 0.1 into swrRace_AILevel; script -1 is "no scripted AI", -2 inherits.
    float ai_level;
    float ai_spread_range;
    int ai_script;
    int ai_spline_variant;

    // Weather: what swrPlayerHUD_SetupTrackOverlay and the Ando Prime block in swrObjJdge_F2
    // decide from the two numbers -- a particle colour and stretch, then a stage per completed
    // lap (cap, wind, optional stretch and sun alpha). !has_weather = inherit; has_weather with
    // !weather_enabled = none, whatever planet the track borrowed.
    bool has_weather;
    bool weather_enabled;
    int weather_color[4];
    float weather_stretch;
    std::vector<TrackWeatherStage> weather_stages;
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

// Weather, driven from the descriptor. Start: right after the game's own per-track weather setup.
// Lap: when the player completes one (stages apply in order). Frame: keeps a "no weather" track
// clear of the game's per-camera re-enable. All no-ops for a track that inherits its weather.
void track_env_WeatherOnTrackSetup();
void track_env_WeatherOnLap(int completed_laps);
void track_env_WeatherOnFrame();
