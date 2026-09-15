#include "track_env.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sound_map.h"
#include "track_manifest.h"
#include "game_deltas/swrWeather_delta.h"// swrWeather_Enable_delta / Disable_delta

extern "C" {
#include <Swr/swrModel.h>// SetSunSpriteAlpha_Maybe_ADDR
#include <globals.h>
#include <types.h>
#include "game_deltas/tracks_delta.h"// DEFAULT_NB_TRACKS, g_aNewTrackInfos, trackCount

extern FILE *hook_log;
}

namespace {
    const char *STOCK_PREFIX = "vanilla:track:";
    // The tables' dimensions (swrMusicTrackTable is [8][3]; subtrack 3 is special-cased by the
    // readers and never indexes them).
    constexpr int NUM_PLANETS = 8;
    constexpr int NUM_TABLE_SUBTRACKS = 3;

    TrackEnv env_default() {
        TrackEnv env = {};
        env.draw_distance = -1.0f;
        env.ai_level = -1.0f;
        env.ai_spread_range = -1.0f;
        env.ai_script = -2;
        env.ai_spline_variant = -1;
        env.dust_planet = -1;
        env.holo_tilt = -1000.0f;// any angle is legal, so "not given" is out of range
        env.holo_spin = -1000.0f;
        return env;
    }
    constexpr float HOLO_NOT_GIVEN = -1000.0f;

    TrackEnv current = env_default();

    bool same_name(const std::string &a, const std::string &b) {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); i++) {
            if (tolower((unsigned char) a[i]) != tolower((unsigned char) b[i]))
                return false;
        }
        return true;
    }

    // A sound the track ships, a data/Sounds.map name, or a bank index written as digits.
    int resolve_sound(const TrackEnv &env, const std::string &text, const char *what) {
        if (text.empty())
            return -1;
        for (const TrackSoundAsset &sound: env.sounds) {
            if (same_name(sound.name, text))
                return sound_map_RegisterCustom(sound.sha256, sound.name);
        }
        if (text.find_first_not_of("0123456789") == std::string::npos)
            return atoi(text.c_str());
        const int index = sound_map_IndexOf(text);
        if (index < 0) {
            fprintf(hook_log,
                    "[track_env] %s '%s' is neither one of the track's sounds nor in "
                    "data/Sounds.map; inherited\n",
                    what, text.c_str());
            fflush(hook_log);
        }
        return index;
    }

    // What the tables held before the current track's values were written over them.
    struct SavedEntries {
        bool active;
        int planet;
        int subtrack;
        int16_t music;
        int16_t intro;
        swrSfxCue *ambient;
        char *cinematic;
        char planet_name[0x40];
        float holo_tilt;
        float holo_spin;
    };
    SavedEntries saved = {};
    // The storage the patched pointers point at, alive for as long as the patch is.
    std::vector<swrSfxCue> ambient_storage;
    std::string cinematic_storage;
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
    *out = env_default();
    out->planet = info.PlanetIdx;
    out->subtrack = info.planetTrackNumber;
    out->favorite_pilot = info.FavoritePilot;
    out->spline_id = (int) info.splineID;
    out->point_to_point = false;// no stock track is
    return true;
}

TrackEnv track_env_FromManifest(const TrackManifest &manifest) {
    TrackEnv env = env_default();
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

    for (const TrackSoundSpec &sound: manifest.sounds)
        env.sounds.push_back({sound.name, sound.sha256, sound.size});
    env.music = spec.music;
    env.intro_music = spec.intro_music;
    env.cutscene = spec.cutscene;
    env.has_ambient = spec.has_ambient;
    for (const TrackAmbientCueSpec &cue: spec.ambient)
        env.ambient.push_back({cue.start, cue.end, cue.sound, cue.random});

    env.draw_distance = spec.draw_distance;
    env.has_fog = spec.has_fog;
    env.fog_enabled = spec.fog_enabled;
    env.fog_near = spec.fog_near;
    for (int i = 0; i < 3; i++)
        env.fog_rgb[i] = spec.fog_rgb[i];
    env.ai_level = spec.ai_level;
    env.ai_spread_range = spec.ai_spread_range;
    env.ai_script = spec.ai_script;
    env.ai_spline_variant = spec.ai_spline_variant;

    env.has_weather = spec.has_weather;
    env.weather_enabled = spec.weather_enabled;
    for (int i = 0; i < 4; i++)
        env.weather_color[i] = spec.weather_color[i];
    env.weather_stretch = spec.weather_stretch;
    for (const TrackWeatherStageSpec &stage: spec.weather_stages)
        env.weather_stages.push_back({stage.lap, stage.cap, stage.velocity_x, stage.velocity_y,
                                      stage.stretch, stage.sun_alpha});
    env.dust_planet = spec.dust_planet;
    env.planet_name = spec.planet_name;
    env.holo_tilt = spec.holo_tilt;
    env.holo_spin = spec.holo_spin;
    return env;
}

void track_env_SetCurrent(const TrackEnv &env) {
    current = env;
}

const TrackEnv &track_env_Current() {
    return current;
}

void track_env_RevertTables() {
    if (!saved.active)
        return;
    if (saved.subtrack < NUM_TABLE_SUBTRACKS) {
        swrMusicTrackTable[saved.planet][saved.subtrack] = saved.music;
        swrSfxPreloadSets[saved.planet * NUM_TABLE_SUBTRACKS + saved.subtrack] = saved.ambient;
    }
    swrMusicPlanetIntroTable[saved.planet] = saved.intro;
    swrPlanetIntroCinematics[saved.planet] = saved.cinematic;
    memcpy(swrPlanetTable[saved.planet].name, saved.planet_name, sizeof(saved.planet_name));
    swrPlanetTable[saved.planet].orientationAngle = saved.holo_tilt;
    swrPlanetTable[saved.planet].spinSpeed = saved.holo_spin;
    saved.active = false;
    fprintf(hook_log, "[track_env] tables for planet %d.%d restored\n", saved.planet,
            saved.subtrack);
    fflush(hook_log);
}

void track_env_ApplyTables(const TrackEnv &env) {
    track_env_RevertTables();

    const bool wants_cinematic = !env.cutscene.empty() && env.cutscene != "none";
    const bool wants_identity = !env.planet_name.empty() || env.holo_tilt != HOLO_NOT_GIVEN ||
        env.holo_spin != HOLO_NOT_GIVEN;
    if (env.music.empty() && env.intro_music.empty() && !wants_cinematic && !env.has_ambient &&
        !wants_identity)
        return;

    // Names become bank indices here rather than at registration: the sound system is not up
    // when the registry first reads the manifests, and a custom wav is appended to the bank the
    // first time a track that names it is applied.
    const int music = resolve_sound(env, env.music, "music");
    const int intro_music = resolve_sound(env, env.intro_music, "intro_music");
    struct ResolvedCue {
        const TrackAmbientCue *cue;
        int sound;
    };
    std::vector<ResolvedCue> cues;
    for (const TrackAmbientCue &cue: env.ambient) {
        const int sound = resolve_sound(env, cue.sound, "ambient sound");
        if (sound >= 0)
            cues.push_back({&cue, sound});
    }
    if (env.planet < 0 || env.planet >= NUM_PLANETS || env.subtrack < 0) {
        fprintf(hook_log, "[track_env] planet %d subtrack %d is outside the tables; nothing applied\n",
                env.planet, env.subtrack);
        fflush(hook_log);
        return;
    }

    saved.active = true;
    saved.planet = env.planet;
    saved.subtrack = env.subtrack;
    saved.intro = swrMusicPlanetIntroTable[env.planet];
    saved.cinematic = swrPlanetIntroCinematics[env.planet];
    memcpy(saved.planet_name, swrPlanetTable[env.planet].name, sizeof(saved.planet_name));
    saved.holo_tilt = swrPlanetTable[env.planet].orientationAngle;
    saved.holo_spin = swrPlanetTable[env.planet].spinSpeed;

    // Identity the track defines for itself, in the row the menus read for its planet.
    if (!env.planet_name.empty()) {
        snprintf(swrPlanetTable[env.planet].name, sizeof(swrPlanetTable[env.planet].name), "%s",
                 env.planet_name.c_str());
    }
    if (env.holo_tilt != HOLO_NOT_GIVEN)
        swrPlanetTable[env.planet].orientationAngle = env.holo_tilt;
    if (env.holo_spin != HOLO_NOT_GIVEN)
        swrPlanetTable[env.planet].spinSpeed = env.holo_spin;
    if (env.subtrack < NUM_TABLE_SUBTRACKS) {
        saved.music = swrMusicTrackTable[env.planet][env.subtrack];
        saved.ambient = swrSfxPreloadSets[env.planet * NUM_TABLE_SUBTRACKS + env.subtrack];
    }

    if (music >= 0 && env.subtrack < NUM_TABLE_SUBTRACKS)
        swrMusicTrackTable[env.planet][env.subtrack] = (int16_t) music;
    if (intro_music >= 0)
        swrMusicPlanetIntroTable[env.planet] = (int16_t) intro_music;
    if (wants_cinematic) {
        cinematic_storage = env.cutscene;
        swrPlanetIntroCinematics[env.planet] = cinematic_storage.data();
    }
    if (env.has_ambient && env.subtrack < NUM_TABLE_SUBTRACKS) {
        ambient_storage.clear();
        for (const ResolvedCue &resolved: cues) {
            swrSfxCue entry = {};
            entry.startProgress = resolved.cue->start;
            entry.endProgress = resolved.cue->end;
            entry.soundId = (int16_t) resolved.sound;
            entry.flags = resolved.cue->random ? 1 : 0;
            ambient_storage.push_back(entry);
        }
        swrSfxCue terminator = {};
        terminator.startProgress = -1.0f;// how the reader finds the end of a list
        ambient_storage.push_back(terminator);
        swrSfxPreloadSets[env.planet * NUM_TABLE_SUBTRACKS + env.subtrack] = ambient_storage.data();
    }

    fprintf(hook_log,
            "[track_env] tables for planet %d.%d: music %d (%s), intro %d (%s), cinematic %s, "
            "%d ambient cue(s)\n",
            env.planet, env.subtrack, music, sound_map_NameOf(music).c_str(), intro_music,
            sound_map_NameOf(intro_music).c_str(),
            env.cutscene.empty() ? "inherited" : env.cutscene.c_str(),
            env.has_ambient ? (int) cues.size() : -1);
    fflush(hook_log);
}

bool track_env_SkipCinematic(const char *znm_name) {
    if (current.cutscene != "none" || znm_name == nullptr)
        return false;
    // Only the pre-race planet intros are the track's to skip; the startup movies are not.
    for (int planet = 0; planet < NUM_PLANETS; planet++) {
        const char *entry = swrPlanetIntroCinematics[planet];
        if (entry != nullptr && strcmp(entry, znm_name) == 0)
            return true;
    }
    return false;
}

// The weather particle system is the delta layer's own (swrWeather_delta.cpp) and reads the game's
// globals every frame, so driving weather is writing those globals. The game's setters are still
// HANG stubs here, and Enable/Disable are hooked, so the deltas are called and the values written
// directly.
namespace {
    int weather_stage_applied = -1;

    void set_sun_alpha(int alpha) {
        // Not reimplemented; the game's own routine, by address.
        typedef void(__cdecl * SetSunSpriteAlpha_t)(int index, unsigned char alpha);
        ((SetSunSpriteAlpha_t) SetSunSpriteAlpha_Maybe_ADDR)(0, (unsigned char) alpha);
    }

    void apply_weather_stage(const TrackWeatherStage &stage) {
        swrWeather_particleCap = stage.cap;
        swrWeather_velocityX = stage.velocity_x;
        swrWeather_velocityY = stage.velocity_y;
        if (stage.stretch > 0.0f)
            swrWeather_stretchFactor = stage.stretch;
        if (stage.sun_alpha >= 0)
            set_sun_alpha(stage.sun_alpha);
    }
}

void track_env_WeatherOnTrackSetup() {
    if (!current.has_weather)
        return;
    weather_stage_applied = -1;
    if (!current.weather_enabled) {
        swrWeather_Disable_delta();
        swrWeather_particleCap = 0;
        fprintf(hook_log, "[track_env] weather: none\n");
        fflush(hook_log);
        return;
    }
    swrWeather_Enable_delta();
    for (int i = 0; i < 4; i++)
        swrWeather_particleColor[i] = (uint8_t) current.weather_color[i];
    swrWeather_stretchFactor = current.weather_stretch > 0.0f ? current.weather_stretch : 1.0f;
    swrWeather_particleCap = 0;
    track_env_WeatherOnLap(0);
    fprintf(hook_log, "[track_env] weather: %d stage(s), colour %d %d %d %d, stretch %.1f\n",
            (int) current.weather_stages.size(), current.weather_color[0],
            current.weather_color[1], current.weather_color[2], current.weather_color[3],
            swrWeather_stretchFactor);
    fflush(hook_log);
}

void track_env_WeatherOnLap(int completed_laps) {
    if (!current.has_weather || !current.weather_enabled)
        return;
    // The stage for the most laps completed so far; stages may be listed in any order.
    int best = -1;
    for (size_t i = 0; i < current.weather_stages.size(); i++) {
        const TrackWeatherStage &stage = current.weather_stages[i];
        if (stage.lap <= completed_laps &&
            (best < 0 || stage.lap >= current.weather_stages[best].lap))
            best = (int) i;
    }
    if (best < 0 || best == weather_stage_applied)
        return;
    weather_stage_applied = best;
    apply_weather_stage(current.weather_stages[best]);
}

void track_env_WeatherOnFrame() {
    // swrObjcMan_UpdateCamera re-enables weather every frame for any track's camera; the cap is
    // what actually gates drawing, so a "no weather" track keeps it at zero.
    if (current.has_weather && !current.weather_enabled)
        swrWeather_particleCap = 0;
}
