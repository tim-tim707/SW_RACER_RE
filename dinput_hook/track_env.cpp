#include "track_env.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sound_map.h"
#include "track_manifest.h"

extern "C" {
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
        return env;
    }

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
    saved.active = false;
    fprintf(hook_log, "[track_env] tables for planet %d.%d restored\n", saved.planet,
            saved.subtrack);
    fflush(hook_log);
}

void track_env_ApplyTables(const TrackEnv &env) {
    track_env_RevertTables();

    const bool wants_cinematic = !env.cutscene.empty() && env.cutscene != "none";
    if (env.music.empty() && env.intro_music.empty() && !wants_cinematic && !env.has_ambient)
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
