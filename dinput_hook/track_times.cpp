#include "track_times.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>

#include <simdjson.h>

#include "build_id.h"// SWR_BUILD_* (generated at build time)
#include "hash_util.h"
#include "track_registry.h"
#include "virtual_block.h"

extern "C" {
#include <Swr/swrObj.h>
#include <Swr/swrRace.h>
#include <Swr/swrSprite.h>
#include <Swr/swrText.h>
#include <engine_config.h>// ELFSAVE_RECORD_TIME_EMPTY
#include <globals.h>
#include <types.h>
#include <types_enums.h>
#include "game_deltas/tracks_delta.h"// DEFAULT_NB_TRACKS, g_aNewTrackInfos

extern FILE *hook_log;
}

namespace {
    // Its own file: the save image is a fixed 0xfd4 bytes with a checksum over it, so there is
    // nowhere in it for any of this, and it holds the game's own records regardless.
    const char *TIMES_PATH = "./assets/custom_times.json";
    constexpr int SCHEMA = 2;
    constexpr int NUM_UPGRADES = 7;

    struct StoredRecord {
        TrackTimeKey key;
        TrackRecord record;
    };

    std::vector<StoredRecord> records;
    bool loaded = false;

    bool same_key(const TrackTimeKey &a, const TrackTimeKey &b) {
        return a.slug == b.slug && a.content_hash == b.content_hash && a.mirror == b.mirror &&
            a.laps == b.laps && a.upgrades == b.upgrades;
    }

    TrackHalfRecord empty_half() {
        TrackHalfRecord half = {};
        half.time = ELFSAVE_RECORD_TIME_EMPTY;
        return half;
    }

    void read_run(simdjson::dom::element parent, TrackRunDetail *run) {
        int64_t number = 0;
        parent["pilot"].get(number);
        run->pilot = (int) number;

        const auto read_bytes = [&](const char *key, uint8_t *out) {
            simdjson::dom::array values;
            if (parent[key].get(values) != simdjson::SUCCESS)
                return;
            int i = 0;
            for (simdjson::dom::element value: values) {
                if (i >= NUM_UPGRADES)
                    break;
                int64_t byte = 0;
                value.get(byte);
                out[i++] = (uint8_t) byte;
            }
        };
        read_bytes("upgrade_levels", run->upgrade_levels);
        read_bytes("upgrade_health", run->upgrade_health);

        double value = 0.0;
        parent["fps_min"].get(value);
        run->fps_min = (float) value;
        value = 0.0;
        parent["fps_avg"].get(value);
        run->fps_avg = (float) value;

        simdjson::dom::array splits;
        if (parent["lap_splits"].get(splits) == simdjson::SUCCESS) {
            for (simdjson::dom::element split: splits) {
                double lap = 0.0;
                split.get(lap);
                run->lap_splits.push_back((float) lap);
            }
        }

        std::string_view text;
        if (parent["date"].get(text) == simdjson::SUCCESS)
            run->date = std::string(text);
        if (parent["build"].get(text) == simdjson::SUCCESS)
            run->build = std::string(text);
    }

    void load() {
        loaded = true;
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.load(TIMES_PATH).get(root) != simdjson::SUCCESS)
            return;// no file yet, or unreadable: start empty rather than refusing to record

        int64_t schema = 0;
        root["schema"].get(schema);
        if (schema != SCHEMA) {
            fprintf(hook_log,
                    "[track_times] %s is schema %lld, this build reads %d -- starting fresh "
                    "(the old file is left alone)\n",
                    TIMES_PATH, (long long) schema, SCHEMA);
            fflush(hook_log);
            return;
        }

        simdjson::dom::array entries;
        if (root["records"].get(entries) != simdjson::SUCCESS)
            return;

        for (simdjson::dom::element entry: entries) {
            StoredRecord stored = {};
            stored.record.total = empty_half();
            stored.record.lap = empty_half();

            std::string_view text;
            if (entry["slug"].get(text) != simdjson::SUCCESS)
                continue;
            stored.key.slug = std::string(text);
            if (entry["content_hash"].get(text) == simdjson::SUCCESS)
                stored.key.content_hash = std::string(text);

            bool flag = false;
            entry["mirror"].get(flag);
            stored.key.mirror = flag;
            flag = false;
            entry["upgrades"].get(flag);
            stored.key.upgrades = flag;

            int64_t number = 0;
            entry["laps"].get(number);
            stored.key.laps = (int) number;

            const auto read_half = [&](const char *name, TrackHalfRecord *half) {
                simdjson::dom::element element;
                if (entry[name].get(element) != simdjson::SUCCESS)
                    return;
                double value = ELFSAVE_RECORD_TIME_EMPTY;
                element["time"].get(value);
                half->time = (float) value;
                std::string_view holder;
                if (element["holder"].get(holder) == simdjson::SUCCESS)
                    half->holder = std::string(holder);
                read_run(element, &half->run);
            };
            read_half("race", &stored.record.total);
            read_half("lap", &stored.record.lap);

            records.push_back(std::move(stored));
        }
        fprintf(hook_log, "[track_times] %d record(s) loaded\n", (int) records.size());
        fflush(hook_log);
    }

    // Player names come from a profile, so they can hold whatever the name-entry screen allows.
    std::string escaped(const std::string &text) {
        std::string out;
        for (char c: text) {
            if (c == '"' || c == '\\') {
                out.push_back('\\');
                out.push_back(c);
            } else if ((unsigned char) c >= 0x20) {
                out.push_back(c);
            }
        }
        return out;
    }

    void write_bytes(FILE *f, const char *key, const uint8_t *values) {
        fprintf(f, "\"%s\": [", key);
        for (int i = 0; i < NUM_UPGRADES; i++)
            fprintf(f, "%s%u", i == 0 ? "" : ", ", values[i]);
        fprintf(f, "]");
    }

    void write_half(FILE *f, const char *name, const TrackHalfRecord &half) {
        fprintf(f, "      \"%s\": {\"time\": %.3f, \"holder\": \"%s\", \"pilot\": %d, ", name,
                half.time, escaped(half.holder).c_str(), half.run.pilot);
        write_bytes(f, "upgrade_levels", half.run.upgrade_levels);
        fprintf(f, ", ");
        write_bytes(f, "upgrade_health", half.run.upgrade_health);
        fprintf(f, ", \"fps_min\": %.1f, \"fps_avg\": %.1f, \"lap_splits\": [", half.run.fps_min,
                half.run.fps_avg);
        for (size_t i = 0; i < half.run.lap_splits.size(); i++)
            fprintf(f, "%s%.3f", i == 0 ? "" : ", ", half.run.lap_splits[i]);
        fprintf(f, "], \"date\": \"%s\", \"build\": \"%s\"}", escaped(half.run.date).c_str(),
                escaped(half.run.build).c_str());
    }

    // Written whole each time: there are a handful of records, and rewriting is what makes a torn
    // file impossible to leave behind.
    void save() {
        FILE *f = fopen(TIMES_PATH, "wb");
        if (!f) {
            fprintf(hook_log, "[track_times] cannot write %s\n", TIMES_PATH);
            fflush(hook_log);
            return;
        }

        fprintf(f, "{\n  \"schema\": %d,\n  \"records\": [\n", SCHEMA);
        for (size_t i = 0; i < records.size(); i++) {
            const StoredRecord &stored = records[i];
            fprintf(f,
                    "    {\n      \"slug\": \"%s\", \"content_hash\": \"%s\",\n"
                    "      \"mirror\": %s, \"laps\": %d, \"upgrades\": %s,\n",
                    escaped(stored.key.slug).c_str(), escaped(stored.key.content_hash).c_str(),
                    stored.key.mirror ? "true" : "false", stored.key.laps,
                    stored.key.upgrades ? "true" : "false");
            write_half(f, "race", stored.record.total);
            fprintf(f, ",\n");
            write_half(f, "lap", stored.record.lap);
            fprintf(f, "\n    }%s\n", i + 1 < records.size() ? "," : "");
        }
        fprintf(f, "  ]\n}\n");
        fclose(f);
    }

    // fps over the run, sampled per frame while racing. The physics is fixed-timestep, so this is
    // not about correctness -- it is what tells a reviewer the run was not made at 12 or 900 fps.
    struct FrameStats {
        int frames;
        double seconds;
        float worst_fps;
    };
    FrameStats frame_stats = {};
    bool results_taken = true;

    // Hashing what was actually raced is what says a stock time was set on unmodified geometry.
    // Keyed by the pair, because that is what a track is made of.
    std::string stock_assets_hash(int model_id, int spline_id) {
        static int cached_model = -1;
        static int cached_spline = -1;
        static std::string cached_hash;
        if (model_id == cached_model && spline_id == cached_spline)
            return cached_hash;

        std::vector<uint8_t> model;
        std::vector<uint8_t> spline;
        std::string hash;
        if (virtual_block_ReadEntry(swrLoader_TYPE_MODEL_BLOCK, (uint32_t) model_id, &model) &&
            virtual_block_ReadEntry(swrLoader_TYPE_SPLINE_BLOCK, (uint32_t) spline_id, &spline)) {
            model.insert(model.end(), spline.begin(), spline.end());
            sha256_hex(model.data(), model.size(), &hash);
        }

        cached_model = model_id;
        cached_spline = spline_id;
        cached_hash = hash;
        return hash;
    }

    // The key for whatever track the game is on. A custom track is named by its manifest; a stock
    // track by its slot and the assets it loaded.
    bool current_key(const swrObjHang *hang, int profile_index, TrackTimeKey *out) {
        if (hang == nullptr)
            return false;

        char laps = hang->numLaps;
        if (hang->isTournamentMode != 0)
            laps = 3;// a tournament race is always three, whatever the menu last held

        out->mirror = hang->bMirror != 0;
        out->laps = laps;
        out->upgrades = track_times_ProfileHasUpgrades(profile_index);

        const int track_index = (int) hang->track_index;
        const TrackManifest *manifest = track_registry_FindByTrackIndex(track_index);
        if (manifest != nullptr) {
            out->slug = manifest->slug;
            out->content_hash = manifest->content_hash;
            return true;
        }

        if (track_index < 0 || track_index >= DEFAULT_NB_TRACKS)
            return false;// a legacy folder pack: no stable identity to record against

        char slug[32];
        snprintf(slug, sizeof(slug), "vanilla:track:%02d", track_index);
        out->slug = slug;
        const TrackInfo &info = g_aNewTrackInfos[track_index];
        out->content_hash = stock_assets_hash(info.trackID, info.splineID);
        return true;
    }

    TrackRunDetail run_detail(int profile_index) {
        TrackRunDetail run = {};
        run.pilot = swrRace_aProfiles[profile_index].pilotId;
        memcpy(run.upgrade_levels, swrRace_aProfiles[profile_index].upgradeLevels, NUM_UPGRADES);
        memcpy(run.upgrade_health, swrRace_aProfiles[profile_index].upgradeHealths, NUM_UPGRADES);
        run.fps_min = frame_stats.worst_fps;
        run.fps_avg = frame_stats.seconds > 0.0
            ? (float) (frame_stats.frames / frame_stats.seconds)
            : 0.0f;

        const time_t now = time(nullptr);
        char stamp[32] = {};
        strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
        run.date = stamp;
        char build[64];
    snprintf(build, sizeof(build), "%s@%s%s", SWR_BUILD_BRANCH, SWR_BUILD_COMMIT,
             SWR_BUILD_DIRTY ? "-dirty" : "");
    run.build = build;
        return run;
    }
}

bool track_times_Get(const TrackTimeKey &key, TrackRecord *out) {
    if (!loaded)
        load();

    for (const StoredRecord &stored: records) {
        if (same_key(stored.key, key)) {
            *out = stored.record;
            return true;
        }
    }

    out->total = empty_half();
    out->lap = empty_half();
    return false;
}

bool track_times_Submit(const TrackTimeKey &key, const TrackRecord &record) {
    if (!loaded)
        load();

    StoredRecord *existing = nullptr;
    for (StoredRecord &stored: records) {
        if (same_key(stored.key, key)) {
            existing = &stored;
            break;
        }
    }
    if (existing == nullptr) {
        records.push_back({key, {empty_half(), empty_half()}});
        existing = &records.back();
    }

    // Each half stands on its own, the way the save image keeps them: a good lap in a bad race
    // still counts, and the two records may belong to different players on different pods.
    bool improved = false;
    if (record.total.time < existing->record.total.time) {
        existing->record.total = record.total;
        improved = true;
    }
    if (record.lap.time < existing->record.lap.time) {
        existing->record.lap = record.lap;
        improved = true;
    }
    if (!improved)
        return false;

    fprintf(hook_log,
            "[track_times] %s (%s laps %d%s%s): race %.3f lap %.3f by '%s' pilot %d, "
            "fps %.0f/%.0f\n",
            key.slug.c_str(), key.content_hash.substr(0, 8).c_str(), key.laps,
            key.mirror ? " mirror" : "", key.upgrades ? " upgraded" : " stock",
            existing->record.total.time, existing->record.lap.time,
            existing->record.total.holder.c_str(), existing->record.total.run.pilot,
            existing->record.total.run.fps_min, existing->record.total.run.fps_avg);
    fflush(hook_log);
    save();
    return true;
}

bool track_times_ProfileHasUpgrades(int profile_index) {
    if (profile_index < 0 || profile_index >= 4)
        return false;

    const swrSaveProfile &profile = swrRace_aProfiles[profile_index];
    for (char level: profile.upgradeLevels) {
        if (level != 0)
            return true;
    }
    return false;
}

extern "C" void track_times_OnRaceStart() {
    results_taken = false;
    frame_stats = {0, 0.0, 0.0f};
}

extern "C" void track_times_OnRaceFrame() {
    const double delta = swrRace_deltaTimeSecs;
    if (delta <= 0.0)
        return;

    frame_stats.frames++;
    frame_stats.seconds += delta;

    // Ignore the first frames of a race: the track has just loaded and the first deltas are the
    // load, not the run.
    const float fps = (float) (1.0 / delta);
    if (frame_stats.frames > 30 && (frame_stats.worst_fps == 0.0f || fps < frame_stats.worst_fps))
        frame_stats.worst_fps = fps;
}

extern "C" void track_times_OnResults(swrObjHang *hang) {
    if (results_taken)
        return;

    TrackTimeKey key;
    if (!current_key(hang, 0, &key))
        return;

    results_taken = true;
    const int locals = hang->num_local_players < 1 ? 1 : hang->num_local_players;
    for (int player = 0; player < locals; player++) {
        const swrScore &score = swrScores[player];

        // Same shape as the game's own record commit: the total is the race, the lap record is the
        // best of the laps actually run (a non-positive entry ends the run). The score struct holds
        // five, so a longer race records the splits it has.
        TrackRunDetail run = run_detail(player);
        float best_lap = ELFSAVE_RECORD_TIME_EMPTY;
        for (int lap = 0; lap < key.laps && lap < 5; lap++) {
            const float lap_time = (&score.results_P1_Lap1)[lap];
            if (lap_time <= 0.0f)
                break;
            run.lap_splits.push_back(lap_time);
            if (lap_time < best_lap)
                best_lap = lap_time;
        }

        TrackRecord candidate;
        candidate.total = {score.results_P1_total_time, swrRace_aProfiles[player].name, run};
        candidate.lap = {best_lap, swrRace_aProfiles[player].name, run};

        if (candidate.total.time >= ELFSAVE_RECORD_TIME_EMPTY &&
            candidate.lap.time >= ELFSAVE_RECORD_TIME_EMPTY)
            continue;// did not finish and set no lap: nothing to record

        if (player != 0)
            key.upgrades = track_times_ProfileHasUpgrades(player);
        track_times_Submit(key, candidate);
    }
}

extern "C" bool track_times_DrawCourseInfoRecords(swrObjHang *hang) {
    // Only where the game cannot draw its own: a stock track keeps its save-image records on
    // screen, and records them here as well.
    if (hang == nullptr || track_registry_FindByTrackIndex((int) hang->track_index) == nullptr)
        return false;

    TrackTimeKey key;
    if (!current_key(hang, 0, &key))
        return false;

    TrackRecord record;
    track_times_Get(key, &record);

    // The same two columns the stock screen draws (swrUI_Front_DrawRecord plus the pilot blocks in
    // swrRace_CourseInfoMenu): label, time, the holder's name, then the pilot they set it on --
    // name and portrait, from the stock sprite slots so it is the same art as the rest of the
    // screen.
    const struct {
        int x;
        char *label;
        const TrackHalfRecord *half;
        int sprite_base;
    } columns[] = {
        {100, "/SCREENTEXT_545/~f4~c~s3-Lap Record", &record.total, 23},
        {220, "/SCREENTEXT_546/~f4~c~sBest Lap", &record.lap, 46},
    };

    for (const auto &column: columns) {
        swrText_CreateTextEntry1(column.x, 55, 0x32, -1, -1, 255, swrText_Translate(column.label));
        if (column.half->time >= ELFSAVE_RECORD_TIME_EMPTY) {
            swrText_CreateTextEntry1(column.x, 62, 0x32, -1, -1, 255, "~c~s--:--.--- ---");
            continue;
        }

        swrText_CreateTimeEntryFormat(column.x + 0x1e, 62, column.half->time, 0x32, -1, -1, 255, 1);

        char text[64] = {};
        snprintf(text, sizeof(text), "%s", column.half->holder.c_str());
        swrRace_DrawRecordHolderName((float) column.x, 70.0f, 255.0f, text);

        const int pilot = column.half->run.pilot;
        if (pilot < 0 || pilot >= 23)
            continue;// not a pilot we can name or draw

        snprintf(text, sizeof(text), "~f4~c~s%s %s",
                 swrText_Translate(swrRacer_PodData[pilot].name),
                 swrText_Translate(swrRacer_PodData[pilot].lastname));
        swrText_CreateTextEntry1(column.x, 78, 163, 190, 17, 255, text);
        swrSprite_SetVisible((short) (column.sprite_base + pilot), true);
        swrSprite_SetPos((short) (column.sprite_base + pilot), column.x - 16, 85);
        swrSprite_SetDim((short) (column.sprite_base + pilot), 0.5f, 0.5f);
        swrSprite_SetColor((short) (column.sprite_base + pilot), 255, 255, 255, 255);
    }
    return true;
}
