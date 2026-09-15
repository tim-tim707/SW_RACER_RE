#include "track_times.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>

#include <simdjson.h>

#include "build_id.h"// SWR_BUILD_* (generated at build time)
#include "hash_util.h"
#include "junkyard_account.h"
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
    // swrScore holds results_P1_Lap1..Lap5, so a run reports at most this many splits however
    // many laps it was set to.
    constexpr int NUM_SCORE_LAP_SPLITS = 5;
    // The first frames of a race time the track load, not the run.
    constexpr int FPS_WARMUP_FRAMES = 30;

    struct StoredRecord {
        TrackTimeKey key;
        TrackRecord record;
        std::string submission;// "pending" | "done" | "rejected" (track_times.h)
    };

    // The results screen writes on the game thread; the submission worker reads and marks from
    // its own. Recursive because the display path calls track_times_Get while already holding it.
    std::recursive_mutex &records_mutex = *new std::recursive_mutex;// never destroyed, see track_catalog.cpp
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

            // A record from before the outbox existed has never been sent, so it is pending.
            stored.submission = "pending";
            if (entry["submission"].get(text) == simdjson::SUCCESS)
                stored.submission = std::string(text);

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

    void appendf(std::string *out, const char *format, ...) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        const int length = vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        if (length < 0)
            return;
        if ((size_t) length < sizeof(buffer)) {
            out->append(buffer, (size_t) length);
            return;
        }
        std::string large((size_t) length + 1, '\0');
        va_start(args, format);
        vsnprintf(large.data(), large.size(), format, args);
        va_end(args);
        out->append(large.data(), (size_t) length);
    }

    void write_bytes(std::string *out, const char *key, const uint8_t *values) {
        appendf(out, "\"%s\": [", key);
        for (int i = 0; i < NUM_UPGRADES; i++)
            appendf(out, "%s%u", i == 0 ? "" : ", ", values[i]);
        appendf(out, "]");
    }

    void write_half(std::string *out, const char *name, const TrackHalfRecord &half) {
        appendf(out, "      \"%s\": {\"time\": %.3f, \"holder\": \"%s\", \"pilot\": %d, ", name,
                half.time, escaped(half.holder).c_str(), half.run.pilot);
        write_bytes(out, "upgrade_levels", half.run.upgrade_levels);
        appendf(out, ", ");
        write_bytes(out, "upgrade_health", half.run.upgrade_health);
        appendf(out, ", \"fps_min\": %.1f, \"fps_avg\": %.1f, \"lap_splits\": [",
                half.run.fps_min, half.run.fps_avg);
        for (size_t i = 0; i < half.run.lap_splits.size(); i++)
            appendf(out, "%s%.3f", i == 0 ? "" : ", ", half.run.lap_splits[i]);
        appendf(out, "], \"date\": \"%s\", \"build\": \"%s\"}", escaped(half.run.date).c_str(),
                escaped(half.run.build).c_str());
    }

    // The file format, for the whole store or for the subset a submission carries.
    std::string serialize(const std::vector<const StoredRecord *> &subset) {
        std::string out;
        appendf(&out, "{\n  \"schema\": %d,\n  \"records\": [\n", SCHEMA);
        for (size_t i = 0; i < subset.size(); i++) {
            const StoredRecord &stored = *subset[i];
            appendf(&out,
                    "    {\n      \"slug\": \"%s\", \"content_hash\": \"%s\",\n"
                    "      \"mirror\": %s, \"laps\": %d, \"upgrades\": %s, \"submission\": \"%s\",\n",
                    escaped(stored.key.slug).c_str(), escaped(stored.key.content_hash).c_str(),
                    stored.key.mirror ? "true" : "false", stored.key.laps,
                    stored.key.upgrades ? "true" : "false", escaped(stored.submission).c_str());
            write_half(&out, "race", stored.record.total);
            appendf(&out, ",\n");
            write_half(&out, "lap", stored.record.lap);
            appendf(&out, "\n    }%s\n", i + 1 < subset.size() ? "," : "");
        }
        appendf(&out, "  ]\n}\n");
        return out;
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
        std::vector<const StoredRecord *> all;
        for (const StoredRecord &stored: records)
            all.push_back(&stored);
        const std::string text = serialize(all);
        fwrite(text.data(), 1, text.size(), f);
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

// Records are stored under the laps actually driven, which a point-to-point track ends after one
// of however many the menu asked for. So: the exact key, else the only record under these
// conditions. A track that really does have records at several lap counts matches exactly and
// never reaches the fallback.
static bool find_record_for_display(const TrackTimeKey &key, TrackRecord *out) {
    std::lock_guard<std::recursive_mutex> lock(records_mutex);
    if (track_times_Get(key, out))
        return true;

    const StoredRecord *only = nullptr;
    for (const StoredRecord &stored: records) {
        if (stored.key.slug != key.slug || stored.key.content_hash != key.content_hash ||
            stored.key.mirror != key.mirror || stored.key.upgrades != key.upgrades)
            continue;
        if (only != nullptr)
            return false;// several lap counts and none of them is the one being raced
        only = &stored;
    }
    if (only == nullptr)
        return false;

    *out = only->record;
    return true;
}

bool track_times_Get(const TrackTimeKey &key, TrackRecord *out) {
    std::lock_guard<std::recursive_mutex> lock(records_mutex);
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
    std::unique_lock<std::recursive_mutex> lock(records_mutex);
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
        records.push_back({key, {empty_half(), empty_half()}, "pending"});
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
    existing->submission = "pending";
    save();
    lock.unlock();
    junkyard_account_OnRecordStored();
    return true;
}

int track_times_PendingCount() {
    std::lock_guard<std::recursive_mutex> lock(records_mutex);
    if (!loaded)
        load();
    int count = 0;
    for (const StoredRecord &stored: records) {
        if (stored.submission == "pending")
            count++;
    }
    return count;
}

std::string track_times_PendingSubmissionBody(std::vector<TrackTimeKey> *keys) {
    std::lock_guard<std::recursive_mutex> lock(records_mutex);
    if (!loaded)
        load();
    std::vector<const StoredRecord *> pending;
    for (const StoredRecord &stored: records) {
        if (stored.submission == "pending") {
            pending.push_back(&stored);
            keys->push_back(stored.key);
        }
    }
    return pending.empty() ? std::string() : serialize(pending);
}

void track_times_MarkSubmission(const std::vector<TrackTimeKey> &keys, const char *state) {
    std::lock_guard<std::recursive_mutex> lock(records_mutex);
    bool changed = false;
    for (StoredRecord &stored: records) {
        for (const TrackTimeKey &key: keys) {
            if (same_key(stored.key, key) && stored.submission != state) {
                stored.submission = state;
                changed = true;
            }
        }
    }
    if (changed)
        save();
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

    const float fps = (float) (1.0 / delta);
    if (frame_stats.frames > FPS_WARMUP_FRAMES &&
        (frame_stats.worst_fps == 0.0f || fps < frame_stats.worst_fps))
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

        // An undriven lap reads back as the empty-record value, not zero (the results sanitizer
        // clamps out-of-range to it). The lap count comes from the run rather than the setting:
        // keying on the requested laps would file a one-traversal track against three-lap runs.
        TrackRunDetail run = run_detail(player);
        float best_lap = ELFSAVE_RECORD_TIME_EMPTY;
        for (int lap = 0; lap < key.laps && lap < NUM_SCORE_LAP_SPLITS; lap++) {
            const float lap_time = (&score.results_P1_Lap1)[lap];
            if (lap_time <= 0.0f || lap_time >= ELFSAVE_RECORD_TIME_EMPTY)
                break;
            run.lap_splits.push_back(lap_time);
            if (lap_time < best_lap)
                best_lap = lap_time;
        }
        if (!run.lap_splits.empty())
            key.laps = (int) run.lap_splits.size();

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
    const bool have = find_record_for_display(key, &record);

    // A point-to-point track has a time, not a lap record. The manifest flag answers that before
    // anything has been raced; the single-split test covers a manifest predating the flag.
    const bool one_traversal = track_registry_IsPointToPoint((int) hang->track_index) ||
        (have && record.total.run.lap_splits.size() == 1);

    // Otherwise the two columns the stock screen draws (swrUI_Front_DrawRecord plus the pilot
    // blocks in swrRace_CourseInfoMenu), pilot art from the stock sprite slots.
    struct Column {
        int x;
        char *label;
        const TrackHalfRecord *half;
        int sprite_base;
    };
    const Column two_columns[] = {
        {100, "/SCREENTEXT_545/~f4~c~s3-Lap Record", &record.total, 23},
        {220, "/SCREENTEXT_546/~f4~c~sBest Lap", &record.lap, 46},
    };
    const Column one_column[] = {
        {160, "~f4~c~sRecord", &record.total, 23},// no laps to qualify it with
    };
    const Column *columns = one_traversal ? one_column : two_columns;
    const int column_count = one_traversal ? 1 : 2;

    for (int i = 0; i < column_count; i++) {
        const Column &column = columns[i];

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
