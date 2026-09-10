#include "track_times.h"

#include <cstdio>
#include <vector>

#include <simdjson.h>

#include "track_registry.h"

extern "C" {
#include <Swr/swrRace.h>
#include <Swr/swrText.h>
#include <Swr/swrObj.h>
#include <globals.h>
#include <types.h>
#include <types_enums.h>
#include <engine_config.h>// ELFSAVE_RECORD_TIME_EMPTY

extern FILE *hook_log;
}

namespace {
    // Its own file, next to the other mod data: the save image is a fixed 0xfd4 bytes with a
    // checksum over it, so there is nowhere in it to put these.
    const char *TIMES_PATH = "./assets/custom_times.json";
    constexpr int SCHEMA = 1;

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

    void load() {
        loaded = true;
        simdjson::dom::parser parser;
        simdjson::dom::element root;
        if (parser.load(TIMES_PATH).get(root) != simdjson::SUCCESS)
            return;// no file yet, or unreadable: start empty rather than refusing to record

        int64_t schema = 0;
        root["schema"].get(schema);
        if (schema != SCHEMA) {
            fprintf(hook_log, "[track_times] %s is schema %lld, this build reads %d -- ignoring\n",
                    TIMES_PATH, (long long) schema, SCHEMA);
            fflush(hook_log);
            return;
        }

        simdjson::dom::array entries;
        if (root["records"].get(entries) != simdjson::SUCCESS)
            return;

        for (simdjson::dom::element entry: entries) {
            StoredRecord stored = {};
            std::string_view text;
            if (entry["slug"].get(text) != simdjson::SUCCESS)
                continue;
            stored.key.slug = std::string(text);
            if (entry["content_hash"].get(text) == simdjson::SUCCESS)
                stored.key.content_hash = std::string(text);
            if (entry["holder"].get(text) == simdjson::SUCCESS)
                stored.record.holder = std::string(text);

            bool flag = false;
            entry["mirror"].get(flag);
            stored.key.mirror = flag;
            flag = false;
            entry["upgrades"].get(flag);
            stored.key.upgrades = flag;

            int64_t number = 0;
            entry["laps"].get(number);
            stored.key.laps = (int) number;
            number = 0;
            entry["pilot"].get(number);
            stored.record.pilot = (int) number;

            double value = ELFSAVE_RECORD_TIME_EMPTY;
            entry["total_time"].get(value);
            stored.record.total_time = (float) value;
            value = ELFSAVE_RECORD_TIME_EMPTY;
            entry["best_lap"].get(value);
            stored.record.best_lap = (float) value;

            records.push_back(std::move(stored));
        }
        fprintf(hook_log, "[track_times] %d record(s) loaded\n", (int) records.size());
        fflush(hook_log);
    }

    // Player names come from a profile, so they can hold anything the name-entry screen allows.
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

    // Written whole each time. There are a handful of records, and rewriting the file is what makes
    // a partial write impossible to leave behind.
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
                    "    {\"slug\": \"%s\", \"content_hash\": \"%s\", \"mirror\": %s, "
                    "\"laps\": %d, \"upgrades\": %s, \"total_time\": %.3f, \"best_lap\": %.3f, "
                    "\"holder\": \"%s\", \"pilot\": %d}%s\n",
                    escaped(stored.key.slug).c_str(), escaped(stored.key.content_hash).c_str(),
                    stored.key.mirror ? "true" : "false", stored.key.laps,
                    stored.key.upgrades ? "true" : "false", stored.record.total_time,
                    stored.record.best_lap, escaped(stored.record.holder).c_str(),
                    stored.record.pilot, i + 1 < records.size() ? "," : "");
        }
        fprintf(f, "  ]\n}\n");
        fclose(f);
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

    out->total_time = ELFSAVE_RECORD_TIME_EMPTY;
    out->best_lap = ELFSAVE_RECORD_TIME_EMPTY;
    out->holder.clear();
    out->pilot = 0;
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
        TrackRecord empty;
        empty.total_time = ELFSAVE_RECORD_TIME_EMPTY;
        empty.best_lap = ELFSAVE_RECORD_TIME_EMPTY;
        empty.pilot = 0;
        records.push_back({key, empty});
        existing = &records.back();
    }

    bool improved = false;
    if (record.total_time < existing->record.total_time) {
        existing->record.total_time = record.total_time;
        existing->record.holder = record.holder;
        existing->record.pilot = record.pilot;
        improved = true;
    }
    if (record.best_lap < existing->record.best_lap) {
        existing->record.best_lap = record.best_lap;
        // The holder follows the full-race record; a lap-only improvement still names whoever set
        // it, so a track nobody has finished still credits the best lap.
        if (existing->record.holder.empty()) {
            existing->record.holder = record.holder;
            existing->record.pilot = record.pilot;
        }
        improved = true;
    }

    if (!improved)
        return false;

    fprintf(hook_log,
            "[track_times] %s (%s laps %d%s%s): total %.3f best lap %.3f by '%s'\n",
            key.slug.c_str(), key.content_hash.substr(0, 8).c_str(), key.laps,
            key.mirror ? " mirror" : "", key.upgrades ? " upgraded" : " stock",
            existing->record.total_time, existing->record.best_lap,
            existing->record.holder.c_str());
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

namespace {
    // The key for the track the game is on, or false when it is not one of ours.
    bool current_key(const swrObjHang *hang, int profile_index, TrackTimeKey *out) {
        if (hang == nullptr)
            return false;

        const TrackManifest *manifest = track_registry_FindByTrackIndex((int) hang->track_index);
        if (manifest == nullptr)
            return false;

        char laps = hang->numLaps;
        if (hang->isTournamentMode != 0)
            laps = 3;// a tournament race is always three, whatever the menu last held

        out->slug = manifest->slug;
        out->content_hash = manifest->content_hash;
        out->mirror = hang->bMirror != 0;
        out->laps = laps;
        out->upgrades = track_times_ProfileHasUpgrades(profile_index);
        return true;
    }

    bool results_taken = true;
}

extern "C" void track_times_OnRaceStart() {
    results_taken = false;
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

        // Same shape as the game's own record commit: the total is the race, the lap record is
        // the best of the laps actually run (a non-positive entry ends the run).
        float best_lap = ELFSAVE_RECORD_TIME_EMPTY;
        for (int lap = 0; lap < key.laps; lap++) {
            const float lap_time = (&score.results_P1_Lap1)[lap];
            if (lap_time <= 0.0f)
                break;
            if (lap_time < best_lap)
                best_lap = lap_time;
        }

        TrackRecord record = {};
        record.total_time = score.results_P1_total_time;
        record.best_lap = best_lap;
        record.holder = swrRace_aProfiles[player].name;
        record.pilot = swrRace_aProfiles[player].pilotId;

        if (record.total_time >= ELFSAVE_RECORD_TIME_EMPTY &&
            record.best_lap >= ELFSAVE_RECORD_TIME_EMPTY)
            continue;// did not finish and set no lap: nothing to record

        if (player != 0)
            key.upgrades = track_times_ProfileHasUpgrades(player);
        track_times_Submit(key, record);
    }
}

extern "C" bool track_times_DrawCourseInfoRecords(swrObjHang *hang) {
    TrackTimeKey key;
    if (!current_key(hang, 0, &key))
        return false;

    TrackRecord record;
    track_times_Get(key, &record);

    // Same two columns, labels and geometry the stock screen uses (swrUI_Front_DrawRecord), so a
    // custom track reads the same as any other and the labels stay translated.
    swrText_CreateTextEntry1(100, 55, 0x32, -1, -1, 255,
                             swrText_Translate("/SCREENTEXT_545/~f4~c~s3-Lap Record"));
    swrText_CreateTextEntry1(220, 55, 0x32, -1, -1, 255,
                             swrText_Translate("/SCREENTEXT_546/~f4~c~sBest Lap"));

    if (record.total_time < ELFSAVE_RECORD_TIME_EMPTY) {
        swrText_CreateTimeEntryFormat(100 + 0x1e, 55 + 7, record.total_time, 0x32, -1, -1, 255, 1);
    } else {
        swrText_CreateTextEntry1(100, 55 + 7, 0x32, -1, -1, 255, "~c~s--:--.--- ---");
    }
    if (record.best_lap < ELFSAVE_RECORD_TIME_EMPTY) {
        swrText_CreateTimeEntryFormat(220 + 0x1e, 55 + 7, record.best_lap, 0x32, -1, -1, 255, 1);
    } else {
        swrText_CreateTextEntry1(220, 55 + 7, 0x32, -1, -1, 255, "~c~s--:--.--- ---");
    }

    if (!record.holder.empty()) {
        char name[32] = {};
        snprintf(name, sizeof(name), "%s", record.holder.c_str());
        swrRace_DrawRecordHolderName(100.0f, 55.0f + 0xf, 255.0f, name);
    }
    return true;
}
