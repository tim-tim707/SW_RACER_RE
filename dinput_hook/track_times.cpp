#include "track_times.h"

#include <cstdio>
#include <vector>

#include <simdjson.h>

#include "track_registry.h"

extern "C" {
#include <Swr/swrRace.h>
#include <Swr/swrText.h>
#include <Swr/swrObj.h>
#include <Swr/swrSprite.h>
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

            bool flag = false;
            entry["mirror"].get(flag);
            stored.key.mirror = flag;
            flag = false;
            entry["upgrades"].get(flag);
            stored.key.upgrades = flag;

            int64_t number = 0;
            entry["laps"].get(number);
            stored.key.laps = (int) number;

            // A file written before the halves were split names one holder for both.
            std::string_view legacy_holder;
            entry["holder"].get(legacy_holder);
            int64_t legacy_pilot = 0;
            entry["pilot"].get(legacy_pilot);

            const auto read_half = [&](const char *time_key, const char *holder_key,
                                       const char *pilot_key, TrackHalfRecord *half) {
                double value = ELFSAVE_RECORD_TIME_EMPTY;
                entry[time_key].get(value);
                half->time = (float) value;

                std::string_view holder;
                half->holder = entry[holder_key].get(holder) == simdjson::SUCCESS
                    ? std::string(holder)
                    : std::string(legacy_holder);
                int64_t pilot = legacy_pilot;
                entry[pilot_key].get(pilot);
                half->pilot = (int) pilot;
            };
            read_half("total_time", "total_holder", "total_pilot", &stored.record.total);
            read_half("best_lap", "lap_holder", "lap_pilot", &stored.record.lap);

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
                    "\"laps\": %d, \"upgrades\": %s, "
                    "\"total_time\": %.3f, \"total_holder\": \"%s\", \"total_pilot\": %d, "
                    "\"best_lap\": %.3f, \"lap_holder\": \"%s\", \"lap_pilot\": %d}%s\n",
                    escaped(stored.key.slug).c_str(), escaped(stored.key.content_hash).c_str(),
                    stored.key.mirror ? "true" : "false", stored.key.laps,
                    stored.key.upgrades ? "true" : "false", stored.record.total.time,
                    escaped(stored.record.total.holder).c_str(), stored.record.total.pilot,
                    stored.record.lap.time, escaped(stored.record.lap.holder).c_str(),
                    stored.record.lap.pilot, i + 1 < records.size() ? "," : "");
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

    out->total = {ELFSAVE_RECORD_TIME_EMPTY, "", 0};
    out->lap = {ELFSAVE_RECORD_TIME_EMPTY, "", 0};
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
        empty.total = {ELFSAVE_RECORD_TIME_EMPTY, "", 0};
        empty.lap = {ELFSAVE_RECORD_TIME_EMPTY, "", 0};
        records.push_back({key, empty});
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
            "[track_times] %s (%s laps %d%s%s): race %.3f by '%s' (pilot %d), "
            "lap %.3f by '%s' (pilot %d)\n",
            key.slug.c_str(), key.content_hash.substr(0, 8).c_str(), key.laps,
            key.mirror ? " mirror" : "", key.upgrades ? " upgraded" : " stock",
            existing->record.total.time, existing->record.total.holder.c_str(),
            existing->record.total.pilot, existing->record.lap.time,
            existing->record.lap.holder.c_str(), existing->record.lap.pilot);
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

        const char *holder = swrRace_aProfiles[player].name;
        const int pilot = swrRace_aProfiles[player].pilotId;
        TrackRecord record;
        record.total = {score.results_P1_total_time, holder, pilot};
        record.lap = {best_lap, holder, pilot};

        if (record.total.time >= ELFSAVE_RECORD_TIME_EMPTY &&
            record.lap.time >= ELFSAVE_RECORD_TIME_EMPTY)
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

    // The same two columns the stock screen draws (swrUI_Front_DrawRecord plus the pilot blocks
    // in swrRace_CourseInfoMenu): label, time, the holder's player name, then the pilot they set
    // it on -- name and portrait. Sprite slots are the stock ones, 23 + pilot for the race record
    // and 46 + pilot for the lap, so the portraits are the same art the rest of the screen uses.
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
        swrText_CreateTextEntry1(column.x, 55, 0x32, -1, -1, 255,
                                 swrText_Translate(column.label));
        if (column.half->time >= ELFSAVE_RECORD_TIME_EMPTY) {
            swrText_CreateTextEntry1(column.x, 62, 0x32, -1, -1, 255, "~c~s--:--.--- ---");
            continue;
        }

        swrText_CreateTimeEntryFormat(column.x + 0x1e, 62, column.half->time, 0x32, -1, -1, 255, 1);

        char text[64] = {};
        snprintf(text, sizeof(text), "%s", column.half->holder.c_str());
        swrRace_DrawRecordHolderName((float) column.x, 70.0f, 255.0f, text);

        const int pilot = column.half->pilot;
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
