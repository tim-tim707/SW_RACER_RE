//
// Records for every track, stock or custom.
//
// The save image holds one number per track per record kind (`record3LapTimes[50]` /
// `recordLapTimes[50]`, indexed `bMirror + track_index * 2`) plus a holder and a pilot, in a fixed
// 0xfd4 bytes with a checksum over it. It cannot say which pod the time was set on, what that pod
// was carrying, what condition its parts were in, how many laps beyond the 3-lap split, or how the
// run was driven -- and a custom track has no slot in it at all. So records live here as well,
// alongside the game's own, which keep working exactly as they do now.
//
// A record is `key -> best run`. Which facts SPLIT records and which merely DESCRIBE them is the
// whole design: put part health in the key and nothing ever beats anything, because two runs on
// different wear become different records; leave the pod out of it and a fully-upgraded run buries
// a stock one. So the key is what the community boards already split on, and everything else rides
// along as evidence -- which is also what makes a submitted record checkable, and what a ghost
// will attach to.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

// What makes two times comparable.
struct TrackTimeKey {
    std::string slug;         // "vanilla:track:NN" for a stock track, else the manifest's slug
    std::string content_hash; // the assets actually raced: proof of unmodified geometry, or which
                              // build of a custom track this was
    bool mirror;
    int laps;
    bool upgrades;// the coarse stock-vs-upgraded split the boards use; exact levels are in the run
};

// Everything known about the run that set a record. None of it splits records.
struct TrackRunDetail {
    int pilot;                // pilot/pod raced
    uint8_t upgrade_levels[7];// traction, turning, accel, top speed, airbrake, cooling, repair
    uint8_t upgrade_health[7];// 0xff = fresh; a worn part is slower, so a worn run is a harder run
    float fps_min;
    float fps_avg;
    std::vector<float> lap_splits;// per-lap times, as far as the run recorded them
    std::string date;
    std::string build;// which mod build produced it
};

struct TrackHalfRecord {
    float time;
    std::string holder;// player name, as the profile spells it
    TrackRunDetail run;
};

// The race and the lap are kept apart the way the save image keeps them: they can belong to
// different players on different pods, and the record screen names both.
struct TrackRecord {
    TrackHalfRecord total;
    TrackHalfRecord lap;
};

// The record for this key, if any. Absent times read back as the game's own empty-record value.
bool track_times_Get(const TrackTimeKey &key, TrackRecord *out);

// Offer a result. Each half is kept only if it beats what is stored, so a good lap in a bad race
// still counts, and the file is written only when something changed.
bool track_times_Submit(const TrackTimeKey &key, const TrackRecord &record);

// Arm the next race: the results screen redraws every frame, so a result is taken once.
extern "C" void track_times_OnRaceStart();

// Per-frame while racing: what the fps evidence is built from.
extern "C" void track_times_OnRaceFrame();

// Offer the finished race's local results, for any track.
extern "C" void track_times_OnResults(struct swrObjHang *hang);

// Draw a custom track's records where the course-info screen draws the stock ones. Returns false
// for a track whose records the game draws itself.
extern "C" bool track_times_DrawCourseInfoRecords(struct swrObjHang *hang);

// Whether a pod carries any upgrade, which is half of what makes two times comparable.
bool track_times_ProfileHasUpgrades(int profile_index);
