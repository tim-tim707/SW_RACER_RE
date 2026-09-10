//
// Records for tracks the save image has no room for.
//
// The game keeps records in a fixed 50-slot array inside swrSaveData, indexed
// `bMirror + track_index * 2` -- the 25 stock tracks times their mirror. A custom track has no
// slot there, so its times live here instead, in their own file with its own version.
//
// A record is keyed by the track's slug AND its content hash: a re-published track is a different
// track to race against, so it starts a new record rather than inheriting one set on other
// geometry. Beyond that the key carries what the game varies -- mirror, lap count -- and whether
// the pod was upgraded, because a time set on a stock pod is not comparable to one set on a
// fully-upgraded one. Those are the same dimensions the community leaderboards split on, so a
// record here can be submitted later without reshaping it.
//
#pragma once

#include <string>

struct TrackTimeKey {
    std::string slug;
    std::string content_hash;
    bool mirror;
    int laps;
    bool upgrades;
};

// The two halves are held separately, the way the save image does it: the best race and the best
// lap can belong to different players on different pods, and the record screen names both.
struct TrackHalfRecord {
    float time;
    std::string holder;// player name, as the profile spells it
    int pilot;         // pilot id, for the name and portrait beside the record
};

struct TrackRecord {
    TrackHalfRecord total;// the full race
    TrackHalfRecord lap;
};

// The record for this key, if any. Absent totals read back as the game's own empty-record value.
bool track_times_Get(const TrackTimeKey &key, TrackRecord *out);

// Offer a result. Each half is kept only if it beats what is stored, so a good lap in a bad race
// still counts, and the file is written only when something changed.
bool track_times_Submit(const TrackTimeKey &key, const TrackRecord &record);

// Arm the next race: the results screen redraws every frame, so a result is taken once.
extern "C" void track_times_OnRaceStart();

// Offer the finished race's local results. Does nothing for a track that has a save slot -- the
// game records those itself.
extern "C" void track_times_OnResults(struct swrObjHang *hang);

// Draw a custom track's records where the course-info screen draws the stock ones. Returns false
// when the selected track is not one of ours, so the caller can leave the screen alone.
extern "C" bool track_times_DrawCourseInfoRecords(struct swrObjHang *hang);

// Whether a pod carries any upgrade, which is half of what makes two times comparable.
bool track_times_ProfileHasUpgrades(int profile_index);
