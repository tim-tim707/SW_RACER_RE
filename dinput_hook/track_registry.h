//
// The track registry: what tracks exist, and which one the game is about to load.
//
// A manifest track (assets/tracks/<slug>/track.json) takes a slot in the inflated track table the
// same way a legacy custom-track folder does, so it shows up in the menus with a name. Unlike a
// legacy pack it does not get its own model/spline ids: it declares the block entries it replaces,
// and the block views (virtual_block.h) serve those entries while the track is loading. Two tracks
// may therefore claim the same block entry -- only one is ever mapped at a time.
//
// The registry is what decides which: at every track load it installs the selected track's views,
// or removes them for a stock or legacy track, so a stock track never inherits another track's
// geometry.
//
#pragma once

#include "track_manifest.h"

// Read every manifest and give each track a slot in the track table. Call once at boot, after the
// legacy custom-track scan (it appends to the same table).
void track_registry_Init();

int track_registry_Count();

// Pick up manifests installed since the last scan, appending them to the track table (existing
// indices never move, so this is safe while the game is running). Returns how many were added.
int track_registry_Rescan();

// The manifest behind a track table index, or null when that index is a stock or legacy track.
const TrackManifest *track_registry_FindByTrackIndex(int track_index);

// Point the block views at whatever track the game is loading now: the selected track's assets,
// or the player's own archives for anything else. Call before the track's model is loaded.
// Whether this track ends after one traversal rather than running laps. Menus use it to stop
// offering a lap count that would do nothing.
extern "C" bool track_registry_IsPointToPoint(int track_index);

extern "C" void track_registry_ApplyForCurrentTrack();

// Game-thread heartbeat from the menus: turns a fetched catalog into track-select entries that are
// not installed yet ("ghosts"), and picks up installs the downloader finished. Cheap when idle.
extern "C" void track_registry_Tick();

// A ghost is a catalog track in the table with nothing on disk. Stock and legacy tracks are always
// installed. Selecting a ghost on course info is what downloads it.
extern "C" bool track_registry_IsInstalled(int track_index);
extern "C" void track_registry_RequestInstall(int track_index);

// 0 = nothing in flight for this track, 1 = downloading (text + fraction describe it),
// 2 = the last install of it failed (text says why).
extern "C" int track_registry_InstallState(int track_index, char *text, int size, float *fraction);

// Whether the last attempt to bind this track's assets failed (a blob missing or not hashing to
// its name). The course-info screen refuses to start such a track rather than racing the stock
// slot it stands in for, and the browser offers to download it again. Cleared by a rescan.
extern "C" bool track_registry_BindFailed(int track_index);
bool track_registry_BindFailedSlug(const std::string &slug);
