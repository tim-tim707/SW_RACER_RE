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
extern "C" void track_registry_ApplyForCurrentTrack();
