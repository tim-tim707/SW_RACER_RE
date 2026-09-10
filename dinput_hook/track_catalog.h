//
// Downloading tracks.
//
// Assets are content-addressed, so the whole protocol is two GETs: a catalog listing tracks and
// their manifests, and one request per asset hash. Nothing about it is dynamic -- blobs are
// immutable and may be cached forever -- so the far end can be static hosting rather than an API,
// and only publishing a track needs a real backend.
//
//   GET <base>/index.json     { "schema": 1, "tracks": [ { slug, name, download_bytes, manifest } ] }
//   GET <base>/blobs/<sha256> one asset
//
// A download only fetches the hashes the content store is missing, so a track sharing textures
// with one already installed costs almost nothing. Every blob is verified against its hash before
// it is written (track_manifest.h), so a truncated or tampered response cannot enter the store.
//
// Network work happens on one worker thread; the game thread only reads the state below.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct CatalogTrack {
    std::string slug;
    std::string name;
    std::string author;
    std::string version;
    std::string content_hash;
    uint64_t download_bytes;
    std::string manifest_json;// stored verbatim: it becomes the installed track.json
    bool installed;           // a manifest with this slug and content hash is already on disk
};

enum class CatalogState {
    Idle,
    Fetching,
    Downloading,
    Failed,
};

// Snapshot for the UI. Copied under a lock, so the panel never reads a half-written state.
struct CatalogStatus {
    CatalogState state;
    std::string message;      // what failed, or what is being downloaded
    std::string active_slug;  // the track being installed
    uint64_t bytes_done;
    uint64_t bytes_total;
    int tracks_installed_since_refresh;
};

// Where the catalog lives ([tracks] catalog_url in SW_RACER_RE.ini).
const std::string &track_catalog_Url();

// Kick off a catalog fetch / an install. Both return immediately; watch the status.
void track_catalog_Refresh();
void track_catalog_Install(const std::string &slug);

// The last fetched catalog, and what the worker is doing.
std::vector<CatalogTrack> track_catalog_Tracks();
CatalogStatus track_catalog_Status();

// True once an install has finished and the registry has not picked it up yet. The game thread
// calls track_catalog_TakePendingRescan() at a safe moment (menus, not mid-race) and rescans.
bool track_catalog_TakePendingRescan();

void track_catalog_Shutdown();
