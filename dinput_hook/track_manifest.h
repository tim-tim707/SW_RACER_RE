//
// Reading a custom track's manifest.
//
// A track ships as `assets/tracks/<slug>/track.json` naming its assets by hash, plus the assets
// themselves in the content store at `assets/content/<first two hex chars>/<sha256>`. Two tracks
// that use the same texture reference the same blob, and a track that reuses the game's own art
// declares nothing for it -- an entry a manifest does not mention is served from the player's own
// archive by the block view (virtual_block.h).
//
// Assets keep the block index the model references, so nothing has to be rewritten to place them:
// the view is assembled as "stock entry, unless a declared index overrides it".
//
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

struct TrackAsset {
    std::string sha256;
    uint32_t block_index;
    uint32_t size;// as declared; a blob of a different length is rejected
};

struct TrackPlacement {
    int planet;
    int planet_track_number;
    int favorite_pilot;
    int overrides_stock_slot;// the stock track this one stands in for, -1 if unset
};

// The "environment" block: a stock preset to copy, then fields given on their own (-1 = not
// given). A manifest with only the older "placement" block is mapped onto this on read, so the
// two never disagree. Resolved into a TrackEnv (track_env.h) at registration and at track load.
struct TrackAmbientCueSpec {
    std::string sound;// a data/Sounds.map name, or a bank index as digits
    float start;
    float end;
    bool random;// retriggered at random intervals rather than looped
};

struct TrackEnvSpec {
    std::string inherit;// "vanilla:track:NN" or empty
    int planet;
    int planet_track_number;
    int favorite_pilot;
    // The per-(planet, subtrack) tables this track wants written its way (track_env.h). Empty =
    // inherit. Sounds are Sounds.map names or bank indices as digits.
    std::string music;
    std::string intro_music;
    std::string cutscene;// a .znm in data/, or "none"
    bool has_ambient;
    std::vector<TrackAmbientCueSpec> ambient;
};

struct TrackManifest {
    int schema;
    std::string slug;
    std::string version;
    std::string name;
    std::string author;
    std::string content_hash;

    TrackAsset model;
    bool has_spline;
    TrackAsset spline;
    std::vector<TrackAsset> textures;

    // A track whose spline does not loop ends after one traversal, so it has no lap count to ask
    // for. Recorded when the track is converted, so a catalog entry knows before it is downloaded.
    bool point_to_point;

    TrackPlacement placement;
    TrackEnvSpec environment;
    std::filesystem::path directory;
};

// Parse one track.json. Returns false (and logs why) for unreadable, unknown-schema or incomplete
// manifests; a manifest naming assets the content store does not hold still parses -- reading the
// assets is what fails then.
bool track_manifest_Read(const std::filesystem::path &path, TrackManifest *out);

// The same, from the manifest text a catalog entry carries. `label` names it in the log;
// `directory` is left empty, since nothing is on disk yet.
bool track_manifest_Parse(const std::string &json, const char *label, TrackManifest *out);

// Every manifest under ./assets/tracks/*/track.json, in directory order.
std::vector<TrackManifest> track_manifest_ScanAll();

// Read one asset out of the content store. Fails if the blob is missing or its length does not
// match the manifest.
bool track_manifest_ReadAsset(const TrackAsset &asset, std::vector<uint8_t> *out);

// Build and install the model / spline / texture views this track needs, over the stock blocks.
// Fails without installing anything if an asset cannot be read, so a broken track cannot leave the
// game with half a track mapped.
bool track_manifest_InstallViews(const TrackManifest &manifest);
// Install the first manifest that reads cleanly, falling back to loose chunks under
// assets/replacement_blocks/. A stand-in until the registry decides which track is being loaded.
void track_manifest_InstallFirstAvailable();
