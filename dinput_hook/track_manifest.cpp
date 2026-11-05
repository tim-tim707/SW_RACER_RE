#include "track_manifest.h"

#include <cstring>
#include <set>

#include <windows.h>
#include <bcrypt.h>

#include <simdjson.h>

#include "virtual_block.h"

extern "C" FILE *hook_log;

namespace fs = std::filesystem;

namespace {
    constexpr int SUPPORTED_SCHEMA = 1;
    const char *TRACKS_DIR = "./assets/tracks";
    const char *CONTENT_DIR = "./assets/content";

    std::string get_string(simdjson::dom::element parent, const char *key, const char *fallback) {
        std::string_view value;
        if (parent[key].get(value) != simdjson::SUCCESS)
            return fallback;
        return std::string(value);
    }

    int64_t get_int(simdjson::dom::element parent, const char *key, int64_t fallback) {
        int64_t value = 0;
        if (parent[key].get(value) != simdjson::SUCCESS)
            return fallback;
        return value;
    }

    // An asset is {sha256, size, format, block_id|block_index}. The index is what the block view
    // needs; a model or spline carries it as block_id, a texture as block_index.
    bool read_asset(simdjson::dom::element element, const char *index_key, TrackAsset *out) {
        std::string_view sha;
        if (element["sha256"].get(sha) != simdjson::SUCCESS || sha.empty())
            return false;

        int64_t index = -1;
        if (element[index_key].get(index) != simdjson::SUCCESS || index < 0)
            return false;

        out->sha256 = std::string(sha);
        out->block_index = (uint32_t) index;
        out->size = (uint32_t) get_int(element, "size", 0);
        return true;
    }

    fs::path blob_path(const std::string &sha256) {
        return fs::path(CONTENT_DIR) / sha256.substr(0, 2) / sha256;
    }

    // The content store names a blob by its hash, so a blob that does not hash to its own name has
    // been corrupted or swapped. Hashing is done through CNG rather than a vendored implementation.
    bool sha256_hex(const std::vector<uint8_t> &data, std::string *out) {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        if (!BCRYPT_SUCCESS(
                BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            return false;

        uint8_t digest[32] = {};
        BCRYPT_HASH_HANDLE hash = nullptr;
        bool ok = BCRYPT_SUCCESS(BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0));
        if (ok) {
            ok = BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR) data.data(), (ULONG) data.size(), 0)) &&
                BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0));
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (!ok)
            return false;

        static const char HEX[] = "0123456789abcdef";
        out->clear();
        for (uint8_t byte: digest) {
            out->push_back(HEX[byte >> 4]);
            out->push_back(HEX[byte & 0xf]);
        }
        return true;
    }

    bool equals_ignoring_case(const std::string &a, const std::string &b) {
        if (a.size() != b.size())
            return false;
        for (size_t i = 0; i < a.size(); i++) {
            if (tolower((unsigned char) a[i]) != tolower((unsigned char) b[i]))
                return false;
        }
        return true;
    }

    // Blobs are immutable, so one verification per hash per session is enough; a track raced twice
    // does not pay for it twice.
    std::set<std::string> verified_blobs;
}

bool track_manifest_Read(const fs::path &path, TrackManifest *out) {
    simdjson::dom::parser parser;
    simdjson::dom::element root;
    if (parser.load(path.generic_string()).get(root) != simdjson::SUCCESS) {
        fprintf(hook_log, "[track_manifest] %s is not readable JSON\n",
                path.generic_string().c_str());
        fflush(hook_log);
        return false;
    }

    TrackManifest manifest = {};
    manifest.schema = (int) get_int(root, "schema", 0);
    if (manifest.schema != SUPPORTED_SCHEMA) {
        fprintf(hook_log, "[track_manifest] %s declares schema %d, this build reads %d\n",
                path.generic_string().c_str(), manifest.schema, SUPPORTED_SCHEMA);
        fflush(hook_log);
        return false;
    }

    manifest.slug = get_string(root, "slug", "");
    manifest.version = get_string(root, "version", "");
    manifest.name = get_string(root, "name", manifest.slug.c_str());
    manifest.content_hash = get_string(root, "content_hash", "");
    simdjson::dom::element author;
    if (root["author"].get(author) == simdjson::SUCCESS)
        manifest.author = get_string(author, "name", "");

    simdjson::dom::element model;
    if (root["model"].get(model) != simdjson::SUCCESS ||
        !read_asset(model, "block_id", &manifest.model)) {
        fprintf(hook_log, "[track_manifest] %s has no usable model asset\n",
                path.generic_string().c_str());
        fflush(hook_log);
        return false;
    }

    simdjson::dom::element spline;
    manifest.has_spline = root["spline"].get(spline) == simdjson::SUCCESS &&
        read_asset(spline, "block_id", &manifest.spline);

    simdjson::dom::array textures;
    if (root["textures"].get(textures) == simdjson::SUCCESS) {
        for (simdjson::dom::element texture: textures) {
            TrackAsset asset;
            if (read_asset(texture, "block_index", &asset))
                manifest.textures.push_back(asset);
        }
    }

    manifest.placement = {0, 0, 0, -1};
    simdjson::dom::element placement;
    if (root["placement"].get(placement) == simdjson::SUCCESS) {
        manifest.placement.planet = (int) get_int(placement, "planet", 0);
        manifest.placement.planet_track_number =
            (int) get_int(placement, "planet_track_number", 0);
        manifest.placement.favorite_pilot = (int) get_int(placement, "favorite_pilot", 0);
        manifest.placement.overrides_stock_slot =
            (int) get_int(placement, "overrides_stock_slot", -1);
    }

    manifest.directory = path.parent_path();
    *out = std::move(manifest);
    return true;
}

std::vector<TrackManifest> track_manifest_ScanAll() {
    std::vector<TrackManifest> manifests;
    std::error_code ec;
    if (!fs::is_directory(TRACKS_DIR, ec))
        return manifests;

    for (const auto &entry: fs::directory_iterator(TRACKS_DIR, ec)) {
        if (!entry.is_directory())
            continue;

        const fs::path path = entry.path() / "track.json";
        if (!fs::is_regular_file(path, ec))
            continue;

        TrackManifest manifest;
        if (!track_manifest_Read(path, &manifest))
            continue;

        fprintf(hook_log, "[track_manifest] %s '%s' by %s: model %u, %s, %u texture(s)\n",
                manifest.slug.c_str(), manifest.name.c_str(),
                manifest.author.empty() ? "?" : manifest.author.c_str(), manifest.model.block_index,
                manifest.has_spline ? "own spline" : "stock spline",
                (unsigned) manifest.textures.size());
        fflush(hook_log);
        manifests.push_back(std::move(manifest));
    }
    return manifests;
}

bool track_manifest_ReadAsset(const TrackAsset &asset, std::vector<uint8_t> *out) {
    const fs::path path = blob_path(asset.sha256);
    FILE *f = fopen(path.generic_string().c_str(), "rb");
    if (!f) {
        fprintf(hook_log, "[track_manifest] content store has no %s\n", asset.sha256.c_str());
        fflush(hook_log);
        return false;
    }

    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (asset.size != 0 && (long) asset.size != size) {
        fprintf(hook_log, "[track_manifest] %s is %ld bytes, the manifest says %u\n",
                asset.sha256.c_str(), size, asset.size);
        fflush(hook_log);
        fclose(f);
        return false;
    }

    out->resize(size > 0 ? size : 0);
    const bool complete = out->empty() || fread(out->data(), 1, out->size(), f) == out->size();
    fclose(f);
    if (!complete)
        return false;

    if (verified_blobs.count(asset.sha256) != 0)
        return true;

    std::string digest;
    if (!sha256_hex(*out, &digest)) {
        fprintf(hook_log, "[track_manifest] could not hash %s to verify it\n",
                asset.sha256.c_str());
        fflush(hook_log);
        return false;
    }
    if (!equals_ignoring_case(digest, asset.sha256)) {
        fprintf(hook_log, "[track_manifest] %s hashes to %s -- corrupted or not the asset the "
                          "manifest names\n",
                asset.sha256.c_str(), digest.c_str());
        fflush(hook_log);
        return false;
    }

    verified_blobs.insert(asset.sha256);
    return true;
}

namespace {
    // Chunks in the content store are the containers extract_raw_asset.py writes: a magic, one or
    // two little-endian sizes, then the payload sections verbatim. The block view wants the payload
    // and the offset its second section starts at.
    bool to_override(const std::vector<uint8_t> &chunk, uint32_t index, VirtualOverride *out) {
        if (chunk.size() < 8)
            return false;

        const bool two_sections = memcmp(chunk.data(), "RAWM", 4) == 0 ||
            memcmp(chunk.data(), "RAWT", 4) == 0;
        if (!two_sections && memcmp(chunk.data(), "RAWS", 4) != 0)
            return false;

        uint32_t first = 0;
        uint32_t second = 0;
        memcpy(&first, chunk.data() + 4, sizeof(first));
        const size_t header = two_sections ? 12 : 8;
        if (two_sections) {
            if (chunk.size() < header)
                return false;
            memcpy(&second, chunk.data() + 8, sizeof(second));
        }
        if (chunk.size() != header + first + second)
            return false;

        out->index = index;
        out->payload.assign(chunk.begin() + header, chunk.end());
        out->split = second != 0 ? first : 0;
        return true;
    }

    bool collect(const TrackAsset &asset, std::vector<VirtualOverride> *overrides) {
        std::vector<uint8_t> chunk;
        VirtualOverride override_entry;
        if (!track_manifest_ReadAsset(asset, &chunk) ||
            !to_override(chunk, asset.block_index, &override_entry)) {
            fprintf(hook_log, "[track_manifest] asset %s is not a usable chunk\n",
                    asset.sha256.c_str());
            fflush(hook_log);
            return false;
        }
        overrides->push_back(std::move(override_entry));
        return true;
    }
}

bool track_manifest_InstallViews(const TrackManifest &manifest) {
    std::vector<VirtualOverride> models;
    std::vector<VirtualOverride> splines;
    std::vector<VirtualOverride> textures;

    if (!collect(manifest.model, &models))
        return false;
    if (manifest.has_spline && !collect(manifest.spline, &splines))
        return false;
    for (const TrackAsset &texture: manifest.textures) {
        if (!collect(texture, &textures))
            return false;
    }

    // Build every view before installing any: a track that is missing an asset should change
    // nothing rather than leave the game reading half of it.
    struct Pending {
        swrLoader_TYPE type;
        VirtualBlockView view;
        bool used;
    };
    Pending pending[3] = {{swrLoader_TYPE_MODEL_BLOCK, {}, false},
                          {swrLoader_TYPE_SPLINE_BLOCK, {}, false},
                          {swrLoader_TYPE_TEXTURE_BLOCK, {}, false}};
    std::vector<VirtualOverride> *by_type[3] = {&models, &splines, &textures};

    for (int i = 0; i < 3; i++) {
        if (by_type[i]->empty())
            continue;

        const char **path = virtual_block_SourcePath(pending[i].type);
        if (path == nullptr || *path == nullptr ||
            !virtual_block_BuildView(pending[i].type, *path, std::move(*by_type[i]),
                                     &pending[i].view))
            return false;
        pending[i].used = true;
    }

    for (Pending &entry: pending) {
        if (entry.used)
            virtual_block_Install(entry.type, std::move(entry.view));
    }

    fprintf(hook_log, "[track_manifest] installed views for '%s' (%s)\n", manifest.slug.c_str(),
            manifest.content_hash.empty() ? "no content hash" : manifest.content_hash.c_str());
    fflush(hook_log);
    return true;
}

void track_manifest_InstallFirstAvailable() {
    for (const TrackManifest &manifest: track_manifest_ScanAll()) {
        if (track_manifest_InstallViews(manifest))
            return;
    }

    virtual_block_LoadFolderOverrides();
}
