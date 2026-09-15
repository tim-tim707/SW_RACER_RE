#include "track_manifest.h"

#include <cstring>
#include <set>

#include <windows.h>
#include <bcrypt.h>

#include <simdjson.h>

#include "hash_util.h"
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

static bool parse_root(simdjson::dom::element root, const char *label, TrackManifest *out);

bool track_manifest_Read(const fs::path &path, TrackManifest *out) {
    simdjson::dom::parser parser;
    simdjson::dom::element root;
    if (parser.load(path.generic_string()).get(root) != simdjson::SUCCESS) {
        fprintf(hook_log, "[track_manifest] %s is not readable JSON\n",
                path.generic_string().c_str());
        fflush(hook_log);
        return false;
    }
    if (!parse_root(root, path.generic_string().c_str(), out))
        return false;
    out->directory = path.parent_path();
    return true;
}

bool track_manifest_Parse(const std::string &json, const char *label, TrackManifest *out) {
    simdjson::dom::parser parser;
    simdjson::dom::element root;
    if (parser.parse(json).get(root) != simdjson::SUCCESS) {
        fprintf(hook_log, "[track_manifest] %s is not readable JSON\n", label);
        fflush(hook_log);
        return false;
    }
    return parse_root(root, label, out);
}

static bool parse_root(simdjson::dom::element root, const char *label, TrackManifest *out) {
    TrackManifest manifest = {};
    manifest.schema = (int) get_int(root, "schema", 0);
    if (manifest.schema != SUPPORTED_SCHEMA) {
        fprintf(hook_log, "[track_manifest] %s declares schema %d, this build reads %d\n", label,
                manifest.schema, SUPPORTED_SCHEMA);
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
        fprintf(hook_log, "[track_manifest] %s has no usable model asset\n", label);
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

    simdjson::dom::element rules;
    if (root["rules"].get(rules) == simdjson::SUCCESS) {
        bool flag = false;
        rules["point_to_point"].get(flag);
        manifest.point_to_point = flag;
    }

    simdjson::dom::array sounds;
    if (root["sounds"].get(sounds) == simdjson::SUCCESS) {
        for (simdjson::dom::element sound: sounds) {
            TrackSoundSpec spec;
            spec.name = get_string(sound, "name", "");
            spec.sha256 = get_string(sound, "sha256", "");
            spec.size = (uint32_t) get_int(sound, "size", 0);
            if (!spec.name.empty() && !spec.sha256.empty())
                manifest.sounds.push_back(spec);
        }
    }

    manifest.placement = {0, 0, 0, -1};
    manifest.environment = {"", -1, -1, -1};
    manifest.environment.draw_distance = -1.0f;
    manifest.environment.ai_level = -1.0f;
    manifest.environment.ai_spread_range = -1.0f;
    manifest.environment.ai_script = -2;
    manifest.environment.ai_spline_variant = -1;
    manifest.environment.dust_planet = -1;
    manifest.environment.holo_tilt = -1000.0f;
    manifest.environment.holo_spin = -1000.0f;
    simdjson::dom::element placement;
    if (root["placement"].get(placement) == simdjson::SUCCESS) {
        manifest.placement.planet = (int) get_int(placement, "planet", 0);
        manifest.placement.planet_track_number =
            (int) get_int(placement, "planet_track_number", 0);
        manifest.placement.favorite_pilot = (int) get_int(placement, "favorite_pilot", 0);
        manifest.placement.overrides_stock_slot =
            (int) get_int(placement, "overrides_stock_slot", -1);
        // The older block said the same thing with a slot number; say it as a preset.
        if (manifest.placement.overrides_stock_slot >= 0)
            manifest.environment.inherit =
                "vanilla:track:" + std::to_string(manifest.placement.overrides_stock_slot);
        manifest.environment.planet = manifest.placement.planet;
        manifest.environment.planet_track_number = manifest.placement.planet_track_number;
        manifest.environment.favorite_pilot = manifest.placement.favorite_pilot;
    }
    simdjson::dom::element environment;
    if (root["environment"].get(environment) == simdjson::SUCCESS) {
        manifest.environment.inherit =
            get_string(environment, "inherit", manifest.environment.inherit.c_str());
        manifest.environment.planet =
            (int) get_int(environment, "planet", manifest.environment.planet);
        manifest.environment.planet_track_number = (int) get_int(
            environment, "planet_track_number", manifest.environment.planet_track_number);
        manifest.environment.favorite_pilot =
            (int) get_int(environment, "favorite_pilot", manifest.environment.favorite_pilot);

        // Sounds may be a name or a number; keep either as text and let track_env resolve it.
        const auto sound_text = [&](const char *key) -> std::string {
            int64_t number = 0;
            if (environment[key].get(number) == simdjson::SUCCESS)
                return std::to_string(number);
            return get_string(environment, key, "");
        };
        manifest.environment.music = sound_text("music");
        manifest.environment.intro_music = sound_text("intro_music");
        manifest.environment.cutscene = get_string(environment, "cutscene", "");

        simdjson::dom::array ambient;
        if (environment["ambient"].get(ambient) == simdjson::SUCCESS) {
            manifest.environment.has_ambient = true;
            for (simdjson::dom::element cue: ambient) {
                TrackAmbientCueSpec spec = {};
                int64_t number = 0;
                if (cue["sound"].get(number) == simdjson::SUCCESS)
                    spec.sound = std::to_string(number);
                else
                    spec.sound = get_string(cue, "sound", "");
                double value = 0.0;
                cue["start"].get(value);
                spec.start = (float) value;
                value = 0.0;
                cue["end"].get(value);
                spec.end = (float) value;
                spec.random = get_string(cue, "mode", "loop") == "random";
                if (!spec.sound.empty())
                    manifest.environment.ambient.push_back(spec);
            }
        }

        double number_value = 0.0;
        if (environment["draw_distance"].get(number_value) == simdjson::SUCCESS)
            manifest.environment.draw_distance = (float) number_value;

        simdjson::dom::element fog;
        bool fog_off = false;
        if (environment["fog"].get(fog_off) == simdjson::SUCCESS && !fog_off) {
            manifest.environment.has_fog = true;
            manifest.environment.fog_enabled = false;
        } else if (environment["fog"].get(fog) == simdjson::SUCCESS && fog.is_object()) {
            manifest.environment.has_fog = true;
            manifest.environment.fog_enabled = true;
            manifest.environment.fog_near = (int) get_int(fog, "near", 996);
            simdjson::dom::array color;
            if (fog["color"].get(color) == simdjson::SUCCESS) {
                int i = 0;
                for (simdjson::dom::element channel: color) {
                    if (i >= 3)
                        break;
                    int64_t value = 0;
                    channel.get(value);
                    manifest.environment.fog_rgb[i++] = (int) value;
                }
            }
        }

        simdjson::dom::element weather;
        bool weather_off = false;
        if (environment["weather"].get(weather_off) == simdjson::SUCCESS && !weather_off) {
            manifest.environment.has_weather = true;
            manifest.environment.weather_enabled = false;
        } else if (environment["weather"].get(weather) == simdjson::SUCCESS && weather.is_object()) {
            TrackEnvSpec &env_spec = manifest.environment;
            env_spec.has_weather = true;
            env_spec.weather_enabled = true;
            env_spec.weather_color[0] = env_spec.weather_color[1] = env_spec.weather_color[2] = 255;
            env_spec.weather_color[3] = 200;
            simdjson::dom::array color;
            if (weather["color"].get(color) == simdjson::SUCCESS) {
                int i = 0;
                for (simdjson::dom::element channel: color) {
                    if (i >= 4)
                        break;
                    int64_t value = 0;
                    channel.get(value);
                    env_spec.weather_color[i++] = (int) value;
                }
            }
            if (weather["stretch"].get(number_value) == simdjson::SUCCESS)
                env_spec.weather_stretch = (float) number_value;
            simdjson::dom::array stages;
            if (weather["stages"].get(stages) == simdjson::SUCCESS) {
                for (simdjson::dom::element stage: stages) {
                    TrackWeatherStageSpec spec = {};
                    spec.lap = (int) get_int(stage, "lap", (int64_t) env_spec.weather_stages.size());
                    spec.cap = (int) get_int(stage, "cap", 0);
                    simdjson::dom::array velocity;
                    if (stage["velocity"].get(velocity) == simdjson::SUCCESS) {
                        int i = 0;
                        for (simdjson::dom::element axis: velocity) {
                            double v = 0.0;
                            axis.get(v);
                            if (i == 0)
                                spec.velocity_x = (float) v;
                            else if (i == 1)
                                spec.velocity_y = (float) v;
                            i++;
                        }
                    }
                    spec.stretch = 0.0f;
                    if (stage["stretch"].get(number_value) == simdjson::SUCCESS)
                        spec.stretch = (float) number_value;
                    spec.sun_alpha = (int) get_int(stage, "sun_alpha", -1);
                    env_spec.weather_stages.push_back(spec);
                }
            }
        }

        manifest.environment.dust_planet = (int) get_int(environment, "dust_planet", -1);
        manifest.environment.planet_name = get_string(environment, "planet_name", "");
        simdjson::dom::element holo;
        if (environment["holo"].get(holo) == simdjson::SUCCESS) {
            if (holo["tilt"].get(number_value) == simdjson::SUCCESS)
                manifest.environment.holo_tilt = (float) number_value;
            if (holo["spin"].get(number_value) == simdjson::SUCCESS)
                manifest.environment.holo_spin = (float) number_value;
        }

        simdjson::dom::element ai;
        if (environment["ai"].get(ai) == simdjson::SUCCESS) {
            if (ai["level"].get(number_value) == simdjson::SUCCESS)
                manifest.environment.ai_level = (float) number_value;
            if (ai["spread"].get(number_value) == simdjson::SUCCESS)
                manifest.environment.ai_spread_range = (float) number_value;
            manifest.environment.ai_script = (int) get_int(ai, "script", -2);
            manifest.environment.ai_spline_variant = (int) get_int(ai, "spline_variant", -1);
        }
    }

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
    if (!sha256_hex(out->data(), out->size(), &digest)) {
        fprintf(hook_log, "[track_manifest] could not hash %s to verify it\n",
                asset.sha256.c_str());
        fflush(hook_log);
        return false;
    }
    if (!equals_ignoring_case(digest, asset.sha256)) {
        // Not the asset its name claims, so nothing can use it; removing it is what lets the next
        // download fetch a good copy instead of skipping a hash the store already "has".
        std::error_code ec;
        fs::remove(path, ec);
        fprintf(hook_log, "[track_manifest] %s hashes to %s -- corrupted or not the asset the "
                          "manifest names; removed from the store\n",
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
