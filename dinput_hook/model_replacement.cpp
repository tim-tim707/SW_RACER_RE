#include "model_replacement.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <regex>
#include <string>
#include <vector>

extern "C" {
#include "game_deltas/tracks_delta.h"// CUSTOM_TRACK_MODELID_BEGIN
}

extern "C" FILE *hook_log;

bool enable_model_replacement = true;

namespace fs = std::filesystem;

// stock modelblock path pointer in the game's .data section (see custom_tracks.cpp).
static const char **const MODELBLOCK_PATH_PTR = (const char **) 0x4B9598;

static std::map<int, fs::path> replacement_models;
static bool loaded_replacement_models_at_least_once = false;

static const char *saved_modelblock_path = nullptr;
static std::string temp_block_path_storage;// keeps the swapped-in path alive

void refresh_replacement_models() {
    loaded_replacement_models_at_least_once = true;
    replacement_models.clear();

    const static std::regex file_regex("([0-9]+)\\.bin");
    const char *dir = "./assets/replacement_models/";
    if (!fs::is_directory(dir)) {
        fprintf(hook_log, "[model_replacement] folder %s does not exist, no model replacements.\n",
                dir);
        fflush(hook_log);
        return;
    }

    for (const auto &entry: fs::recursive_directory_iterator(dir)) {
        if (!entry.is_regular_file())
            continue;

        const std::string filename = entry.path().filename().generic_string();
        std::smatch match;
        if (std::regex_match(filename, match, file_regex)) {
            const int id = std::stoi(match.str(1));
            replacement_models[id] = entry.path();
            fprintf(hook_log, "[model_replacement] found replacement for model %d: %s\n", id,
                    entry.path().generic_string().c_str());
        }
    }
    fflush(hook_log);
}

bool try_prepare_loose_model(MODELID *model_id) {
    if (!enable_model_replacement)
        return false;

    if (!loaded_replacement_models_at_least_once)
        refresh_replacement_models();

    // only stock model ids; the custom-track id range is handled separately.
    if ((int) *model_id < 0 || (int) *model_id >= CUSTOM_TRACK_MODELID_BEGIN)
        return false;

    const auto it = replacement_models.find((int) *model_id);
    if (it == replacement_models.end())
        return false;

    const std::string src = it->second.generic_string();

    // read the raw chunk file
    FILE *f = fopen(src.c_str(), "rb");
    if (!f) {
        fprintf(hook_log, "[model_replacement] could not open %s\n", src.c_str());
        fflush(hook_log);
        return false;
    }
    fseek(f, 0, SEEK_END);
    const long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char magic[4] = {};
    uint32_t mask_size = 0;
    uint32_t model_size = 0;
    if (file_size < 12 || fread(magic, 1, 4, f) != 4 || fread(&mask_size, 4, 1, f) != 1 ||
        fread(&model_size, 4, 1, f) != 1 || memcmp(magic, "RAWM", 4) != 0 ||
        (long) (12 + mask_size + model_size) != file_size) {
        fprintf(hook_log, "[model_replacement] %s is not a valid raw chunk, ignoring.\n",
                src.c_str());
        fflush(hook_log);
        fclose(f);
        return false;
    }

    // assemble a single-entry modelblock:
    //   [count=1][W0=mask_off][W1=model_off][W2=end]  then mask payload then model payload.
    // all four header words are big-endian; the payloads are copied verbatim (already big-endian).
    const uint32_t header_size = 16;// count + 3 offset words
    const uint32_t mask_off = header_size;
    const uint32_t model_off = header_size + mask_size;
    const uint32_t end_off = header_size + mask_size + model_size;

    std::vector<uint8_t> block(end_off);
    const auto store_be = [&](uint32_t off, uint32_t v) {
        *(uint32_t *) &block[off] = __builtin_bswap32(v);
    };
    store_be(0, 1);
    store_be(4, mask_off);
    store_be(8, model_off);
    store_be(12, end_off);

    if (fread(&block[mask_off], 1, mask_size, f) != mask_size ||
        fread(&block[model_off], 1, model_size, f) != model_size) {
        fprintf(hook_log, "[model_replacement] short read on %s, ignoring.\n", src.c_str());
        fflush(hook_log);
        fclose(f);
        return false;
    }
    fclose(f);

    // write the assembled block next to the replacements, using a relative path under the
    // game dir (matches how custom tracks point the loader at a file, and avoids any
    // absolute-path quirks in the game's old CRT fopen).
    temp_block_path_storage = "./assets/replacement_models/.loose_model_cache.bin";
    FILE *out = fopen(temp_block_path_storage.c_str(), "wb");
    if (!out) {
        fprintf(hook_log, "[model_replacement] could not write temp block %s\n",
                temp_block_path_storage.c_str());
        fflush(hook_log);
        return false;
    }
    fwrite(block.data(), 1, block.size(), out);
    fclose(out);

    // point the modelblock path at our temp block and remap to its single entry.
    saved_modelblock_path = *MODELBLOCK_PATH_PTR;
    *MODELBLOCK_PATH_PTR = temp_block_path_storage.c_str();
    fprintf(hook_log, "[model_replacement] replacing model %d from %s\n", (int) *model_id,
            src.c_str());
    fflush(hook_log);
    *model_id = (MODELID) 0;
    return true;
}

void finalize_loose_model() {
    if (saved_modelblock_path) {
        *MODELBLOCK_PATH_PTR = saved_modelblock_path;
        saved_modelblock_path = nullptr;
    }
}
