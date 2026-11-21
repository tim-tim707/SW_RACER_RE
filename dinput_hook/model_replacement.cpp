#include "model_replacement.h"

#include "custom_tracks.h"// SWR_MODELBLOCK_PATH_PTR
#include "game_deltas/pod_edits.h"// pod_workspace (the pod editor's baked models)

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <regex>
#include <windows.h>// MoveFileExW
#include <string>
#include <vector>

extern "C" {
#include "game_deltas/tracks_delta.h"// CUSTOM_TRACK_MODELID_BEGIN
}

extern "C" FILE *hook_log;

bool enable_model_replacement = true;

namespace fs = std::filesystem;



static std::map<int, fs::path> replacement_models;
static std::map<int, std::string> skipped_replacements;
static bool loaded_replacement_models_at_least_once = false;

static const char *saved_modelblock_path = nullptr;
static std::string temp_block_path_storage;// keeps the swapped-in path alive

// The folders holding replacement models: the game's, then the pod editor's workspace
// (Desktop/SWEP1R Pod Editor/replacement_models, written by its Build & install), which wins.
static std::vector<fs::path> replacement_dirs() {
    std::vector<fs::path> dirs = {"./assets/replacement_models/"};
    if (!pod_workspace().empty())
        dirs.push_back(pod_workspace() / L"replacement_models");
    return dirs;
}

// Folder change stamps at the last scan: a model built while the game runs is picked up at the
// next model load (adding / replacing a file changes its folder's write time).
static std::vector<fs::file_time_type> scanned_stamps;
static std::vector<fs::file_time_type> folder_stamps() {
    std::vector<fs::file_time_type> out;
    for (const fs::path &d: replacement_dirs()) {
        std::error_code ec;
        out.push_back(fs::last_write_time(d, ec));
    }
    return out;
}

void refresh_replacement_models() {
    loaded_replacement_models_at_least_once = true;
    replacement_models.clear();
    skipped_replacements.clear();
    scanned_stamps = folder_stamps();

    const static std::regex file_regex("([0-9]+)\\.bin");
    for (const fs::path &dir: replacement_dirs()) {
        std::error_code ec;
        if (!fs::is_directory(dir, ec))
            continue;
        for (const auto &entry: fs::recursive_directory_iterator(dir, ec)) {
            if (!entry.is_regular_file())
                continue;

            const std::string filename = entry.path().filename().generic_string();
            std::smatch match;
            if (std::regex_match(filename, match, file_regex)) {
                const int id = std::stoi(match.str(1));
                // A model built by the pod editor carries <id>.base: the fingerprint of the base model it
                // was built from. If this game's base model for that id is different (the file came from
                // other game data), it would load as garbage or not at all: leave it out and say so.
                {
                    std::ifstream stamp(fs::path(entry.path()).replace_extension(L".base"));
                    std::string want;
                    if (stamp && std::getline(stamp, want)) {
                        while (!want.empty() && (want.back() == '\r' || want.back() == ' '))
                            want.pop_back();
                        std::vector<uint8_t> mask, data;
                        if (!want.empty() && read_base_model(id, mask, data)) {
                            const std::string have = model_fingerprint(mask, data);
                            if (have != want) {
                                skipped_replacements[id] = "built on a different version of model " + std::to_string(id) +
                                                           " (" + want + ") than this game has (" + have + ")";
                                fprintf(hook_log, "[model_replacement] ignoring %ls: %s\n", entry.path().c_str(),
                                        skipped_replacements[id].c_str());
                                continue;
                            }
                        }
                    }
                }
                replacement_models[id] = entry.path();
                fprintf(hook_log, "[model_replacement] found replacement for model %d: %ls\n", id,
                        entry.path().c_str());
            }
        }
    }
    fflush(hook_log);
}

bool try_prepare_loose_model(MODELID *model_id) {
    if (!enable_model_replacement)
        return false;

    if (!loaded_replacement_models_at_least_once || folder_stamps() != scanned_stamps)
        refresh_replacement_models();

    // only stock model ids; the custom-track id range is handled separately.
    if ((int) *model_id < 0 || (int) *model_id >= CUSTOM_TRACK_MODELID_BEGIN)
        return false;

    const auto it = replacement_models.find((int) *model_id);
    if (it == replacement_models.end())
        return false;

    const std::string src = it->second.generic_string();

    // read the raw chunk file (wide path: the workspace is on the user's Desktop)
    FILE *f = _wfopen(it->second.c_str(), L"rb");
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
    // The folder may not exist (a game folder without the mod's assets/ folder): make it.
    temp_block_path_storage = "./assets/replacement_models/.loose_model_cache.bin";
    std::error_code dir_ec;
    fs::create_directories(fs::path(temp_block_path_storage).parent_path(), dir_ec);
    FILE *out = fopen(temp_block_path_storage.c_str(), "wb");
    if (!out) {
        const int err = errno;
        fprintf(hook_log, "[model_replacement] could not write temp block %s (%s)\n", temp_block_path_storage.c_str(),
                strerror(err));
        // Still no (a read-only game folder?): the pod editor's workspace on the Desktop, by full path.
        if (!pod_workspace().empty()) {
            temp_block_path_storage = (pod_workspace() / L".loose_model_cache.bin").generic_string();
            out = fopen(temp_block_path_storage.c_str(), "wb");
            if (out)
                fprintf(hook_log, "[model_replacement] using %s for the temp block instead\n", temp_block_path_storage.c_str());
        }
        if (!out) {
            fprintf(hook_log, "[model_replacement] could not write the temp block anywhere: model replacement is off\n");
            fflush(hook_log);
            return false;
        }
    }
    fwrite(block.data(), 1, block.size(), out);
    fclose(out);

    // point the modelblock path at our temp block and remap to its single entry.
    saved_modelblock_path = *SWR_MODELBLOCK_PATH_PTR;
    *SWR_MODELBLOCK_PATH_PTR = temp_block_path_storage.c_str();
    fprintf(hook_log, "[model_replacement] replacing model %d from %s\n", (int) *model_id,
            src.c_str());
    fflush(hook_log);
    *model_id = (MODELID) 0;
    return true;
}

void finalize_loose_model() {
    if (saved_modelblock_path) {
        *SWR_MODELBLOCK_PATH_PTR = saved_modelblock_path;
        saved_modelblock_path = nullptr;
    }
}

// ---- writing the replacements into the game's model block -----------------------------------
// out_modelblock.bin: [u32 count][count x (u32 mask offset, u32 model offset)][u32 end], all
// big-endian, then each entry's mask + model data back to back (4-byte aligned).
namespace {
    uint32_t be32(const uint8_t *p) {
        return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) | ((uint32_t) p[2] << 8) | p[3];
    }
    void put_be32(std::vector<uint8_t> &v, size_t at, uint32_t x) {
        v[at] = (uint8_t) (x >> 24);
        v[at + 1] = (uint8_t) (x >> 16);
        v[at + 2] = (uint8_t) (x >> 8);
        v[at + 3] = (uint8_t) x;
    }
    bool read_file(const fs::path &p, std::vector<uint8_t> &out) {
        FILE *f = _wfopen(p.c_str(), L"rb");
        if (!f)
            return false;
        fseek(f, 0, SEEK_END);
        const long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        out.resize(n > 0 ? (size_t) n : 0);
        const bool ok = n >= 0 && fread(out.data(), 1, out.size(), f) == out.size();
        fclose(f);
        return ok;
    }
    // Replace `target` with `data` through a temp file (the game opens the block on each load).
    bool write_file_replacing(const fs::path &target, const std::vector<uint8_t> &data, std::string &msg) {
        const fs::path tmp = fs::path(target).concat(L".tmp");
        FILE *f = _wfopen(tmp.c_str(), L"wb");
        if (!f) {
            msg = "Cannot write " + tmp.string() + " (is the game folder read-only?)";
            return false;
        }
        const bool ok = fwrite(data.data(), 1, data.size(), f) == data.size();
        fclose(f);
        if (!ok || !MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            std::error_code ec;
            fs::remove(tmp, ec);
            msg = "Cannot replace " + target.string() + " (in use?)";
            return false;
        }
        return true;
    }
}// namespace

bool read_base_model(int id, std::vector<uint8_t> &mask, std::vector<uint8_t> &data) {
    std::error_code ec;
    const char *path = fs::exists(MODELBLOCK_ORIGINAL_PATH, ec) ? MODELBLOCK_ORIGINAL_PATH : MODELBLOCK_PATH;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = false;
    uint8_t head[4];
    if (id >= 0 && fread(head, 1, 4, f) == 4 && (uint32_t) id < be32(head)) {
        uint8_t w[12];
        if (fseek(f, 4 + 8 * id, SEEK_SET) == 0 && fread(w, 1, 12, f) == 12) {
            const uint32_t mask_off = be32(w), model_off = be32(w + 4), end = be32(w + 8);
            if (model_off >= mask_off && end >= model_off && end - mask_off < (64u << 20)) {
                mask.resize(model_off - mask_off);
                data.resize(end - model_off);
                ok = fseek(f, (long) mask_off, SEEK_SET) == 0 && fread(mask.data(), 1, mask.size(), f) == mask.size() &&
                     fread(data.data(), 1, data.size(), f) == data.size();
            }
        }
    }
    fclose(f);
    return ok;
}

std::string model_fingerprint(const std::vector<uint8_t> &mask, const std::vector<uint8_t> &data) {
    uint32_t h = 2166136261u;
    for (uint8_t b: mask) {
        h ^= b;
        h *= 16777619u;
    }
    for (uint8_t b: data) {
        h ^= b;
        h *= 16777619u;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%x.%x-%08x", (unsigned) mask.size(), (unsigned) data.size(), h);
    return buf;
}

const std::map<int, std::string> &skipped_replacement_models() {
    if (!loaded_replacement_models_at_least_once || folder_stamps() != scanned_stamps)
        refresh_replacement_models();
    return skipped_replacements;
}

const std::map<int, fs::path> &current_replacement_models() {
    if (!loaded_replacement_models_at_least_once || folder_stamps() != scanned_stamps)
        refresh_replacement_models();
    return replacement_models;
}

bool write_replacements_into_modelblock(std::string &msg) {
    std::error_code ec;
    // The stock block: the backup if one was kept, else the game's file (which becomes the backup).
    const bool have_backup = fs::exists(MODELBLOCK_ORIGINAL_PATH, ec);
    std::vector<uint8_t> stock;
    if (!read_file(have_backup ? MODELBLOCK_ORIGINAL_PATH : MODELBLOCK_PATH, stock) || stock.size() < 8) {
        msg = "Cannot read the model block.";
        return false;
    }
    const uint32_t count = be32(stock.data());
    const size_t header = 4 + 4 * (2 * (size_t) count + 1);
    if (count == 0 || count > 10000 || header > stock.size() || be32(&stock[4 + 8 * count]) != stock.size()) {
        msg = "The model block's header doesn't look right; nothing written.";
        return false;
    }
    const auto &repl = current_replacement_models();
    std::vector<uint8_t> out(header, 0);
    put_be32(out, 0, count);
    int replaced = 0;
    std::string ids;
    for (uint32_t i = 0; i < count; i++) {
        const uint32_t mask_off = be32(&stock[4 + 8 * i]), model_off = be32(&stock[8 + 8 * i]);
        const uint32_t end = be32(&stock[12 + 8 * i]);
        const uint8_t *mask = &stock[mask_off], *model = &stock[model_off];
        size_t mask_size = model_off - mask_off, model_size = end - model_off;
        std::vector<uint8_t> rawm;// a replacement: its mask + model instead of the stock ones
        auto it = repl.find((int) i);
        if (it != repl.end() && read_file(it->second, rawm) && rawm.size() >= 12 && memcmp(rawm.data(), "RAWM", 4) == 0) {
            uint32_t ms, mm;
            memcpy(&ms, &rawm[4], 4);
            memcpy(&mm, &rawm[8], 4);
            if (12 + (size_t) ms + mm == rawm.size() && ms % 4 == 0 && mm % 4 == 0) {
                mask = &rawm[12];
                model = &rawm[12 + ms];
                mask_size = ms;
                model_size = mm;
                replaced++;
                ids += (ids.empty() ? "" : ", ") + std::to_string(i);
            } else {
                fprintf(hook_log, "[model_replacement] %ls is not a valid RAWM file, kept the stock model %u\n",
                        it->second.c_str(), i);
            }
        }
        put_be32(out, 4 + 8 * i, (uint32_t) out.size());
        out.insert(out.end(), mask, mask + mask_size);
        put_be32(out, 8 + 8 * i, (uint32_t) out.size());
        out.insert(out.end(), model, model + model_size);
    }
    put_be32(out, 4 + 8 * count, (uint32_t) out.size());
    if (replaced == 0) {
        msg = "No replacement models to write (build one in the pod editor first).";
        return false;
    }
    if (!have_backup) {
        fs::copy_file(MODELBLOCK_PATH, MODELBLOCK_ORIGINAL_PATH, ec);
        if (ec) {
            msg = "Cannot keep the stock block as out_modelblock.original.bin: " + ec.message();
            return false;
        }
    }
    if (!write_file_replacing(MODELBLOCK_PATH, out, msg))
        return false;
    msg = "Wrote " + std::to_string(replaced) + " model(s) into out_modelblock.bin (" + ids +
          "). The stock block is kept as out_modelblock.original.bin. Restart the race to load them.";
    fprintf(hook_log, "[model_replacement] %s\n", msg.c_str());
    fflush(hook_log);
    return true;
}

bool restore_original_modelblock(std::string &msg) {
    std::error_code ec;
    if (!fs::exists(MODELBLOCK_ORIGINAL_PATH, ec)) {
        msg = "No out_modelblock.original.bin: the block is already the stock one.";
        return false;
    }
    std::vector<uint8_t> stock;
    if (!read_file(MODELBLOCK_ORIGINAL_PATH, stock)) {
        msg = "Cannot read out_modelblock.original.bin.";
        return false;
    }
    if (!write_file_replacing(MODELBLOCK_PATH, stock, msg))
        return false;
    fs::remove(MODELBLOCK_ORIGINAL_PATH, ec);
    msg = "Restored the stock out_modelblock.bin. Restart the race to load it.";
    fprintf(hook_log, "[model_replacement] %s\n", msg.c_str());
    fflush(hook_log);
    return true;
}
