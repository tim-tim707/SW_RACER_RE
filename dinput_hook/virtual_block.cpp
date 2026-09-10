#include "virtual_block.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>

#include "hook_helper.h"
#include "patch.h"

extern "C" FILE *hook_log;

namespace {
    // Indexed by swrLoader_TYPE, which the game uses as a small dense enum.
    constexpr int NUM_BLOCK_TYPES = 4;

    std::optional<VirtualBlockView> views[NUM_BLOCK_TYPES];

    // Reads served from a view vs delegated to the file, per type. Reported on close so a load can
    // be seen to have gone through the view without logging every read (there are thousands).
    struct ReadStats {
        uint32_t from_header;
        uint32_t from_memory;
        uint32_t from_file;
        uint32_t unmapped;
        uint32_t wrong_block;// the path was swapped, so the view does not describe this file
    };
    ReadStats stats[NUM_BLOCK_TYPES];

    bool valid_type(swrLoader_TYPE type) {
        return (int) type >= 0 && (int) type < NUM_BLOCK_TYPES;
    }

    const char *type_name(swrLoader_TYPE type) {
        switch (type) {
            case swrLoader_TYPE_MODEL_BLOCK:
                return "model";
            case swrLoader_TYPE_SPRITE_BLOCK:
                return "sprite";
            case swrLoader_TYPE_SPLINE_BLOCK:
                return "spline";
            case swrLoader_TYPE_TEXTURE_BLOCK:
                return "texture";
            default:
                return "?";
        }
    }

    // The region covering [offset, offset + size), or nullptr when the read spans a boundary or
    // falls in a hole.
    const VirtualRegion *find_region(const VirtualBlockView &view, long offset, size_t size) {
        // A full layout holds one region per block entry (~1700 for textures), so search rather
        // than walk.
        auto it = std::upper_bound(view.regions.begin(), view.regions.end(), offset,
                                   [](long value, const VirtualRegion &region) {
                                       return value < region.virtual_offset;
                                   });
        if (it == view.regions.begin())
            return nullptr;

        --it;
        if (offset + (long) size <= it->virtual_offset + (long) it->size)
            return &*it;
        return nullptr;
    }
}

namespace {
    // Words per table entry. The loader reads a model entry as three consecutive words
    // (mask_off, model_off, and the next entry's mask_off as its end), a texture entry as two
    // (pixels_off, palette_off, ending where the next entry's pixels begin) and a spline entry as
    // one (ending at the next entry's offset). Every layout therefore needs one extra slot past
    // the last entry to terminate it.
    int table_words(swrLoader_TYPE type) {
        switch (type) {
            case swrLoader_TYPE_MODEL_BLOCK:
            case swrLoader_TYPE_TEXTURE_BLOCK:
                return 2;
            case swrLoader_TYPE_SPLINE_BLOCK:
                return 1;
            default:
                return 0;
        }
    }

    uint32_t read_be32(const std::vector<uint8_t> &bytes, size_t offset) {
        return (uint32_t) bytes[offset] << 24 | (uint32_t) bytes[offset + 1] << 16 |
            (uint32_t) bytes[offset + 2] << 8 | (uint32_t) bytes[offset + 3];
    }

    void write_be32(std::vector<uint8_t> &bytes, size_t offset, uint32_t value) {
        bytes[offset] = (uint8_t) (value >> 24);
        bytes[offset + 1] = (uint8_t) (value >> 16);
        bytes[offset + 2] = (uint8_t) (value >> 8);
        bytes[offset + 3] = (uint8_t) value;
    }

    // One entry of the source block: where its payload starts and ends, and where its second
    // section begins relative to the start (0 when it has none).
    struct SourceEntry {
        uint32_t begin;
        uint32_t end;
        uint32_t split;
    };

    bool read_source_entries(swrLoader_TYPE type, const char *path,
                             std::vector<SourceEntry> *entries) {
        FILE *f = fopen(path, "rb");
        if (!f)
            return false;

        const int words = table_words(type);
        uint8_t count_bytes[4] = {};
        if (fread(count_bytes, 1, sizeof(count_bytes), f) != sizeof(count_bytes)) {
            fclose(f);
            return false;
        }
        const uint32_t count = (uint32_t) count_bytes[0] << 24 | (uint32_t) count_bytes[1] << 16 |
            (uint32_t) count_bytes[2] << 8 | count_bytes[3];

        // The table plus its terminating slot.
        std::vector<uint8_t> table(4u * words * (count + 1));
        if (table.empty() || fread(table.data(), 1, table.size(), f) != table.size()) {
            fclose(f);
            return false;
        }
        fclose(f);

        entries->resize(count);
        for (uint32_t i = 0; i < count; i++) {
            const uint32_t first = read_be32(table, 4u * words * i);
            const uint32_t next_first = read_be32(table, 4u * words * (i + 1));
            uint32_t split = 0;
            if (words == 2) {
                const uint32_t second = read_be32(table, 4u * words * i + 4);
                // A texture with no palette stores 0; a model's second section always follows.
                split = second != 0 ? second - first : 0;
            }
            (*entries)[i] = {first, next_first, split};
        }
        return true;
    }
}

bool virtual_block_BuildView(swrLoader_TYPE type, const char *source_path,
                             std::vector<VirtualOverride> overrides, VirtualBlockView *out) {
    const int words = table_words(type);
    if (words == 0 || source_path == nullptr || out == nullptr)
        return false;

    std::vector<SourceEntry> source;
    if (!read_source_entries(type, source_path, &source)) {
        fprintf(hook_log, "[virtual_block] cannot read source block '%s'\n", source_path);
        fflush(hook_log);
        return false;
    }

    uint32_t count = (uint32_t) source.size();
    for (const VirtualOverride &override_entry: overrides) {
        if (override_entry.payload.empty() || override_entry.split > override_entry.payload.size()) {
            fprintf(hook_log, "[virtual_block] malformed override for entry %u\n",
                    override_entry.index);
            fflush(hook_log);
            return false;
        }
        count = count > override_entry.index + 1 ? count : override_entry.index + 1;
    }

    VirtualBlockView view;
    view.source_path = source_path;
    view.owned.reserve(overrides.size());

    // Payloads start past the table; the whole table is synthesized, so nothing depends on the
    // source block's own header size.
    const size_t header_size = 4u + 4u * words * (count + 1);
    view.header.assign(header_size, 0);
    write_be32(view.header, 0, count);

    long cursor = (long) header_size;
    for (uint32_t i = 0; i < count; i++) {
        VirtualOverride *replacement = nullptr;
        for (VirtualOverride &candidate: overrides) {
            if (candidate.index == i) {
                replacement = &candidate;
                break;
            }
        }

        uint32_t size = 0;
        uint32_t split = 0;
        if (replacement != nullptr) {
            split = replacement->split;
            view.owned.push_back(std::move(replacement->payload));
            size = (uint32_t) view.owned.back().size();
            view.regions.push_back({cursor, size, view.owned.back().data(), 0});
        } else if (i < source.size() && source[i].end > source[i].begin) {
            size = source[i].end - source[i].begin;
            split = source[i].split;
            view.regions.push_back({cursor, size, nullptr, (long) source[i].begin});
        } else {
            // An index past the source block that nothing overrides: leave it empty rather than
            // pointing the game at bytes that do not exist.
            write_be32(view.header, 4u + 4u * words * i, (uint32_t) cursor);
            if (words == 2)
                write_be32(view.header, 4u + 4u * words * i + 4, 0);
            continue;
        }

        write_be32(view.header, 4u + 4u * words * i, (uint32_t) cursor);
        if (words == 2)
            write_be32(view.header, 4u + 4u * words * i + 4, split != 0 ? (uint32_t) cursor + split : 0);
        cursor += size;
    }
    // Terminating slot: the last entry ends here.
    write_be32(view.header, 4u + 4u * words * count, (uint32_t) cursor);

    *out = std::move(view);
    return true;
}

void virtual_block_Install(swrLoader_TYPE type, VirtualBlockView view) {
    if (!valid_type(type))
        return;

    views[type] = std::move(view);
    stats[type] = {};
    fprintf(hook_log, "[virtual_block] installed %s view: %u byte header, %u region(s)\n",
            type_name(type), (unsigned) views[type]->header.size(),
            (unsigned) views[type]->regions.size());
    fflush(hook_log);
}

void virtual_block_Remove(swrLoader_TYPE type) {
    if (!valid_type(type) || !views[type].has_value())
        return;

    fprintf(hook_log, "[virtual_block] removed %s view\n", type_name(type));
    fflush(hook_log);
    views[type].reset();
}

bool virtual_block_IsInstalled(swrLoader_TYPE type) {
    return valid_type(type) && views[type].has_value();
}

namespace {
    typedef FILE **(*swrLoader_TypeToFileFn)(swrLoader_TYPE);

    FILE *block_handle(swrLoader_TYPE type) {
        FILE **file = ((swrLoader_TypeToFileFn) swrLoader_TypeToFile_ADDR)(type);
        return file ? *file : nullptr;
    }

    // The path pointer the game reads when it opens a block. Swapping these is how a custom track
    // substitutes its own archive (custom_tracks.cpp); the sprite block is never swapped.
    const char **block_path(swrLoader_TYPE type) {
        switch (type) {
            case swrLoader_TYPE_SPLINE_BLOCK:
                return (const char **) 0x004B9590;
            case swrLoader_TYPE_TEXTURE_BLOCK:
                return (const char **) 0x004B9594;
            case swrLoader_TYPE_MODEL_BLOCK:
                return (const char **) 0x004B9598;
            default:
                return nullptr;
        }
    }

    // Opens are frequent; only a change of the path a block reads is worth a line.
    std::string last_open_path[NUM_BLOCK_TYPES];
}

// 0x0042d680
void swrLoader_OpenBlock_delta(swrLoader_TYPE type) {
    // The game opens a block only when its handle is NULL, so a path swap while the handle is still
    // open is silently ignored and the next read comes from the previous archive. Log what the
    // handle and the path pointer are on the way in; a mismatch is the bug.
    const char **path = block_path(type);
    if (path != nullptr && valid_type(type) && last_open_path[type] != (*path ? *path : "")) {
        last_open_path[type] = *path ? *path : "";
        fprintf(hook_log, "[virtual_block] %s block now reads '%s' (handle=%p on entry)\n",
                type_name(type), last_open_path[type].c_str(), (const void *) block_handle(type));
        fflush(hook_log);
    }

    // The real file is opened either way: a view falls back to it for every entry it does not
    // override, and the game's own handle is what the original ReadAt uses.
    hook_call_original(swrLoader_OpenBlock, type);
}

// 0x0042d640
size_t swrLoader_ReadAt_delta(swrLoader_TYPE type, long offset, void *dst, size_t size) {
    if (!valid_type(type) || !views[type].has_value())
        return hook_call_original(swrLoader_ReadAt, type, offset, dst, size);

    const VirtualBlockView &view = *views[type];

    // A view's fall-through offsets only mean anything in the block it was built from, and a
    // custom track swaps the block path out from under us. Serve the real file instead.
    const char **path = block_path(type);
    if (path != nullptr && *path != nullptr && view.source_path != *path) {
        stats[type].wrong_block++;
        return hook_call_original(swrLoader_ReadAt, type, offset, dst, size);
    }

    if (offset >= 0 && offset + (long) size <= (long) view.header.size()) {
        memcpy(dst, view.header.data() + offset, size);
        stats[type].from_header++;
        return 1;// the original returns fread's element count
    }

    if (const VirtualRegion *region = find_region(view, offset, size)) {
        const long within = offset - region->virtual_offset;
        if (region->memory != nullptr) {
            memcpy(dst, region->memory + within, size);
            stats[type].from_memory++;
            return 1;
        }
        stats[type].from_file++;
        return hook_call_original(swrLoader_ReadAt, type, region->file_offset + within, dst, size);
    }

    // Not covered by the view: pass the read through unchanged rather than failing it, so a
    // consumer we have not accounted for still sees the real block.
    stats[type].unmapped++;
    return hook_call_original(swrLoader_ReadAt, type, offset, dst, size);
}

// 0x0042d6f0
void swrLoader_CloseBlock_delta(swrLoader_TYPE type) {
    if (valid_type(type) && views[type].has_value()) {
        const ReadStats &s = stats[type];
        fprintf(hook_log,
                "[virtual_block] %s block closed: %u header, %u memory, %u file, %u unmapped, "
                "%u other-block read(s)\n",
                type_name(type), s.from_header, s.from_memory, s.from_file, s.unmapped,
                s.wrong_block);
        fflush(hook_log);
        stats[type] = {};
    }

    hook_call_original(swrLoader_CloseBlock, type);
}

// Replacing a reverse-hooked function detours the stock address but leaves the decomp reimpl in
// src/ unpatched, so delta code that calls the reimpl symbol stops reaching the stock code and
// runs the dormant body instead. For this family that is a real behaviour change:
// src/Swr/swrLoader.c's swrLoader_OpenBlock has the block paths hardcoded, while the stock code
// reads them from the pointers a custom track swaps -- so swrModel_InitializeTextureBuffer_delta,
// which calls the reimpl symbol, would silently re-open the stock archive and size the texture
// buffer from it (custom-track textures then render white). Route the reimpl at our delta too, so
// every caller lands in one place regardless of which symbol it called.
static void route_reimpl_to_delta(void *reimpl, void *delta) {
    uint8_t jmp[5] = {0xE9};
    const int32_t rel = (int32_t) ((uintptr_t) delta - ((uintptr_t) reimpl + sizeof(jmp)));
    memcpy(&jmp[1], &rel, sizeof(rel));
    WriteMemory("virtual_block", reimpl, jmp, sizeof(jmp));
}

namespace {
    // A discrete chunk as extract_raw_asset.py writes it: magic, one or two little-endian sizes,
    // then the payload sections verbatim. The container tells us where an entry's second section
    // starts, which is what the block's table has to encode.
    bool read_chunk(const std::filesystem::path &path, uint32_t index, VirtualOverride *out) {
        FILE *f = fopen(path.generic_string().c_str(), "rb");
        if (!f)
            return false;

        char magic[4] = {};
        uint32_t first = 0;
        uint32_t second = 0;
        if (fread(magic, 1, sizeof(magic), f) != sizeof(magic) || fread(&first, 4, 1, f) != 1) {
            fclose(f);
            return false;
        }

        const bool two_sections = memcmp(magic, "RAWM", 4) == 0 || memcmp(magic, "RAWT", 4) == 0;
        if (two_sections && fread(&second, 4, 1, f) != 1) {
            fclose(f);
            return false;
        }
        if (!two_sections && memcmp(magic, "RAWS", 4) != 0) {
            fclose(f);
            return false;
        }

        std::vector<uint8_t> payload(first + second);
        const bool complete =
            payload.empty() || fread(payload.data(), 1, payload.size(), f) == payload.size();
        fclose(f);
        if (!complete || payload.empty())
            return false;

        // RAWT with no palette has one section; RAWM always has two (mask then model).
        *out = {index, std::move(payload), second != 0 ? first : 0u};
        return true;
    }

    // ./assets/replacement_blocks/<model|spline|texture>/<entry index>.bin
    std::vector<VirtualOverride> load_folder_overrides(swrLoader_TYPE type) {
        std::vector<VirtualOverride> overrides;
        const std::filesystem::path folder =
            std::filesystem::path("./assets/replacement_blocks") / type_name(type);
        std::error_code ec;
        if (!std::filesystem::is_directory(folder, ec))
            return overrides;

        for (const auto &entry: std::filesystem::directory_iterator(folder, ec)) {
            if (!entry.is_regular_file())
                continue;

            const std::string stem = entry.path().stem().generic_string();
            if (stem.empty() || stem.find_first_not_of("0123456789") != std::string::npos)
                continue;

            VirtualOverride loaded;
            if (!read_chunk(entry.path(), (uint32_t) std::stoul(stem), &loaded)) {
                fprintf(hook_log, "[virtual_block] ignoring %s: not a readable chunk\n",
                        entry.path().generic_string().c_str());
                fflush(hook_log);
                continue;
            }
            fprintf(hook_log, "[virtual_block] %s entry %u <- %s (%u bytes, split %u)\n",
                    type_name(type), loaded.index, entry.path().filename().generic_string().c_str(),
                    (unsigned) loaded.payload.size(), loaded.split);
            overrides.push_back(std::move(loaded));
        }
        fflush(hook_log);
        return overrides;
    }
}

// Install a view per block type for whatever discrete chunks are on disk. Runs before the game
// touches a block, while the path pointers still name the stock archives.
void virtual_block_LoadFolderOverrides() {
    const swrLoader_TYPE types[] = {swrLoader_TYPE_MODEL_BLOCK, swrLoader_TYPE_SPLINE_BLOCK,
                                    swrLoader_TYPE_TEXTURE_BLOCK};
    for (swrLoader_TYPE type: types) {
        std::vector<VirtualOverride> overrides = load_folder_overrides(type);
        if (overrides.empty())
            continue;

        const char **path = block_path(type);
        VirtualBlockView view;
        if (path != nullptr && *path != nullptr &&
            virtual_block_BuildView(type, *path, std::move(overrides), &view))
            virtual_block_Install(type, std::move(view));
    }
}

void virtual_block_RegisterHooks() {
    // All three are reverse-hooked (registered in hook_generated) -> replace only.
    hook_replace(swrLoader_OpenBlock, swrLoader_OpenBlock_delta);
    hook_replace(swrLoader_ReadAt, swrLoader_ReadAt_delta);
    hook_replace(swrLoader_CloseBlock, swrLoader_CloseBlock_delta);

    route_reimpl_to_delta((void *) swrLoader_OpenBlock, (void *) swrLoader_OpenBlock_delta);
    route_reimpl_to_delta((void *) swrLoader_ReadAt, (void *) swrLoader_ReadAt_delta);
    route_reimpl_to_delta((void *) swrLoader_CloseBlock, (void *) swrLoader_CloseBlock_delta);

    virtual_block_LoadFolderOverrides();
}
