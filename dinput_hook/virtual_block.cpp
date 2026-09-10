#include "virtual_block.h"

#include <cstring>
#include <optional>

#include "hook_helper.h"

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
    // falls in a hole. Regions are sorted, so this is a walk; a block load reads one payload
    // section at a time, so the linear scan stays short in practice.
    const VirtualRegion *find_region(const VirtualBlockView &view, long offset, size_t size) {
        for (const VirtualRegion &region: view.regions) {
            if (offset < region.virtual_offset)
                break;
            if (offset + (long) size <= region.virtual_offset + (long) region.size)
                return &region;
        }
        return nullptr;
    }
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

// 0x0042d680
void swrLoader_OpenBlock_delta(swrLoader_TYPE type) {
    // The real file is opened either way: a view falls back to it for every entry it does not
    // override, and the game's own handle is what the original ReadAt uses.
    hook_call_original(swrLoader_OpenBlock, type);
}

// 0x0042d640
size_t swrLoader_ReadAt_delta(swrLoader_TYPE type, long offset, void *dst, size_t size) {
    if (!valid_type(type) || !views[type].has_value())
        return hook_call_original(swrLoader_ReadAt, type, offset, dst, size);

    const VirtualBlockView &view = *views[type];

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
                "[virtual_block] %s block closed: %u header, %u memory, %u file, %u unmapped "
                "read(s)\n",
                type_name(type), s.from_header, s.from_memory, s.from_file, s.unmapped);
        fflush(hook_log);
        stats[type] = {};
    }

    hook_call_original(swrLoader_CloseBlock, type);
}

void virtual_block_RegisterHooks() {
    // All three are reverse-hooked (registered in hook_generated) -> replace only.
    hook_replace(swrLoader_OpenBlock, swrLoader_OpenBlock_delta);
    hook_replace(swrLoader_ReadAt, swrLoader_ReadAt_delta);
    hook_replace(swrLoader_CloseBlock, swrLoader_CloseBlock_delta);
}
