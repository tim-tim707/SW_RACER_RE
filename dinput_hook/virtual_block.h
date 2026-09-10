//
// Virtual asset blocks.
//
// Every packed block (model / spline / texture / sprite) is read through three functions --
// swrLoader_OpenBlock, swrLoader_ReadAt, swrLoader_CloseBlock -- and each is a flat
// [count][offset table][payloads] file, big-endian. Detouring those three lets a block be served
// from memory instead of from disk, so a custom track can supply its own model, spline and
// textures as discrete assets rather than shipping a rewritten copy of the game's whole archive
// (which is what assets/custom_tracks/ does today, via a block-path swap).
//
// A view describes the block the game should see: a synthesized header plus regions that each
// resolve either to memory we own or to a byte range of the real file. Nothing is registered yet,
// so with no view installed every call falls straight through to the original.
//
#pragma once

#include <cstdint>
#include <vector>

extern "C" {
#include <Swr/swrLoader.h>
}

// One payload region of the virtual block. Exactly one of `memory` / `file_offset` applies:
// memory != nullptr serves an override, otherwise the read is delegated to the real block file.
struct VirtualRegion {
    long virtual_offset;
    uint32_t size;
    const uint8_t *memory;
    long file_offset;
};

// The block the game sees in place of the file. `header` is served for reads below its end;
// everything past it is resolved through `regions` (sorted by virtual_offset, non-overlapping).
struct VirtualBlockView {
    std::vector<uint8_t> header;
    std::vector<VirtualRegion> regions;
    // Payload buffers the regions point into, kept alive for as long as the view is installed.
    std::vector<std::vector<uint8_t>> owned;
};

// Install / remove the view for one block type. Installing takes ownership of the view; removing
// returns the type to plain pass-through. A view must stay installed for as long as the game may
// read that block (i.e. across the load it was built for).
void virtual_block_Install(swrLoader_TYPE type, VirtualBlockView view);
void virtual_block_Remove(swrLoader_TYPE type);
bool virtual_block_IsInstalled(swrLoader_TYPE type);

void virtual_block_RegisterHooks();

// The three loader detours. With no view installed for `type` these are pass-throughs.
void swrLoader_OpenBlock_delta(swrLoader_TYPE type);
size_t swrLoader_ReadAt_delta(swrLoader_TYPE type, long offset, void *dst, size_t size);
void swrLoader_CloseBlock_delta(swrLoader_TYPE type);
