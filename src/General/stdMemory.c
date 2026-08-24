#include "stdMemory.h"

#include "macros.h"
#include "globals.h"
#include "engine_config.h"

#include <Platform/cstdlib.h>
#include <string.h>

// Arena allocator for small blocks (<= DAALLOC_SMALL_ALLOC_MAX). Serves the request from a
// per-page free list by best fit, splitting the chosen free block and refreshing the arena's
// cached largest-free-block hint; grows a new page (or falls back to daSmallAlloc) when needed.
// 0x0048d7e0
void* daAlloc(uint32_t size)
{
    if (DAALLOC_SMALL_ALLOC_MAX < size) {
        return daSmallAlloc(size);
    }

    uint32_t needed = (size + 3) & ~3u;// round the payload up to 4 bytes
    uint32_t needTotal = needed + 8;// + block header

    // Find an in-use arena whose cached free block is big enough (stop at the first free slot).
    int slot = 0;
    while (slot < DAALLOC_ARENA_COUNT) {
        if (daAlloc_struct[slot].inUse == 0 || needed <= daAlloc_struct[slot].bestFreeSize) {
            break;
        }
        slot++;
    }

    // None fit: claim a free/empty slot and carve it a fresh page.
    if (slot == DAALLOC_ARENA_COUNT || daAlloc_struct[slot].inUse == 0) {
        slot = 0;
        while (slot < DAALLOC_ARENA_COUNT) {
            if (daAlloc_struct[slot].inUse == 0 || daAlloc_struct[slot].page == NULL) {
                break;
            }
            slot++;
        }
        if (slot == DAALLOC_ARENA_COUNT) {
            return daSmallAlloc(needed);
        }

        daBlock* page = (daBlock*) malloc(DAALLOC_PAGE_SIZE);
        if (page == NULL) {
            return daSmallAlloc(needed);
        }

        daArena* arena = &daAlloc_struct[slot];
        arena->page = page;
        arena->bestFree = page;
        arena->bestFreeSize = DAALLOC_PAGE_SIZE - 16;
        arena->inUse = 1;

        // one free block spanning the page, followed by a zero-size end sentinel
        page->size = DAALLOC_PAGE_SIZE - 8;
        page->prevSize = 0;
        page->owner = arena;
        daBlock* sentinel = (daBlock*) ((char*) page + (DAALLOC_PAGE_SIZE - 8));
        sentinel->size = 0;
        sentinel->prevSize = DAALLOC_PAGE_SIZE - 8;
        sentinel->owner = arena;
    }

    daArena* arena = &daAlloc_struct[slot];

    // best fit: the free block that leaves the smallest leftover
    daBlock* best = NULL;
    uint16_t bestLeftover = DAALLOC_PAGE_SIZE;
    for (daBlock* b = (daBlock*) arena->page; b->size != 0;) {
        uint16_t step = b->size;
        if ((b->size & DABLOCK_ALLOCATED) == 0) {
            uint16_t leftover = (uint16_t) (b->size - needTotal);
            if (leftover < bestLeftover) {
                best = b;
                bestLeftover = leftover;
            }
        } else {
            step &= DABLOCK_SIZE_MASK;
        }
        b = (daBlock*) ((char*) b + step);
    }

    // allocate, splitting the remainder into a new free block
    uint16_t origSize = best->size;
    best->size = (uint16_t) needTotal | DABLOCK_ALLOCATED;
    if (origSize != needTotal) {
        daBlock* split = (daBlock*) ((char*) best + needTotal);
        split->size = (uint16_t) (origSize - needTotal);
        split->prevSize = (uint16_t) needTotal;
        ((daBlock*) ((char*) best + origSize))->prevSize = (uint16_t) (origSize - needTotal);
    }
    best->owner = arena;

    // if we consumed the cached largest-free block, rescan for the new largest
    if (best == arena->bestFree) {
        daBlock* largest = NULL;
        uint16_t largestSize = 8;
        for (daBlock* b = (daBlock*) arena->page; b->size != 0;) {
            uint16_t step = b->size;
            if ((b->size & DABLOCK_ALLOCATED) == 0) {
                if (largestSize < b->size) {
                    largestSize = b->size;
                    largest = b;
                }
            } else {
                step &= DABLOCK_SIZE_MASK;
            }
            b = (daBlock*) ((char*) b + step);
        }
        arena->bestFree = largest;
        arena->bestFreeSize = (largestSize > 8) ? (uint16_t) (largestSize - 8) : 0;
    }

    return best + 1;
}

// Free a daAlloc / daSmallAlloc block. Standalone blocks (owner == NULL) go straight to free();
// arena blocks are coalesced with any free neighbours and the arena's largest-free hint refreshed,
// releasing the whole page back to free() once it is entirely free again.
// 0x0048d9a0
void daFree(void* alloc)
{
    daBlock* block = (daBlock*) ((char*) alloc - 8);
    daArena* owner = block->owner;
    if (owner == NULL) {
        free(block);
        return;
    }

    if ((block->size & DABLOCK_ALLOCATED) == 0 ||
        (uint16_t) (owner - &daAlloc_struct[0]) > DAALLOC_ARENA_COUNT - 1) {
        (*stdPlatform_hostServices_ptr->warningPrint)(
            "Attempting to dispose a bogus or already-disposed-of block!");
        return;
    }

    uint32_t merged = block->size & DABLOCK_SIZE_MASK;
    // coalesce with the following block if it is free
    daBlock* next = (daBlock*) ((char*) block + merged);
    if ((next->size & DABLOCK_ALLOCATED) == 0) {
        merged += next->size;
    }
    // coalesce with the preceding block if it is free
    daBlock* prev = (daBlock*) ((char*) block - block->prevSize);
    if ((prev->size & DABLOCK_ALLOCATED) == 0) {
        merged += prev->size;
        block = prev;
    }

    uint16_t mergedSize = (uint16_t) merged;
    block->size = mergedSize;
    ((daBlock*) ((char*) block + mergedSize))->prevSize = mergedSize;

    uint32_t usable = mergedSize - 8;
    if (owner->bestFreeSize < usable) {
        if (mergedSize == DAALLOC_PAGE_SIZE - 8) {// the block now spans the whole page
            free(owner->page);
            owner->page = NULL;
            owner->bestFreeSize = 0;
            owner->bestFree = NULL;
            return;
        }
        owner->bestFreeSize = usable;
        owner->bestFree = block;
    }
}

// Resize a daAlloc / daSmallAlloc block: allocate the new size, copy across the smaller of the
// request and the old payload, then free the old block. NULL old behaves as daAlloc; size 0 as daFree.
// 0x0048da80
void* daRealloc(void* old, uint32_t size)
{
    if (old == NULL) {
        return daAlloc(size);
    }
    if (size == 0) {
        daFree(old);
        return NULL;
    }

    void* neu = daAlloc(size);

    uint32_t oldSize;
    if (((daBlock*) ((char*) old - 8))->owner == NULL) {
        oldSize = *(uint32_t*) ((char*) old - 8);// daSmallAlloc: full size_t size header
    } else {
        oldSize = *(uint16_t*) ((char*) old - 8) & ~DABLOCK_ALLOCATED;// arena block size (mask alloc bit)
    }

    if (neu == NULL) {
        return NULL;
    }

    uint32_t copy = (oldSize - 8 <= size) ? (oldSize - 8) : size;
    memcpy(neu, old, copy);
    daFree(old);
    return neu;
}

// Fallback allocator for requests the daAlloc arena can't serve (oversized, or all arena
// slots full): a plain malloc of size + an 8-byte header. The header's second word is 0,
// which is the owner-arena pointer daFree checks to tell a standalone block (free()) from
// an arena block. Returns the user pointer 8 bytes past the header.
// 0x0048db10
void* daSmallAlloc(int size)
{
    size_t* alloc = (size_t*)malloc(size + 8);
    if (alloc == NULL)
        return NULL;
    alloc[0] = size + 8;
    alloc[1] = 0;
    return alloc + 2;
}
