#include "stdMemory.h"

#include "macros.h"

#include <Platform/cstdlib.h>

// 0x0048d7e0
void* daAlloc(uint32_t size)
{
    HANG("TODO");
    return NULL;
}

// 0x0048d9a0
void daFree(void* alloc)
{
    HANG("TODO");
}

// 0x0048da80
void* daRealloc(void* old, uint32_t size)
{
    HANG("TODO");
    return NULL;
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
