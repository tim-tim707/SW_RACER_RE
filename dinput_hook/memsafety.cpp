#include "memsafety.h"

#if SWR_ASAN

#include "hook_helper.h"

#include <sanitizer/asan_interface.h>
#include <sanitizer/common_interface_defs.h>

#include <windows.h>
#include <cstdint>
#include <cstdio>

extern "C" {
#include <General/stdMemory.h>
#include <Swr/swrAssetBuffer.h>
#include <engine_config.h>
#include <types.h>
#include <types_enums.h>
#include <globals.h>
}

extern "C" void hook_function(const char *function_name, uint32_t original_address,
                              uint8_t *hook_address);

// Freed daAlloc blocks are held back this many frees before the game really releases them, so a
// stale pointer keeps hitting poison instead of a block the arena has already handed out again.
#define MEMSAFETY_QUARANTINE_BLOCKS (4096)

typedef void *(*daAllocFn)(uint32_t);
typedef void (*daFreeFn)(void *);
typedef void (*swrAssetBuffer_ResetToIndexFn)(int);
typedef void (*swrAssetBuffer_SetBufferFn)(char *);

static void *quarantine[MEMSAFETY_QUARANTINE_BLOCKS];
static uint32_t quarantineHead;

// Headers sit inside memory this file poisons, so every header read is uninstrumented.
__attribute__((no_sanitize("address"))) static daBlock *memsafety_BlockOf(void *p) {
    return (daBlock *) ((char *) p - sizeof(daBlock));
}

__attribute__((no_sanitize("address"))) static uint32_t memsafety_PayloadSize(void *p) {
    daBlock *block = memsafety_BlockOf(p);
    if (block->owner == NULL)
        return *(uint32_t *) block - sizeof(daBlock);// daSmallAlloc: full size_t header
    return (block->size & DABLOCK_SIZE_MASK) - sizeof(daBlock);
}

__attribute__((no_sanitize("address"))) static void memsafety_Release(void *p) {
    daBlock *block = memsafety_BlockOf(p);
    daArena *owner = block->owner;
    if (owner == NULL) {
        // Standalone blocks go back to the game's CRT heap, which reuses them without telling us.
        ASAN_UNPOISON_MEMORY_REGION(p, memsafety_PayloadSize(p));
        hook_call_original((daFreeFn) daFree_ADDR, p);
        return;
    }

    void *page = owner->page;
    hook_call_original((daFreeFn) daFree_ADDR, p);
    // A fully free page is returned to the CRT heap as well.
    if (page != NULL && owner->page == NULL)
        ASAN_UNPOISON_MEMORY_REGION(page, DAALLOC_PAGE_SIZE);
}

__attribute__((no_sanitize("address"))) static void *daAlloc_memsafety(uint32_t size) {
    void *p = hook_call_original((daAllocFn) daAlloc_ADDR, size);
    // Only the requested bytes: the 4-byte rounding slack stays poisoned and catches overruns.
    if (p != NULL)
        ASAN_UNPOISON_MEMORY_REGION(p, size);
    return p;
}

__attribute__((no_sanitize("address"))) static void daFree_memsafety(void *p) {
    if (p == NULL) {
        hook_call_original((daFreeFn) daFree_ADDR, p);
        return;
    }
    // A live block is never poisoned, so this only scans on a free of already-freed memory.
    if (__asan_address_is_poisoned(p)) {
        for (void *q: quarantine) {
            if (q == p) {
                fprintf(hook_log, "[memsafety] double daFree(%p); stack in the ASan report\n", p);
                fflush(hook_log);
                __sanitizer_print_stack_trace();
                return;
            }
        }
    }

    ASAN_POISON_MEMORY_REGION(p, memsafety_PayloadSize(p));

    void *evicted = quarantine[quarantineHead];
    quarantine[quarantineHead] = p;
    quarantineHead = (quarantineHead + 1) % MEMSAFETY_QUARANTINE_BLOCKS;
    if (evicted != NULL)
        memsafety_Release(evicted);
}

// Rewinding releases everything above the reset slot's base; poison it through to the arena end.
__attribute__((no_sanitize("address"))) static void swrAssetBuffer_ResetToIndex_memsafety(int index) {
    hook_call_original((swrAssetBuffer_ResetToIndexFn) swrAssetBuffer_ResetToIndex_ADDR, index);
    char *top = (&assetBuffer)[assetBufferIndex];
    if (top != NULL && top < assetBufferEnd)
        ASAN_POISON_MEMORY_REGION(top, assetBufferEnd - top);
}

// Loaders write the new asset first and bump the top afterwards; unpoison what the bump hands out.
__attribute__((no_sanitize("address"))) static void swrAssetBuffer_SetBuffer_memsafety(char *ptr) {
    char *oldTop = (&assetBuffer)[assetBufferIndex];
    hook_call_original((swrAssetBuffer_SetBufferFn) swrAssetBuffer_SetBuffer_ADDR, ptr);
    if (oldTop == NULL || ptr == NULL)
        return;
    if (ptr > oldTop)
        ASAN_UNPOISON_MEMORY_REGION(oldTop, ptr - oldTop);
    else if (ptr < oldTop)
        ASAN_POISON_MEMORY_REGION(ptr, oldTop - ptr);
}

extern "C" void memsafety_Init(void) {
    CreateDirectoryA("crashes", nullptr);// ignore ERROR_ALREADY_EXISTS
    __sanitizer_set_report_path("crashes\\asan");
    fprintf(hook_log, "[memsafety] AddressSanitizer build; reports go to crashes\\asan.<pid>\n");
    fflush(hook_log);
}

extern "C" void memsafety_RegisterHooks(void) {
    hook_function("daAlloc", (uint32_t) daAlloc_ADDR, (uint8_t *) daAlloc_memsafety);
    hook_function("daFree", (uint32_t) daFree_ADDR, (uint8_t *) daFree_memsafety);
    hook_function("swrAssetBuffer_ResetToIndex", (uint32_t) swrAssetBuffer_ResetToIndex_ADDR,
                  (uint8_t *) swrAssetBuffer_ResetToIndex_memsafety);
    hook_function("swrAssetBuffer_SetBuffer", (uint32_t) swrAssetBuffer_SetBuffer_ADDR,
                  (uint8_t *) swrAssetBuffer_SetBuffer_memsafety);
}

#else

extern "C" void memsafety_Init(void) {}
extern "C" void memsafety_RegisterHooks(void) {}

#endif
