#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#define RDCACHE_MAX_VERTICES (0x14000U) // something wrong with references
#define RDCACHE_MAX_TRIS (0x400)
// Free vertex-pool headroom rdCache_GetProcEntry keeps in reserve so the
// worst-case single face returned by it always fits before the next flush.
#define RDCACHE_MIN_FREE_VERTICES (0x50)

// daAlloc arena allocator (stdMemory.c).
#define DAALLOC_PAGE_SIZE (0x7c00)       // bytes per arena page, malloc'd on demand
#define DAALLOC_ARENA_COUNT (0x421)      // number of daAlloc_struct arena slots (1057)
#define DAALLOC_SMALL_ALLOC_MAX (0x1000) // requests larger than this bypass the arena (daSmallAlloc)

// Save / profile persistence (elfSaveLoad, swrRace.c).
#define ELFSAVE_VERSION_MAGIC (0x10003)      // 4-byte magic prefixed to tgfd.dat and .sav profile exports
#define ELFSAVE_NB_TRACKS (25)               // tracks in the record tables (x2 slots each: normal + mirror)
#define ELFSAVE_RECORD_TIME_EMPTY (3599.99f) // record-slot default; at/above this the UI shows "--:--.---"
#define ELFSAVE_DEFAULT_PILOTS (0x22e01)     // pilot-unlock bitfield of a fresh profile
#define ELFSAVE_DEFAULT_TRUGUTS (400)        // starting currency of a fresh profile

#endif // ENGINE_CONFIG_H
