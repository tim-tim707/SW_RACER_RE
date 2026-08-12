#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#define RDCACHE_MAX_VERTICES (0x14000U) // something wrong with references
#define RDCACHE_MAX_TRIS (0x400)
// Free vertex-pool headroom rdCache_GetProcEntry keeps in reserve so the
// worst-case single face returned by it always fits before the next flush.
#define RDCACHE_MIN_FREE_VERTICES (0x50)

// Geometry of the stdControl axis table (stdControl_aAxisPos / stdControl_aJoysticks).
// The engine reserves a fixed band of axis slots per joystick device, so device N's axes
// occupy [N * STDCONTROL_AXES_PER_JOYSTICK, +STDCONTROL_AXES_PER_JOYSTICK). The table is
// not a whole number of bands: the last device's band is clipped by the table size.
#define STDCONTROL_NUM_AXIS_SLOTS (15)
#define STDCONTROL_AXES_PER_JOYSTICK (6)

// daAlloc arena allocator (stdMemory.c).
#define DAALLOC_PAGE_SIZE (0x7c00)       // bytes per arena page, malloc'd on demand
#define DAALLOC_ARENA_COUNT (0x421)      // number of daAlloc_struct arena slots (1057)
#define DAALLOC_SMALL_ALLOC_MAX (0x1000) // requests larger than this bypass the arena (daSmallAlloc)

#endif // ENGINE_CONFIG_H
