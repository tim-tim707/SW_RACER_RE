#ifndef RDCACHE_H
#define RDCACHE_H

#include "types.h"

#define rdCache_GetProcEntry_ADDR (0x0048dba0)

#define rdCache_Flush_ADDR (0x0048dce0)

#define rdCache_AddProcFace_ADDR (0x0048de10)

// 0x0048dba0
// rdProcEntry*
void* rdCache_GetProcEntry(void);

// 0x0048dce0
void rdCache_Flush(void);

int rdCache_AddProcFace(unsigned int nbVertices, char flags);

#endif // RDCACHE_H
