#ifndef STD_MEMORY_H
#define STD_MEMORY_H

#include "types.h"

#define daAlloc_ADDR (0x0048d7e0)
#define daFree_ADDR (0x0048d9a0)
#define daRealloc_ADDR (0x0048da80)

void* daAlloc(uint32_t);
void daFree(void*);
void* daRealloc(void*, uint32_t);

#endif // STD_MEMORY_H
